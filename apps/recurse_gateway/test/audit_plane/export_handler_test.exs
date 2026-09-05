defmodule Recurse.Gateway.AuditPlane.ExportHandlerTest do
  @moduledoc """
  Contract tests for `Recurse.Gateway.AuditPlane.ExportHandler` (F002 T061 /
  FR-022). Cedar-gated by `Recurse::Action::ExportEvidence`; delegates to
  `Recurse.Gateway.AuditPlane.EvidenceZipBuilder`.

  `async: false` — BundleLoader + ProviderRegistry are singletons.
  """

  use ExUnit.Case, async: false

  setup_all do
    Recurse.Gateway.Test.KernelFixture.boot()
  end

  alias Recurse.Gateway.AuditPlane.ExportHandler
  alias Recurse.Gateway.Policy.BundleLoader
  alias Recurse.Gateway.ProviderRegistry
  alias Recurse.Gateway.Test.JwtTestHelper
  alias Recurse.Providers.Impls.PostgresMerkleLedger
  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.{SigningKey, Tenant}
  alias Recurse.Providers.Repo
  alias Recurse.Shared.Attestation.{Envelope, OuterContainer, SignedPredicate}
  alias Recurse.Shared.Ulid

  @tenant_id "01HQZN5K7J8M9N0P1Q2R3S4T5V"
  @test_kms_key_id "arn:aws:kms:us-east-1:123:key/test"
  @test_signing_pem "-----BEGIN PUBLIC KEY-----\nTESTKEY\n-----END PUBLIC KEY-----\n"
  @archive_chain_anchor <<0::size(256)>>

  # Inline stub that returns deterministic payload bytes for get_payload calls.
  defmodule StubStorage do
    @moduledoc false
    @behaviour Recurse.Providers.StorageProvider

    @impl true
    def init(_), do: {:ok, %{}}

    @impl true
    def put_payload(_state, _bytes, _ctx), do: {:ok, %{uri: "s3://stub/x", hash: <<0::256>>}}

    @impl true
    def get_payload(_state, payload_uri, _ctx) do
      {:ok, ~s|{"payload_uri":"#{payload_uri}"}|}
    end

    @impl true
    def delete_payload(_state, _uri, _ctx), do: :ok

    @impl true
    def capabilities(_state), do: [:get, :put]

    @impl true
    def healthcheck(_state), do: :ok

    @impl true
    def terminate(_state, _reason), do: :ok
  end

  setup do
    :ok = Ecto.Adapters.SQL.Sandbox.checkout(Repo)

    bundle_path = write_bundle()

    entity_schema_path =
      Path.join([
        Application.app_dir(:recurse_gateway, "priv"),
        "cedar",
        "schema.cedarschema.json"
      ])

    _pid =
      start_supervised!(
        Supervisor.child_spec(
          {BundleLoader,
           bundle_path: bundle_path,
           entity_schema_path: entity_schema_path,
           trap_sighup: false,
           name: nil},
          id: make_ref()
        )
      )

    ProviderRegistry.install_raw!(%{
      llm: {Recurse.Gateway.Test.StubLLM, %{}},
      ledger: {PostgresMerkleLedger, %{repo: Repo, pubsub: Recurse.PubSub, config: %{}}},
      storage: {StubStorage, %{}},
      secrets: {Recurse.Gateway.Test.StubSecretsProvider, %{}},
      tenant_id: @tenant_id,
      signer: "observed://gateway/test"
    })

    previous_validator_opts = Application.get_env(:recurse_gateway, :jwt_validator_opts)

    Application.put_env(:recurse_gateway, :jwt_validator_opts,
      audience: "recurse-gateway-test",
      issuer: "https://test-broker.example.invalid",
      known_kids: [
        {"test-key-rs256", JwtTestHelper.public_jwk(:rs256)}
      ]
    )

    on_exit(fn ->
      ProviderRegistry.uninstall()

      if previous_validator_opts do
        Application.put_env(:recurse_gateway, :jwt_validator_opts, previous_validator_opts)
      else
        Application.delete_env(:recurse_gateway, :jwt_validator_opts)
      end
    end)

    :ok
  end

  test "returns 400 when run_ids list is missing" do
    jwt = mint_jwt("tenant_auditor")

    conn =
      build_post("/v1/audit/export", %{})
      |> Plug.Conn.put_req_header("authorization", "Bearer " <> jwt)
      |> ExportHandler.handle()

    assert conn.status == 400
    assert %{"error" => "ERR_BAD_REQUEST"} = JSON.decode!(conn.resp_body)
  end

  test "returns 403 for `caller` role" do
    jwt = mint_jwt("caller")

    conn =
      build_post("/v1/audit/export", %{"run_ids" => [Ecto.UUID.generate()]})
      |> Plug.Conn.put_req_header("authorization", "Bearer " <> jwt)
      |> ExportHandler.handle()

    assert conn.status == 403
  end

  test "tenant_auditor + single known run_id → 200 zip body with expected members" do
    {:ok, bundle_ref} = Recurse.Gateway.Policy.BundleLoader.current_bundle()
    envelope = build_envelope(policy_canonical_hash: bundle_ref.canonical_hash)
    run_id = envelope.signed_predicate.run_id
    {:ok, _} = PostgresMerkleLedger.commit_attestation(envelope)
    seed_signing_key()

    jwt = mint_jwt("tenant_auditor")

    conn =
      build_post("/v1/audit/export", %{"run_ids" => [run_id]})
      |> Plug.Conn.put_req_header("authorization", "Bearer " <> jwt)
      |> ExportHandler.handle()

    assert conn.status == 200

    assert {"content-type", ct} = Enum.find(conn.resp_headers, &match?({"content-type", _}, &1))
    assert String.starts_with?(ct, "application/zip")

    # Expected zip members for the single-run shape.
    assert {:ok, entries} = :zip.unzip(conn.resp_body, [:memory])
    names = Enum.map(entries, fn {name, _bytes} -> IO.iodata_to_binary(name) end)
    assert "signed_predicate.json" in names
    assert "outer_container.json" in names
    assert "payload.json" in names
    assert "inclusion_proof.transitem" in names
    assert "signing_key.pem" in names
    assert "policy_bundle.cedar" in names
    assert "manifest.json" in names
  end

  test "tenant_auditor + two run_ids → 200 outer zip-of-zips with inner zips per run" do
    {:ok, bundle_ref} = Recurse.Gateway.Policy.BundleLoader.current_bundle()
    env_1 = build_envelope(policy_canonical_hash: bundle_ref.canonical_hash)
    env_2 = build_envelope(policy_canonical_hash: bundle_ref.canonical_hash)
    run_id_1 = env_1.signed_predicate.run_id
    run_id_2 = env_2.signed_predicate.run_id
    {:ok, _} = PostgresMerkleLedger.commit_attestation(env_1)
    {:ok, _} = PostgresMerkleLedger.commit_attestation(env_2)
    seed_signing_key()

    jwt = mint_jwt("tenant_auditor")

    conn =
      build_post("/v1/audit/export", %{"run_ids" => [run_id_1, run_id_2]})
      |> Plug.Conn.put_req_header("authorization", "Bearer " <> jwt)
      |> ExportHandler.handle()

    assert conn.status == 200
    assert {:ok, outer_entries} = :zip.unzip(conn.resp_body, [:memory])
    outer_names = Enum.map(outer_entries, fn {n, _} -> IO.iodata_to_binary(n) end)
    assert "evidence-#{run_id_1}.zip" in outer_names
    assert "evidence-#{run_id_2}.zip" in outer_names
  end

  # -- Helpers --------------------------------------------------------------

  defp build_post(path, body) do
    bytes = JSON.encode!(body)

    :post
    |> Plug.Test.conn(path, bytes)
    |> Plug.Conn.put_req_header("content-type", "application/json")
    |> parse_json!()
  end

  defp parse_json!(conn) do
    Plug.Parsers.call(
      conn,
      Plug.Parsers.init(parsers: [:json], pass: ["*/*"], json_decoder: JSON)
    )
  end

  defp mint_jwt(recurse_role) do
    JwtTestHelper.mint_test_jwt(
      recurse_role: recurse_role,
      audience: "recurse-gateway-test",
      issuer: "https://test-broker.example.invalid"
    )
  end

  defp write_bundle do
    source =
      Path.join([
        Application.app_dir(:recurse_gateway, "priv"),
        "reference_policies",
        "platform_roles.cedar"
      ])
      |> File.read!()

    path = Path.join(System.tmp_dir!(), "export_bundle_#{System.unique_integer()}.cedar")
    File.write!(path, source)
    on_exit(fn -> File.rm(path) end)
    path
  end

  defp build_envelope(opts) do
    tenant_id = @tenant_id
    session_id = Ecto.UUID.generate()
    run_id = Ecto.UUID.generate()

    Tenant.changeset(%Tenant{}, %{
      tenant_id: tenant_id,
      display_name: "test",
      tier: :standalone_gateway,
      created_at: DateTime.utc_now()
    })
    |> Repo.insert(on_conflict: :nothing, conflict_target: :tenant_id)

    policy_canonical_hash =
      Keyword.get(opts, :policy_canonical_hash, :crypto.hash(:sha256, "policy-" <> run_id))

    sp = %SignedPredicate{
      envelope_version: "1.0",
      run_id: run_id,
      step_id: run_id,
      turn_id: run_id,
      session_id: session_id,
      session_chain_position: 0,
      event_kind: :llm_call,
      timestamp: DateTime.utc_now() |> DateTime.to_iso8601(),
      tenant_id: tenant_id,
      machine_identity: %{observed_jwt_subject: "a", observed_jwt_issuer: "i"},
      principal: %{"kind" => "obo_human"},
      policy_canonical_hash: policy_canonical_hash,
      payload_hash: :crypto.hash(:sha256, "payload-" <> run_id),
      payload_uri: "s3://bucket/tenants/#{tenant_id}/runs/#{run_id}.json",
      correlation_id: Ulid.generate(),
      signer: @test_kms_key_id
    }

    oc = %OuterContainer{
      verification_level: :signed,
      tier_completeness_advisory: :partial,
      session_chain_epoch: 0,
      session_state: :active
    }

    Envelope.new(sp, oc, %{"signatures" => [%{"sig" => Base.encode64(<<0::size(8 * 72)>>)}]})
  end

  # Insert a signing_keys archive row so the zip builder can find the PEM.
  defp seed_signing_key do
    now = DateTime.utc_now()

    identity = %{
      tenant_id: @tenant_id,
      kms_key_id: @test_kms_key_id,
      key_version: "v1",
      public_key_pem: @test_signing_pem,
      algorithm: :ecdsa_p256,
      first_seen_at: now
    }

    chain_hash =
      :crypto.hash(:sha256, @archive_chain_anchor <> SigningKey.canonical_row_bytes(identity))

    attrs =
      identity
      |> Map.put(:last_seen_at, now)
      |> Map.put(:chain_hash, chain_hash)
      |> Map.put(:inserted_at, now)

    %SigningKey{}
    |> SigningKey.insert_changeset(attrs)
    |> Repo.insert(on_conflict: :nothing, conflict_target: [:kms_key_id, :key_version])
  end
end
