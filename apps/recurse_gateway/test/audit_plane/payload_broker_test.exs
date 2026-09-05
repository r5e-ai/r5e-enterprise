defmodule Recurse.Gateway.AuditPlane.PayloadBrokerTest do
  @moduledoc """
  Contract tests for `Recurse.Gateway.AuditPlane.PayloadBroker` (F002 T062 /
  FR-020). Cedar-gated by `Recurse::Action::ReadPayload`.

  `async: false` — BundleLoader + ProviderRegistry are singletons.
  """

  use ExUnit.Case, async: false

  setup_all do
    Recurse.Gateway.Test.KernelFixture.boot()
  end

  alias Recurse.Gateway.AuditPlane.PayloadBroker
  alias Recurse.Gateway.AuditPlane.PredicateOnlyUri
  alias Recurse.Gateway.Policy.BundleLoader
  alias Recurse.Gateway.ProviderRegistry
  alias Recurse.Gateway.Test.JwtTestHelper
  alias Recurse.Providers.Impls.PostgresMerkleLedger
  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Tenant
  alias Recurse.Providers.Repo
  alias Recurse.Shared.Attestation.{Envelope, OuterContainer, SignedPredicate}
  alias Recurse.Shared.Ulid

  @tenant_id "01HQZN5K7J8M9N0P1Q2R3S4T5V"

  # Inline stub: returns canned payload bytes for any known payload URI.
  defmodule StubStorage do
    @moduledoc false
    @behaviour Recurse.Providers.StorageProvider

    @impl true
    def init(_), do: {:ok, %{payloads: %{}}}

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
      storage: {StubStorage, %{payloads: %{}}},
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

  test "returns 400 when run_id query param is missing" do
    jwt = mint_jwt("tenant_auditor")

    conn =
      :get
      |> Plug.Test.conn("/v1/audit/payload")
      |> Plug.Conn.put_req_header("authorization", "Bearer " <> jwt)
      |> PayloadBroker.handle()

    assert conn.status == 400
    assert %{"error" => "ERR_BAD_REQUEST"} = JSON.decode!(conn.resp_body)
  end

  test "returns 404 when run_id is unknown" do
    jwt = mint_jwt("tenant_auditor")

    conn =
      :get
      |> Plug.Test.conn("/v1/audit/payload?run_id=#{Ecto.UUID.generate()}")
      |> Plug.Conn.put_req_header("authorization", "Bearer " <> jwt)
      |> PayloadBroker.handle()

    assert conn.status == 404
    assert %{"error" => "ERR_NOT_FOUND"} = JSON.decode!(conn.resp_body)
  end

  test "returns 403 for `caller` role" do
    envelope = build_envelope()
    run_id = envelope.signed_predicate.run_id
    {:ok, _} = PostgresMerkleLedger.commit_attestation(envelope)

    jwt = mint_jwt("caller")

    conn =
      :get
      |> Plug.Test.conn("/v1/audit/payload?run_id=#{run_id}")
      |> Plug.Conn.put_req_header("authorization", "Bearer " <> jwt)
      |> PayloadBroker.handle()

    assert conn.status == 403
  end

  test "streams the payload bytes for tenant_auditor on a known run_id" do
    envelope = build_envelope()
    run_id = envelope.signed_predicate.run_id
    {:ok, _} = PostgresMerkleLedger.commit_attestation(envelope)

    jwt = mint_jwt("tenant_auditor")

    conn =
      :get
      |> Plug.Test.conn("/v1/audit/payload?run_id=#{run_id}")
      |> Plug.Conn.put_req_header("authorization", "Bearer " <> jwt)
      |> PayloadBroker.handle()

    assert conn.status == 200

    assert {"content-type", "application/json; charset=utf-8"} =
             Enum.find(conn.resp_headers, &match?({"content-type", _}, &1))

    body = JSON.decode!(conn.resp_body)
    assert is_binary(body["payload_uri"])
    assert String.contains?(body["payload_uri"], run_id)
  end

  # Issue #60 — imported receipts are predicate-only by design (the JSONL
  # importer hashes the source-session entry into the signed_predicate; no
  # separate payload bytes are CAS-stashed). The broker must short-circuit
  # to 422 ERR_PREDICATE_ONLY rather than asking the StorageProvider to
  # fetch a non-existent S3 object.
  test "returns 422 ERR_PREDICATE_ONLY for imported receipts (recurse://import/...)" do
    envelope =
      build_envelope_with_payload_uri(
        PredicateOnlyUri.build_imported("claude_code", Ecto.UUID.generate())
      )

    run_id = envelope.signed_predicate.run_id
    {:ok, _} = PostgresMerkleLedger.commit_attestation(envelope)

    jwt = mint_jwt("tenant_auditor")

    conn =
      :get
      |> Plug.Test.conn("/v1/audit/payload?run_id=#{run_id}")
      |> Plug.Conn.put_req_header("authorization", "Bearer " <> jwt)
      |> PayloadBroker.handle()

    assert conn.status == 422
    body = JSON.decode!(conn.resp_body)
    assert body["error"] == "ERR_PREDICATE_ONLY"
    assert is_binary(body["error_description"])
    assert String.contains?(body["error_description"], "predicate-only")
    # The imported URI is echoed in the description so SIEM forwarders +
    # auditor diagnostics can confirm provenance without a second roundtrip.
    assert String.contains?(body["error_description"], "recurse://import/")
    assert is_binary(body["correlation_id"])
  end

  # System events (`:ui_login`, `:ui_session`, `:ui_query`, etc.) are also
  # predicate-only but shipped pre-issue-#60 with a 200 + structured marker
  # body that the SPA's `isPredicateOnlyMarker` recognizes. Preserve that
  # backwards-compatible behavior — changing it would break the deployed
  # SPA's existing rendering path for system-event Payload tab clicks.
  test "returns 200 with predicate_only:true marker for system events (recurse://system/predicate-only/...)" do
    envelope = build_envelope_with_payload_uri(PredicateOnlyUri.build(Ecto.UUID.generate()))
    run_id = envelope.signed_predicate.run_id
    {:ok, _} = PostgresMerkleLedger.commit_attestation(envelope)

    jwt = mint_jwt("tenant_auditor")

    conn =
      :get
      |> Plug.Test.conn("/v1/audit/payload?run_id=#{run_id}")
      |> Plug.Conn.put_req_header("authorization", "Bearer " <> jwt)
      |> PayloadBroker.handle()

    assert conn.status == 200
    body = JSON.decode!(conn.resp_body)
    assert body["predicate_only"] == true
    assert is_binary(body["payload_uri"])
    assert String.starts_with?(body["payload_uri"], "recurse://system/predicate-only/")
  end

  # -- Helpers --------------------------------------------------------------

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

    path = Path.join(System.tmp_dir!(), "payload_bundle_#{System.unique_integer()}.cedar")
    File.write!(path, source)
    on_exit(fn -> File.rm(path) end)
    path
  end

  defp build_envelope, do: build_envelope_with_payload_uri(nil)

  # Builds a test envelope; if `override_uri` is non-nil, it replaces the
  # default `s3://...` payload_uri with the given URI (used by the
  # predicate-only short-circuit tests for issue #60).
  defp build_envelope_with_payload_uri(override_uri) do
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

    payload_uri = override_uri || "s3://bucket/tenants/#{tenant_id}/runs/#{run_id}.json"

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
      policy_canonical_hash: :crypto.hash(:sha256, "policy-" <> run_id),
      payload_hash: :crypto.hash(:sha256, "payload-" <> run_id),
      payload_uri: payload_uri,
      correlation_id: Ulid.generate(),
      signer: "arn:aws:kms:us-east-1:123:key/test"
    }

    oc = %OuterContainer{
      verification_level: :signed,
      tier_completeness_advisory: :partial,
      session_chain_epoch: 0,
      session_state: :active
    }

    Envelope.new(sp, oc, %{"signatures" => [%{"sig" => Base.encode64(<<0::size(8 * 72)>>)}]})
  end
end
