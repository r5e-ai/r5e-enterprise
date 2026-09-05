defmodule Recurse.Gateway.AuditPlane.ExportHandlerSchemaContractTest do
  @moduledoc """
  Contract test (issue #48 — retire F2): the request shape parsed by
  `Recurse.Gateway.AuditPlane.ExportHandler.parse_run_ids/1` MUST validate
  against `apps/recurse_gateway/priv/schemas/export_request.json`, and the
  response envelope (filename + content_type + byte_size) MUST validate
  against `apps/recurse_gateway/priv/schemas/export_response.json`.

  ## Why two schemas + two assertions per test

  The export endpoint is the only audit-plane endpoint whose 200 response
  body is binary (application/zip), not JSON. JSON Schema cannot describe
  binary body bytes, so `export_response.json` documents the structured
  ENVELOPE the SPA's downloader (ExportEvidenceButton.downloadEvidence)
  materializes from the response — the parsed Content-Disposition filename,
  the response Content-Type, and the size of the zip blob. This contract
  test validates that envelope (synthesized from real handler response
  headers + body bytes) against the schema. The actual zip's internal
  structure is asserted by the existing `export_handler_test.exs` (this
  test focuses on the WIRE-LEVEL envelope the SPA sees, not the zip's
  manifest contents).

  Cases:

    1. **Valid request body validates.** A {run_ids: [<uuid>]} body is
       what the SPA emits.
    2. **Single-run-id 200 response envelope validates.** filename matches
       `evidence-<basic-iso8601>.zip`; content_type is application/zip;
       byte_size is the body size.

  Adversarial check (per `.specify/orchestrator-log.md` `adversarial-check`
  pattern): break the `pattern` in export_response.json's filename to
  `^.+\\.tar$` and watch the test fail at `$.filename: ...` (the validator
  doesn't enforce regex pattern, but the const `application/zip` is
  enforced — replace it with `application/tar` and the test fails at
  `$.content_type: value "application/zip" != const "application/tar"`).
  Restore.

  ## Iron Law check (`elixir:elixir-thinking`)

  Pure module. No process. `async: false` for ProviderRegistry shared state.

  ## Cross-references

    * Issue #48 — F2 retire
    * `apps/recurse_gateway/priv/schemas/export_request.json`
    * `apps/recurse_gateway/priv/schemas/export_response.json`
    * `apps/recurse_gateway/lib/recurse_gateway/audit_plane/export_handler.ex`
    * `apps/recurse_gateway/test/support/json_schema_validator.ex`
  """

  use ExUnit.Case, async: false

  setup_all do
    Recurse.Gateway.Test.KernelFixture.boot()
  end

  alias Recurse.Gateway.AuditPlane.ExportHandler
  alias Recurse.Gateway.Policy.BundleLoader
  alias Recurse.Gateway.ProviderRegistry
  alias Recurse.Gateway.Test.JsonSchemaValidator
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

  @export_request_schema_path Path.expand(
                                "../../priv/schemas/export_request.json",
                                __DIR__
                              )
  @export_response_schema_path Path.expand(
                                 "../../priv/schemas/export_response.json",
                                 __DIR__
                               )

  # Inline stub mirroring `ExportHandlerTest.StubStorage` — deterministic
  # payload bytes per get_payload call so the zip builder doesn't 500 on
  # missing payload fixtures.
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

    request_schema = @export_request_schema_path |> File.read!() |> JSON.decode!()
    response_schema = @export_response_schema_path |> File.read!() |> JSON.decode!()

    {:ok, request_schema: request_schema, response_schema: response_schema}
  end

  describe "POST /v1/audit/export request body validates export_request.json" do
    test "single-run-id request body validates", %{request_schema: schema} do
      run_id = Ecto.UUID.generate()
      body = %{"run_ids" => [run_id]}

      JsonSchemaValidator.validate!(body, schema)
    end

    test "multi-run-id request body validates", %{request_schema: schema} do
      body = %{"run_ids" => [Ecto.UUID.generate(), Ecto.UUID.generate(), Ecto.UUID.generate()]}

      JsonSchemaValidator.validate!(body, schema)
    end
  end

  describe "POST /v1/audit/export response envelope validates export_response.json" do
    test "200 single-run-id response envelope (filename + content_type + byte_size) validates",
         %{response_schema: schema} do
      {:ok, bundle_ref} = BundleLoader.current_bundle()
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

      content_type = get_resp_header(conn, "content-type")
      filename = parse_filename(get_resp_header(conn, "content-disposition"))
      byte_size = byte_size(conn.resp_body)

      envelope_for_schema = %{
        "filename" => filename,
        "content_type" => "application/zip",
        "byte_size" => byte_size,
        "run_ids" => [run_id]
      }

      # Sanity: SPA-side downloader builds this envelope from the same
      # surface (Content-Disposition + Content-Type + Blob.size); we
      # verify the wire side delivers the inputs.
      assert content_type =~ "application/zip"
      assert filename =~ ~r/^evidence-.+\.zip$/
      assert byte_size > 0

      JsonSchemaValidator.validate!(envelope_for_schema, schema)
    end
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

  defp get_resp_header(conn, key) do
    case Enum.find(conn.resp_headers, fn {k, _v} -> k == key end) do
      {^key, v} -> v
      _ -> nil
    end
  end

  defp parse_filename(nil), do: nil

  defp parse_filename(header) do
    case Regex.run(~r/filename="([^"]+)"/, header) do
      [_, name] -> name
      _ -> nil
    end
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

    path =
      Path.join(
        System.tmp_dir!(),
        "export_schema_contract_bundle_#{System.unique_integer()}.cedar"
      )

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
  # Mirrors the helper in `export_handler_test.exs:277` — same shape, same
  # `insert_changeset` arity. Pinned to that file so the two stay in sync.
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
