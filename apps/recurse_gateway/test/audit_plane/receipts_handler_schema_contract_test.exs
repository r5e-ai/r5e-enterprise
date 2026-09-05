defmodule Recurse.Gateway.AuditPlane.ReceiptsHandlerSchemaContractTest do
  @moduledoc """
  Contract test (issue #48 — retire F2): the actual response body emitted
  by `Recurse.Gateway.AuditPlane.ReceiptsHandler` MUST validate against
  `apps/recurse_gateway/priv/schemas/audit_receipts_list_response.json`.

  This is the test that prevents the next round of "the SPA's hand-
  maintained `ReceiptRow` interface drifted away from the handler's
  emitted JSON" from shipping silently. The 4-field-name + 1-status-atom
  drift in MR !51's prior reflect was exactly this class.

  Two cases:

    1. **F002-shape (no facets):** `?facets=true` is omitted; the response
       is `{receipts: [...], cursor: ...}`. Every receipt row carries the
       full F001 split-envelope shape. `additionalProperties: false` at
       every level catches keys that drift in.

    2. **F004 facets shape:** `?facets=true` set; response includes a top-
       level `facets: {event_kind, policy_decision, verification_level}`
       map per FR-012 + issue #44. The schema's `facets` property is
       optional; setting it bumps validation through the full facets
       sub-schema.

  Adversarial check (per `.specify/orchestrator-log.md` `adversarial-check`
  pattern, 5/5 unprompted across MRs !54-!63): break a `required` field
  in the schema (e.g., remove `cursor` from the top-level required list)
  and watch this test stay green when it should fail. Restore. Then break
  a field NAME in the schema (e.g., rename `outer_container` to
  `outer_container_typo`) and watch the test fail with a precise message
  pointing at `$.receipts[0]: missing required key "outer_container_typo"`.

  ## Iron Law check (`elixir:elixir-thinking` / `elixir:phoenix-thinking`)

  Pure module. No process. The handler test setup is reused (BundleLoader
  + ProviderRegistry singleton); `async: false` for the same reason.

  ## Cross-references

    * Issue #48 — F2 retire
    * `apps/recurse_gateway/priv/schemas/audit_receipts_list_response.json`
    * `apps/recurse_gateway/lib/recurse_gateway/audit_plane/receipts_handler.ex`
      `render_response/4` — produces the shape under test
    * `apps/recurse_gateway/test/support/json_schema_validator.ex`
  """

  use ExUnit.Case, async: false

  setup_all do
    Recurse.Gateway.Test.KernelFixture.boot()
  end

  alias Recurse.Gateway.AuditPlane.ReceiptsHandler
  alias Recurse.Gateway.Policy.BundleLoader
  alias Recurse.Gateway.ProviderRegistry
  alias Recurse.Gateway.Test.JsonSchemaValidator
  alias Recurse.Gateway.Test.JwtTestHelper
  alias Recurse.Providers.Impls.PostgresMerkleLedger
  alias Recurse.Providers.Repo
  alias Recurse.Shared.Attestation.{Envelope, OuterContainer, SignedPredicate}
  alias Recurse.Shared.Ulid

  @tenant_id "01HQZN5K7J8M9N0P1Q2R3S4T5V"

  @schema_path Path.expand(
                 "../../priv/schemas/audit_receipts_list_response.json",
                 __DIR__
               )

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
      storage: {Recurse.Gateway.Test.StubStorage, %{}},
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

    schema = @schema_path |> File.read!() |> JSON.decode!()

    {:ok, schema: schema}
  end

  describe "GET /v1/audit/receipts response validates audit_receipts_list_response.json" do
    test "F002 shape (no facets) — empty page", %{schema: schema} do
      jwt = mint_jwt(recurse_role: "tenant_auditor")

      conn =
        jwt
        |> build_conn()
        |> ReceiptsHandler.handle()

      assert conn.status == 200

      body = JSON.decode!(conn.resp_body)
      JsonSchemaValidator.validate!(body, schema)
    end

    test "F002 shape (no facets) — populated page with 2 receipts of mixed kinds",
         %{schema: schema} do
      llm_envelope = build_envelope(event_kind: :llm_call)
      tool_envelope = build_envelope(event_kind: :tool_call)

      {:ok, _} = PostgresMerkleLedger.commit_attestation(llm_envelope)
      {:ok, _} = PostgresMerkleLedger.commit_attestation(tool_envelope)

      jwt = mint_jwt(recurse_role: "tenant_auditor")

      conn =
        jwt
        |> build_conn()
        |> ReceiptsHandler.handle()

      assert conn.status == 200

      body = JSON.decode!(conn.resp_body)
      assert length(body["receipts"]) == 2

      JsonSchemaValidator.validate!(body, schema)
    end

    test "F004 facets shape — empty universe still emits 3-axis facet maps",
         %{schema: schema} do
      jwt = mint_jwt(recurse_role: "tenant_auditor")

      conn =
        jwt
        |> build_conn()
        |> with_query("facets=true")
        |> ReceiptsHandler.handle()

      assert conn.status == 200

      body = JSON.decode!(conn.resp_body)
      # Facets present + every required axis is a map (issue #44 contract).
      assert is_map(body["facets"])
      assert is_map(body["facets"]["event_kind"])
      assert is_map(body["facets"]["policy_decision"])
      assert is_map(body["facets"]["verification_level"])

      JsonSchemaValidator.validate!(body, schema)
    end

    test "F004 facets shape — populated universe with mixed kinds",
         %{schema: schema} do
      for kind <- [:llm_call, :tool_call, :ui_query] do
        env = build_envelope(event_kind: kind)
        {:ok, _} = PostgresMerkleLedger.commit_attestation(env)
      end

      jwt = mint_jwt(recurse_role: "tenant_auditor")

      conn =
        jwt
        |> build_conn()
        |> with_query("facets=true")
        |> ReceiptsHandler.handle()

      assert conn.status == 200

      body = JSON.decode!(conn.resp_body)
      JsonSchemaValidator.validate!(body, schema)
    end
  end

  # -- Helpers --------------------------------------------------------------

  defp build_conn(jwt) do
    conn = Plug.Test.conn(:get, "/v1/audit/receipts")

    case jwt do
      nil -> conn
      token -> Plug.Conn.put_req_header(conn, "authorization", "Bearer " <> token)
    end
  end

  defp with_query(conn, query_string) do
    %{conn | query_string: query_string}
  end

  defp mint_jwt(opts) do
    JwtTestHelper.mint_test_jwt(
      recurse_role: Keyword.fetch!(opts, :recurse_role),
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
        "receipts_schema_contract_bundle_#{System.unique_integer()}.cedar"
      )

    File.write!(path, source)
    on_exit(fn -> File.rm(path) end)
    path
  end

  defp build_envelope(opts) do
    event_kind = Keyword.get(opts, :event_kind, :llm_call)
    tenant_id = @tenant_id
    session_id = Ecto.UUID.generate()
    run_id = Ecto.UUID.generate()

    Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Tenant.changeset(
      %Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Tenant{},
      %{
        tenant_id: tenant_id,
        display_name: "test",
        tier: :standalone_gateway,
        created_at: DateTime.utc_now()
      }
    )
    |> Repo.insert(on_conflict: :nothing, conflict_target: :tenant_id)

    sp = %SignedPredicate{
      envelope_version: "1.0",
      run_id: run_id,
      step_id: run_id,
      turn_id: run_id,
      session_id: session_id,
      session_chain_position: 0,
      event_kind: event_kind,
      timestamp: DateTime.utc_now() |> DateTime.to_iso8601(),
      tenant_id: tenant_id,
      machine_identity: %{
        observed_jwt_subject: "alice@example.com",
        observed_jwt_issuer: "https://issuer.example.com"
      },
      principal: %{"kind" => "obo_human", "subject" => "alice@example.com"},
      policy_canonical_hash: :crypto.hash(:sha256, "policy-" <> run_id),
      payload_hash: :crypto.hash(:sha256, "payload-" <> run_id),
      payload_uri: "s3://bucket/tenants/#{tenant_id}/runs/#{run_id}.json",
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
