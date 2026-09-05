defmodule Recurse.Gateway.Admin.LocalVerifyHandlerSchemaContractTest do
  @moduledoc """
  Contract test (issue #48 — retire F2): the actual response body emitted
  by `Recurse.Gateway.Admin.LocalVerifyHandler` MUST validate against
  `apps/recurse_gateway/priv/schemas/verify_response.json`.

  Cases:

    1. **Failing receipt — "fail" overall_status path:** commit a basic
       envelope where DSSE signature won't verify (test SecretsProvider
       has no PEM matching the synthetic observed signer); the handler
       still emits the canonical 5-check + overall_status + verified_at
       shape. We validate the SHAPE, not the verification outcome.

    2. **Missing receipt — 404 envelope path:** out of scope for THIS
       schema (the F001 error envelope is `error_envelope.json`); we
       only need to assert the *200 happy-path* JSON validates.

  The schema's `enum`s pin the contract: `overall_status` must be `"pass"`
  or `"fail"`; `checks[].name` must be one of the five known atoms
  (`signature`, `local_merkle_inclusion`, `global_merkle_inclusion`,
  `policy_hash_match`, `payload_hash_match`); `checks[].status` must be
  `"pass"` or `"fail"`. Drift any of those atoms in `local_verify_handler.ex`
  and this test fails with a precise message.

  Adversarial check (per `.specify/orchestrator-log.md` `adversarial-check`
  pattern): introduce a typo in the schema's `name` enum (e.g.,
  `local_merkle_inclusio`) and watch the test fail at
  `$.checks[1].name: value "local_merkle_inclusion" is not in enum [...]`.
  Restore. Then drop `verified_at` from the schema's `required` list and
  watch the schema NOT catch a handler that forgot to emit it (a real
  regression risk). Restore.

  ## Iron Law check (`elixir:elixir-thinking`)

  Pure module. No process. `async: false` for the same reason all
  ProviderRegistry-touching tests are non-async.

  ## Cross-references

    * Issue #48 — F2 retire
    * `apps/recurse_gateway/priv/schemas/verify_response.json`
    * `apps/recurse_gateway/lib/recurse_gateway/admin/local_verify_handler.ex`
      `run_checks_and_respond/3` — produces the shape under test
    * `apps/recurse_gateway/test/support/json_schema_validator.ex`
  """

  use ExUnit.Case, async: false

  setup_all do
    Recurse.Gateway.Test.KernelFixture.boot()
  end

  alias Recurse.Gateway.Admin.LocalVerifyHandler
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
                 "../../priv/schemas/verify_response.json",
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

  describe "POST /v1/audit/receipts/:run_id/verify response validates verify_response.json" do
    test "200 happy-path JSON validates against the schema even when checks fail",
         %{schema: schema} do
      envelope = build_envelope()
      run_id = envelope.signed_predicate.run_id
      {:ok, _} = PostgresMerkleLedger.commit_attestation(envelope)

      jwt = mint_jwt(recurse_role: "tenant_auditor")
      conn = build_post_conn(jwt, "/v1/audit/receipts/#{run_id}/verify", run_id)
      conn = LocalVerifyHandler.handle(conn)

      assert conn.status == 200

      body = JSON.decode!(conn.resp_body)

      # Sanity: the shape we're asserting matches what `local_verify_handler.ex`
      # documents in its moduledoc — overall_status is "pass" or "fail";
      # checks is a 5-element array; each check has step + name + status +
      # explanation. We're validating the SHAPE here, not the verification
      # outcome. Stub-key receipts won't verify; that's fine.
      assert body["run_id"] == run_id
      assert body["overall_status"] in ["pass", "fail"]
      assert length(body["checks"]) == 5

      JsonSchemaValidator.validate!(body, schema)
    end
  end

  # -- Helpers --------------------------------------------------------------

  defp build_post_conn(jwt, path, run_id) do
    conn = Plug.Test.conn(:post, path, "")
    conn = %{conn | path_params: %{"run_id" => run_id}}
    Plug.Conn.put_req_header(conn, "authorization", "Bearer " <> jwt)
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
        "verify_schema_contract_bundle_#{System.unique_integer()}.cedar"
      )

    File.write!(path, source)
    on_exit(fn -> File.rm(path) end)
    path
  end

  defp build_envelope do
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
      event_kind: :llm_call,
      timestamp: DateTime.utc_now() |> DateTime.to_iso8601(),
      tenant_id: tenant_id,
      machine_identity: %{
        observed_jwt_subject: "alice@example.com",
        observed_jwt_issuer: "https://issuer.example.com"
      },
      principal: %{"kind" => "obo_human", "subject" => "alice@example.com"},
      policy_canonical_hash: :crypto.hash(:sha256, "policy-" <> run_id),
      payload_hash: :crypto.hash(:sha256, "payload-" <> run_id),
      # Use an `recurse://import/...` URI so the payload-hash check
      # short-circuits via PredicateOnlyUri.kind/1 → :imported (no storage
      # fetch). We don't need DSSE to actually verify (stub keys); we
      # only need the handler to emit a valid 5-check JSON shape so the
      # contract test can assert it validates against verify_response.json.
      payload_uri: "recurse://import/test/#{run_id}",
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
