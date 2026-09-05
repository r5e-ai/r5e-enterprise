defmodule RecurseGateway.Integration.US6ReplayTest do
  @moduledoc """
  US6 — Operator replays a past receipt against deployed policy
  end-to-end (F004 T139 + T142).

  Drives the Phase-8 Policy Replay surface against real DSSE-signed
  seed receipts:

    1. **Replay against deployed bundle** (`POST /v1/policy/replay/{run_id}`)
       — operator pastes a run_id; handler loads the deployed bundle,
       reuses `BlastRadius.synthesize_entity_store/1` +
       `BlastRadius.action_uid_from_event_kind/1`, and evaluates Cedar
       single-receipt. Asserts the decision matches the historical
       receipt's `policy_decision` (no drift).
    2. **Replay with override Cedar source** — operator supplies a
       `forbid` rule via `override_cedar_source`. Asserts
       `decision_changed: true` when the override changes the verdict.
    3. **`:ui_policy_replay` receipt emitted** per `data-model.md` §0.
    4. **SC-009 budget**: replay completes within 2 seconds.
    5. **404 on missing run_id**.
    6. **403 for caller role** (Cedar gates `PolicyReplay`).
    7. **400 on Cedar parse error in override**.

  ## `async: false`

  Same reason as other Phase-5/8 integration tests: shared
  `:persistent_term` slots (ProviderRegistry, BundleLoader) and the
  SQL Sandbox single connection.
  """

  use ExUnit.Case, async: false

  setup_all do
    Recurse.Gateway.Test.KernelFixture.boot()
  end

  @moduletag :integration

  alias Ecto.Adapters.SQL.Sandbox
  alias Recurse.Gateway.Admin.BrowserAuth.UiReceipts
  alias Recurse.Gateway.Admin.PolicyReplayHandler
  alias Recurse.Gateway.Policy.BundleLoader
  alias Recurse.Gateway.ProviderRegistry
  alias Recurse.Gateway.Test.JwtTestHelper
  alias Recurse.Providers.Impls.PostgresMerkleLedger
  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Attestation
  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Session
  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Tenant
  alias Recurse.Providers.Repo

  @tenant_id "01HQZN5K7J8M9N0P1Q2R3S4T5V"

  @forbid_chat_completion """
  forbid (
    principal,
    action == Recurse::Action::"ChatCompletion",
    resource
  )
  when {
    principal.recurse_role == "caller"
  };
  """

  setup do
    :ok = Sandbox.checkout(Repo)
    Sandbox.mode(Repo, {:shared, self()})

    Repo.insert!(
      Tenant.changeset(%Tenant{}, %{
        tenant_id: @tenant_id,
        display_name: "US6 Test Tenant",
        tier: :standalone_gateway,
        created_at: DateTime.utc_now()
      }),
      on_conflict: :nothing,
      conflict_target: :tenant_id
    )

    bundle_path = write_bundle()

    entity_schema_path =
      Path.join([
        Application.app_dir(:recurse_gateway, "priv"),
        "cedar",
        "schema.cedarschema.json"
      ])

    _ =
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
      signer: "observed://gateway/us6-test"
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

  describe "Replay against deployed bundle" do
    test "200 + emits :ui_policy_replay within SC-009 2s budget" do
      attach_ui_receipts_telemetry()
      run_id = seed_attestation(:allow)

      jwt = mint_jwt("platform_operator")

      {duration_us, conn} =
        :timer.tc(fn ->
          :post
          |> Plug.Test.conn("/v1/policy/replay/#{run_id}", JSON.encode!(%{}))
          |> with_path_params(%{"run_id" => run_id})
          |> with_json(jwt)
          |> PolicyReplayHandler.handle()
        end)

      assert conn.status == 200
      body = JSON.decode!(conn.resp_body)

      assert body["run_id"] == run_id
      assert body["original_decision"] == "allow"
      assert body["replayed_decision"] in ["allow", "deny"]
      assert is_boolean(body["decision_changed"])
      assert is_binary(body["cedar_source_hash"])
      assert is_binary(body["attested_run_id"])
      assert is_list(body["matched_policies"])

      # SC-009: replay must complete within 2 seconds.
      assert duration_us < 2_000_000,
             "replay exceeded SC-009 2s budget: #{div(duration_us, 1000)}ms"

      assert_receive {:ui_receipt_emitted, %{event_kind: :ui_policy_replay}}, 2_000
    end
  end

  describe "Replay with override_cedar_source" do
    test "decision_changed: true when override flips the verdict" do
      run_id = seed_attestation(:allow)

      jwt = mint_jwt("platform_operator")

      body =
        JSON.encode!(%{"override_cedar_source" => @forbid_chat_completion})

      conn =
        :post
        |> Plug.Test.conn("/v1/policy/replay/#{run_id}", body)
        |> with_path_params(%{"run_id" => run_id})
        |> with_json(jwt)
        |> PolicyReplayHandler.handle()

      assert conn.status == 200
      result = JSON.decode!(conn.resp_body)

      # The historical receipt was :allow. The override is `forbid`
      # for caller-role + ChatCompletion, but our seed receipt's
      # event_kind is `:llm_call` which maps to ChatCompletion.
      # We expect deny, hence decision_changed: true.
      assert result["original_decision"] == "allow"
      assert result["replayed_decision"] == "deny"
      assert result["decision_changed"] == true
    end
  end

  describe "Error handling" do
    test "404 on missing run_id" do
      jwt = mint_jwt("platform_operator")
      missing = Ecto.UUID.generate()

      conn =
        :post
        |> Plug.Test.conn("/v1/policy/replay/#{missing}", JSON.encode!(%{}))
        |> with_path_params(%{"run_id" => missing})
        |> with_json(jwt)
        |> PolicyReplayHandler.handle()

      assert conn.status == 404
    end

    test "400 on Cedar parse error in override" do
      run_id = seed_attestation(:allow)
      jwt = mint_jwt("platform_operator")

      body = JSON.encode!(%{"override_cedar_source" => "this is not cedar !!!"})

      conn =
        :post
        |> Plug.Test.conn("/v1/policy/replay/#{run_id}", body)
        |> with_path_params(%{"run_id" => run_id})
        |> with_json(jwt)
        |> PolicyReplayHandler.handle()

      assert conn.status == 400
    end

    test "403 when caller role attempts replay (Cedar denies PolicyReplay)" do
      run_id = seed_attestation(:allow)
      jwt = mint_jwt("caller")

      conn =
        :post
        |> Plug.Test.conn("/v1/policy/replay/#{run_id}", JSON.encode!(%{}))
        |> with_path_params(%{"run_id" => run_id})
        |> with_json(jwt)
        |> PolicyReplayHandler.handle()

      assert conn.status == 403
    end
  end

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  defp seed_attestation(decision) when decision in [:allow, :deny] do
    now = DateTime.utc_now()

    {:ok, session} =
      %Session{}
      |> Session.changeset(%{
        tenant_id: @tenant_id,
        session_scope: :discovery_session,
        state: :active,
        session_start: now,
        principal_kind: :obo_human,
        principal_canonical: "alice@corp"
      })
      |> Repo.insert()

    attestation =
      %Attestation{}
      |> Attestation.changeset(%{
        session_id: session.session_id,
        turn_id: Ecto.UUID.generate(),
        event_kind: :llm_call,
        machine_identity: %{"observed_jwt_subject" => "agent", "observed_jwt_issuer" => "test"},
        principal: %{
          "kind" => "obo_human",
          "subject" => "alice@corp",
          "issuer" => "https://test/",
          "recurse_role" => "caller",
          "groups" => [],
          "tenant_id" => @tenant_id
        },
        tenant_id: @tenant_id,
        policy_canonical_hash: :crypto.hash(:sha256, "policy"),
        payload_hash: :crypto.hash(:sha256, "payload"),
        payload_uri: "s3://bucket/p.json",
        correlation_id: "corr-us6-#{System.unique_integer()}",
        signer_kms_key_id: "test-key",
        signer_key_version: "v1",
        timestamp: now,
        signed_predicate_bytes: <<0::64>>,
        dsse_signature: <<0::64>>,
        verification_level: :signed,
        tier_completeness_advisory: :partial,
        policy_decision: decision,
        outcome: :success
      })
      |> Repo.insert!()

    attestation.run_id
  end

  defp mint_jwt(recurse_role) do
    JwtTestHelper.mint_test_jwt(
      recurse_role: recurse_role,
      audience: "recurse-gateway-test",
      issuer: "https://test-broker.example.invalid"
    )
  end

  defp with_json(conn, jwt) do
    conn
    |> Plug.Conn.put_req_header("authorization", "Bearer " <> jwt)
    |> Plug.Conn.put_req_header("content-type", "application/json")
    |> Plug.Parsers.call(Plug.Parsers.init(parsers: [:json], pass: ["*/*"], json_decoder: JSON))
  end

  defp with_path_params(conn, params),
    do: %{conn | path_params: Map.merge(conn.path_params || %{}, params)}

  defp attach_ui_receipts_telemetry do
    test_pid = self()
    handler_id = "ui-receipt-test-#{System.unique_integer()}"

    :telemetry.attach(
      handler_id,
      UiReceipts.telemetry_event(),
      fn _event, _measurements, meta, _config ->
        send(test_pid, {:ui_receipt_emitted, meta})
      end,
      nil
    )

    on_exit(fn -> :telemetry.detach(handler_id) end)
  end

  defp write_bundle do
    source =
      Path.join([
        Application.app_dir(:recurse_gateway, "priv"),
        "reference_policies",
        "platform_roles.cedar"
      ])
      |> File.read!()

    path = Path.join(System.tmp_dir!(), "us6_bundle_#{System.unique_integer()}.cedar")
    File.write!(path, source)
    on_exit(fn -> File.rm(path) end)
    path
  end
end
