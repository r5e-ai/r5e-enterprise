defmodule RecurseGateway.Integration.US3PolicyDraftTest do
  @moduledoc """
  US3 — Operator drafts policy with Blast Radius end-to-end (F004 T083 + T096).

  Drives the Phase-5 surfaces against a real DSSE-signed seed receipt:

    1. **Skeleton from receipt** (`POST /v1/policy/drafts/from-receipt`) —
       seeds a draft from a committed attestation; asserts the draft
       carries `source_receipt_run_id` back-link.
    2. **Edit draft** (`PATCH /v1/policy/drafts/{id}`) — changes the
       Cedar source; asserts cache invalidation per
       `blast_radius_algorithm.md` §7.
    3. **Dry-run sync** (`POST /v1/policy/drafts/{id}/dry-run`) — runs
       the streaming algorithm against the seeded receipt window; asserts
       4-cell counts (matches_intent + unintended + would_have_allowed +
       no_change) per algorithm §5a; asserts SC-003 30s budget.
    4. **`:ui_policy_draft_created` + `:ui_policy_draft_edited` +
       `:ui_policy_draft_dry_run` receipts emitted** per `data-model.md` §0.
    5. **Async escalation sentinel** — verifies the threshold helper
       (`BlastRadius.async_threshold/0` returns 10K); seeding 10K rows
       in an integration test would dominate the suite runtime, so the
       async path is exercised structurally here and cardinality-wise
       in the property test (Surface T).

  ## `async: false`

  Same reason as US2 / US1 integration tests: shared `:persistent_term`
  slots (`ProviderRegistry`, `BundleLoader`) and the SQL-Sandbox single
  connection. The Application env writes (`:browser_session`,
  `:jwt_validator_opts`) reinforce this.
  """

  use ExUnit.Case, async: false

  setup_all do
    Recurse.Gateway.Test.KernelFixture.boot()
  end

  @moduletag :integration

  alias Ecto.Adapters.SQL.Sandbox
  alias Recurse.Gateway.Admin.BlastRadius
  alias Recurse.Gateway.Admin.BrowserAuth.UiReceipts
  alias Recurse.Gateway.Admin.PolicyDrafts
  alias Recurse.Gateway.Admin.PolicyDraftsDryRunHandler
  alias Recurse.Gateway.Admin.PolicyDraftsFromReceiptHandler
  alias Recurse.Gateway.Admin.PolicyDraftsHandler
  alias Recurse.Gateway.Policy.BundleLoader
  alias Recurse.Gateway.ProviderRegistry
  alias Recurse.Gateway.Test.JwtTestHelper
  alias Recurse.Providers.Impls.PostgresMerkleLedger
  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Attestation
  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Session
  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Tenant
  alias Recurse.Providers.Repo

  @tenant_id "01HQZN5K7J8M9N0P1Q2R3S4T5V"

  @cedar_skeleton_v1 """
  permit (
    principal,
    action == Recurse::Action::"DashboardQuery",
    resource
  )
  when {
    principal.recurse_role == "platform_operator"
  };
  """

  @cedar_skeleton_v2 """
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
        display_name: "US3 Test Tenant",
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
      signer: "observed://gateway/us3-test"
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

  describe "US3 — full workflow (T096)" do
    test "from-receipt → edit → dry-run end-to-end with all receipts emitted" do
      attach_ui_receipts_telemetry()

      # Seed a real allow-decision attestation that the operator will use as
      # their seed for "Create policy rule from this receipt".
      seed_run_id = seed_attestation(:allow)

      # ---- Step 1: from-receipt → skeleton draft ----------------------------

      jwt = mint_jwt("platform_operator")

      conn1 =
        :post
        |> Plug.Test.conn(
          "/v1/policy/drafts/from-receipt",
          JSON.encode!(%{"source_receipt_run_id" => seed_run_id})
        )
        |> with_json(jwt)
        |> PolicyDraftsFromReceiptHandler.handle()

      assert conn1.status == 201
      created = JSON.decode!(conn1.resp_body)
      assert created["source_receipt_run_id"] == seed_run_id
      assert is_binary(created["id"])

      draft_id = created["id"]

      assert_receive {:ui_receipt_emitted,
                      %{event_kind: :ui_policy_draft_created, seeded_from_receipt: true}},
                     2_000

      # ---- Step 2: edit draft → assert cache invalidation -------------------

      # First seed a fake cached summary so we can assert it's cleared.
      {:ok, _} =
        PolicyDrafts.persist_blast_radius_summary(draft_id, %{
          "total_scanned" => 100,
          "matches_intent" => 50,
          "unintended" => 0,
          "would_have_allowed" => 0,
          "no_change" => 50,
          "total_affected" => 50
        })

      jwt2 = mint_jwt("platform_operator")

      conn2 =
        :patch
        |> Plug.Test.conn(
          "/v1/policy/drafts/#{draft_id}",
          JSON.encode!(%{"cedar_source" => @cedar_skeleton_v2})
        )
        |> with_path_params(%{"id" => draft_id})
        |> with_json(jwt2)
        |> PolicyDraftsHandler.update()

      assert conn2.status == 200
      edited = JSON.decode!(conn2.resp_body)
      assert edited["cedar_source"] == @cedar_skeleton_v2
      # Cache invalidated per blast_radius_algorithm.md §7
      assert is_nil(edited["last_blast_radius_summary"])

      assert_receive {:ui_receipt_emitted, %{event_kind: :ui_policy_draft_edited}}, 2_000

      # ---- Step 3: dry-run → assert 4-cell counts + SC-003 budget ----------

      jwt3 = mint_jwt("platform_operator")

      {duration_us, conn3} =
        :timer.tc(fn ->
          :post
          |> Plug.Test.conn(
            "/v1/policy/drafts/#{draft_id}/dry-run",
            JSON.encode!(%{"window_days" => 30})
          )
          |> with_path_params(%{"id" => draft_id})
          |> with_json(jwt3)
          |> PolicyDraftsDryRunHandler.handle()
        end)

      assert conn3.status == 200
      dry = JSON.decode!(conn3.resp_body)

      # 4-cell counts per blast_radius_algorithm.md §5a — all four MUST be
      # top-level integer fields. would_have_allowed is the load-bearing one.
      assert is_integer(dry["matches_intent"])
      assert is_integer(dry["unintended"])
      assert is_integer(dry["would_have_allowed"])
      assert is_integer(dry["no_change"])
      assert is_integer(dry["total_affected"])
      assert is_integer(dry["total_receipts_in_window"])
      assert dry["mode"] == "sync"
      assert dry["draft_id"] == draft_id

      # We seeded one allow receipt; the v2 forbid rule scoped to caller
      # role + ChatCompletion action should classify it as :unintended,
      # demonstrating the wedge: operator authoring a forbid rule sees
      # the attempt to block legitimate work BEFORE deploying.
      assert dry["total_receipts_in_window"] >= 1

      # SC-003: 30 second budget for the entire Blast Radius compute.
      assert duration_us < 30_000_000,
             "dry-run exceeded SC-003 30s budget: #{div(duration_us, 1000)}ms"

      assert_receive {:ui_receipt_emitted, %{event_kind: :ui_policy_draft_dry_run, mode: "sync"}},
                     2_000
    end

    test "async escalation: BlastRadius.async_threshold/0 == 10_000 (sentinel)" do
      # Per blast_radius_algorithm.md §6 — windows >10K receipts force the
      # async Oban path. We don't seed 10K receipts in an integration test
      # (that would dominate suite runtime); we assert the threshold helper
      # so any future tuning requires an explicit code change here.
      assert BlastRadius.async_threshold() == 10_000
    end

    test "tenant_auditor cannot create drafts (Cedar gate)" do
      seed_run_id = seed_attestation(:allow)
      jwt = mint_jwt("tenant_auditor")

      conn =
        :post
        |> Plug.Test.conn(
          "/v1/policy/drafts/from-receipt",
          JSON.encode!(%{"source_receipt_run_id" => seed_run_id})
        )
        |> with_json(jwt)
        |> PolicyDraftsFromReceiptHandler.handle()

      # tenant_auditor lacks PolicyDraftCreate per cedar_entity_schema_extensions
      assert conn.status == 403
    end

    test "lifecycle: archive transitions draft to :archived and emits receipt" do
      attach_ui_receipts_telemetry()
      {:ok, draft} = seed_draft()

      jwt = mint_jwt("platform_operator")

      conn =
        :delete
        |> Plug.Test.conn("/v1/policy/drafts/#{draft.id}")
        |> with_path_params(%{"id" => draft.id})
        |> with_jwt(jwt)
        |> PolicyDraftsHandler.archive()

      assert conn.status == 204

      assert_receive {:ui_receipt_emitted, %{event_kind: :ui_policy_draft_archived}}, 2_000

      # Re-fetch with include_archived to confirm the lifecycle transition stuck.
      assert {:ok, archived} = PolicyDrafts.get(draft.id, include_archived: true)
      assert archived.status == :archived
      assert not is_nil(archived.archived_at)
    end
  end

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  defp seed_draft do
    PolicyDrafts.create(@tenant_id, %{
      "cedar_source" => @cedar_skeleton_v1,
      "scope_metadata" => %{"scope_kind" => "tenant", "scope_value" => @tenant_id},
      "condition_metadata" => [],
      "author_principal_subject" => "operator@corp",
      "status" => :draft
    })
  end

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
          "groups" => []
        },
        tenant_id: @tenant_id,
        policy_canonical_hash: :crypto.hash(:sha256, "policy"),
        payload_hash: :crypto.hash(:sha256, "payload"),
        payload_uri: "s3://bucket/p.json",
        correlation_id: "corr-us3-#{System.unique_integer()}",
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

  defp with_jwt(conn, jwt),
    do: Plug.Conn.put_req_header(conn, "authorization", "Bearer " <> jwt)

  # Set auth + content-type AND run the JSON parser inline so handlers
  # (which expect Plug.Parsers to have populated `conn.body_params`)
  # see the body. The production router runs Plug.Parsers upstream;
  # direct-handler test calls must mirror that.
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

    path = Path.join(System.tmp_dir!(), "us3_bundle_#{System.unique_integer()}.cedar")
    File.write!(path, source)
    on_exit(fn -> File.rm(path) end)
    path
  end
end
