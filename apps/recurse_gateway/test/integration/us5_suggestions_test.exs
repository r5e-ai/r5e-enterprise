defmodule RecurseGateway.Integration.US5SuggestionsTest do
  @moduledoc """
  US5 — Operator reviews suggestions end-to-end (F004 T123 + T137).

  Boots Gateway with seeded receipt fixtures matching each of the 5
  heuristic patterns; runs the heuristic engine; runs the LLM engine
  with a stubbed `LLMProvider`. Asserts:

    1. All 5 heuristic patterns produce at least one suggestion via
       `HeuristicRunner.run_for_window/2`.
    2. The HeuristicRunner cron-driven path emits
       `:ui_policy_suggestion_generated` per the canonical matrix.
    3. Operator opens UI → clicks "Adopt as draft" → asserts new
       `policy_drafts` row + suggestion status flip + receipts
       (`:ui_policy_suggestion_adopted` + `:ui_policy_draft_created`)
       visible in audit log.
    4. Manual `POST /v1/policy/suggestions/refresh` rate-limit fires
       after 6 attempts/hour (the 7th call returns 429).
    5. SuggestPolicyPattern audit-agent tool's `:upstream_unavailable`
       branch flips green now that the runners exist (the operator path
       through the agent works).
    6. FR-035 sparseness: a sparse window (<100 receipts) yields zero
       suggestions and the run row carries the
       `error: "skipped_sparse_window"` marker.

  ## `async: false`

  Same reason as other Phase-5/6 integration tests: shared
  `:persistent_term` slots (ProviderRegistry, BundleLoader) and the SQL
  Sandbox single connection. Application env writes
  (`:jwt_validator_opts`) reinforce this.
  """

  use ExUnit.Case, async: false

  setup_all do
    Recurse.Gateway.Test.KernelFixture.boot()
  end

  @moduletag :integration

  alias Ecto.Adapters.SQL.Sandbox
  alias Recurse.Gateway.Admin.BrowserAuth.UiReceipts
  alias Recurse.Gateway.Admin.PolicyDrafts.PolicyDraft
  alias Recurse.Gateway.Admin.PolicySuggestions
  alias Recurse.Gateway.Admin.PolicySuggestions.PolicySuggestion
  alias Recurse.Gateway.Admin.PolicySuggestionsHandler
  alias Recurse.Gateway.Policy.BundleLoader
  alias Recurse.Gateway.ProviderRegistry
  alias Recurse.Gateway.SuggestionEngine.Heuristic.AnomalousBurst
  alias Recurse.Gateway.SuggestionEngine.Heuristic.CrossTenantAccess
  alias Recurse.Gateway.SuggestionEngine.Heuristic.RecurringAllow
  alias Recurse.Gateway.SuggestionEngine.Heuristic.RecurringDeny
  alias Recurse.Gateway.SuggestionEngine.Heuristic.StaleRoleCreep
  alias Recurse.Gateway.SuggestionEngine.HeuristicRunner
  alias Recurse.Gateway.SuggestionEngine.LlmRunner
  alias Recurse.Gateway.Test.JwtTestHelper
  alias Recurse.Providers.Impls.PostgresMerkleLedger
  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Attestation
  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Session
  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Tenant
  alias Recurse.Providers.Repo

  @tenant_id "01HQZN5K7J8M9N0P1Q2R3S4T5V"

  setup do
    :ok = Sandbox.checkout(Repo)
    Sandbox.mode(Repo, {:shared, self()})

    Repo.insert!(
      Tenant.changeset(%Tenant{}, %{
        tenant_id: @tenant_id,
        display_name: "US5 Test Tenant",
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
      llm: {__MODULE__.StubLLM, %{}},
      ledger: {PostgresMerkleLedger, %{repo: Repo, pubsub: Recurse.PubSub, config: %{}}},
      storage: {Recurse.Gateway.Test.StubStorage, %{}},
      secrets: {Recurse.Gateway.Test.StubSecretsProvider, %{}},
      tenant_id: @tenant_id,
      signer: "observed://gateway/us5-test"
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

  describe "Heuristic patterns trigger over seeded fixtures" do
    test "all 5 patterns produce ≥1 suggestion against a crafted window" do
      window = build_combined_pattern_window()

      assert [_ | _] = RecurringAllow.detect(window)
      assert [_ | _] = RecurringDeny.detect(window)
      assert [_ | _] = AnomalousBurst.detect(window)
      assert [_ | _] = CrossTenantAccess.detect(window)
      assert [_ | _] = StaleRoleCreep.detect(window)
    end
  end

  describe "HeuristicRunner — sparseness suppression (FR-035)" do
    test "<100 receipts → run_for_window returns []" do
      # 50 attestations in the window — under the 100-receipt threshold.
      seed_attestations(50, decision: :allow, principal_subject: "alice@corp")

      assert {:ok, []} = HeuristicRunner.run_for_window(@tenant_id, %{})
    end

    test "≥100 receipts → run_for_window returns suggestions" do
      # 150 allows for one principal — should trigger RecurringAllow.
      seed_attestations(150, decision: :allow, principal_subject: "alice@corp")

      assert {:ok, suggestions} = HeuristicRunner.run_for_window(@tenant_id, %{})
      assert is_list(suggestions)
      # At least the recurring_allow pattern should fire.
      assert Enum.any?(suggestions, &(&1.pattern_name == :recurring_allow))
    end
  end

  describe "HeuristicRunner — cron-driven persistence path" do
    test "perform/1 emits :ui_policy_suggestion_generated for each persisted suggestion" do
      attach_ui_receipts_telemetry()
      seed_attestations(150, decision: :allow, principal_subject: "alice@corp")

      assert :ok =
               HeuristicRunner.perform(%Oban.Job{
                 args: %{"tenant_id" => @tenant_id}
               })

      assert_receive {:ui_receipt_emitted, %{event_kind: :ui_policy_suggestion_generated}}, 5_000

      # PolicySuggestion row landed in DB.
      suggestions = PolicySuggestions.list(%{tenant_id: @tenant_id, status: :active})
      assert suggestions != []
    end

    test "perform/1 with sparse window writes skipped_sparse_window marker" do
      seed_attestations(20, decision: :allow, principal_subject: "alice@corp")

      assert :ok =
               HeuristicRunner.perform(%Oban.Job{
                 args: %{"tenant_id" => @tenant_id}
               })

      # Look up the most recent run row.
      import Ecto.Query

      run =
        Repo.one(
          from(r in Recurse.Gateway.Admin.PolicySuggestions.PolicySuggestionRun,
            where: r.tenant_id == ^@tenant_id,
            order_by: [desc: r.scheduled_at],
            limit: 1
          )
        )

      assert run != nil
      assert run.error == "skipped_sparse_window"
      assert run.suggestions_generated_count == 0
    end
  end

  describe "Operator workflow — list, view, adopt" do
    test "Adopt-as-draft creates draft + flips status + emits both receipts" do
      attach_ui_receipts_telemetry()
      {:ok, suggestion} = seed_active_suggestion()

      jwt = mint_jwt("platform_operator")

      conn =
        :post
        |> Plug.Test.conn("/v1/policy/suggestions/#{suggestion.id}/adopt", "")
        |> with_path_params(%{"id" => suggestion.id})
        |> with_jwt(jwt)
        |> PolicySuggestionsHandler.adopt()

      assert conn.status == 201
      body = JSON.decode!(conn.resp_body)
      assert is_binary(body["draft_id"])

      assert_receive {:ui_receipt_emitted, %{event_kind: :ui_policy_suggestion_adopted}}, 2_000
      assert_receive {:ui_receipt_emitted, %{event_kind: :ui_policy_draft_created}}, 2_000

      # Verify lifecycle: suggestion status flipped + adopted_as_draft_id set.
      {:ok, %PolicySuggestion{status: :adopted_as_draft, adopted_as_draft_id: draft_id}} =
        PolicySuggestions.get(suggestion.id)

      assert draft_id == body["draft_id"]

      # Verify draft exists with the suggestion's Cedar.
      {:ok, %PolicyDraft{cedar_source: cedar}} =
        Recurse.Gateway.Admin.PolicyDrafts.get(draft_id, include_archived: false)

      assert cedar == suggestion.proposed_cedar
    end
  end

  describe "Manual refresh rate-limit (FR-030a)" do
    test "7th call within window returns 429" do
      jwt = mint_jwt("platform_operator")

      # First 6 calls should succeed (202).
      for _ <- 1..6 do
        conn =
          :post
          |> Plug.Test.conn("/v1/policy/suggestions/refresh", JSON.encode!(%{}))
          |> Plug.Conn.put_private(:policy_suggestions_refresh_backend, CountingBackend)
          |> with_json(jwt)
          |> PolicySuggestionsHandler.refresh()

        assert conn.status == 202
      end

      # 7th call should fail with 429.
      conn7 =
        :post
        |> Plug.Test.conn("/v1/policy/suggestions/refresh", JSON.encode!(%{}))
        |> Plug.Conn.put_private(:policy_suggestions_refresh_backend, CountingBackend)
        |> with_json(jwt)
        |> PolicySuggestionsHandler.refresh()

      assert conn7.status == 429
      assert {"retry-after", _} = List.keyfind(conn7.resp_headers, "retry-after", 0)
    end
  end

  describe "LLM runner — unavailable execution" do
    test "run_for_window refuses even when observations and a provider exist" do
      seed_attestations(150, decision: :allow, principal_subject: "alice@corp")

      result = LlmRunner.run_for_window(@tenant_id, %{})
      assert result == {:error, :capability_unavailable}
    end
  end

  test "already queued LLM jobs are cancelled as unavailable" do
    assert {:cancel, :capability_unavailable} =
             LlmRunner.perform(%Oban.Job{args: %{"tenant_id" => @tenant_id}})
  end

  describe "SuggestPolicyPattern audit-agent tool — Phase 7 dependency" do
    test "operator path now succeeds since runners exist (Code.ensure_loaded? hits)" do
      seed_attestations(150, decision: :allow, principal_subject: "alice@corp")

      input = %{"source" => "heuristic", "window_days" => 30}
      ctx = %{tenant_id: @tenant_id, principal: %{recurse_role: "platform_operator"}}

      # The tool should now reach into HeuristicRunner.run_for_window/2 and
      # return the suggestions (rather than the previous
      # `:runners_not_yet_implemented` short-circuit).
      result = Recurse.Gateway.Admin.AuditAgent.Tools.SuggestPolicyPattern.call(input, ctx)

      assert {:ok, %{"suggestions" => suggestions}} = result
      assert is_list(suggestions)
    end
  end

  # ---------------------------------------------------------------------------
  # Helpers — fixture builders
  # ---------------------------------------------------------------------------

  defp seed_attestations(count, opts) do
    decision = Keyword.fetch!(opts, :decision)
    principal_subject = Keyword.fetch!(opts, :principal_subject)
    now = DateTime.utc_now()

    {:ok, session} =
      %Session{}
      |> Session.changeset(%{
        tenant_id: @tenant_id,
        session_scope: :discovery_session,
        state: :active,
        session_start: now,
        principal_kind: :obo_human,
        principal_canonical: principal_subject
      })
      |> Repo.insert()

    Enum.each(1..count, fn i ->
      %Attestation{}
      |> Attestation.changeset(%{
        session_id: session.session_id,
        turn_id: Ecto.UUID.generate(),
        event_kind: :llm_call,
        machine_identity: %{
          "observed_jwt_subject" => "agent",
          "observed_jwt_issuer" => "test"
        },
        principal: %{
          "kind" => "obo_human",
          "subject" => principal_subject,
          "issuer" => "https://test/",
          "recurse_role" => "caller",
          "groups" => [],
          "tenant_id" => @tenant_id
        },
        tenant_id: @tenant_id,
        policy_canonical_hash: :crypto.hash(:sha256, "policy"),
        payload_hash: :crypto.hash(:sha256, "payload"),
        payload_uri: "s3://bucket/p.json",
        correlation_id: "corr-us5-#{i}-#{System.unique_integer()}",
        signer_kms_key_id: "test-key",
        signer_key_version: "v1",
        timestamp: DateTime.add(now, -i * 60, :second),
        signed_predicate_bytes: <<0::64>>,
        dsse_signature: <<0::64>>,
        verification_level: :signed,
        tier_completeness_advisory: :partial,
        policy_decision: decision,
        outcome: :success
      })
      |> Repo.insert!()
    end)

    :ok
  end

  defp seed_active_suggestion do
    {:ok, run} =
      PolicySuggestions.start_run(%{
        tenant_id: @tenant_id,
        source: :heuristic,
        scheduled_at: DateTime.utc_now()
      })

    PolicySuggestions.create(@tenant_id, %{
      source: :heuristic,
      confidence_score: 75,
      pattern_summary: "alice@corp invoked search_kb 60 times — codify it",
      proposed_cedar:
        "permit (principal == Recurse::Principal::Human::\"alice@corp\", " <>
          "action == Recurse::Action::\"ChatCompletion\", resource);",
      generation_run_id: run.id,
      status: :active,
      generated_at: DateTime.utc_now()
    })
  end

  # Crafted window that triggers all 5 patterns. Reuses the property-test
  # fixtures' shape conventions (composing instead of importing).
  defp build_combined_pattern_window do
    base = ~U[2026-04-24 00:00:00.000000Z]

    recurring_allows =
      for i <- 1..60 do
        receipt("alice@corp", "search_kb", :allow,
          committed_at: DateTime.add(base, -i * 60, :second)
        )
      end

    recurring_denies =
      for i <- 1..12 do
        receipt("bob@corp", "bash_exec", :deny,
          committed_at: DateTime.add(base, -i * 60, :second),
          matched_policy: "platform_roles.cedar:line:42"
        )
      end

    burst =
      for i <- 1..4 do
        receipt("carol@corp", "http_get", :allow,
          committed_at: DateTime.add(base, -i * 600, :second)
        )
      end

    cross_tenant =
      for i <- 1..3 do
        receipt("dan@corp", "search_kb", :allow,
          committed_at: DateTime.add(base, -i * 60, :second),
          tenant_attribute: "tenant-foreign"
        )
      end

    role_creep_recent =
      for i <- 1..15 do
        receipt("eve@corp", "bash_exec", :allow,
          committed_at: DateTime.add(base, -i * 3600, :second)
        )
      end

    role_creep_baseline =
      for offset <- 1..15, action <- ["search_kb", "chat_completion", "http_get"] do
        seconds_back = (8 + offset) * 86_400 + 3600

        receipt("eve@corp", action, :allow,
          committed_at: DateTime.add(base, -seconds_back, :second)
        )
      end

    recurring_allows ++
      recurring_denies ++ burst ++ cross_tenant ++ role_creep_recent ++ role_creep_baseline
  end

  defp receipt(subject, action, decision, opts) do
    %{
      principal_subject: subject,
      action_label: action,
      resource_kind: "LLMEndpoint",
      policy_decision: decision,
      committed_at: Keyword.fetch!(opts, :committed_at),
      principal_kind: :obo_human,
      principal_tenant_id: "tenant-a",
      tenant_attribute: Keyword.get(opts, :tenant_attribute),
      matched_policy: Keyword.get(opts, :matched_policy)
    }
  end

  # ---------------------------------------------------------------------------
  # Helpers — auth + plumbing
  # ---------------------------------------------------------------------------

  defp mint_jwt(recurse_role) do
    JwtTestHelper.mint_test_jwt(
      recurse_role: recurse_role,
      audience: "recurse-gateway-test",
      issuer: "https://test-broker.example.invalid"
    )
  end

  defp with_jwt(conn, jwt),
    do: Plug.Conn.put_req_header(conn, "authorization", "Bearer " <> jwt)

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

    path = Path.join(System.tmp_dir!(), "us5_bundle_#{System.unique_integer()}.cedar")
    File.write!(path, source)
    on_exit(fn -> File.rm(path) end)
    path
  end

  # Inline StubLLM module returning a structured-output response that
  # matches the LlmRunner's prompt schema so the parse path succeeds.
  # Mirrors the convention from f004_phase2_attestation_wiring_test.exs.
  defmodule StubLLM do
    @moduledoc false
    @behaviour Recurse.Providers.LLMProvider
    @impl true
    def init(_), do: {:ok, %{}}
    @impl true
    def chat_complete(_state, _req, _ctx) do
      content =
        JSON.encode!(%{
          "suggestions" => [
            %{
              "pattern_summary" => "alice@corp invoked search_kb 150 times — codify it",
              "proposed_cedar" =>
                "permit (principal == Recurse::Principal::Human::\"alice@corp\", action, resource);",
              "confidence" => 75,
              "rationale" => "high-volume unanimous allow"
            }
          ]
        })

      {:ok,
       %{
         "choices" => [
           %{"message" => %{"role" => "assistant", "content" => content}}
         ],
         "usage" => %{"total_tokens" => 1234}
       }}
    end

    @impl true
    def chat_complete_stream(_state, _req, _ctx), do: {:ok, []}
    @impl true
    def capabilities(_state), do: [:sync]
    @impl true
    def healthcheck(_state), do: :ok
    @impl true
    def terminate(_state, _reason), do: :ok
  end
end

defmodule CountingBackend do
  @moduledoc false
  # ETS-backed counter so concurrent test cases don't share state.
  # Keyed by (test pid + key) so each test's counter starts fresh.
  def hit(key, _scale, limit, _amount) do
    table = ensure_table()
    counter_key = {self(), key}
    count = :ets.update_counter(table, counter_key, {2, 1}, {counter_key, 0})

    if count > limit do
      {:deny, 60_000}
    else
      {:allow, count}
    end
  end

  defp ensure_table do
    case :ets.whereis(:counting_backend_state) do
      :undefined ->
        :ets.new(:counting_backend_state, [
          :public,
          :named_table,
          :set,
          read_concurrency: true,
          write_concurrency: true
        ])

      ref ->
        ref
    end
  end
end
