defmodule Recurse.Gateway.Admin.PolicySuggestionsHandlerContractTest do
  @moduledoc """
  Contract tests for the F004 Phase-7 (US5) policy-suggestions surface (T124).

  Asserts each of the five suggestion endpoints against the contract in
  `specs/004-audit-console/contracts/audit_api_extensions.md`:

    * `GET /v1/policy/suggestions`              — list (`DashboardQuery` / `:ui_query`)
    * `GET /v1/policy/suggestions/{id}`         — fetch single (`PolicySuggestionView` / `:ui_policy_suggestion_viewed`)
    * `POST /v1/policy/suggestions/{id}/adopt`  — adopt (`PolicySuggestionAdopt` / `:ui_policy_suggestion_adopted`)
    * `POST /v1/policy/suggestions/{id}/dismiss` — dismiss (`PolicySuggestionDismiss` / `:ui_policy_suggestion_dismissed`)
    * `POST /v1/policy/suggestions/refresh`     — manual refresh (`PolicySuggestionRefresh` / `:ui_policy_suggestion_refresh_requested`)

  Each test asserts the `event_kind` emitted matches the canonical matrix
  at `data-model.md` §0 verbatim. Drift fails CI.

  `async: false` because BundleLoader + ProviderRegistry are singletons.
  """

  use ExUnit.Case, async: false

  setup_all do
    Recurse.Gateway.Test.KernelFixture.boot()
  end

  alias Recurse.Gateway.Admin.BrowserAuth.UiReceipts
  alias Recurse.Gateway.Admin.PolicySuggestions
  alias Recurse.Gateway.Admin.PolicySuggestionsHandler
  alias Recurse.Gateway.Policy.BundleLoader
  alias Recurse.Gateway.ProviderRegistry
  alias Recurse.Gateway.Test.JwtTestHelper
  alias Recurse.Providers.Impls.PostgresMerkleLedger
  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Tenant
  alias Recurse.Providers.Repo

  @tenant_id "01HQZN5K7J8M9N0P1Q2R3S4T5V"
  # GAN-review fix (PR-readiness #1, 2026-04-25): used by the cross-tenant
  # rejection tests below. Belongs to a different tenant than the JWT we
  # mint; mutation paths MUST return 404 (not 200, not 403) per
  # FR-006 + Constitution Principle V.
  @other_tenant_id "01HQZN5K7J8M9N0P1Q2R3S4T0X"

  setup do
    :ok = Ecto.Adapters.SQL.Sandbox.checkout(Repo)
    Ecto.Adapters.SQL.Sandbox.mode(Repo, {:shared, self()})

    Repo.insert!(
      Tenant.changeset(%Tenant{}, %{
        tenant_id: @tenant_id,
        display_name: "Phase-7 Test Tenant",
        tier: :standalone_gateway,
        created_at: DateTime.utc_now()
      }),
      on_conflict: :nothing,
      conflict_target: :tenant_id
    )

    # GAN-review fix (PR-readiness #1): seed a second tenant so cross-tenant
    # rejection tests can insert a suggestion owned by it.
    Repo.insert!(
      Tenant.changeset(%Tenant{}, %{
        tenant_id: @other_tenant_id,
        display_name: "Phase-7 Other Tenant",
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
      signer: "observed://gateway/policy-suggestions-contract-test"
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

  describe "GET /v1/policy/suggestions" do
    test "200 + emits :ui_query (query_kind=policy_suggestions)" do
      attach_ui_receipts_telemetry()
      {:ok, _suggestion} = seed_suggestion()

      jwt = mint_jwt("platform_operator")

      conn =
        :get
        |> Plug.Test.conn("/v1/policy/suggestions")
        |> with_jwt(jwt)
        |> PolicySuggestionsHandler.list()

      assert conn.status == 200
      body = JSON.decode!(conn.resp_body)
      assert is_list(body["suggestions"])
      assert body["suggestions"] != []

      assert_receive {:ui_receipt_emitted,
                      %{event_kind: :ui_query, query_kind: "policy_suggestions"}},
                     2_000
    end
  end

  describe "GET /v1/policy/suggestions/{id}" do
    test "200 with full body + emits :ui_policy_suggestion_viewed" do
      attach_ui_receipts_telemetry()
      {:ok, suggestion} = seed_suggestion()

      jwt = mint_jwt("platform_operator")

      conn =
        :get
        |> Plug.Test.conn("/v1/policy/suggestions/#{suggestion.id}")
        |> with_path_params(%{"id" => suggestion.id})
        |> with_jwt(jwt)
        |> PolicySuggestionsHandler.get_one()

      assert conn.status == 200
      body = JSON.decode!(conn.resp_body)
      assert body["id"] == suggestion.id
      assert body["proposed_cedar"] == suggestion.proposed_cedar

      assert_receive {:ui_receipt_emitted, %{event_kind: :ui_policy_suggestion_viewed}}, 2_000
    end

    test "404 for missing suggestion" do
      jwt = mint_jwt("platform_operator")
      missing = Ecto.UUID.generate()

      conn =
        :get
        |> Plug.Test.conn("/v1/policy/suggestions/#{missing}")
        |> with_path_params(%{"id" => missing})
        |> with_jwt(jwt)
        |> PolicySuggestionsHandler.get_one()

      assert conn.status == 404
    end
  end

  describe "POST /v1/policy/suggestions/{id}/adopt" do
    test "201 + emits :ui_policy_suggestion_adopted AND :ui_policy_draft_created" do
      attach_ui_receipts_telemetry()
      {:ok, suggestion} = seed_suggestion()

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
      assert body["suggestion_id"] == suggestion.id

      assert_receive {:ui_receipt_emitted, %{event_kind: :ui_policy_suggestion_adopted}}, 2_000
      assert_receive {:ui_receipt_emitted, %{event_kind: :ui_policy_draft_created}}, 2_000
    end

    test "403 for tenant_auditor (write actions blocked)" do
      {:ok, suggestion} = seed_suggestion()
      jwt = mint_jwt("tenant_auditor")

      conn =
        :post
        |> Plug.Test.conn("/v1/policy/suggestions/#{suggestion.id}/adopt", "")
        |> with_path_params(%{"id" => suggestion.id})
        |> with_jwt(jwt)
        |> PolicySuggestionsHandler.adopt()

      assert conn.status == 403
    end
  end

  describe "POST /v1/policy/suggestions/{id}/dismiss" do
    test "204 + emits :ui_policy_suggestion_dismissed" do
      attach_ui_receipts_telemetry()
      {:ok, suggestion} = seed_suggestion()

      jwt = mint_jwt("platform_operator")

      conn =
        :post
        |> Plug.Test.conn("/v1/policy/suggestions/#{suggestion.id}/dismiss", "")
        |> with_path_params(%{"id" => suggestion.id})
        |> with_jwt(jwt)
        |> PolicySuggestionsHandler.dismiss()

      assert conn.status == 204

      assert_receive {:ui_receipt_emitted, %{event_kind: :ui_policy_suggestion_dismissed}}, 2_000
    end
  end

  # ---------------------------------------------------------------------------
  # GAN-review fix (PR-readiness #1, 2026-04-25): cross-tenant rejection on
  # mutation paths. Symmetrical to the `:tenant_scope` guard now exposed on
  # `PolicySuggestions.get/2`. Cross-tenant access MUST return 404 (not 403)
  # so the response leaks nothing about whether the resource exists. Defends
  # FR-006 + Constitution Principle V.
  #
  # Note: `adopt/3` writes TWO rows (suggestion + draft); the new draft must
  # NOT be created when the suggestion-id-tenant guard rejects the request.
  # We assert the post-rejection draft count matches the pre-rejection count
  # (== 0 in the cross-tenant case).
  # ---------------------------------------------------------------------------

  describe "POST /v1/policy/suggestions/{id}/adopt — cross-tenant" do
    test "404 (not 201) when suggestion belongs to a different tenant" do
      attach_ui_receipts_telemetry()
      foreign_suggestion = seed_foreign_suggestion()

      pre_draft_count = count_drafts_for_tenant(@other_tenant_id)

      jwt = mint_jwt("platform_operator")

      conn =
        :post
        |> Plug.Test.conn("/v1/policy/suggestions/#{foreign_suggestion.id}/adopt", "")
        |> with_path_params(%{"id" => foreign_suggestion.id})
        |> with_jwt(jwt)
        |> PolicySuggestionsHandler.adopt()

      assert conn.status == 404

      refute_receive {:ui_receipt_emitted, %{event_kind: :ui_policy_suggestion_adopted}}, 500
      refute_receive {:ui_receipt_emitted, %{event_kind: :ui_policy_draft_created}}, 500

      # `adopt/3` is the two-row transactional write; verify the foreign
      # tenant's draft table did NOT grow (Repo.transact rolled back).
      assert count_drafts_for_tenant(@other_tenant_id) == pre_draft_count

      # And the foreign suggestion is still :active (not :adopted_as_draft).
      {:ok, reloaded} =
        PolicySuggestions.get(foreign_suggestion.id, tenant_scope: @other_tenant_id)

      assert reloaded.status == :active
      assert is_nil(reloaded.adopted_as_draft_id)
    end
  end

  describe "POST /v1/policy/suggestions/{id}/dismiss — cross-tenant" do
    test "404 (not 204) when suggestion belongs to a different tenant" do
      attach_ui_receipts_telemetry()
      foreign_suggestion = seed_foreign_suggestion()

      jwt = mint_jwt("platform_operator")

      conn =
        :post
        |> Plug.Test.conn("/v1/policy/suggestions/#{foreign_suggestion.id}/dismiss", "")
        |> with_path_params(%{"id" => foreign_suggestion.id})
        |> with_jwt(jwt)
        |> PolicySuggestionsHandler.dismiss()

      assert conn.status == 404

      refute_receive {:ui_receipt_emitted, %{event_kind: :ui_policy_suggestion_dismissed}}, 500

      # Foreign suggestion still :active (not :dismissed).
      {:ok, reloaded} =
        PolicySuggestions.get(foreign_suggestion.id, tenant_scope: @other_tenant_id)

      assert reloaded.status == :active
      assert is_nil(reloaded.dismissed_at)
    end
  end

  describe "POST /v1/policy/suggestions/refresh" do
    test "202 + emits :ui_policy_suggestion_refresh_requested" do
      attach_ui_receipts_telemetry()
      jwt = mint_jwt("platform_operator")

      conn =
        :post
        |> Plug.Test.conn("/v1/policy/suggestions/refresh", JSON.encode!(%{}))
        |> with_json(jwt)
        |> PolicySuggestionsHandler.refresh()

      assert conn.status == 202
      body = JSON.decode!(conn.resp_body)
      assert is_binary(body["run_id"])
      assert body["sources_triggered"] == ["heuristic"]
      run = Repo.get!(Recurse.Gateway.Admin.PolicySuggestions.PolicySuggestionRun, body["run_id"])
      assert run.source == :heuristic

      assert_receive {:ui_receipt_emitted,
                      %{event_kind: :ui_policy_suggestion_refresh_requested}},
                     2_000
    end

    test "explicit LLM refresh refuses without creating a suggestion run" do
      alias Recurse.Gateway.Admin.PolicySuggestions.PolicySuggestionRun
      before_runs = Repo.aggregate(PolicySuggestionRun, :count)
      jwt = mint_jwt("platform_operator")

      conn =
        :post
        |> Plug.Test.conn("/v1/policy/suggestions/refresh", JSON.encode!(%{"sources" => ["llm"]}))
        |> with_json(jwt)
        |> PolicySuggestionsHandler.refresh()

      assert conn.status == 503
      assert Repo.aggregate(PolicySuggestionRun, :count) == before_runs
    end

    test "429 with Retry-After when rate limit exceeded" do
      jwt = mint_jwt("platform_operator")

      # Inject a stub rate-limit backend that always denies. We thread it
      # through `conn.private[:policy_suggestions_refresh_backend]` which the
      # handler honors when set.
      conn =
        :post
        |> Plug.Test.conn("/v1/policy/suggestions/refresh", JSON.encode!(%{}))
        |> Plug.Conn.put_private(:policy_suggestions_refresh_backend, AlwaysDenyBackend)
        |> with_json(jwt)
        |> PolicySuggestionsHandler.refresh()

      assert conn.status == 429
      assert {"retry-after", _} = List.keyfind(conn.resp_headers, "retry-after", 0)
    end
  end

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  defp seed_suggestion do
    {:ok, run} =
      PolicySuggestions.start_run(%{
        tenant_id: @tenant_id,
        source: :heuristic,
        scheduled_at: DateTime.utc_now()
      })

    PolicySuggestions.create(@tenant_id, %{
      source: :heuristic,
      confidence_score: 80,
      pattern_summary: "test pattern summary",
      proposed_cedar:
        "permit (principal == Recurse::Principal::Human::\"alice@corp\", " <>
          "action == Recurse::Action::\"ChatCompletion\", resource);",
      generation_run_id: run.id,
      status: :active,
      generated_at: DateTime.utc_now()
    })
  end

  # GAN-review fix (PR-readiness #1): seed a suggestion owned by a DIFFERENT
  # tenant from the JWT's tenant. Used by the cross-tenant rejection tests.
  defp seed_foreign_suggestion do
    {:ok, run} =
      PolicySuggestions.start_run(%{
        tenant_id: @other_tenant_id,
        source: :heuristic,
        scheduled_at: DateTime.utc_now()
      })

    {:ok, suggestion} =
      PolicySuggestions.create(@other_tenant_id, %{
        source: :heuristic,
        confidence_score: 80,
        pattern_summary: "foreign-tenant pattern summary",
        proposed_cedar:
          "permit (principal == Recurse::Principal::Human::\"bob@other-corp\", " <>
            "action == Recurse::Action::\"ChatCompletion\", resource);",
        generation_run_id: run.id,
        status: :active,
        generated_at: DateTime.utc_now()
      })

    suggestion
  end

  defp count_drafts_for_tenant(tenant_id) do
    import Ecto.Query

    Recurse.Gateway.Admin.PolicyDrafts.PolicyDraft
    |> where([d], d.tenant_id == ^tenant_id)
    |> Repo.aggregate(:count, :id)
  end

  defp mint_jwt(recurse_role) do
    JwtTestHelper.mint_test_jwt(
      recurse_role: recurse_role,
      audience: "recurse-gateway-test",
      issuer: "https://test-broker.example.invalid"
    )
  end

  defp with_jwt(conn, jwt) do
    Plug.Conn.put_req_header(conn, "authorization", "Bearer " <> jwt)
  end

  defp with_json(conn, jwt) do
    conn
    |> Plug.Conn.put_req_header("authorization", "Bearer " <> jwt)
    |> Plug.Conn.put_req_header("content-type", "application/json")
    |> Plug.Parsers.call(Plug.Parsers.init(parsers: [:json], pass: ["*/*"], json_decoder: JSON))
  end

  defp with_path_params(conn, params) do
    %{conn | path_params: Map.merge(conn.path_params || %{}, params)}
  end

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

    path =
      Path.join(System.tmp_dir!(), "policy_suggestions_bundle_#{System.unique_integer()}.cedar")

    File.write!(path, source)
    on_exit(fn -> File.rm(path) end)
    path
  end
end

defmodule AlwaysDenyBackend do
  @moduledoc false
  def hit(_key, _scale, _limit, _amount), do: {:deny, 60_000}
end
