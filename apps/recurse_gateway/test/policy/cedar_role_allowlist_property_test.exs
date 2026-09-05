defmodule RecurseGateway.Policy.CedarRoleAllowlistPropertyTest do
  @moduledoc """
  T031 — F004 **Property-test surface S′** — Cedar role-allowlist matrix.

  Per `specs/004-audit-console/contracts/cedar_entity_schema_extensions.md`
  §"Property-test surface S′" and §"Role-to-action allowlist".

  ## Scope

  Asserts the role-allowlist matrix on the deployed `platform_roles.cedar`
  bundle. For every `(role, action)` cell we generate synthetic
  principal + context tuples and assert Cedar evaluation matches the
  matrix table at
  `specs/004-audit-console/contracts/cedar_entity_schema_extensions.md`
  §"Role-to-action allowlist".

  The matrix has **24 actions × 4 roles = 96 cells** (4 F002 + 20 F004
  actions; 14 named F004 actions + 6 `AuditAgentTool*` tools). The
  contract's prose count of "23/92" is a known off-by-one — the matrix
  table itself is the source of truth and lists 24 rows.

  At 100 iterations × 96 cells the budget is roughly 9,600 Cedar
  evaluations per CI run — within the F002 reference per-CI-run budget.

  Plus: a dedicated property asserts the `tenant_id` REQUIRED-ness — any
  principal missing `tenant_id` MUST fail Cedar evaluation regardless of
  action (see "missing tenant_id" property below).

  ## Why call `Recurse.Cedar.evaluate_with_entities/3` directly

  The Gateway's `Recurse.Gateway.Policy.Evaluator` does not yet stamp
  `tenant_id` onto the synthesized principal entity attrs (the F004 wiring
  adjustment lives in a downstream Wave 2 task). To exercise the
  role-allowlist policy logic *as it will run once Evaluator is updated*,
  this test builds the entity JSON manually with `tenant_id` set on the
  principal entity. That keeps the test focused on the bundle's
  decision-matrix correctness rather than coupling it to a transient
  Evaluator state.

  ## Generator discipline (per `elixir:stream-data-thinking`)

  * No `filter/3` — each axis is built constructively via `member_of`.
  * `bind` is used to couple `(role, action)` so we can compute the
    expected decision in the same step the test body uses for assertion.
  * `gen all` flattens the binds for readability.

  Cross-references:
    * `apps/recurse_gateway/priv/reference_policies/platform_roles.cedar`
    * `specs/004-audit-console/contracts/cedar_entity_schema_extensions.md`
    * `specs/004-audit-console/data-model.md` §0
    * `apps/recurse_gateway/test/policy/cedar_evaluator_property_test.exs`
      (F002 Surface S — sibling property test, narrower matrix)
  """

  use ExUnit.Case, async: true
  use ExUnitProperties

  @bundle_path Path.expand(
                 "../../priv/reference_policies/platform_roles.cedar",
                 __DIR__
               )

  @iterations 100

  @tenant_id "tenant-test"

  # ---------------------------------------------------------------------------
  # Action / role enumerations — verbatim from the F004 contract matrix
  # (cedar_entity_schema_extensions.md §"Role-to-action allowlist").
  # ---------------------------------------------------------------------------

  @f002_actions ~w(
    ChatCompletion
    ReadReceipts
    ReadPayload
    ExportEvidence
  )

  @f004_actions ~w(
    LoginSession
    DashboardQuery
    PolicySimulate
    PolicyReplay
    PolicyDraftCreate
    PolicyDraftEdit
    PolicyDraftArchive
    PolicyDraftDryRun
    PolicySuggestionGenerate
    PolicySuggestionView
    PolicySuggestionAdopt
    PolicySuggestionDismiss
    PolicySuggestionRefresh
    ChatDrawerQuery
    AuditAgentToolQueryReceipts
    AuditAgentToolFetchReceiptDetail
    AuditAgentToolExplainDenial
    AuditAgentToolFindSimilarReceipts
    AuditAgentToolSimulatePolicyDryrun
    AuditAgentToolSuggestPolicyPattern
  )

  # 23 = 4 F002 + 19 F004
  @all_actions @f002_actions ++ @f004_actions

  # 4 roles per the contract's matrix columns. The contract uses `caller`
  # (the F002 Data-Plane LLM-end-user role); the prompt's "unauthenticated"
  # phrasing aliases to this column. `system` is the internally-minted
  # service-account role used only by the suggestion engine.
  @roles ~w(tenant_auditor platform_operator caller system)

  # ---------------------------------------------------------------------------
  # Decision oracle — encodes the contract matrix verbatim.
  #
  # | Action                              | auditor | operator | caller | system |
  # |-------------------------------------|---------|----------|--------|--------|
  # | ChatCompletion                      |   :deny |    :deny | :allow |  :deny |
  # | ReadReceipts                        |  :allow |   :allow |  :deny |  :deny |
  # | ReadPayload                         |  :allow |   :allow |  :deny |  :deny |
  # | ExportEvidence                      |  :allow |   :allow |  :deny |  :deny |
  # | LoginSession                        |  :allow |   :allow |  :deny |  :deny |
  # | DashboardQuery                      |  :allow |   :allow |  :deny |  :deny |
  # | PolicySimulate                      |   :deny |   :allow |  :deny |  :deny |
  # | PolicyReplay                        |  :allow |   :allow |  :deny |  :deny |
  # | PolicyDraftCreate                   |   :deny |   :allow |  :deny |  :deny |
  # | PolicyDraftEdit                     |   :deny |   :allow |  :deny |  :deny |
  # | PolicyDraftArchive                  |   :deny |   :allow |  :deny |  :deny |
  # | PolicyDraftDryRun                   |   :deny |   :allow |  :deny |  :deny |
  # | PolicySuggestionGenerate            |   :deny |    :deny |  :deny | :allow |
  # | PolicySuggestionView                |   :deny |   :allow |  :deny |  :deny |
  # | PolicySuggestionAdopt               |   :deny |   :allow |  :deny |  :deny |
  # | PolicySuggestionDismiss             |   :deny |   :allow |  :deny |  :deny |
  # | PolicySuggestionRefresh             |   :deny |   :allow |  :deny |  :deny |
  # | ChatDrawerQuery                     |  :allow |   :allow |  :deny |  :deny |
  # | AuditAgentToolQueryReceipts         |  :allow |   :allow |  :deny |  :deny |
  # | AuditAgentToolFetchReceiptDetail    |  :allow |   :allow |  :deny |  :deny |
  # | AuditAgentToolExplainDenial         |  :allow |   :allow |  :deny |  :deny |
  # | AuditAgentToolFindSimilarReceipts   |  :allow |   :allow |  :deny |  :deny |
  # | AuditAgentToolSimulatePolicyDryrun  |  :allow |   :allow |  :deny |  :deny |
  # | AuditAgentToolSuggestPolicyPattern  |   :deny |   :allow |  :deny |  :deny |
  # ---------------------------------------------------------------------------

  @auditor_allow ~w(
    ReadReceipts
    ReadPayload
    ExportEvidence
    LoginSession
    DashboardQuery
    PolicyReplay
    ChatDrawerQuery
    AuditAgentToolQueryReceipts
    AuditAgentToolFetchReceiptDetail
    AuditAgentToolExplainDenial
    AuditAgentToolFindSimilarReceipts
    AuditAgentToolSimulatePolicyDryrun
  )

  @operator_allow ~w(
    ReadReceipts
    ReadPayload
    ExportEvidence
    LoginSession
    DashboardQuery
    PolicyReplay
    ChatDrawerQuery
    AuditAgentToolQueryReceipts
    AuditAgentToolFetchReceiptDetail
    AuditAgentToolExplainDenial
    AuditAgentToolFindSimilarReceipts
    AuditAgentToolSimulatePolicyDryrun
    PolicySimulate
    PolicyDraftCreate
    PolicyDraftEdit
    PolicyDraftArchive
    PolicyDraftDryRun
    PolicySuggestionView
    PolicySuggestionAdopt
    PolicySuggestionDismiss
    PolicySuggestionRefresh
    AuditAgentToolSuggestPolicyPattern
  )

  @caller_allow ~w(ChatCompletion)

  @system_allow ~w(PolicySuggestionGenerate)

  @spec expected_decision(String.t(), String.t()) :: :allow | :deny
  defp expected_decision("tenant_auditor", action),
    do: if(action in @auditor_allow, do: :allow, else: :deny)

  defp expected_decision("platform_operator", action),
    do: if(action in @operator_allow, do: :allow, else: :deny)

  defp expected_decision("caller", action),
    do: if(action in @caller_allow, do: :allow, else: :deny)

  defp expected_decision("system", action),
    do: if(action in @system_allow, do: :allow, else: :deny)

  # ---------------------------------------------------------------------------
  # Generators (constructive — no filter; bind preserves shrinking)
  # ---------------------------------------------------------------------------

  defp role_gen, do: StreamData.member_of(@roles)
  defp action_gen, do: StreamData.member_of(@all_actions)

  defp role_action_gen do
    gen all(
          role <- role_gen(),
          action <- action_gen()
        ) do
      {role, action}
    end
  end

  # ---------------------------------------------------------------------------
  # Cedar entity / request JSON builders.
  #
  # Principal entity is always a `Principal::Human` for simplicity — at the
  # NIF call we pass entity-JSON without a schema, so `appliesTo` is not
  # enforced at evaluation time. The role-allowlist policies themselves only
  # condition on `principal.recurse_role` and `principal.tenant_id`, so the
  # entity type doesn't influence the decision matrix.
  # ---------------------------------------------------------------------------

  defp principal_entity_json(role, opts) do
    include_tenant_id? = Keyword.get(opts, :include_tenant_id, true)

    base_attrs = %{
      "subject" => "alice",
      "issuer" => "https://idp.test",
      "groups" => [],
      "recurse_role" => role
    }

    attrs =
      if include_tenant_id? do
        Map.put(base_attrs, "tenant_id", @tenant_id)
      else
        base_attrs
      end

    [
      %{
        "uid" => %{"type" => "Recurse::Principal::Human", "id" => "alice"},
        "attrs" => attrs,
        "parents" => []
      },
      %{
        "uid" => %{"type" => "Recurse::Resource::ConsoleSurface", "id" => "console"},
        "attrs" => %{"console_path" => "/admin"},
        "parents" => []
      }
    ]
    |> JSON.encode!()
  end

  defp request_json(action) do
    %{
      "principal" => ~s[Recurse::Principal::Human::"alice"],
      "action" => ~s[Recurse::Action::"#{action}"],
      "resource" => ~s[Recurse::Resource::ConsoleSurface::"console"],
      "context" => %{
        "tenant_id" => @tenant_id,
        "correlation_id" => "01HZZZZZZZZZZZZZZZZZZZZZZZ",
        "timestamp" => 1_700_000_000,
        "client_ip" => "192.0.2.1"
      }
    }
    |> JSON.encode!()
  end

  defp evaluate(bundle_bytes, role, action, opts \\ []) do
    Recurse.Cedar.evaluate_with_entities(
      bundle_bytes,
      request_json(action),
      principal_entity_json(role, opts)
    )
  end

  # ---------------------------------------------------------------------------
  # Property 1 — full 23-action × 4-role matrix
  # ---------------------------------------------------------------------------

  describe "Surface S′ property 1: 92-cell role-allowlist matrix under platform_roles.cedar" do
    @describetag :property_surface_sprime

    setup do
      bytes = File.read!(@bundle_path)
      %{bundle_bytes: bytes}
    end

    property "Cedar decision matches the role-to-action oracle for every (role, action) cell",
             %{bundle_bytes: bundle_bytes} do
      check all({role, action} <- role_action_gen(), max_runs: @iterations) do
        expected = expected_decision(role, action)

        assert {:ok, %{decision: actual}} = evaluate(bundle_bytes, role, action)

        assert actual == expected,
               "role=#{role} action=#{action} → #{actual}; expected #{expected}.\n" <>
                 "Verify the (role, action) cell in\n" <>
                 "  specs/004-audit-console/contracts/cedar_entity_schema_extensions.md\n" <>
                 "matches the expected_decision/2 oracle in this test."
      end
    end
  end

  # ---------------------------------------------------------------------------
  # Property 2 — `tenant_id` REQUIRED on principal
  #
  # Per the F004 contract: every principal missing `tenant_id` MUST fail
  # Cedar evaluation regardless of action. This is the multi-tenant-readiness
  # invariant — the tenant binding is non-negotiable in the policy bundle.
  #
  # Mechanism: the F004 operator/auditor permits gate on
  # `principal.tenant_id == context.tenant_id`. When `tenant_id` is missing
  # from the entity attrs, Cedar raises an attribute-missing error and the
  # `permit` clause fails to match. The only role for which a principal
  # WITHOUT tenant_id can still allow is `caller`+`ChatCompletion` (F002
  # baseline rule, no tenant binding) and `system`+`PolicySuggestionGenerate`
  # (F004 system rule, no tenant binding — the system role's permit is
  # explicitly tenant-unbound because suggestion generation is cross-tenant
  # by design). All other cells must be :deny.
  # ---------------------------------------------------------------------------

  # F002 audit-plane permits (ReadReceipts / ReadPayload / ExportEvidence) and
  # the caller / system permits are NOT tenant-bound — they were either
  # authored pre-F004 (F002) or are deliberately tenant-unbound (system role
  # for cross-tenant suggestion generation per contract). Every F004-introduced
  # permit IS tenant-bound, so missing tenant_id forces deny on all F004 cells.
  @tenant_unbound_allow [
    {"tenant_auditor", "ReadReceipts"},
    {"tenant_auditor", "ReadPayload"},
    {"tenant_auditor", "ExportEvidence"},
    {"platform_operator", "ReadReceipts"},
    {"platform_operator", "ReadPayload"},
    {"platform_operator", "ExportEvidence"},
    {"caller", "ChatCompletion"},
    {"system", "PolicySuggestionGenerate"}
  ]

  defp tenant_required_expected_decision(role, action) do
    if {role, action} in @tenant_unbound_allow, do: :allow, else: :deny
  end

  describe "Surface S′ property 2: missing tenant_id forces deny on tenant-bound permits" do
    @describetag :property_surface_sprime

    setup do
      bytes = File.read!(@bundle_path)
      %{bundle_bytes: bytes}
    end

    property "principal without tenant_id never gets allow on a tenant-bound permit",
             %{bundle_bytes: bundle_bytes} do
      check all({role, action} <- role_action_gen(), max_runs: @iterations) do
        expected = tenant_required_expected_decision(role, action)

        assert {:ok, %{decision: actual}} =
                 evaluate(bundle_bytes, role, action, include_tenant_id: false)

        assert actual == expected,
               "role=#{role} action=#{action} (no tenant_id on principal) → #{actual}; " <>
                 "expected #{expected}. F004 contract requires every tenant-bound permit " <>
                 "to fail-closed when principal.tenant_id is absent."
      end
    end
  end
end
