defmodule Recurse.Gateway.Admin.AuditAgent.Tools.SuggestPolicyPatternTest do
  @moduledoc """
  Contract test for Tool 6 — `suggest_policy_pattern` (F004 T104).

  **Operator-only**: auditors are denied at the Cedar gate.

  **Phase-7 forward-ref**: the heuristic and LLM runners
  (`Recurse.Gateway.SuggestionEngine.{HeuristicRunner, LlmRunner}`) DO
  NOT yet exist. The tool dispatches via `Code.ensure_loaded?/1` and
  returns `{:error, :runners_not_yet_implemented}`; the Runtime maps
  that to `{:error, :upstream_unavailable, run_id}` with an emitted
  attestation carrying `outcome: "upstream_error"`. When Phase 7
  ships, the runners exist and this test will need to grow positive
  cases.
  """

  use ExUnit.Case, async: false

  setup_all do
    Recurse.Gateway.Test.KernelFixture.boot()
  end

  alias Recurse.Gateway.Admin.AuditAgent.Runtime
  alias Recurse.Gateway.Admin.AuditAgent.TestHelper
  alias Recurse.Gateway.Admin.AuditAgent.Tools.SuggestPolicyPattern

  setup do
    TestHelper.setup_fixture()
    TestHelper.attach_telemetry()
    :ok
  end

  describe "behaviour callbacks" do
    test "stable identifiers" do
      assert SuggestPolicyPattern.name() == "suggest_policy_pattern"

      assert SuggestPolicyPattern.cedar_action() ==
               ~s|Recurse::Action::"AuditAgentToolSuggestPolicyPattern"|

      assert SuggestPolicyPattern.event_kind() ==
               :ui_chat_skill_invoked_suggest_policy_pattern
    end
  end

  describe "operator-only Cedar gate" do
    test "AUDITOR is denied (write-adjacent capability)" do
      ctx = TestHelper.build_ctx("tenant_auditor")

      assert {:error, :forbidden, _} =
               Runtime.dispatch("suggest_policy_pattern", %{"source" => "heuristic"}, %{
                 identity_ctx: ctx,
                 tenant_id: TestHelper.tenant_id(),
                 conversation_id: Ecto.UUID.generate()
               })

      assert_receive {:ui_receipt_emitted, %{event_kind: :ui_chat, outcome: "policy_denied"}},
                     2_000
    end

    test "OPERATOR passes Cedar; tool dispatches to HeuristicRunner (Phase 7 landed)" do
      ctx = TestHelper.build_ctx("platform_operator")

      # Phase 7 landed `Recurse.Gateway.SuggestionEngine.HeuristicRunner` —
      # the `Code.ensure_loaded?/1` guard now hits, and the tool dispatches
      # to `run_for_window/2` instead of the pre-Phase-7
      # `:upstream_unavailable` short-circuit. With no seeded receipts the
      # window is sparse so the runner returns `{:ok, []}` per FR-035 —
      # the tool surface returns `{:ok, %{...}}` with `suggestions: []`.
      assert {:ok, %{"suggestions" => suggestions, "source" => "heuristic"}, run_id} =
               Runtime.dispatch("suggest_policy_pattern", %{"source" => "heuristic"}, %{
                 identity_ctx: ctx,
                 tenant_id: TestHelper.tenant_id(),
                 conversation_id: Ecto.UUID.generate()
               })

      assert is_list(suggestions)
      assert is_binary(run_id)

      assert_receive {:ui_receipt_emitted,
                      %{
                        event_kind: :ui_chat_skill_invoked_suggest_policy_pattern,
                        outcome: "success"
                      }},
                     2_000
    end
  end

  describe "input validation" do
    test "missing source → invalid_input + NO receipt" do
      ctx = TestHelper.build_ctx("platform_operator")

      assert {:error, :invalid_input, _} =
               Runtime.dispatch("suggest_policy_pattern", %{}, %{
                 identity_ctx: ctx,
                 tenant_id: TestHelper.tenant_id(),
                 conversation_id: Ecto.UUID.generate()
               })

      refute_receive {:ui_receipt_emitted, _}, 200
    end
  end

  describe "Phase-7 forward-ref discipline" do
    test "uses Code.ensure_loaded?/1 for the runners (defensive guard exists)" do
      # The grep-style assertion: the source contains the string
      # `Code.ensure_loaded?` so future maintainers can't accidentally
      # remove the guard without tripping this test.
      source = File.read!(SuggestPolicyPattern.module_info(:compile)[:source])
      assert source =~ "Code.ensure_loaded?"
    end
  end
end
