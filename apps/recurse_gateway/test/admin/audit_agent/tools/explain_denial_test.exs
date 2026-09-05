defmodule Recurse.Gateway.Admin.AuditAgent.Tools.ExplainDenialTest do
  @moduledoc """
  Contract test for Tool 3 — `explain_denial` (F004 T101).

  LLM-calling tool: also asserts token-budget enforcement
  (≤2K input / ≤1K output per call) per
  `audit_agent_tools.md` §"Cost guardrails".
  """

  use ExUnit.Case, async: false

  setup_all do
    Recurse.Gateway.Test.KernelFixture.boot()
  end

  alias Recurse.Gateway.Admin.AuditAgent.Runtime
  alias Recurse.Gateway.Admin.AuditAgent.TestHelper
  alias Recurse.Gateway.Admin.AuditAgent.Tools.ExplainDenial
  alias Recurse.Gateway.ProviderRegistry

  setup do
    TestHelper.setup_fixture()
    TestHelper.attach_telemetry()
    :ok
  end

  describe "behaviour callbacks" do
    test "stable identifiers" do
      assert ExplainDenial.name() == "explain_denial"

      assert ExplainDenial.cedar_action() ==
               ~s|Recurse::Action::"AuditAgentToolExplainDenial"|

      assert ExplainDenial.event_kind() == :ui_chat_skill_invoked_explain_denial
    end

    test "token budgets match contract (≤2K in / ≤1K out per call)" do
      assert ExplainDenial.per_call_max_input_tokens() == 2_000
      assert ExplainDenial.per_call_max_output_tokens() == 1_000
    end
  end

  describe "valid input → output + receipt" do
    test "explanation is bounded + receipt emitted" do
      run_id = TestHelper.seed_attestation(policy_decision: :deny)
      ctx = TestHelper.build_ctx("tenant_auditor")

      {:ok, output, attested_run_id} =
        Runtime.dispatch("explain_denial", %{"run_id" => run_id}, %{
          identity_ctx: ctx,
          tenant_id: TestHelper.tenant_id(),
          conversation_id: Ecto.UUID.generate()
        })

      assert is_binary(attested_run_id)
      assert is_binary(output["explanation"])
      assert output["tokens_in"] >= 0
      assert output["tokens_out"] >= 0
      assert run_id in output["attested_run_ids"]

      assert_receive {:ui_receipt_emitted, %{event_kind: :ui_chat_skill_invoked_explain_denial}},
                     2_000
    end

    test "upstream returning >1K tokens is bounded by the per-call output budget" do
      # Swap LLM to oversize stub.
      :ok = swap_llm(Recurse.Gateway.Test.AuditAgentStubLLMOversize)

      run_id = TestHelper.seed_attestation(policy_decision: :deny)
      ctx = TestHelper.build_ctx("tenant_auditor")

      {:ok, output, _run_id} =
        Runtime.dispatch("explain_denial", %{"run_id" => run_id}, %{
          identity_ctx: ctx,
          tenant_id: TestHelper.tenant_id(),
          conversation_id: Ecto.UUID.generate()
        })

      max_bytes = ExplainDenial.per_call_max_output_tokens() * 4
      assert byte_size(output["explanation"]) <= max_bytes
    end
  end

  describe "Cedar deny" do
    test "caller role denied" do
      run_id = TestHelper.seed_attestation()
      ctx = TestHelper.build_ctx("caller")

      assert {:error, :forbidden, _} =
               Runtime.dispatch("explain_denial", %{"run_id" => run_id}, %{
                 identity_ctx: ctx,
                 tenant_id: TestHelper.tenant_id(),
                 conversation_id: Ecto.UUID.generate()
               })

      assert_receive {:ui_receipt_emitted, %{event_kind: :ui_chat, outcome: "policy_denied"}},
                     2_000
    end
  end

  describe "input validation" do
    test "missing run_id → invalid_input + NO receipt" do
      ctx = TestHelper.build_ctx("tenant_auditor")

      assert {:error, :invalid_input, _} =
               Runtime.dispatch("explain_denial", %{}, %{
                 identity_ctx: ctx,
                 tenant_id: TestHelper.tenant_id(),
                 conversation_id: Ecto.UUID.generate()
               })

      refute_receive {:ui_receipt_emitted, _}, 200
    end
  end

  defp swap_llm(mod) do
    {:ok, current} = ProviderRegistry.fetch()

    ProviderRegistry.install_raw!(%{
      llm: {mod, %{}},
      ledger: current.ledger,
      storage: current.storage,
      secrets: current.secrets,
      tenant_id: current.tenant_id,
      signer: current.signer
    })

    :ok
  end
end
