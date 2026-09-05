defmodule Recurse.Gateway.Admin.AuditAgent.Tools.QueryReceiptsTest do
  @moduledoc """
  Contract test for Tool 1 — `query_receipts` (F004 T099).

  Per `property_test_surface_catalog_f004.md` §"Audit-agent tool
  contract tests", asserts:

    a) Valid input → output validates against the output schema +
       exactly one `:ui_chat_skill_invoked_query_receipts` receipt.
    b) Cedar deny for an unauthorized role → `:policy_denied`-class
       receipt (in this implementation: a `:ui_chat` outcome=policy_denied
       per Runtime.emit_policy_denied/3).
    c) Input validation failure → no Cedar call, no receipt.
  """

  use ExUnit.Case, async: false

  setup_all do
    Recurse.Gateway.Test.KernelFixture.boot()
  end

  alias Recurse.Gateway.Admin.AuditAgent.Runtime
  alias Recurse.Gateway.Admin.AuditAgent.TestHelper
  alias Recurse.Gateway.Admin.AuditAgent.Tools.QueryReceipts

  setup do
    TestHelper.setup_fixture()
    TestHelper.attach_telemetry()
    :ok
  end

  describe "behaviour callbacks" do
    test "name/0 / cedar_action/0 / event_kind/0 are stable" do
      assert QueryReceipts.name() == "query_receipts"

      assert QueryReceipts.cedar_action() ==
               ~s|Recurse::Action::"AuditAgentToolQueryReceipts"|

      assert QueryReceipts.event_kind() == :ui_chat_skill_invoked_query_receipts
    end

    test "input_schema/0 + output_schema/0 are well-formed maps" do
      assert %{"type" => "object"} = QueryReceipts.input_schema()
      assert %{"type" => "object", "required" => required} = QueryReceipts.output_schema()
      assert "receipts" in required
      assert "total_match_count_estimate" in required
    end
  end

  describe "valid input → output + receipt" do
    test "auditor: empty filters returns receipts list + emits one receipt" do
      _ = TestHelper.seed_attestation()

      ctx = TestHelper.build_ctx("tenant_auditor")

      {:ok, output, run_id} =
        Runtime.dispatch("query_receipts", %{}, %{
          identity_ctx: ctx,
          tenant_id: TestHelper.tenant_id(),
          conversation_id: Ecto.UUID.generate()
        })

      assert is_binary(run_id)
      assert is_list(output["receipts"])
      assert is_integer(output["total_match_count_estimate"])

      assert_receive {:ui_receipt_emitted, %{event_kind: :ui_chat_skill_invoked_query_receipts}},
                     2_000
    end
  end

  describe "Cedar deny" do
    test "caller (no F004 console role) → forbidden + outcome=policy_denied receipt" do
      ctx = TestHelper.build_ctx("caller")

      assert {:error, :forbidden, deny_run_id} =
               Runtime.dispatch("query_receipts", %{}, %{
                 identity_ctx: ctx,
                 tenant_id: TestHelper.tenant_id(),
                 conversation_id: Ecto.UUID.generate()
               })

      assert is_binary(deny_run_id)

      assert_receive {:ui_receipt_emitted, %{event_kind: :ui_chat, outcome: "policy_denied"}},
                     2_000
    end
  end

  describe "input validation" do
    test "non-integer limit → invalid_input + NO receipt" do
      ctx = TestHelper.build_ctx("tenant_auditor")

      assert {:error, :invalid_input, _details} =
               Runtime.dispatch("query_receipts", %{"limit" => "not-an-integer"}, %{
                 identity_ctx: ctx,
                 tenant_id: TestHelper.tenant_id(),
                 conversation_id: Ecto.UUID.generate()
               })

      refute_receive {:ui_receipt_emitted, _}, 200
    end

    test "extra unknown field → invalid_input + NO receipt" do
      ctx = TestHelper.build_ctx("tenant_auditor")

      assert {:error, :invalid_input, _details} =
               Runtime.dispatch("query_receipts", %{"unknown_field" => 1}, %{
                 identity_ctx: ctx,
                 tenant_id: TestHelper.tenant_id(),
                 conversation_id: Ecto.UUID.generate()
               })

      refute_receive {:ui_receipt_emitted, _}, 200
    end
  end
end
