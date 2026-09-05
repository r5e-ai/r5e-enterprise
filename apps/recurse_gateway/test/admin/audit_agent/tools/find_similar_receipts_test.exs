defmodule Recurse.Gateway.Admin.AuditAgent.Tools.FindSimilarReceiptsTest do
  @moduledoc """
  Contract test for Tool 4 — `find_similar_receipts` (F004 T102).
  """

  use ExUnit.Case, async: false

  setup_all do
    Recurse.Gateway.Test.KernelFixture.boot()
  end

  alias Recurse.Gateway.Admin.AuditAgent.Runtime
  alias Recurse.Gateway.Admin.AuditAgent.TestHelper
  alias Recurse.Gateway.Admin.AuditAgent.Tools.FindSimilarReceipts

  setup do
    TestHelper.setup_fixture()
    TestHelper.attach_telemetry()
    :ok
  end

  describe "behaviour callbacks" do
    test "stable identifiers" do
      assert FindSimilarReceipts.name() == "find_similar_receipts"

      assert FindSimilarReceipts.cedar_action() ==
               ~s|Recurse::Action::"AuditAgentToolFindSimilarReceipts"|

      assert FindSimilarReceipts.event_kind() ==
               :ui_chat_skill_invoked_find_similar_receipts
    end
  end

  describe "valid input → output + receipt" do
    test "finds receipts sharing principal_subject + emits attestation" do
      seed = TestHelper.seed_attestation(subject: "alice@corp")
      _other = TestHelper.seed_attestation(subject: "alice@corp")
      _unrelated = TestHelper.seed_attestation(subject: "bob@corp")

      ctx = TestHelper.build_ctx("tenant_auditor")

      {:ok, output, attested_run_id} =
        Runtime.dispatch("find_similar_receipts", %{"run_id" => seed}, %{
          identity_ctx: ctx,
          tenant_id: TestHelper.tenant_id(),
          conversation_id: Ecto.UUID.generate()
        })

      assert is_binary(attested_run_id)
      assert output["seed_run_id"] == seed
      assert is_list(output["similar_receipts"])
      assert "principal_subject" in output["match_dimensions"]
      assert seed in output["attested_run_ids"]

      assert_receive {:ui_receipt_emitted,
                      %{event_kind: :ui_chat_skill_invoked_find_similar_receipts}},
                     2_000
    end
  end

  describe "Cedar deny" do
    test "caller role denied" do
      seed = TestHelper.seed_attestation()
      ctx = TestHelper.build_ctx("caller")

      assert {:error, :forbidden, _} =
               Runtime.dispatch("find_similar_receipts", %{"run_id" => seed}, %{
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
               Runtime.dispatch("find_similar_receipts", %{}, %{
                 identity_ctx: ctx,
                 tenant_id: TestHelper.tenant_id(),
                 conversation_id: Ecto.UUID.generate()
               })

      refute_receive {:ui_receipt_emitted, _}, 200
    end
  end
end
