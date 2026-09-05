defmodule Recurse.Gateway.Admin.AuditAgent.Tools.FetchReceiptDetailTest do
  @moduledoc """
  Contract test for Tool 2 — `fetch_receipt_detail` (F004 T100).
  """

  use ExUnit.Case, async: false

  setup_all do
    Recurse.Gateway.Test.KernelFixture.boot()
  end

  alias Recurse.Gateway.Admin.AuditAgent.Runtime
  alias Recurse.Gateway.Admin.AuditAgent.TestHelper
  alias Recurse.Gateway.Admin.AuditAgent.Tools.FetchReceiptDetail

  setup do
    TestHelper.setup_fixture()
    TestHelper.attach_telemetry()
    :ok
  end

  describe "behaviour callbacks" do
    test "stable identifiers" do
      assert FetchReceiptDetail.name() == "fetch_receipt_detail"

      assert FetchReceiptDetail.cedar_action() ==
               ~s|Recurse::Action::"AuditAgentToolFetchReceiptDetail"|

      assert FetchReceiptDetail.event_kind() ==
               :ui_chat_skill_invoked_fetch_receipt_detail
    end
  end

  describe "valid input → output + receipt" do
    test "fetches a real receipt and emits the per-tool attestation" do
      run_id = TestHelper.seed_attestation()
      ctx = TestHelper.build_ctx("tenant_auditor")

      {:ok, output, attested_run_id} =
        Runtime.dispatch("fetch_receipt_detail", %{"run_id" => run_id}, %{
          identity_ctx: ctx,
          tenant_id: TestHelper.tenant_id(),
          conversation_id: Ecto.UUID.generate()
        })

      assert is_binary(attested_run_id)
      assert output["run_id"] == run_id
      assert output["event_kind"] in ["llm_call", "policy_denied"]
      assert run_id in output["attested_run_ids"]

      assert_receive {:ui_receipt_emitted,
                      %{event_kind: :ui_chat_skill_invoked_fetch_receipt_detail}},
                     2_000
    end
  end

  describe "Cedar deny" do
    test "caller role denied with deny receipt" do
      run_id = TestHelper.seed_attestation()
      ctx = TestHelper.build_ctx("caller")

      assert {:error, :forbidden, _deny_id} =
               Runtime.dispatch("fetch_receipt_detail", %{"run_id" => run_id}, %{
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
               Runtime.dispatch("fetch_receipt_detail", %{}, %{
                 identity_ctx: ctx,
                 tenant_id: TestHelper.tenant_id(),
                 conversation_id: Ecto.UUID.generate()
               })

      refute_receive {:ui_receipt_emitted, _}, 200
    end
  end
end
