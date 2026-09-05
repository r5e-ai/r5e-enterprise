defmodule Recurse.Gateway.Admin.AuditAgent.Tools.SimulatePolicyDryrunTest do
  @moduledoc """
  Contract test for Tool 5 — `simulate_policy_dryrun` (F004 T103).
  """

  use ExUnit.Case, async: false

  setup_all do
    Recurse.Gateway.Test.KernelFixture.boot()
  end

  alias Recurse.Gateway.Admin.AuditAgent.Runtime
  alias Recurse.Gateway.Admin.AuditAgent.TestHelper
  alias Recurse.Gateway.Admin.AuditAgent.Tools.SimulatePolicyDryrun

  @cedar_skeleton """
  permit (
    principal,
    action == Recurse::Action::"DashboardQuery",
    resource
  )
  when {
    principal.recurse_role == "platform_operator" && principal.tenant_id == context.tenant_id
  };
  """

  setup do
    TestHelper.setup_fixture()
    TestHelper.attach_telemetry()
    :ok
  end

  describe "behaviour callbacks" do
    test "stable identifiers" do
      assert SimulatePolicyDryrun.name() == "simulate_policy_dryrun"

      assert SimulatePolicyDryrun.cedar_action() ==
               ~s|Recurse::Action::"AuditAgentToolSimulatePolicyDryrun"|

      assert SimulatePolicyDryrun.event_kind() ==
               :ui_chat_skill_invoked_simulate_policy_dryrun
    end
  end

  describe "valid input → output + receipt" do
    test "auditor (read-only) CAN simulate; emits attestation" do
      input = build_simulate_input()
      ctx = TestHelper.build_ctx("tenant_auditor")

      {:ok, output, attested_run_id} =
        Runtime.dispatch("simulate_policy_dryrun", input, %{
          identity_ctx: ctx,
          tenant_id: TestHelper.tenant_id(),
          conversation_id: Ecto.UUID.generate()
        })

      assert is_binary(attested_run_id)
      assert output["decision"] in ["allow", "deny"]
      assert is_list(output["matched_policies"])

      assert_receive {:ui_receipt_emitted,
                      %{event_kind: :ui_chat_skill_invoked_simulate_policy_dryrun}},
                     2_000
    end
  end

  describe "Cedar deny" do
    test "caller role denied" do
      input = build_simulate_input()
      ctx = TestHelper.build_ctx("caller")

      assert {:error, :forbidden, _} =
               Runtime.dispatch("simulate_policy_dryrun", input, %{
                 identity_ctx: ctx,
                 tenant_id: TestHelper.tenant_id(),
                 conversation_id: Ecto.UUID.generate()
               })

      assert_receive {:ui_receipt_emitted, %{event_kind: :ui_chat, outcome: "policy_denied"}},
                     2_000
    end
  end

  describe "input validation" do
    test "missing required cedar_source → invalid_input + NO receipt" do
      ctx = TestHelper.build_ctx("tenant_auditor")

      assert {:error, :invalid_input, _} =
               Runtime.dispatch(
                 "simulate_policy_dryrun",
                 %{"principal" => %{}, "action" => "x", "resource" => %{}},
                 %{
                   identity_ctx: ctx,
                   tenant_id: TestHelper.tenant_id(),
                   conversation_id: Ecto.UUID.generate()
                 }
               )

      refute_receive {:ui_receipt_emitted, _}, 200
    end
  end

  defp build_simulate_input do
    %{
      "cedar_source" => @cedar_skeleton,
      "principal" => %{
        "kind" => "obo_human",
        "id" => "alice@corp",
        "attrs" => %{
          "subject" => "alice@corp",
          "issuer" => "https://test/",
          "groups" => [],
          "recurse_role" => "platform_operator",
          "tenant_id" => TestHelper.tenant_id()
        }
      },
      "action" => ~s|Recurse::Action::"DashboardQuery"|,
      "resource" => %{
        "kind" => "Recurse::Resource::ConsoleSurface",
        "id" => "policy_simulate",
        "attrs" => %{}
      },
      "context" => %{"tenant_id" => TestHelper.tenant_id()}
    }
  end
end
