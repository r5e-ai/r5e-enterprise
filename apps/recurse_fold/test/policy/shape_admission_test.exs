defmodule Recurse.Fold.Policy.ShapeAdmissionTest do
  @moduledoc """
  §8: a `PolicyShape` is validated by the engine at `authorize`.

  Two checks live here and one lives in the kernel, and which fires first
  matters enough to pin:

    * the **name** must be the derived `{engine}.{kind}`. The kernel settles
      that at `validateStructure`, which runs *before* `authorize`, so a
      wrong-named shape never reaches this engine and the message a caller
      sees is the kernel's. The engine keeps the check for the direct-call
      path (and as belt to the kernel's braces), and the first test below
      pins both halves.
    * the **paths** must type against the target Kind's admitted schema, and
      a `*` shape may read only envelope paths. Neither has a kernel
      counterpart: the kernel does not know what a shape's strings mean.
  """
  use ExUnit.Case, async: false

  setup_all do
    Recurse.Fold.FreshKernel.boot()
  end

  import Recurse.Fold.TestHelpers

  alias Recurse.Fold.Policy.Cedar

  defp admit_shape(spec, name \\ nil) do
    {g, v, k} = Cedar.shape_coordinates()
    admit(g, v, k, name || Cedar.shape_name(spec["kind"]), spec)
  end

  defp shape(overrides) do
    Map.merge(
      %{
        "kind" => "gateway.r5e.io/v1alpha1/ToolResult",
        "engine" => "cedar",
        "action" => "record_result",
        "resourceType" => "ToolUse",
        "resourceId" => "spec.outcome"
      },
      overrides
    )
  end

  test "a well-formed shape is admitted" do
    # AgentSession, because a shape for it is the E2 workaround this group
    # documents (the `cedar.*` fallback cannot name a `server`-named
    # instance) — not, as it once was, because it was the one Kind no
    # other file in this suite admitted a shape for. This file has a
    # kernel of its own now; what it admits reaches nothing else.
    assert {:ok, receipt} =
             admit_shape(
               shape(%{
                 "kind" => "gateway.r5e.io/v1alpha1/AgentSession",
                 "action" => "open_session",
                 "resourceType" => "Session",
                 "resourceId" => "spec.harness",
                 "context" => %{
                   "purpose" => %{"path" => "spec.purpose", "whenAbsent" => "absent"}
                 }
               })
             )

    assert receipt["name"] == "cedar.gateway.r5e.io/v1alpha1/AgentSession"
    assert receipt["policy"]["decision"] == "allow"
  end

  test "a shape whose path does not type against the target Kind is denied, naming the path" do
    assert {:denied, receipt} =
             admit_shape(
               shape(%{
                 "kind" => "gateway.r5e.io/v1alpha1/LlmResponse",
                 "resourceId" => "spec.nope"
               })
             )

    assert receipt["reason"] =~ "authorize: policy shape refused:"
    assert receipt["reason"] =~ "resourceId"
    assert receipt["reason"] =~ "declares no property \"nope\""
    # K8 (RC review 2026-09-05): the refusal names the engine that made it.
    # It used to arrive as a 2-tuple and be recorded as engine "unknown" —
    # the kernel's word for "a policy that predates the metadata contract"
    # — which left a policy-management refusal unable to say what refused it.
    assert receipt["policy"]["engine"] == "cedar"
    assert receipt["policy"]["decision"] == "deny"
    assert receipt["policy"]["engineBuild"] =~ "bytes:sha256:"
    assert receipt["policy"]["evaluation"] == nil
    assert receipt["policy"]["note"] =~ "refused the candidate before any evaluation"
  end

  test "a context path that descends into an open object is denied" do
    assert {:denied, receipt} =
             admit_shape(
               shape(%{
                 "kind" => "gateway.r5e.io/v1alpha1/ToolCall",
                 "resourceId" => "spec.tool",
                 "context" => %{"cmd" => %{"path" => "spec.args.command"}}
               })
             )

    assert receipt["reason"] =~ "context.cmd"
    assert receipt["reason"] =~ "object with no declared properties"
  end

  test "a resourceId that is not a string is denied" do
    assert {:denied, receipt} =
             admit_shape(
               shape(%{
                 "kind" => "gateway.r5e.io/v1alpha1/ToolResult",
                 "resourceId" => "spec.durationMs"
               })
             )

    assert receipt["reason"] =~ "resourceId"
    assert receipt["reason"] =~ "requires string"
  end

  test "a `*` shape reading a non-envelope path is denied" do
    assert {:denied, receipt} =
             admit_shape(
               %{
                 "kind" => "*",
                 "engine" => "cedar",
                 "action" => "admit",
                 "resourceType" => "@kind",
                 "resourceId" => "spec.tool"
               },
               "cedar.*"
             )

    assert receipt["reason"] =~ "only @ envelope fields and literals"
    # And nothing was superseded: the admitted `cedar.*` still stands.
    assert shape_entry("*")["spec"]["resourceId"] == "@kind"
  end

  test "a shape for a Kind that is not admitted is denied" do
    assert {:denied, receipt} =
             admit_shape(shape(%{"kind" => "nowhere.r5e.io/v1/Ghost"}))

    assert receipt["reason"] =~ "is not admitted on this chain"
  end

  describe "the name is the kernel's to settle, and it settles it first" do
    test "a wrong name is denied by the kernel at validateStructure, before policy runs" do
      assert {:denied, receipt} = admit_shape(shape(%{}), "cedar.something-else")

      assert receipt["reason"] =~ "validateStructure"
      assert receipt["reason"] =~ "naming mode \"derived\""
      # No policy block at all: the gate never reached authorize.
      refute Map.has_key?(receipt, "policy")
    end

    test "the engine's own name check is the belt to that braces" do
      # Reachable only by calling the engine directly, which is what makes
      # it belt-and-braces rather than dead code.
      assert {:error, reason} = Cedar.check_shape(shape(%{}), "cedar.something-else")
      assert reason =~ "is not the derived name"
    end
  end
end
