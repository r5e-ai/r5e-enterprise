# SPDX-License-Identifier: AGPL-3.0-only
defmodule Recurse.Fold.Policy.CompositionTest do
  use ExUnit.Case, async: false
  import Recurse.Fold.TestHelpers
  alias Recurse.Fold.Policy.Cedar

  setup do
    Recurse.Fold.FreshKernel.boot()
  end

  defp request(kind \\ "ToolCall") do
    %{
      actor: actor(),
      group: group(),
      version: version(),
      kind: kind,
      name: nil,
      spec: %{"tool" => "ls"},
      identity: "signed",
      authority_refs: [],
      authority_roots: [],
      resolved: []
    }
  end

  test "both workload Kinds wrap a real upstream denial without evaluating the fold" do
    for kind <- ["ToolCall", "LlmCall"] do
      req = request(kind)
      assert {:deny, reason, upstream} = R5e.Policy.KernelCedar.authorize(req)
      assert {:deny, ^reason, meta} = Cedar.authorize(req)
      assert meta["decision"] == "deny"
      assert meta["bundleRef"] == Cedar.bundle_ref()
      assert meta["upstreamPolicy"] == upstream
      assert meta["evaluation"] == nil
      assert meta["evaluated"] == false
      assert meta["bundle"] == nil
      assert meta["matched"] == []
      assert meta["note"] == "upstream refused; not evaluated here"
      assert meta["reason"] == "upstreamRefused"
      assert meta["generations"] == upstream["generations"]
      assert meta["derivedObjects"] == upstream["derivedObjects"]
      assert is_binary(upstream["evaluation"])
    end
  end

  test "an upstream error remains an error with its evidence intact" do
    {:ok, previous, _} = R5e.ResourceStore.get("core.r5e.io", "v1", "PolicyBundle", "active")
    missing = "bytes:sha256:" <> String.duplicate("a", 64)
    changed = put_in(previous, ["spec", "sourceRef"], %{"$ref" => missing})
    R5e.ResourceStore.put("core.r5e.io", "v1", "PolicyBundle", "active", changed)

    on_exit(fn ->
      R5e.ResourceStore.put("core.r5e.io", "v1", "PolicyBundle", "active", previous)
    end)

    assert {:deny, _, meta} = Cedar.authorize(request())
    assert meta["decision"] == "error"
    assert meta["upstreamPolicy"]["decision"] == "error"
    assert meta["evaluation"] == nil
    assert meta["generations"] == meta["upstreamPolicy"]["generations"]
  end

  test "normal allow and fold denial retain both evaluation records" do
    for {tool, args, outcome} <- [{"ls", %{}, :ok}, {"shell", %{"command" => "rm -rf /"}, :deny}] do
      req = %{
        request()
        | authority_roots: [R5e.DSSE.node_key_id()],
          spec: %{"tool" => tool, "args" => args}
      }

      result = Cedar.authorize(req)
      assert elem(result, 0) == outcome
      meta = elem(result, tuple_size(result) - 1)
      assert meta["upstreamPolicy"]["decision"] == "allow"
      assert meta["evaluation"] in meta["derivedObjects"]
      assert meta["upstreamPolicy"]["evaluation"] in meta["derivedObjects"]
    end
  end

  test "equal generations compose; independent reads and objects survive on denial" do
    upstream = %{
      "decision" => "allow",
      "generations" => %{"shared" => 1, "upstream" => 2},
      "derivedObjects" => ["upstream-object", "shared-object"]
    }

    local = %{
      "decision" => "deny",
      "generations" => %{"shared" => 1, "local" => 3},
      "derivedObjects" => ["local-object", "shared-object"]
    }

    assert {:deny, "local refusal", meta} =
             Cedar.compose({:deny, "local refusal", local}, upstream)

    assert meta["decision"] == "deny"
    assert meta["generations"] == %{"shared" => 1, "upstream" => 2, "local" => 3}
    assert meta["derivedObjects"] == ["upstream-object", "shared-object", "local-object"]
    assert meta["upstreamPolicy"] == upstream
  end

  test "conflicting generations refuse without changing the evaluated decision" do
    req = %{request() | authority_roots: [R5e.DSSE.node_key_id()]}
    assert {:ok, evaluated} = Cedar.authorize(req)
    upstream = evaluated["upstreamPolicy"]
    local = Map.delete(evaluated, "upstreamPolicy")
    {ref, seq} = Enum.at(upstream["generations"], 0)
    local = put_in(local, ["generations", ref], seq + 1)
    assert {:deny, _, meta} = Cedar.compose({:ok, local}, upstream)
    assert meta["decision"] == "error"
    assert meta["stage"] == "composition"
    assert meta["evaluation"] == nil
    assert meta["generationConflicts"][ref] == %{"upstream" => seq, "local" => seq + 1}
    refute Map.has_key?(meta["generations"], ref)
    assert meta["upstreamPolicy"]["decision"] == "allow"
    assert meta["upstreamPolicy"]["evaluation"] == evaluated["evaluation"]
    assert meta["upstreamPolicy"]["upstreamPolicy"] == upstream
    assert meta["derivedObjects"] == evaluated["derivedObjects"]
    record = evaluation_of(%{"policy" => meta["upstreamPolicy"]})

    for key <- ~w(engine engineBuild bundle source shape decision matched) do
      assert record[key] == meta["upstreamPolicy"][key]
    end
  end

  test "an upstream-denied admission exports and verifies with the fold wrapper" do
    content = put_object("test prompt")

    {:ok, prompt} =
      admit_gateway("Prompt", nil, %{"contentRef" => %{"$ref" => content}, "role" => "user"})

    {:denied, receipt} =
      admit_as("unendorsed", group(), version(), "LlmCall", nil, %{
        "model" => "claude-sonnet-4",
        "provider" => "anthropic",
        "transport" => "https",
        "prompt" => %{"$ref" => "gateway.r5e.io/v1alpha1/Prompt/" <> prompt["name"]}
      })

    meta = receipt["policy"]
    assert meta["bundleRef"] == Cedar.bundle_ref()
    assert meta["decision"] == "deny"
    assert meta["evaluation"] == nil
    assert meta["upstreamPolicy"]["evaluation"] in receipt["derivedObjects"]
    dest = Path.join(System.tmp_dir!(), "fold-composition-#{System.unique_integer([:positive])}")
    on_exit(fn -> File.rm_rf(dest) end)
    {:ok, ^dest, _} = R5e.Export.run(dest)
    {:ok, report} = RecurseVerify.run(dest)
    assert report.findings == [], Enum.join(report.findings, "\n")
    assert Enum.any?(report.checked, &String.starts_with?(&1, "upstream policy[1]:"))
  end
end
