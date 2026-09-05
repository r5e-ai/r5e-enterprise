defmodule Recurse.Fold.EndToEndTest do
  @moduledoc """
  Story 1 of spec 010, in process, through the fold: one model call, two
  tool intents (one refused), a response binding both, and a result — then
  export and verify offline with the unchanged r5e-core verifier.

  It is the same sequence `scripts/fold-demo.sh` drives over HTTP, run here
  through `R5e.Admission.admit/1` so the assertions can reach the receipts,
  the resolution manifests and the evaluation records directly. Nothing
  about the bundle is special-cased for the fold; that is the claim being
  tested.

  `async: false` with a kernel of its own (`setup_all`): the `:r5e`
  application is a singleton, so a fresh kernel per file is still one
  kernel at a time. What that buys here is that the chain this file counts
  is the chain this file wrote, plus the fold's own boot.
  """
  use ExUnit.Case, async: false

  setup_all do
    Recurse.Fold.FreshKernel.boot()
  end

  import Recurse.Fold.TestHelpers

  @prompt "list the files, then remove the temp directory"
  @completion ~s({"content":"I'll list the files first, then remove /tmp/scratch."})

  test "one turn of agent work, governed by the chain, verified offline" do
    before = log_counts()

    # 1. the prompt bytes, admitted as a CasObject — the `PUT /cas` act.
    prompt_ref = put_object(@prompt, "text/plain")

    # 2. the prompt artifact, citing them.
    {:ok, prompt} =
      admit_gateway("Prompt", nil, %{"contentRef" => %{"$ref" => prompt_ref}, "role" => "user"})

    assert manifest(prompt) == [{"/contentRef", "bytes", prompt_ref}]
    prompt_path = "gateway.r5e.io/v1alpha1/Prompt/" <> prompt["name"]

    # 3. the call. Its shape is `cedar.gateway.r5e.io/v1alpha1/LlmCall`:
    #    asking a model is an act with its own action and resource.
    {:ok, call} =
      admit_gateway("LlmCall", nil, %{
        "model" => "claude-sonnet-4",
        "prompt" => %{"$ref" => prompt_path},
        "provider" => "anthropic",
        "transport" => "https"
      })

    assert manifest(call) == [{"/prompt", "kind", prompt_path}]
    assert entry_of(call, "/prompt")["generation"] == prompt["seq"]

    assert call["policy"]["shape"] ==
             shape_entry("gateway.r5e.io/v1alpha1/LlmCall")["specAddress"]

    assert %{"path" => "spec.provider", "value" => "anthropic"} in evaluation_of(call)[
             "resolution"
           ]

    # 4. two tool intents, in the model's order. The first asks for
    #    something the bundle refuses; only the policy decides that.
    {:denied, rm} =
      admit_gateway("ToolCall", nil, %{
        "tool" => "shell",
        "args" => %{"command" => "rm -rf /tmp/scratch"},
        "gatewayContext" => gateway_context(),
        "llmCall" => %{"$ref" => call["eventRef"]},
        "index" => 0
      })

    assert rm["reason"] =~ "authorize: cedar denied"
    assert rm["reason"] =~ ~s(Action::"invoke_tool" on ToolUse::"shell")

    # The denial resolved its refs before policy saw it — the manifest is on
    # the denial's record too, because asking is itself an act.
    assert manifest(rm) == [{"/llmCall", "event", call["eventRef"]}]

    policy = rm["policy"]
    assert policy["engine"] == "cedar"
    assert policy["decision"] == "deny"
    assert policy["matched"] == ["policy1"]
    assert policy["bundle"] == bundle_entry()["specAddress"]
    assert policy["source"] == bundle_entry()["spec"]["sourceRef"]["$ref"]
    assert policy["shape"] == shape_entry("gateway.r5e.io/v1alpha1/ToolCall")["specAddress"]
    assert policy["engineBuild"] == Recurse.Fold.Policy.EngineBuild.address()
    assert is_binary(policy["evaluation"])

    # The gateway's normalized context was presented: the denial's own
    # record says which model proposed `rm -rf`.
    record = evaluation_of(rm)

    assert %{"path" => "spec.gatewayContext.model", "value" => "claude-sonnet-4"} in record[
             "resolution"
           ]

    assert Jason.decode!(Base.decode64!(record["requestBytes"]))["context"]["model"] ==
             "claude-sonnet-4"

    # And the record replays: the cited policy text, the recorded bytes, the
    # same engine, the same answer. This is the thing the verifier
    # deliberately does not do and says so on every run.
    {:ok, source} = R5e.CAS.get(record["source"])

    assert {:ok, %{decision: :deny, matched_policies: ["policy1"]}} =
             Recurse.Cedar.evaluate_with_entities(
               source,
               Base.decode64!(record["requestBytes"]),
               Base.decode64!(record["entitiesBytes"])
             )

    # 5. the same tool, a harmless command: the deny is selective.
    {:ok, ls} =
      admit_gateway("ToolCall", nil, %{
        "tool" => "shell",
        "args" => %{"command" => "ls -la"},
        "gatewayContext" => gateway_context(),
        "llmCall" => %{"$ref" => call["eventRef"]},
        "index" => 1
      })

    assert ls["policy"]["decision"] == "allow"
    assert ls["policy"]["bundle"] == policy["bundle"]

    # 6. the completion bytes and the artifact citing them.
    completion_ref = put_object(@completion, "application/json")

    {:ok, completion} =
      admit_gateway("Completion", nil, %{
        "contentRef" => %{"$ref" => completion_ref},
        "mediaType" => "application/json"
      })

    completion_path = "gateway.r5e.io/v1alpha1/Completion/" <> completion["name"]

    # 7. the response, binding bytes and both intents — admitted and denied.
    {:ok, response} =
      admit_gateway("LlmResponse", nil, %{
        "llmCall" => %{"$ref" => call["eventRef"]},
        "outcome" => "ok",
        "completion" => %{"$ref" => completion_path},
        "toolCalls" => [%{"$ref" => rm["eventRef"]}, %{"$ref" => ls["eventRef"]}],
        "upstreamStatus" => 200,
        "usage" => %{"inputTokens" => 41, "outputTokens" => 18}
      })

    assert manifest(response) == [
             {"/completion", "kind", completion_path},
             {"/llmCall", "event", call["eventRef"]},
             {"/toolCalls/0", "event", rm["eventRef"]},
             {"/toolCalls/1", "event", ls["eventRef"]}
           ]

    # `outcome: any` on `toolCalls` is what makes a refused act citable.
    assert entry_of(response, "/toolCalls/0")["outcome"] == "denied"
    assert entry_of(response, "/toolCalls/1")["outcome"] == "admitted"

    # 8. the result of the tool call that was allowed.
    {:ok, result} =
      admit_gateway("ToolResult", nil, %{
        "toolCall" => %{"$ref" => ls["eventRef"]},
        "outcome" => "ok",
        "result" => %{"stdout" => "total 0\n"},
        "durationMs" => 12
      })

    assert manifest(result) == [{"/toolCall", "event", ls["eventRef"]}]

    # Nine admission events for the sequence: eight granted, one denied.
    # Still a delta rather than an absolute, because the fold's boot is on
    # this chain too and its event count is the seeding's business.
    counts = log_counts()
    assert counts.granted - before.granted == 8
    assert counts.denied - before.denied == 1

    # ---- export, then verify with the unchanged r5e-core verifier ----

    dest = Path.join(System.tmp_dir!(), "fold-bundle-#{System.unique_integer([:positive])}")
    on_exit(fn -> File.rm_rf(dest) end)
    {:ok, ^dest, manifest} = R5e.Export.run(dest)

    assert manifest["missingObjects"] == []
    assert policy["evaluation"] in manifest["derivedObjects"]

    {:ok, report} = RecurseVerify.run(dest)
    assert report.findings == [], Enum.join(report.findings, "\n")

    policy_line = line(report, "policy:")
    assert policy_line =~ "cite a policy evaluation record"
    assert policy_line =~ "engine, engineBuild, bundle, source, shape, decision and matched"
    assert policy_line =~ "NOT proof that evaluating it yields the recorded decision"

    cas_line = line(report, "cas:")
    assert cas_line =~ "kernel-derived (each cited by a receipt's policy evaluation"

    refs_line = line(report, "refs:")
    assert refs_line =~ "every one re-derived from this bundle"

    # The policy text, the prompt and the completion all travelled into the
    # bundle's CAS, and so did every evaluation record.
    for address <- [
          policy["source"],
          prompt_ref,
          completion_ref,
          policy["evaluation"],
          policy["engineBuild"]
        ] do
      assert RecurseVerify.CAS.intact?(Path.join(dest, "cas"), address),
             "#{address} was not swept into the bundle"
    end

    # The nine Kinds are in the bundle with the scope their authors wrote.
    kinds =
      Path.wildcard(Path.join(dest, "kinds/*.json"))
      |> Enum.map(&(&1 |> File.read!() |> Jason.decode!()))
      |> Enum.filter(&(&1["group"] == "gateway.r5e.io"))

    assert length(kinds) == 9

    for kind <- kinds do
      assert kind["scopeDefaulted"] == false
      assert kind["epistemicScope"]["doesNotClaim"] != []
      assert is_map(kind["naming"])
    end

    IO.puts("\n" <> RecurseVerify.format(report))
  end

  defp gateway_context do
    %{
      "principal_id" => "test-user",
      "principal_kind" => "human",
      "tenant" => "test-tenant",
      "model" => "claude-sonnet-4"
    }
  end

  defp manifest(receipt) do
    assert receipt["resolvedRefs"] == payload_for(receipt)["resolvedRefs"],
           "the receipt's manifest and the recorded one differ"

    for entry <- receipt["resolvedRefs"], do: {entry["path"], entry["class"], entry["value"]}
  end

  defp entry_of(receipt, path), do: Enum.find(receipt["resolvedRefs"], &(&1["path"] == path))

  defp line(report, prefix), do: Enum.find(report.checked, &String.starts_with?(&1, prefix))
end
