defmodule Recurse.Fold.RestartTest do
  @moduledoc """
  The fold-v2 defect, and the fix, as one run.

  Fold v2 wrote a policy evaluation record inside every decision and
  registered it as a kernel-derived object (schema-lite v2 §5) — in
  memory. The class was correct while the node stayed up. It was not on
  the record. So a node that restarted replayed its log, rebuilt every
  other derived view, and rebuilt the derived class as *empty*; the export
  taken afterwards listed `derivedObjects: []` while twenty-four receipts
  on the same chain still cited an evaluation record by address, and the
  verifier reported each of those citations as a finding — bytes in the
  bundle that nothing accounted for.

  The fix is one contract key: the engine reports `derivedObjects` on its
  policy metadata, the kernel copies it onto the event payload beside
  `policy`, and `R5e.RefIndex` reads it back at every replay. This test is
  what makes that falsifiable rather than asserted. It runs the Story-1
  sequence, exports, **stops the kernel and starts it again over the same
  data directory**, exports a second time, and compares:

    * the derived class is non-empty after the restart;
    * the two exports' `derivedObjects` are equal;
    * the post-restart bundle verifies with no findings.

  Revert the kernel's copy of the key and the second export's list is
  empty, the equality fails, and the verifier reports one finding per
  evaluation record. That is the shape of the defect, and it is what this
  file exists to catch coming back.
  """
  use ExUnit.Case, async: false

  setup_all do
    Recurse.Fold.FreshKernel.boot()
  end

  import Recurse.Fold.TestHelpers

  @prompt "list the files, then remove the temp directory"
  @completion ~s({"content":"I'll list the files first, then remove /tmp/scratch."})

  test "the derived class, the export and the verifier all survive a restart" do
    receipts = story_one()

    # Every decision after the fold's boot wrote a record, and every one
    # of them is named by the payload of the admission that wrote it —
    # which is the half of this that lives on the chain.
    evaluations = receipts |> Enum.flat_map(&(&1["derivedObjects"] || [])) |> Enum.uniq()

    assert evaluations != []

    for receipt <- receipts, address = receipt["policy"]["evaluation"], is_binary(address) do
      assert address in receipt["derivedObjects"],
             "the receipt does not carry its authoritative policy record"

      assert payload_for(receipt)["derivedObjects"] == receipt["derivedObjects"],
             "the recorded payload does not carry every record the receipt names"

      if upstream = receipt["policy"]["upstreamPolicy"] do
        assert upstream["evaluation"] in receipt["derivedObjects"],
               "the receipt omits its upstream kernel evaluation record"
      end
    end

    before_restart = export!("before")
    assert before_restart["derivedObjects"] != []

    for address <- evaluations do
      assert address in before_restart["derivedObjects"]
    end

    # ---- the restart. Nothing is thrown away; the views are rebuilt ----
    :ok = Recurse.Fold.FreshKernel.bounce()

    # The falsification, at its smallest: the index was reset and refilled
    # from the log, and the class is still there.
    assert R5e.RefIndex.derived_objects() != []

    for address <- evaluations do
      assert R5e.RefIndex.derived?(address),
             "#{address} was lost by the restart — the class is in memory only again"
    end

    # Booting again re-ran the fold's seeding, and it added nothing: the
    # chain the second export describes is the chain the first did.
    after_restart = export!("after")
    assert after_restart["events"] == before_restart["events"]

    assert after_restart["derivedObjects"] == before_restart["derivedObjects"],
           "the export changed across a restart — derivedObjects is not a function of the log"

    assert after_restart["missingObjects"] == []

    # ---- and the post-restart bundle verifies, offline ----
    {:ok, report} = RecurseVerify.run(after_restart["_dest"])
    assert report.findings == [], Enum.join(report.findings, "\n")

    cas_line = Enum.find(report.checked, &String.starts_with?(&1, "cas:"))

    assert cas_line =~ "kernel-derived",
           "the cas line does not mention the derived class: #{cas_line}"

    assert cas_line =~
             "the export's list is exactly the union of the payloads' own derivedObjects"

    policy_line = Enum.find(report.checked, &String.starts_with?(&1, "policy:"))
    assert policy_line =~ "cite a policy evaluation record"
    assert policy_line =~ "each declared kernel-derived"
  end

  # The same sequence `fold_end_to_end_test.exs` asserts on in detail and
  # `scripts/fold-demo.sh` drives over HTTP; here it is only the source of
  # a chain with evaluation records on it, so it asserts outcomes and
  # nothing more.
  defp story_one do
    prompt_ref = put_object(@prompt, "text/plain")

    {:ok, prompt} =
      admit_gateway("Prompt", nil, %{"contentRef" => %{"$ref" => prompt_ref}, "role" => "user"})

    {:ok, call} =
      admit_gateway("LlmCall", nil, %{
        "model" => "claude-sonnet-4",
        "prompt" => %{"$ref" => "gateway.r5e.io/v1alpha1/Prompt/" <> prompt["name"]},
        "provider" => "anthropic",
        "transport" => "https"
      })

    # Denied, and its evaluation record is evidence of the refusal — so it
    # is on the payload like any other and has to survive the restart too.
    {:denied, rm} =
      admit_gateway("ToolCall", nil, %{
        "tool" => "shell",
        "args" => %{"command" => "rm -rf /tmp/scratch"},
        "gatewayContext" => gateway_context(),
        "llmCall" => %{"$ref" => call["eventRef"]},
        "index" => 0
      })

    {:ok, ls} =
      admit_gateway("ToolCall", nil, %{
        "tool" => "shell",
        "args" => %{"command" => "ls -la"},
        "gatewayContext" => gateway_context(),
        "llmCall" => %{"$ref" => call["eventRef"]},
        "index" => 1
      })

    completion_ref = put_object(@completion, "application/json")

    {:ok, completion} =
      admit_gateway("Completion", nil, %{
        "contentRef" => %{"$ref" => completion_ref},
        "mediaType" => "application/json"
      })

    {:ok, response} =
      admit_gateway("LlmResponse", nil, %{
        "llmCall" => %{"$ref" => call["eventRef"]},
        "outcome" => "ok",
        "completion" => %{
          "$ref" => "gateway.r5e.io/v1alpha1/Completion/" <> completion["name"]
        },
        "toolCalls" => [%{"$ref" => rm["eventRef"]}, %{"$ref" => ls["eventRef"]}],
        "upstreamStatus" => 200,
        "usage" => %{"inputTokens" => 41, "outputTokens" => 18}
      })

    {:ok, result} =
      admit_gateway("ToolResult", nil, %{
        "toolCall" => %{"$ref" => ls["eventRef"]},
        "outcome" => "ok",
        "result" => %{"stdout" => "total 0\n"},
        "durationMs" => 12
      })

    [prompt, call, rm, ls, completion, response, result]
  end

  defp gateway_context do
    %{
      "principal_id" => "test-user",
      "principal_kind" => "human",
      "tenant" => "test-tenant",
      "model" => "claude-sonnet-4"
    }
  end

  defp export!(label) do
    dest =
      Path.join(System.tmp_dir!(), "fold-restart-#{label}-#{System.unique_integer([:positive])}")

    on_exit(fn -> File.rm_rf(dest) end)
    {:ok, ^dest, manifest} = R5e.Export.run(dest)
    Map.put(manifest, "_dest", dest)
  end
end
