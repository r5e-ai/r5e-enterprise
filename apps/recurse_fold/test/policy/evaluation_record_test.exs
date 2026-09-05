defmodule Recurse.Fold.Policy.EvaluationRecordTest do
  @moduledoc """
  §8's evaluation record: its closed schema, its equality invariant with
  the receipt, the generations the engine captured — and the thing the
  verifier deliberately does not do, which is replay.
  """
  use ExUnit.Case, async: false

  setup_all do
    Recurse.Fold.FreshKernel.boot()
  end

  import Recurse.Fold.TestHelpers

  alias Recurse.Fold.Policy.EvaluationRecord

  @invariant ~w(engine engineBuild bundle source shape decision matched)

  setup do
    {:ok, receipt} =
      admit_tool_call(%{"tool" => "shell", "args" => %{"command" => "ls -la"}})

    %{receipt: receipt, record: evaluation_of(receipt), meta: receipt["policy"]}
  end

  test "the record is a closed schema — those twelve keys and no others", ctx do
    assert Map.keys(ctx.record) |> Enum.sort() == Enum.sort(EvaluationRecord.keys())
    assert ctx.record["format"] == "r5e.policy-evaluation/1"
  end

  test "the record is registered as a kernel-derived object", ctx do
    address = ctx.meta["evaluation"]
    assert R5e.RefIndex.derived?(address)
    assert address in R5e.RefIndex.derived_objects()
    # §5: a derived object is never unreferenced — the admission that wrote
    # it is what cites it.
    refute R5e.RefIndex.unreferenced?(address)
  end

  test "the record's address is the hash of its canonical bytes", ctx do
    {:ok, bytes} = R5e.CAS.get(ctx.meta["evaluation"])
    assert "bytes:" <> R5e.Canonical.hash_bytes(bytes) == ctx.meta["evaluation"]
    assert bytes == R5e.Canonical.encode(ctx.record)
  end

  test "§8's equality invariant holds between the record and the receipt", ctx do
    for key <- @invariant do
      assert ctx.record[key] == ctx.meta[key], "#{key} differs between record and receipt"
    end
  end

  test "the record names the target Kind's admitted specAddress", ctx do
    {:ok, kind} = R5e.KindRegistry.get("gateway.r5e.io", "v1alpha1", "ToolCall")
    assert ctx.record["kindDefinition"] == kind.spec_address

    # And that address is on the chain, as the verifier requires.
    definition =
      Enum.find(payloads(), fn payload ->
        payload["outcome"] == "admitted" and payload["target"]["kind"] == "KindDefinition" and
          R5e.Canonical.hash(payload["spec"]) == ctx.record["kindDefinition"]
      end)

    assert definition["spec"]["kind"] == "ToolCall"
  end

  test "resolution is sorted by path and records absences as \"absent\"", ctx do
    paths = Enum.map(ctx.record["resolution"], & &1["path"])
    assert paths == Enum.sort(paths)

    assert %{"path" => "spec.tool", "value" => "shell"} in ctx.record["resolution"]

    assert %{"path" => "spec.gatewayContext.model", "value" => "absent"} in ctx.record[
             "resolution"
           ]
  end

  test "matched is sorted", ctx do
    assert ctx.record["matched"] == Enum.sort(ctx.record["matched"])
  end

  test "the receipt captured the generations it read (§7)", ctx do
    bundle = bundle_entry()
    shape = shape_entry("gateway.r5e.io/v1alpha1/ToolCall")

    {:ok, core_bundle, _lineage} =
      R5e.ResourceStore.get("core.r5e.io", "v1", "PolicyBundle", "active")

    assert ctx.meta["generations"] == %{
             "core.r5e.io/v1/PolicyBundle/active" => core_bundle["admissionSeq"],
             "gateway.r5e.io/v1alpha1/PolicyBundle/active" => bundle["admissionSeq"],
             "gateway.r5e.io/v1alpha1/PolicyShape/cedar.gateway.r5e.io/v1alpha1/ToolCall" =>
               shape["admissionSeq"]
           }

    assert is_integer(bundle["admissionSeq"])
  end

  test "the record replays: the same bytes, the same engine, the same answer", ctx do
    {:ok, source} = R5e.CAS.get(ctx.record["source"])
    {:ok, request_json} = Base.decode64(ctx.record["requestBytes"])
    {:ok, entities_json} = Base.decode64(ctx.record["entitiesBytes"])

    assert {:ok, %{decision: decision, matched_policies: matched}} =
             Recurse.Cedar.evaluate_with_entities(source, request_json, entities_json)

    assert to_string(decision) == ctx.record["decision"]
    assert Enum.sort(matched) == ctx.record["matched"]

    # And the bytes are what a reader would expect: the request the engine
    # was asked, not a canonicalized paraphrase of it.
    assert Jason.decode!(request_json)["resource"] == ~s(ToolUse::"shell")
  end

  test "a denial's record replays to the denial", _ctx do
    {:denied, receipt} =
      admit_tool_call(%{"tool" => "shell", "args" => %{"command" => "rm -rf /tmp/scratch"}})

    record = evaluation_of(receipt)
    assert record["decision"] == "deny"
    assert record["matched"] == ["policy1"]

    {:ok, source} = R5e.CAS.get(record["source"])
    {:ok, request_json} = Base.decode64(record["requestBytes"])
    {:ok, entities_json} = Base.decode64(record["entitiesBytes"])

    assert {:ok, %{decision: :deny, matched_policies: ["policy1"]}} =
             Recurse.Cedar.evaluate_with_entities(source, request_json, entities_json)
  end

  test "an erased record reads as erased, not as a pass" do
    assert {:error, reason} =
             EvaluationRecord.fetch("bytes:sha256:" <> String.duplicate("e", 64))

    assert reason =~ "the evaluation input may have been erased"
  end

  test "two identical evaluations produce one object" do
    spec = %{"tool" => "shell", "args" => %{"command" => "echo same"}, "purpose" => "dedupe"}
    {:ok, first} = admit_tool_call(spec)
    {:ok, second} = admit_tool_call(spec)

    assert first["policy"]["evaluation"] == second["policy"]["evaluation"]
  end
end
