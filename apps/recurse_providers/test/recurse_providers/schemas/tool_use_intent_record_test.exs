defmodule Recurse.Providers.Schemas.ToolUseIntentRecordTest do
  @moduledoc """
  Schema-layer (in-memory) unit tests for
  `Recurse.Providers.Schemas.ToolUseIntentRecord`.

  Exercises `changeset/2`: required fields, decision enum,
  decision-branch consistency (allow/deny ↔ cedar_rule_id/deny_reason),
  hash length, parallel_index range. Does NOT hit Postgres.
  """

  use ExUnit.Case, async: true

  alias Recurse.Providers.Schemas.ToolUseIntentRecord

  @tenant_id "01ARZ3NDEKTSV4RRFFQ69G5FAV"
  @sha32 :crypto.strong_rand_bytes(32)

  defp allow_attrs(overrides \\ %{}) do
    %{
      tenant_id: @tenant_id,
      llm_call_record_id: 42,
      tool_name: "edit",
      tool_args_hash: @sha32,
      tool_args_inlined: %{"path" => "/etc/foo"},
      decision: "allow",
      tool_args_size_bytes: 247,
      call_id: "call_abc",
      extracted_at: ~U[2026-05-07 12:00:00.000000Z]
    }
    |> Map.merge(overrides)
  end

  defp deny_attrs(overrides \\ %{}) do
    %{
      tenant_id: @tenant_id,
      llm_call_record_id: 42,
      tool_name: "shell",
      tool_args_hash: @sha32,
      tool_args_inlined: %{"command" => "rm -rf /"},
      decision: "deny",
      cedar_rule_id: "rule_no_destructive",
      deny_reason: "Tool call 'shell' blocked by policy rule_no_destructive: command pattern matched 'rm -rf'.",
      tool_args_size_bytes: 247,
      call_id: "call_def",
      extracted_at: ~U[2026-05-07 12:00:01.000000Z]
    }
    |> Map.merge(overrides)
  end

  describe "changeset/2 — happy path" do
    test "valid allow attrs produce a valid changeset" do
      cs = ToolUseIntentRecord.changeset(%ToolUseIntentRecord{}, allow_attrs())
      assert cs.valid?, "expected valid; got errors: #{inspect(cs.errors)}"
    end

    test "valid deny attrs produce a valid changeset" do
      cs = ToolUseIntentRecord.changeset(%ToolUseIntentRecord{}, deny_attrs())
      assert cs.valid?, "expected valid; got errors: #{inspect(cs.errors)}"
    end

    test "tool_args_inlined nil (over-threshold args) is accepted" do
      cs =
        ToolUseIntentRecord.changeset(
          %ToolUseIntentRecord{},
          allow_attrs(%{tool_args_inlined: nil})
        )

      assert cs.valid?
    end

    test "parallel_index nil (non-parallel) is accepted" do
      cs =
        ToolUseIntentRecord.changeset(
          %ToolUseIntentRecord{},
          allow_attrs(%{parallel_index: nil})
        )

      assert cs.valid?
    end

    test "parallel_index 0 (first of parallel batch) is accepted" do
      cs =
        ToolUseIntentRecord.changeset(
          %ToolUseIntentRecord{},
          allow_attrs(%{parallel_index: 0})
        )

      assert cs.valid?
    end

    test "llm_call_record_id is NOT required at changeset time (Multi wires it)" do
      attrs = Map.delete(allow_attrs(), :llm_call_record_id)
      cs = ToolUseIntentRecord.changeset(%ToolUseIntentRecord{}, attrs)

      assert cs.valid?,
             "Multi step ordering supplies llm_call_record_id post-cast; changeset should not block"
    end
  end

  describe "changeset/2 — required fields" do
    test "missing all required fields surfaces all errors" do
      cs = ToolUseIntentRecord.changeset(%ToolUseIntentRecord{}, %{})
      refute cs.valid?

      keys = Keyword.keys(cs.errors)
      assert :tenant_id in keys
      assert :tool_name in keys
      assert :tool_args_hash in keys
      assert :decision in keys
      assert :tool_args_size_bytes in keys
      assert :call_id in keys
      assert :extracted_at in keys
    end
  end

  describe "decision enum" do
    test "accepts allow" do
      cs = ToolUseIntentRecord.changeset(%ToolUseIntentRecord{}, allow_attrs())
      assert cs.valid?
    end

    test "accepts deny" do
      cs = ToolUseIntentRecord.changeset(%ToolUseIntentRecord{}, deny_attrs())
      assert cs.valid?
    end

    test "rejects unknown decision" do
      cs =
        ToolUseIntentRecord.changeset(
          %ToolUseIntentRecord{},
          allow_attrs(%{decision: "maybe"})
        )

      refute cs.valid?
      assert Keyword.has_key?(cs.errors, :decision)
    end
  end

  describe "decision-branch consistency" do
    test "allow with cedar_rule_id set is rejected" do
      attrs = allow_attrs(%{cedar_rule_id: "rule_xyz"})
      cs = ToolUseIntentRecord.changeset(%ToolUseIntentRecord{}, attrs)
      refute cs.valid?
      assert Keyword.has_key?(cs.errors, :cedar_rule_id)
    end

    test "allow with deny_reason set is rejected" do
      attrs = allow_attrs(%{deny_reason: "shouldn't be here"})
      cs = ToolUseIntentRecord.changeset(%ToolUseIntentRecord{}, attrs)
      refute cs.valid?
      assert Keyword.has_key?(cs.errors, :deny_reason)
    end

    test "deny without deny_reason is rejected" do
      attrs = Map.delete(deny_attrs(), :deny_reason)
      cs = ToolUseIntentRecord.changeset(%ToolUseIntentRecord{}, attrs)
      refute cs.valid?
      assert Keyword.has_key?(cs.errors, :deny_reason)
    end

    test "deny without cedar_rule_id is allowed (fail-closed eval failure)" do
      attrs = Map.delete(deny_attrs(), :cedar_rule_id)
      cs = ToolUseIntentRecord.changeset(%ToolUseIntentRecord{}, attrs)

      assert cs.valid?,
             "deny may have null cedar_rule_id when it's a fail-closed evaluation failure"
    end
  end

  describe "tool_args_hash length" do
    test "rejects hash that is not 32 bytes" do
      cs =
        ToolUseIntentRecord.changeset(
          %ToolUseIntentRecord{},
          allow_attrs(%{tool_args_hash: <<1, 2, 3>>})
        )

      refute cs.valid?
      assert Keyword.has_key?(cs.errors, :tool_args_hash)
    end
  end

  describe "size + index ranges" do
    test "rejects negative tool_args_size_bytes" do
      cs =
        ToolUseIntentRecord.changeset(
          %ToolUseIntentRecord{},
          allow_attrs(%{tool_args_size_bytes: -1})
        )

      refute cs.valid?
      assert Keyword.has_key?(cs.errors, :tool_args_size_bytes)
    end

    test "rejects negative parallel_index" do
      cs =
        ToolUseIntentRecord.changeset(
          %ToolUseIntentRecord{},
          allow_attrs(%{parallel_index: -1})
        )

      refute cs.valid?
      assert Keyword.has_key?(cs.errors, :parallel_index)
    end
  end
end
