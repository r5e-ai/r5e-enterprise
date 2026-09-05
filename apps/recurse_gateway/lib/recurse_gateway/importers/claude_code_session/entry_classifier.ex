defmodule Recurse.Gateway.Importers.ClaudeCodeSession.EntryClassifier do
  @moduledoc false

  alias Recurse.Gateway.Extractors.ClaudeCodeJsonl

  @type tool_result :: %{
          id: String.t(),
          content: term(),
          is_error?: boolean()
        }

  @type receipt_spec :: %{
          required(:event_kind) => :llm_call | :tool_call,
          required(:source_event_kind) => :chat_completion | :tool_call,
          required(:summary) => String.t(),
          required(:natural_key) => String.t(),
          required(:timestamp) => DateTime.t() | nil,
          optional(:turn_key) => String.t(),
          required(:source_metadata) => map(),
          required(:content_metadata) => map(),
          required(:outcome) => :success | :upstream_error,
          # Tool-call extractor enriched tags; nil for non-tool_call specs.
          optional(:tags) => map() | nil
        }

  @spec source_kind() :: String.t()
  def source_kind, do: "claude_code_session_jsonl"

  @spec source_label() :: String.t()
  def source_label, do: "Claude Code JSONL"

  @spec source_session_id(map()) :: String.t() | nil
  def source_session_id(entry) do
    string_value(entry["sessionId"]) ||
      string_value(entry["session_id"]) ||
      get_in(entry, ["message", "sessionId"]) ||
      get_in(entry, ["message", "session_id"])
  end

  @spec timestamp(map()) :: DateTime.t() | nil
  def timestamp(entry) do
    case string_value(entry["timestamp"]) do
      nil ->
        nil

      timestamp ->
        case DateTime.from_iso8601(timestamp) do
          {:ok, datetime, _offset} -> datetime
          {:error, _reason} -> nil
        end
    end
  end

  @spec tool_results(map()) :: %{optional(String.t()) => tool_result()}
  def tool_results(entry) do
    entry
    |> content_blocks()
    |> Enum.filter(&(block_type(&1) == "tool_result"))
    |> Enum.reduce(%{}, fn block, acc ->
      case string_value(block["tool_use_id"]) || string_value(block["id"]) do
        nil ->
          acc

        id ->
          Map.put(acc, id, %{
            id: id,
            content: Map.get(block, "content"),
            is_error?: block["is_error"] == true
          })
      end
    end)
  end

  @spec receipt_specs(map(), %{optional(String.t()) => tool_result()}, keyword()) :: [
          receipt_spec()
        ]
  def receipt_specs(entry, tool_results, opts) do
    case entry["type"] do
      "assistant" ->
        assistant_receipts(entry, tool_results, opts)

      _other ->
        []
    end
  end

  defp assistant_receipts(entry, tool_results, opts) do
    blocks = content_blocks(entry)
    text = text_content(blocks)
    tool_blocks = Enum.filter(blocks, &(block_type(&1) == "tool_use"))

    text_receipts =
      cond do
        text != "" ->
          [chat_completion_receipt(entry, text)]

        Keyword.get(opts, :skip_thinking?, true) ->
          []

        has_thinking?(blocks) ->
          [thinking_receipt(entry)]

        true ->
          []
      end

    tool_receipts =
      tool_blocks
      |> Enum.with_index()
      |> Enum.map(fn {block, index} -> tool_receipt(entry, block, index, tool_results) end)

    text_receipts ++ tool_receipts
  end

  defp chat_completion_receipt(entry, text) do
    %{
      event_kind: :llm_call,
      source_event_kind: :chat_completion,
      summary: "Assistant message (redacted)",
      timestamp: timestamp(entry),
      natural_key: natural_key(entry, "chat_completion"),
      turn_key: turn_key(entry),
      source_metadata: claude_metadata(entry),
      content_metadata: text_metadata(text),
      outcome: :success
    }
  end

  defp thinking_receipt(entry) do
    %{
      event_kind: :llm_call,
      source_event_kind: :chat_completion,
      summary: "[thinking content omitted]",
      timestamp: timestamp(entry),
      natural_key: natural_key(entry, "thinking"),
      turn_key: turn_key(entry),
      source_metadata: claude_metadata(entry),
      content_metadata: %{"redaction_status" => "thinking_skipped"},
      outcome: :success
    }
  end

  defp tool_receipt(entry, block, index, tool_results) do
    tool_id = string_value(block["id"]) || string_value(block["tool_use_id"])
    tool_name = string_value(block["name"]) || "unknown_tool"
    result = if is_nil(tool_id), do: nil, else: Map.get(tool_results, tool_id)
    suffix = "tool_call:#{tool_id || index}"
    tool_input = Map.get(block, "input", %{})

    # Tool-call extractor pipeline (2026-04-30): produces schema-on-read
    # enriched tags (category, scope_kind, semantic_args, ...) from the
    # raw tool_use block. NOT signed; lives in `outer_container.tags`.
    tags = ClaudeCodeJsonl.extract(block)

    %{
      event_kind: :tool_call,
      source_event_kind: :tool_call,
      summary: "Tool call: #{tool_name}",
      timestamp: timestamp(entry),
      natural_key: natural_key(entry, suffix),
      turn_key: turn_key(entry),
      source_metadata: claude_metadata(entry),
      content_metadata: tool_metadata(block, result),
      outcome: outcome(result),
      # B7 — non-signed UI metadata. `tool_name` is the short tool
      # identifier; `tool_summary` is a 1-line, PII-aware
      # human-readable description. The extractor's `display_summary` is
      # richer; B7 fields are kept for backwards-compat with pre-tags
      # consumers.
      tool_name: tool_name,
      tool_summary: tool_summary(tool_name, tool_input),
      # Tool-call extractor — full schema-on-read tags map.
      tags: tags
    }
  end

  # B7 — derive a 1-line, PII-aware summary of a tool call from its
  # name and JSON input. Strategy (per the demo punch-list spec):
  #
  #   * `Bash`           — `"Bash: <first 60 chars of command>"`
  #   * `Edit` / `Write` — `"<Tool>: <file_path>"` (path only; no diff)
  #   * `Read`           — `"Read: <file_path>"`
  #   * `Glob` / `Grep`  — `"<Tool>: <pattern>"`
  #   * everything else  — `"<tool_name> (args redacted)"`
  #
  # The bytes returned here are NOT signed and NOT hashed — they're a
  # rendering hint for the audit-log row. Raw arguments stay in the
  # signed payload (`payload_uri` + `payload_hash`); auditors needing
  # the full args open the receipt detail. Truncation + path-only
  # extraction are the PII guard for the row surface.
  #
  # The dispatch table maps each tool to a `{input_field, format}`
  # tuple so the per-tool branch in `tool_summary/2` stays a single
  # case-statement; no per-tool clause body. Adding a new tool is a
  # one-line edit to `@tool_summary_recipes` only.
  @tool_summary_recipes %{
    "Bash" => {"command", :truncate60},
    "Edit" => {"file_path", :path},
    "Write" => {"file_path", :path},
    "MultiEdit" => {"file_path", :path},
    "Read" => {"file_path", :path},
    "Glob" => {"pattern", :truncate60},
    "Grep" => {"pattern", :truncate60},
    "WebFetch" => {"url", :truncate80}
  }

  @spec tool_summary(String.t(), map()) :: String.t()
  def tool_summary(tool_name, input) when is_map(input) do
    case Map.get(@tool_summary_recipes, tool_name) do
      nil ->
        "#{tool_name} (args redacted)"

      {field, format} ->
        format_tool_summary(tool_name, format, Map.get(input, field))
    end
  end

  def tool_summary(tool_name, _input), do: "#{tool_name} (args redacted)"

  defp format_tool_summary(tool_name, :path, raw),
    do: "#{tool_name}: #{string_value(raw) || "(no path)"}"

  defp format_tool_summary(tool_name, :truncate60, raw),
    do: "#{tool_name}: #{truncate(string_value(raw) || "(empty)", 60)}"

  defp format_tool_summary(tool_name, :truncate80, raw),
    do: "#{tool_name}: #{truncate(string_value(raw) || "(empty)", 80)}"

  defp truncate(s, max) when is_binary(s) and is_integer(max) and max > 0 do
    if String.length(s) <= max do
      s
    else
      String.slice(s, 0, max) <> "..."
    end
  end

  defp natural_key(entry, suffix) do
    source = source_session_id(entry) || "unknown-session"

    entry_id =
      string_value(entry["uuid"]) || string_value(entry["requestId"]) || stable_json_hash(entry)

    "#{source}:#{entry_id}:#{suffix}"
  end

  defp turn_key(entry) do
    source = source_session_id(entry) || "unknown-session"

    entry_id =
      string_value(entry["uuid"]) || string_value(entry["requestId"]) || stable_json_hash(entry)

    "#{source}:#{entry_id}"
  end

  defp content_blocks(%{"message" => %{"content" => content}}), do: normalize_content(content)
  defp content_blocks(%{"content" => content}), do: normalize_content(content)
  defp content_blocks(_entry), do: []

  defp normalize_content(content) when is_list(content), do: Enum.filter(content, &is_map/1)
  defp normalize_content(%{} = content), do: [content]

  defp normalize_content(content) when is_binary(content),
    do: [%{"type" => "text", "text" => content}]

  defp normalize_content(_content), do: []

  defp text_content(blocks) do
    blocks
    |> Enum.filter(&(block_type(&1) == "text"))
    |> Enum.map(&string_value(&1["text"]))
    |> Enum.reject(&is_nil/1)
    |> Enum.join("\n")
    |> String.trim()
  end

  defp has_thinking?(blocks) do
    Enum.any?(blocks, &(block_type(&1) in ["thinking", "redacted_thinking"]))
  end

  defp block_type(block), do: string_value(block["type"])

  defp claude_metadata(entry) do
    %{
      "entry_uuid" => entry["uuid"],
      "parent_uuid" => entry["parentUuid"],
      "request_id" => entry["requestId"],
      "model" => get_in(entry, ["message", "model"]),
      "usage" => get_in(entry, ["message", "usage"]),
      "cwd" => redacted_string_metadata(entry["cwd"]),
      "git_branch" => redacted_string_metadata(entry["gitBranch"]),
      "version" => entry["version"]
    }
  end

  defp text_metadata(text) do
    redacted_value_metadata(text)
  end

  defp tool_metadata(tool_block, result) do
    encoded_input = Jason.encode!(Map.get(tool_block, "input", %{}))
    tool_id = tool_block["id"] || tool_block["tool_use_id"]

    %{
      "tool" => %{
        "id" => tool_id,
        "name" => tool_block["name"] || "unknown_tool",
        "input" => redacted_value_metadata(encoded_input),
        "result" => tool_result_metadata(result)
      }
    }
  end

  defp tool_result_metadata(nil), do: %{"present" => false}

  defp tool_result_metadata(%{content: content, is_error?: is_error?}) do
    encoded = Jason.encode!(content)

    encoded
    |> redacted_value_metadata()
    |> Map.merge(%{"present" => true, "is_error" => is_error?})
  end

  defp outcome(%{is_error?: true}), do: :upstream_error
  defp outcome(_result), do: :success

  defp string_value(value) when is_binary(value), do: value
  defp string_value(_value), do: nil

  defp stable_json_hash(value) do
    value
    |> Jason.encode!()
    |> sha256_hex()
  end

  defp redacted_string_metadata(value) when is_binary(value) do
    redacted_value_metadata(value)
  end

  defp redacted_string_metadata(_value), do: nil

  defp redacted_value_metadata(value) when is_binary(value) do
    %{
      "redaction_status" => "redacted",
      "sha256" => sha256_hex(value),
      "length" => byte_size(value),
      "truncated_preview?" => false
    }
  end

  defp sha256_hex(value) do
    :crypto.hash(:sha256, value)
    |> Base.encode16(case: :lower)
  end
end
