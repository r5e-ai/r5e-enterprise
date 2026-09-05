defmodule Recurse.Shared.LlmProxy.Parsers.AnthropicMessagesTest do
  @moduledoc """
  Fixture-driven tests for `Recurse.Shared.LlmProxy.Parsers.AnthropicMessages`
  (spec 012 S4). Every capture in `test/fixtures/anthropic_messages/` is
  replayed through the parser with the proxy's verdict protocol simulated:
  at each `{:cedar_eval, id}` marker the harness applies the configured
  verdict and dispatches the drained directives in place, rendering
  `:flush_pending` as a visible `<<DENIAL id>>` marker so stream order
  can be asserted.
  """

  # Log capture observes every process, including other Anthropic parser tests.
  # Run after async modules so their deliberate drift cannot enter this capture.
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias Recurse.Shared.LlmProxy.Parsers.AnthropicMessages, as: Parser
  alias Recurse.Shared.LlmProxy.ToolUseIntent

  @fixtures Path.expand("../../../fixtures/anthropic_messages", __DIR__)

  defp fixture(name), do: File.read!(Path.join(@fixtures, name))

  defp sse_fixtures do
    @fixtures |> File.ls!() |> Enum.filter(&String.ends_with?(&1, ".sse")) |> Enum.sort()
  end

  # Split `bytes` into chunks of the given sizes (the last chunk takes
  # the remainder).
  defp chunk(bytes, sizes) do
    {chunks, rest} =
      Enum.reduce(sizes, {[], bytes}, fn size, {acc, rest} ->
        if rest == "" do
          {acc, ""}
        else
          n = min(size, byte_size(rest))
          {[binary_part(rest, 0, n) | acc], binary_part(rest, n, byte_size(rest) - n)}
        end
      end)

    chunks = Enum.reverse(chunks)
    if rest == "", do: chunks, else: chunks ++ [rest]
  end

  # `verdicts` is a map of call_id → :allow | :deny (default :allow).
  # Returns %{intents, out, summary}; `out` is the concatenated client
  # bytes with `<<DENIAL id>>` where the proxy would inject.
  defp run(bytes, opts \\ []) do
    sizes = Keyword.get(opts, :chunks, [byte_size(bytes)])
    verdicts = Keyword.get(opts, :verdicts, %{})
    init = Keyword.get(opts, :init, [])
    state = Parser.init(init)

    {state, intents, out} =
      Enum.reduce(chunk(bytes, sizes), {state, [], []}, fn c, {st, intents, out} ->
        {st, new_intents, directives} = Parser.parse_chunk(st, c)
        {st, out} = dispatch(st, directives, verdicts, out)
        {st, intents ++ new_intents, out}
      end)

    {summary, trailing} = Parser.finalize(state)
    {_st, out} = dispatch(state, trailing, verdicts, out)
    %{intents: intents, out: IO.iodata_to_binary(Enum.reverse(out)), summary: summary}
  end

  defp dispatch(state, directives, verdicts, out) do
    Enum.reduce(directives, {state, out}, fn
      {:forward, b}, {st, o} ->
        {st, [b | o]}

      {:parser_error, _}, {st, o} ->
        {st, o}

      {:suppress, _}, {st, o} ->
        {st, o}

      :flush_pending, {st, o} ->
        {st, ["<<DENIAL>>" | o]}

      {:cedar_eval, id}, {st, o} ->
        decision = Map.get(verdicts, id, :allow)
        {st, drained} = Parser.apply_verdict(st, id, decision, denial_text: "denied #{id}")
        # `:flush_pending` inside the drained list is where the proxy
        # injects; render it with the id so ordering can be asserted.
        drained =
          Enum.map(drained, fn
            :flush_pending -> {:forward, "<<DENIAL #{id}>>"}
            d -> d
          end)

        dispatch(st, drained, verdicts, o)
    end)
  end

  defp events_in(sse),
    do: sse |> String.split("\n\n") |> Enum.count(&String.contains?(&1, "data:"))

  defp frames(sse) do
    sse |> String.split("\n\n", trim: true) |> Enum.map(&(&1 <> "\n\n"))
  end

  # ---------------------------------------------------------------------------
  # Identity
  # ---------------------------------------------------------------------------

  describe "identity" do
    test "version/0 is the first 16 hex chars of the SHA-256 over this parser + shared.ex" do
      assert Parser.version() =~ ~r/^[0-9a-f]{16}$/

      dir = Path.expand("../../../../lib/recurse_shared/llm_proxy/parsers", __DIR__)

      source =
        File.read!(Path.join(dir, "anthropic_messages.ex")) <>
          File.read!(Path.join(dir, "shared.ex"))

      expected =
        :crypto.hash(:sha256, source) |> Base.encode16(case: :lower) |> binary_part(0, 16)

      assert Parser.version() == expected

      # The OpenAI parser hashes the same way, so a shared.ex change moves
      # both versions.
      oai =
        File.read!(Path.join(dir, "openai_responses.ex")) <>
          File.read!(Path.join(dir, "shared.ex"))

      assert Recurse.Shared.LlmProxy.Parsers.OpenaiResponses.version() ==
               :crypto.hash(:sha256, oai) |> Base.encode16(case: :lower) |> binary_part(0, 16)
    end

    test "format/1 carries the anthropic-version only; betas are recorded separately" do
      assert Parser.format([]) == "anthropic_messages"
      assert Parser.format(anthropic_version: "2023-06-01") == "anthropic_messages/2023-06-01"

      assert Parser.format(
               anthropic_version: "2023-06-01",
               anthropic_beta: "oauth-2025-04-20,claude-code-20250219"
             ) == "anthropic_messages/2023-06-01"

      assert Parser.betas_requested([]) == []
      assert Parser.betas_requested(anthropic_beta: " ") == []

      assert Parser.betas_requested(anthropic_beta: "oauth-2025-04-20, claude-code-20250219,") ==
               ["oauth-2025-04-20", "claude-code-20250219"]

      summary =
        Parser.init(anthropic_version: "2023-06-01", anthropic_beta: "oauth-2025-04-20")
        |> Parser.current_summary()

      assert summary.format == "anthropic_messages/2023-06-01"
      assert summary.betas_requested == ["oauth-2025-04-20"]
    end

    test "accepts_json_body?/0" do
      assert Parser.accepts_json_body?()
    end
  end

  # ---------------------------------------------------------------------------
  # Every fixture: byte-faithful under allow, fully recognised, no drift logs
  # ---------------------------------------------------------------------------

  describe "every SSE fixture (allow-all)" do
    test "is forwarded byte-for-byte, fully recognised, and logs no unhandled line" do
      for name <- sse_fixtures() do
        sse = fixture(name)

        {result, log} = with_log(fn -> run(sse) end)

        assert result.out == sse, "#{name}: output bytes differ from upstream"
        assert result.summary.events_total == events_in(sse), "#{name}: events_total"
        assert result.summary.events_unhandled == 0, "#{name}: events_unhandled"
        assert result.summary.unhandled_types == [], "#{name}: unhandled_types"
        assert result.summary.model == "claude-haiku-4-5-20251001", "#{name}: model"
        assert String.starts_with?(result.summary.response_id, "msg_"), "#{name}: response_id"
        assert is_integer(result.summary.prompt_token_count), "#{name}: prompt tokens"
        assert is_integer(result.summary.completion_token_count), "#{name}: completion tokens"
        # The module is synchronous because log capture is process-global.
        # Counters above also verify drift directly for this parser invocation.
        refute log =~ "AnthropicMessages parser: unhandled", "#{name}: drift log line"
      end
    end

    test "is byte-faithful under adversarial chunking (1-byte and 7-byte chunks)" do
      for name <- sse_fixtures(), size <- [1, 7, 64] do
        sse = fixture(name)
        whole = run(sse)
        split = run(sse, chunks: List.duplicate(size, div(byte_size(sse), size) + 1))
        assert split.out == sse, "#{name} @#{size}: bytes"

        assert Enum.map(split.intents, & &1.call_id) == Enum.map(whole.intents, & &1.call_id),
               "#{name} @#{size}: intents"

        assert Enum.map(split.intents, & &1.tool_args_hash) ==
                 Enum.map(whole.intents, & &1.tool_args_hash)

        assert split.summary.events_total == whole.summary.events_total
      end
    end
  end

  # ---------------------------------------------------------------------------
  # Per-fixture expectations
  # ---------------------------------------------------------------------------

  describe "single_tool_use_bash.sse" do
    test "extracts one Bash intent with the assembled input and the toolu id" do
      result = run(fixture("single_tool_use_bash.sse"))

      assert [%ToolUseIntent{} = intent] = result.intents
      assert intent.call_id == "toolu_01LZV8Ni38xTJKZoqdQM8Pdk"
      assert intent.tool_name == "Bash"

      assert intent.tool_args == %{
               "command" => "ls -la",
               "description" => "List files in the current directory"
             }

      assert intent.parallel_index == nil
      assert intent.provider_event_span.block_index == 1
      assert length(intent.provider_event_span.event_indices) == 14

      assert intent.provider_event_span.end_byte_offset >
               intent.provider_event_span.start_byte_offset

      assert result.summary.intent_count == 1
      assert result.summary.tool_use_count == 1
      assert result.summary.stop_reason == "tool_use"
      assert result.summary.prompt_token_count == 10
      assert result.summary.completion_token_count == 181
      assert result.summary.reasoning_token_count == 102
      assert result.summary.usage["cache_read_input_tokens"] == 32_255
      assert result.summary.server_tool_uses == []
    end
  end

  describe "parallel_tool_use.sse" do
    test "extracts Read then Bash at successive indices" do
      result = run(fixture("parallel_tool_use.sse"))

      assert [read, bash] = result.intents
      assert read.tool_name == "Read"
      assert read.tool_args == %{"file_path" => "/home/user/spike/run/README.md"}
      assert read.provider_event_span.block_index == 1
      assert bash.tool_name == "Bash"
      assert bash.tool_args["command"] == "pwd"
      assert bash.provider_event_span.block_index == 2
      # The first block closed before the second opened, so the stream had
      # not revealed the parallelism yet (documented heuristic).
      assert [nil, 1] == Enum.map(result.intents, & &1.parallel_index)
      assert result.summary.tool_use_count == 2
    end
  end

  describe "tool_use_write_read.sse" do
    test "extracts Write then Read" do
      result = run(fixture("tool_use_write_read.sse"))
      assert ["Write", "Read"] == Enum.map(result.intents, & &1.tool_name)

      assert [%{"file_path" => _, "content" => _}, %{"file_path" => _}] =
               Enum.map(result.intents, & &1.tool_args)
    end
  end

  describe "text-only fixtures" do
    test "produce no intents and end_turn" do
      for name <-
            ~w(text_only.sse session_title.sse hook_denied_followup.sse single_tool_use_bash_followup.sse) do
        result = run(fixture(name))
        assert result.intents == [], name
        assert result.summary.intent_count == 0, name
        assert result.summary.stop_reason == "end_turn", name
      end
    end
  end

  describe "non-streaming JSON bodies" do
    test "the side_query message is forwarded verbatim and summarised" do
      body = fixture("non_streaming_state_summary.response.json")
      result = run(body, chunks: [100, 100, 100, 100, 100, 100, 100, 100, 100, 100])

      assert result.out == body
      assert result.intents == []
      assert result.summary.model == "claude-haiku-4-5-20251001"
      assert result.summary.response_id == "msg_011Cef2VE9U89owipNRhDtXf"
      assert result.summary.stop_reason == "end_turn"
      assert result.summary.prompt_token_count == 103
      assert result.summary.completion_token_count == 74
      assert result.summary.events_total == 2
      assert result.summary.events_unhandled == 0
    end

    test "the error body is forwarded verbatim with its error type recorded" do
      body = fixture("error_not_found.response.json")
      result = run(body)
      assert result.out == body
      assert result.summary.error_type == "not_found_error"
      assert result.summary.events_unhandled == 0
      assert result.summary.intent_count == 0
    end

    test "a JSON message with tool_use blocks is held, evaluated, and rewritten on deny" do
      message = %{
        "type" => "message",
        "id" => "msg_json",
        "model" => "claude-haiku-4-5-20251001",
        "role" => "assistant",
        "content" => [
          %{"type" => "text", "text" => "Running it."},
          %{
            "type" => "tool_use",
            "id" => "toolu_A",
            "name" => "Bash",
            "input" => %{"command" => "rm -rf /tmp/x"}
          },
          %{
            "type" => "tool_use",
            "id" => "toolu_B",
            "name" => "Read",
            "input" => %{"file_path" => "/x"}
          }
        ],
        "stop_reason" => "tool_use",
        "usage" => %{"input_tokens" => 5, "output_tokens" => 9}
      }

      body = Jason.encode!(message)

      allowed = run(body)
      assert allowed.out == body
      assert ["toolu_A", "toolu_B"] == Enum.map(allowed.intents, & &1.call_id)
      assert [0, 1] == Enum.map(allowed.intents, & &1.parallel_index)

      partial = run(body, verdicts: %{"toolu_A" => :deny})
      decoded = Jason.decode!(partial.out)

      assert [
               %{"type" => "text"},
               %{"type" => "text", "text" => "denied toolu_A"},
               %{"type" => "tool_use", "id" => "toolu_B"}
             ] = decoded["content"]

      assert decoded["stop_reason"] == "tool_use"

      all = run(body, verdicts: %{"toolu_A" => :deny, "toolu_B" => :deny})
      decoded = Jason.decode!(all.out)
      assert Enum.all?(decoded["content"], &(&1["type"] == "text"))
      refute Enum.any?(decoded["content"], &Map.has_key?(&1, "signature"))
      assert decoded["stop_reason"] == "end_turn"
      assert all.summary.denied_count == 2
    end

    test "a body that never completes is forwarded raw at finalize and counted as unparsed" do
      partial = ~s({"type":"message","content":[)
      {result, _log} = with_log(fn -> run(partial) end)
      assert result.out == ""
      assert result.summary.unhandled_types == ["stream:unparsed"]
      assert result.summary.events_unhandled == 1
    end

    test "non-JSON, non-SSE bytes pass through untouched and count as unparsed" do
      html = "<html><body>502</body></html>\n\nmore"
      {result, log} = with_log(fn -> run(html, chunks: [5, 5, 5, 5, 5, 5, 5, 5]) end)
      assert result.out == ""
      assert result.summary.unhandled_types == ["stream:unparsed"]
      assert result.summary.events_unhandled == 1
      assert log =~ "unhandled stream unparsed"
    end

    test "bytes after a complete JSON body are forwarded and counted once" do
      body = fixture("non_streaming_state_summary.response.json")
      trailing = "\n\ntrailing bytes the upstream should not have sent"
      n = byte_size(body)
      {result, _log} = with_log(fn -> run(body <> trailing, chunks: [n, 7, 9, 1000]) end)

      assert result.out == body
      assert result.intents == []
      assert result.summary.unhandled_types == ["stream:trailing_bytes"]
      assert result.summary.events_unhandled == 1
    end

    test "trailing bytes behind a held JSON body follow it in upstream order" do
      message = %{
        "type" => "message",
        "id" => "msg_t",
        "model" => "m",
        "content" => [
          %{
            "type" => "tool_use",
            "id" => "toolu_T",
            "name" => "Bash",
            "input" => %{"command" => "ls"}
          }
        ],
        "stop_reason" => "tool_use"
      }

      body = Jason.encode!(message)
      state = Parser.init()
      {state, [_intent], [{:cedar_eval, "toolu_T"}]} = Parser.parse_chunk(state, body)

      {state, [], [{:parser_error, :unrecognized_event}]} =
        with_log(fn -> Parser.parse_chunk(state, "\ntail") end) |> elem(0)

      # The transport must stop; the pending tool is not released.
      {summary, []} = Parser.finalize(state)
      assert summary.unhandled_types == ["stream:trailing_bytes"]
    end
  end

  # ---------------------------------------------------------------------------
  # Nothing is dropped silently (S4 review): every unclassified path counts
  # ---------------------------------------------------------------------------

  describe "unclassified paths count as drift" do
    @message_start ~s|event: message_start\ndata: {"type":"message_start","message":{"id":"msg_u","model":"m","usage":{"input_tokens":1}}}\n\n|
    @tool_start ~s|event: content_block_start\ndata: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_U","name":"Bash","input":{}}}\n\n|
    @tool_delta ~s|event: content_block_delta\ndata: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\\"command\\":\\"rm"}}\n\n|
    @message_delta ~s|event: message_delta\ndata: {"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":7}}\n\n|
    @message_stop ~s|event: message_stop\ndata: {"type":"message_stop"}\n\n|

    test "(a) a tool_use block whose content_block_stop never arrives is suppressed at EOF and counted" do
      stream = @message_start <> @tool_start <> @tool_delta
      {result, log} = with_log(fn -> run(stream) end)

      assert result.out == @message_start
      assert result.intents == []
      assert result.summary.unhandled_types == ["block:tool_use_unterminated"]
      assert result.summary.events_unhandled == 1
      assert log =~ "unhandled content_block type=\"tool_use_unterminated\""
    end

    test "(a) an intent whose verdict never arrives is suppressed at EOF, counted, and the stop_reason rewritten" do
      sse = fixture("single_tool_use_bash.sse")
      state = Parser.init()
      {state, [intent], directives} = Parser.parse_chunk(state, sse)
      assert {:cedar_eval, intent.call_id} in directives

      # No apply_verdict: the caller walked away.
      {{summary, trailing}, _log} = with_log(fn -> Parser.finalize(state) end)
      forwarded = for {:forward, b} <- directives ++ trailing, into: "", do: b
      suppressed = for {:suppress, b} <- trailing, into: "", do: b

      refute forwarded =~ intent.call_id
      refute forwarded =~ "input_json_delta"
      assert suppressed =~ intent.call_id
      assert forwarded =~ ~s("stop_reason":"end_turn")
      assert forwarded =~ "message_stop"
      assert summary.unhandled_types == ["block:tool_use_unevaluated"]
      assert summary.events_unhandled == 1
    end

    test "(a) JSON mode: a held body whose verdict never arrives is forwarded with the block rewritten" do
      body =
        Jason.encode!(%{
          "type" => "message",
          "id" => "msg_j",
          "model" => "m",
          "content" => [
            %{"type" => "text", "text" => "hi"},
            %{
              "type" => "tool_use",
              "id" => "toolu_J",
              "name" => "Bash",
              "input" => %{"command" => "ls"}
            }
          ],
          "stop_reason" => "tool_use"
        })

      state = Parser.init()
      {state, [_], [{:cedar_eval, "toolu_J"}]} = Parser.parse_chunk(state, body)
      {{summary, trailing}, _log} = with_log(fn -> Parser.finalize(state) end)
      assert [{:forward, out}] = trailing
      decoded = Jason.decode!(out)

      assert [%{"type" => "text", "text" => "hi"}, %{"type" => "text", "text" => text}] =
               decoded["content"]

      assert text =~ "no policy verdict"
      assert decoded["stop_reason"] == "end_turn"
      assert summary.unhandled_types == ["block:tool_use_unevaluated"]
    end

    test "(b) CR-only SSE line endings are parsed like LF" do
      cr = fixture("single_tool_use_bash.sse") |> String.replace("\n", "\r")
      result = run(cr, chunks: [17, 300, 5, 1000])

      assert result.out == cr
      assert [%{tool_name: "Bash"}] = result.intents
      assert result.summary.events_unhandled == 0
      assert result.summary.events_total == events_in(fixture("single_tool_use_bash.sse"))
    end

    test "(b) an SSE tail cut before its data line counts as unparsed" do
      stream = @message_start <> "event: message_st"
      {result, _log} = with_log(fn -> run(stream) end)
      assert result.out == @message_start
      assert result.summary.unhandled_types == ["stream:unparsed"]

      # A trailing comment or whitespace is not drift.
      clean = run(@message_start <> ": bye")
      assert clean.out == @message_start <> ": bye"
      assert clean.summary.events_unhandled == 0
    end

    test "(b) a prefix that never became JSON or SSE counts as unparsed at EOF" do
      {result, _log} = with_log(fn -> run("dat") end)
      assert result.out == ""
      assert result.summary.unhandled_types == ["stream:unparsed"]

      blank = run("  \n")
      assert blank.out == ""
      assert blank.summary.events_unhandled == 0
    end

    test "(c) a parser raise switches to passthrough, drains what was held, and counts parser:raised" do
      partial = "event: content_block_delta\n"

      rest =
        ~s|data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{}"}}\n\n|

      state = Parser.init()
      {state, [], d1} = Parser.parse_chunk(state, @message_start <> @tool_start <> partial)
      assert d1 == [{:forward, @message_start}]

      # Corrupt a field the event path arithmetic touches so the next
      # data event raises inside consume_chunk.
      corrupt = %{state | event_index: :corrupt}
      {{state, [], d2}, log} = with_log(fn -> Parser.parse_chunk(corrupt, rest) end)

      assert d2 == [{:parser_error, :raised}]
      assert log =~ "suppressing the rest of the stream"

      {state, [], d3} = Parser.parse_chunk(state, @message_stop)
      assert d3 == [{:parser_error, :failed}]

      {summary, []} = Parser.finalize(state)
      assert summary.unhandled_types == ["parser:raised"]
      assert summary.events_unhandled == 1
    end

    test "(c) a raise with a corrupt state still forwards the chunk and counts" do
      corrupt = %{Parser.init() | sse_buffer: :corrupt, mode: :sse}
      {{state, [], d}, _log} = with_log(fn -> Parser.parse_chunk(corrupt, @message_start) end)
      assert d == [{:parser_error, :raised}]
      assert {_state, [], [{:parser_error, :failed}]} = Parser.parse_chunk(state, "x")
      {summary, []} = Parser.finalize(state)
      assert "parser:raised" in summary.unhandled_types
    end

    test "(d) a duplicate content_block_start at a held index suppresses both blocks and counts" do
      dup_start =
        ~s|event: content_block_start\ndata: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_DUP","name":"Bash","input":{}}}\n\n|

      dup_delta =
        ~s|event: content_block_delta\ndata: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\\"command\\":\\"rm -rf /\\"}"}}\n\n|

      stop = ~s|event: content_block_stop\ndata: {"type":"content_block_stop","index":0}\n\n|

      stream =
        @message_start <>
          @tool_start <>
          @tool_delta <> dup_start <> dup_delta <> stop <> @message_delta <> @message_stop

      {result, _log} = with_log(fn -> run(stream, chunks: [40, 200, 33, 1000]) end)

      assert String.starts_with?(result.out, @message_start)
      refute result.out =~ "toolu_"
      refute result.out =~ "content_block"
      assert result.out == @message_start
      assert result.intents == []
      assert result.summary.unhandled_types == ["block:duplicate_index"]
      assert result.summary.events_unhandled == 1
    end

    test "(f) an integral-float index names the same block" do
      sse = fixture("single_tool_use_bash.sse")
      floated = Regex.replace(~r/"index":(\d+)/, sse, "\"index\":\\1.0")
      assert floated != sse

      result = run(floated)
      assert result.out == floated
      assert [%{tool_name: "Bash", call_id: "toolu_01LZV8Ni38xTJKZoqdQM8Pdk"}] = result.intents
      assert result.summary.events_unhandled == 0

      denied = run(floated, verdicts: %{"toolu_01LZV8Ni38xTJKZoqdQM8Pdk" => :deny})
      refute denied.out =~ ~s("id":"toolu_01LZV8Ni38xTJKZoqdQM8Pdk")
      refute denied.out =~ "input_json_delta"
      assert denied.out =~ "<<DENIAL toolu_01LZV8Ni38xTJKZoqdQM8Pdk>>"
    end
  end

  # ---------------------------------------------------------------------------
  # Denial semantics (streaming)
  # ---------------------------------------------------------------------------

  describe "denial (streaming)" do
    test "single deny suppresses the tool_use frames, injects in place, and rewrites stop_reason" do
      sse = fixture("single_tool_use_bash.sse")
      result = run(sse, verdicts: %{"toolu_01LZV8Ni38xTJKZoqdQM8Pdk" => :deny})

      refute result.out =~ "tool_use\",\"id\""
      refute result.out =~ "input_json_delta"
      assert result.out =~ "<<DENIAL toolu_01LZV8Ni38xTJKZoqdQM8Pdk>>"

      # Order: thinking block … <<DENIAL>> … message_delta (rewritten) … message_stop
      [before, after_] = String.split(result.out, "<<DENIAL toolu_01LZV8Ni38xTJKZoqdQM8Pdk>>")
      assert before =~ ~s|"index":0|
      assert before =~ "content_block_stop"
      refute before =~ "message_delta"
      assert after_ =~ ~s|"stop_reason":"end_turn"|
      refute after_ =~ ~s|"stop_reason":"tool_use"|
      assert after_ =~ "event: message_delta\ndata: {"
      assert after_ =~ ~r/event: message_stop\ndata: \{"type":"message_stop"\s*\}\n\n$/

      # Everything before the injection point is byte-identical to upstream.
      assert String.starts_with?(sse, before)
      assert result.summary.denied_count == 1
    end

    test "single deny under adversarial chunking keeps the same output" do
      sse = fixture("single_tool_use_bash.sse")
      verdicts = %{"toolu_01LZV8Ni38xTJKZoqdQM8Pdk" => :deny}
      whole = run(sse, verdicts: verdicts)

      for size <- [1, 3, 17, 200] do
        split =
          run(sse,
            verdicts: verdicts,
            chunks: List.duplicate(size, div(byte_size(sse), size) + 1)
          )

        assert split.out == whole.out, "@#{size}"
      end
    end

    test "parallel: deny first (index 1), allow second (index 2) keeps the allowed block byte-identical" do
      sse = fixture("parallel_tool_use.sse")
      result = run(sse, verdicts: %{"toolu_013iKmeig7uPdkLij7KhffFn" => :deny})

      # Allowed Bash block (index 2) intact, in order after the injection.
      bash_frames = frames(sse) |> Enum.filter(&(&1 =~ ~s|"index":2|))
      assert bash_frames != []
      assert Enum.all?(bash_frames, &String.contains?(result.out, &1))
      refute result.out =~ ~s|"id":"toolu_013iKmeig7uPdkLij7KhffFn"|

      [before, after_] = String.split(result.out, "<<DENIAL toolu_013iKmeig7uPdkLij7KhffFn>>")
      refute before =~ ~s|"index":2|
      assert after_ =~ ~s|"index":2|
      # Not all denied: stop_reason untouched, message_delta byte-identical.
      assert after_ =~ ~s|"stop_reason":"tool_use"|
      message_delta = frames(sse) |> Enum.find(&(&1 =~ "event: message_delta"))
      assert String.contains?(result.out, message_delta)
    end

    test "parallel: allow first, deny second (index 2) keeps the allowed block byte-identical" do
      sse = fixture("parallel_tool_use.sse")
      result = run(sse, verdicts: %{"toolu_01EjmhwZRKW4c5niPcH9jP3Q" => :deny})

      read_frames = frames(sse) |> Enum.filter(&(&1 =~ ~s|"index":1|))
      assert Enum.all?(read_frames, &String.contains?(result.out, &1))
      refute result.out =~ ~s|"name":"Bash"|

      [before, after_] = String.split(result.out, "<<DENIAL toolu_01EjmhwZRKW4c5niPcH9jP3Q>>")
      assert before =~ ~s|"index":1|
      assert after_ =~ "event: message_delta"
      assert after_ =~ ~s|"stop_reason":"tool_use"|
    end

    test "parallel: all denied rewrites stop_reason to end_turn once" do
      sse = fixture("parallel_tool_use.sse")

      result =
        run(sse,
          verdicts: %{
            "toolu_013iKmeig7uPdkLij7KhffFn" => :deny,
            "toolu_01EjmhwZRKW4c5niPcH9jP3Q" => :deny
          }
        )

      refute result.out =~ "input_json_delta"
      assert result.out =~ "<<DENIAL toolu_013iKmeig7uPdkLij7KhffFn>>"
      assert result.out =~ "<<DENIAL toolu_01EjmhwZRKW4c5niPcH9jP3Q>>"
      assert result.out =~ ~s|"stop_reason":"end_turn"|
      refute result.out =~ ~s|"stop_reason":"tool_use"|
      assert length(String.split(result.out, "event: message_delta")) == 2
      assert result.summary.denied_count == 2
      assert result.summary.intent_count == 2
    end

    test "denial_opts/2 names the suppressed block's index" do
      sse = fixture("parallel_tool_use.sse")
      state = Parser.init()
      {state, intents, _} = Parser.parse_chunk(state, sse)
      assert length(intents) == 2
      assert Parser.denial_opts(state, "toolu_013iKmeig7uPdkLij7KhffFn") == [output_index: 1]
      assert Parser.denial_opts(state, "toolu_01EjmhwZRKW4c5niPcH9jP3Q") == [output_index: 2]
      assert Parser.denial_opts(state, "nope") == []
    end

    test "apply_verdict/4 is total on unknown or already-decided ids" do
      state = Parser.init()
      assert {^state, []} = Parser.apply_verdict(state, "toolu_missing", :deny)
      {state, _, _} = Parser.parse_chunk(state, fixture("single_tool_use_bash.sse"))
      {state, _} = Parser.apply_verdict(state, "toolu_01LZV8Ni38xTJKZoqdQM8Pdk", :allow)
      assert {^state, []} = Parser.apply_verdict(state, "toolu_01LZV8Ni38xTJKZoqdQM8Pdk", :deny)
    end
  end

  # ---------------------------------------------------------------------------
  # Drift accounting
  # ---------------------------------------------------------------------------

  describe "drift" do
    @drift_stream """
    event: message_start
    data: {"type":"message_start","message":{"id":"msg_d","model":"claude-x","usage":{"input_tokens":1}}}

    event: content_block_start
    data: {"type":"content_block_start","index":0,"content_block":{"type":"widget","payload":"SECRET"}}

    event: content_block_delta
    data: {"type":"content_block_delta","index":0,"delta":{"type":"widget_delta","value":"SECRET"}}

    event: content_block_stop
    data: {"type":"content_block_stop","index":0}

    event: content_block_start
    data: {"type":"content_block_start","index":1,"content_block":{"type":"server_tool_use","id":"srvtoolu_1","name":"web_search","input":{}}}

    event: content_block_delta
    data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\\"query\\":\\"x\\"}"}}

    event: content_block_stop
    data: {"type":"content_block_stop","index":1}

    event: telemetry
    data: {"type":"telemetry","latency_ms":3,"secret":"SECRET"}

    event: content_block_start
    data: {"type":"content_block_start","index":2,"content_block":{"type":"tool_use","id":"toolu_Z","name":"Read","input":{}}}

    event: content_block_delta
    data: {"type":"content_block_delta","index":2,"delta":{"type":"input_json_delta","partial_json":"{\\"file_path\\":\\"/a\\"}"}}

    event: content_block_stop
    data: {"type":"content_block_stop","index":2}

    event: message_delta
    data: {"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":7}}

    event: message_stop
    data: {"type":"message_stop"}

    """

    test "unknown executable content is suppressed and drift is sampled by keys only" do
      {result, log} = with_log(fn -> run(@drift_stream) end)

      assert result.out == ""
      assert result.summary.events_total == 13
      assert result.summary.events_unhandled == 3

      assert result.summary.unhandled_types == [
               "block:widget",
               "delta:widget_delta",
               "event:telemetry"
             ]

      assert result.summary.unhandled_samples["event:telemetry"] == "keys=latency_ms,secret,type"
      refute inspect(result.summary.unhandled_samples) =~ "SECRET"

      assert log =~
               ~s|AnthropicMessages parser: unhandled event type="telemetry" keys=["latency_ms", "secret", "type"]|

      assert log =~ ~s|unhandled content_block type="widget"|
      assert log =~ ~s|unhandled delta type="widget_delta"|

      # The server-side tool use is recognised, recorded, and not an intent.
      assert result.summary.server_tool_uses == [
               %{type: "server_tool_use", name: "web_search", id: "srvtoolu_1", index: 1}
             ]

      assert [%{call_id: "toolu_Z", tool_name: "Read"}] = result.intents
    end

    test "a tool_use block without an id is suppressed and counted" do
      stream = """
      event: content_block_start
      data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","input":{}}}

      event: content_block_stop
      data: {"type":"content_block_stop","index":0}

      """

      {result, log} = with_log(fn -> run(stream) end)
      assert result.out == ""
      assert result.intents == []
      assert result.summary.unhandled_types == ["block:tool_use_without_id"]
      assert log =~ "unhandled"
    end
  end

  # ---------------------------------------------------------------------------
  # Framing edge cases + totality
  # ---------------------------------------------------------------------------

  describe "framing" do
    test "comments, retry lines, CRLF terminators, and multi-line data are tolerated" do
      stream =
        ": keep-alive\r\n\r\n" <>
          ~s|retry: 1000\nevent: message_start\ndata: {"type":"message_start",\r\ndata: "message":{"id":"msg_x","model":"m"}}\n\n| <>
          ~s|event: message_stop\ndata: {"type":"message_stop"}\n\n|

      result = run(stream, chunks: [3, 9, 20, 4, 1000])
      assert result.out == stream
      assert result.summary.response_id == "msg_x"
      assert result.summary.model == "m"
      assert result.summary.events_total == 2
      assert result.summary.events_unhandled == 0
    end

    test "parse_chunk never raises and forwards every byte on garbage" do
      garbage = <<0, 255, 1, 2, "data: {not json\n\n", 200, 201, "\n\n">>
      state = Parser.init()
      {state, [], directives} = Parser.parse_chunk(state, garbage)
      {_summary, trailing} = Parser.finalize(state)
      out = for {:forward, b} <- directives ++ trailing, into: "", do: b
      assert out == ""
    end

    test "non-binary input is a no-op forward" do
      assert {_state, [], [{:forward, ""}]} = Parser.parse_chunk(Parser.init(), :nope)
    end

    test "finalize on an untouched parser returns a complete summary" do
      {summary, []} = Parser.finalize(Parser.init(anthropic_version: "2023-06-01"))
      assert summary.events_total == 0
      assert summary.events_unhandled == 0
      assert summary.unhandled_types == []
      assert summary.intent_count == 0
      assert summary.format == "anthropic_messages/2023-06-01"
      assert summary.model == nil
    end
  end
end
