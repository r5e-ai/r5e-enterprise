defmodule Recurse.Shared.LlmProxy.Parsers.AdmissionBoundaryTest do
  use ExUnit.Case, async: true
  alias Recurse.Shared.LlmProxy.Parsers.{AnthropicMessages, OpenaiResponses}

  defp event(type, fields), do: Jason.encode!(Map.put(fields, "type", type))
  defp forwards(dirs), do: for({:forward, bytes} <- dirs, into: "", do: bytes)

  test "OpenAI malformed JSON and unknown executable events require transport refusal" do
    for bytes <- ["{invalid", event("response.new_tool_call", %{"command" => "danger"})] do
      {_st, [], dirs} = OpenaiResponses.parse_chunk(OpenaiResponses.init(transport: :ws), bytes)
      assert Enum.any?(dirs, &match?({:parser_error, _}, &1))
      assert forwards(dirs) == ""
    end
  end

  test "ordinary OpenAI text, reasoning and message items remain supported" do
    for bytes <- [
          event("response.output_text.delta", %{"delta" => "hello"}),
          event("response.output_item.added", %{"item" => %{"type" => "message", "id" => "m"}}),
          event("response.output_item.added", %{"item" => %{"type" => "reasoning", "id" => "r"}})
        ] do
      {_st, [], dirs} = OpenaiResponses.parse_chunk(OpenaiResponses.init(transport: :ws), bytes)
      assert forwards(dirs) == bytes
    end
  end

  test "orphan tool completion cannot use the normal-frame path" do
    bytes =
      event("response.function_call_arguments.done", %{"call_id" => "absent", "arguments" => "{}"})

    {_st, _, dirs} = OpenaiResponses.parse_chunk(OpenaiResponses.init(transport: :ws), bytes)
    assert Enum.any?(dirs, &match?({:parser_error, _}, &1))
    assert forwards(dirs) == ""
  end

  test "terminal OpenAI output cannot reintroduce an unadmitted tool" do
    bytes =
      event("response.completed", %{
        "response" => %{
          "output" => [
            %{
              "type" => "function_call",
              "call_id" => "absent",
              "name" => "Bash",
              "arguments" => "{}"
            }
          ]
        }
      })

    {_st, _, dirs} = OpenaiResponses.parse_chunk(OpenaiResponses.init(transport: :ws), bytes)
    assert {:parser_error, :unadmitted_terminal_output} in dirs
    assert forwards(dirs) == ""
  end

  test "Anthropic truncated JSON cannot be released at EOF" do
    bytes = ~s({"type":"message","content":[{"type":"tool_use")
    {st, [], dirs} = AnthropicMessages.parse_chunk(AnthropicMessages.init(), bytes)
    {_summary, tail} = AnthropicMessages.finalize(st)
    assert forwards(dirs ++ tail) == ""
    assert {:parser_error, :incomplete_json} in tail
  end

  test "Anthropic tool without correlation id cannot become normal output" do
    bytes =
      "event: content_block_start\ndata: " <>
        event("content_block_start", %{
          "index" => 0,
          "content_block" => %{"type" => "tool_use", "name" => "Bash", "input" => %{}}
        }) <>
        "\n\nevent: content_block_stop\ndata: " <>
        event("content_block_stop", %{"index" => 0}) <> "\n\n"

    {_st, [], dirs} = AnthropicMessages.parse_chunk(AnthropicMessages.init(), bytes)
    assert {:parser_error, :unrecognized_event} in dirs
    assert forwards(dirs) == ""
  end

  defp tool_stream do
    item = %{
      "type" => "function_call",
      "id" => "i1",
      "call_id" => "c1",
      "name" => "Bash",
      "arguments" => ~s({"command":"pwd"})
    }

    opening = event("response.output_item.added", %{"item" => Map.put(item, "arguments", "")})

    done =
      event("response.function_call_arguments.done", %{
        "call_id" => "c1",
        "arguments" => item["arguments"]
      })

    {opening, done, item}
  end

  test "terminal output waits for verdict, retains allowed item and drops denied item" do
    {opening, done, item} = tool_stream()
    terminal = event("response.completed", %{"response" => %{"output" => [item]}})

    wire =
      Enum.map_join([opening, done, terminal], &("data: " <> &1 <> "\n\n")) <> "data: [DONE]\n\n"

    {state, [_intent], dirs} = OpenaiResponses.parse_chunk(OpenaiResponses.init(), wire)
    refute Enum.any?(dirs, &match?({:parser_error, _}, &1))
    refute forwards(dirs) =~ "response.completed"
    {_, pending_tail} = OpenaiResponses.finalize(state)
    assert Enum.any?(pending_tail, &match?({:parser_error, _}, &1))

    {allowed, drained} = OpenaiResponses.apply_verdict(state, "c1", :allow)
    {_, allowed_tail} = OpenaiResponses.finalize(allowed)
    assert forwards(dirs ++ drained ++ allowed_tail) == wire

    {denied, _} = OpenaiResponses.apply_verdict(state, "c1", :deny)
    {_, denied_tail} = OpenaiResponses.finalize(denied)
    assert forwards(denied_tail) =~ "response.completed"
    refute forwards(denied_tail) =~ "function_call"
  end

  test "repeated executable items cannot change their admitted name or arguments" do
    {opening, done, item} = tool_stream()
    state = OpenaiResponses.init(transport: :ws)
    {state, [], _} = OpenaiResponses.parse_chunk(state, opening)
    {state, [_intent], _} = OpenaiResponses.parse_chunk(state, done)
    {state, _} = OpenaiResponses.apply_verdict(state, "c1", :allow)

    for changed <- [
          Map.put(item, "name", "DeleteAll"),
          Map.put(item, "arguments", ~s({"command":"rm"}))
        ],
        type <- ["response.output_item.done", "response.completed"] do
      fields =
        if type == "response.completed",
          do: %{"response" => %{"output" => [changed]}},
          else: %{"item" => changed}

      {_state, _, dirs} = OpenaiResponses.parse_chunk(state, event(type, fields))
      assert Enum.any?(dirs, &match?({:parser_error, _}, &1))
      assert forwards(dirs) == ""
    end

    {_state, _, dirs} =
      OpenaiResponses.parse_chunk(
        state,
        event("response.function_call_arguments.delta", %{"call_id" => "c1", "delta" => "danger"})
      )

    assert {:parser_error, :changed_tool_after_intent} in dirs
  end

  test "response creation is not completion and pending WS tools fail at EOF" do
    {state, _, _} =
      OpenaiResponses.parse_chunk(
        OpenaiResponses.init(transport: :ws),
        event("response.created", %{"response" => %{}})
      )

    refute OpenaiResponses.current_summary(state)[:completion_seen?]
    {opening, _, _} = tool_stream()
    {state, _, _} = OpenaiResponses.parse_chunk(state, opening)
    {_, tail} = OpenaiResponses.finalize(state)
    assert {:parser_error, :incomplete_stream} in tail
  end

  test "streamed and completed argument representations must agree before admission" do
    {opening, _done, item} = tool_stream()

    for done_type <- ["response.function_call_arguments.done", "response.output_item.done"] do
      {state, [], _} = OpenaiResponses.parse_chunk(OpenaiResponses.init(transport: :ws), opening)

      {state, [], _} =
        OpenaiResponses.parse_chunk(
          state,
          event("response.function_call_arguments.delta", %{
            "call_id" => "c1",
            "delta" => ~s({"command":"alpha"})
          })
        )

      fields =
        if done_type == "response.output_item.done",
          do: %{"item" => Map.put(item, "arguments", ~s({"command":"beta"}))},
          else: %{"call_id" => "c1", "arguments" => ~s({"command":"beta"})}

      {_state, intents, dirs} = OpenaiResponses.parse_chunk(state, event(done_type, fields))
      assert intents == []
      assert Enum.any?(dirs, &match?({:parser_error, _}, &1))
      assert forwards(dirs) == ""
    end
  end
end
