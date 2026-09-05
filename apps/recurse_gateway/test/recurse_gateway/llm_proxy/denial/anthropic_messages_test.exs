defmodule Recurse.Gateway.LlmProxy.DenialInjector.AnthropicMessagesTest do
  @moduledoc """
  Contract tests for `Recurse.Gateway.LlmProxy.DenialInjector.AnthropicMessages`
  (spec 012 S4; `contracts/denial_injector.md` §"Anthropic Messages").

    * the three replacement events are a valid `text` content block at
      the suppressed block's index, with no `signature`;
    * `sse_frame/1` emits the `event:` line the Anthropic SDK dispatches on;
    * the dispatcher routes `:anthropic_messages` and renders the same
      text through `render_text/5`;
    * the replacement round-trips through the parser as a text block
      (what Claude Code echoes back next turn).
  """

  use ExUnit.Case, async: true

  alias Recurse.Gateway.LlmProxy.DenialInjector
  alias Recurse.Gateway.LlmProxy.DenialInjector.AnthropicMessages, as: Injector
  alias Recurse.Shared.LlmProxy.Parsers.AnthropicMessages, as: Parser
  alias Recurse.Shared.LlmProxy.ToolUseIntent

  @template "Tool call '{tool_name}' (call_id: {call_id}) was blocked by org policy.\n- Rule: {rule_id}\n- Reason: {reason}{? - Try alternative: {suggested_alternative}}{? - To appeal: {appeal_uri}}"

  defp intent(opts \\ []) do
    {:ok, intent} =
      ToolUseIntent.new(%{
        call_id: Keyword.get(opts, :call_id, "toolu_01LZV8Ni38xTJKZoqdQM8Pdk"),
        tool_name: Keyword.get(opts, :tool_name, "Bash"),
        tool_args: %{"command" => "rm -rf /tmp/x"},
        provider_event_span: %{start_byte_offset: 0, end_byte_offset: 10, event_indices: [1]}
      })

    intent
  end

  @deny %{rule_id: "policy0", reason: "denied_by_cedar_policy", suggested_alternative: nil}

  test "emits start/delta/stop for a text block at the given index, without a signature" do
    events = Injector.inject_denial(intent(), @deny, @template, output_index: 2)
    assert [start, delta, stop] = Enum.map(events, &Jason.decode!/1)

    assert start == %{
             "type" => "content_block_start",
             "index" => 2,
             "content_block" => %{"type" => "text", "text" => ""}
           }

    assert %{
             "type" => "content_block_delta",
             "index" => 2,
             "delta" => %{"type" => "text_delta", "text" => text}
           } =
             delta

    assert text =~
             "Tool call 'Bash' (call_id: toolu_01LZV8Ni38xTJKZoqdQM8Pdk) was blocked by org policy."

    assert text =~ "- Rule: policy0"
    assert text =~ "- Reason: denied_by_cedar_policy"
    refute text =~ "Try alternative"
    refute text =~ "To appeal"
    assert stop == %{"type" => "content_block_stop", "index" => 2}
    refute Map.has_key?(start["content_block"], "signature")
    refute Map.has_key?(start["content_block"], "id")
  end

  test "index defaults to 0 and a pre-rendered denial_text is used verbatim" do
    events = Injector.inject_denial(intent(), @deny, @template, denial_text: "NOPE")
    [start, delta, _stop] = Enum.map(events, &Jason.decode!/1)
    assert start["index"] == 0
    assert delta["delta"]["text"] == "NOPE"
  end

  test "audit context binds the appeal line and the bundle hash" do
    events =
      Injector.inject_denial(intent(), @deny, @template <> "{? bundle {cedar_bundle_hash_short}}",
        audit_context: %{
          appeal_uri: "https://appeal.example",
          cedar_bundle_hash: :binary.copy(<<0xAB>>, 32)
        }
      )

    [_, delta, _] = Enum.map(events, &Jason.decode!/1)
    assert delta["delta"]["text"] =~ "- To appeal: https://appeal.example"
    assert delta["delta"]["text"] =~ "bundle abababababab"
  end

  test "sse_frame/1 carries the event line the Anthropic SDK dispatches on" do
    [start | _] = Injector.inject_denial(intent(), @deny, @template)
    assert Injector.sse_frame(start) == "event: content_block_start\ndata: " <> start <> "\n\n"
    assert DenialInjector.sse_frame(:anthropic_messages, start) == Injector.sse_frame(start)
    assert DenialInjector.sse_frame(:openai_responses, "{}") == "data: {}\n\n"
    assert Injector.sse_frame("not json") == "event: message\ndata: not json\n\n"
  end

  test "dispatcher routes :anthropic_messages and render_text/5 matches the delta text" do
    events = DenialInjector.inject_denial(:anthropic_messages, intent(), @deny, @template)
    assert length(events) == 3
    [_, delta, _] = Enum.map(events, &Jason.decode!/1)

    assert delta["delta"]["text"] ==
             DenialInjector.render_text(:anthropic_messages, intent(), @deny, @template)
  end

  test "the replacement block round-trips through the parser as a plain text block" do
    frames =
      DenialInjector.inject_denial(:anthropic_messages, intent(), @deny, @template,
        output_index: 1
      )
      |> Enum.map(&Injector.sse_frame/1)
      |> Enum.join()

    stream =
      ~s|event: message_start\ndata: {"type":"message_start","message":{"id":"msg_x","model":"m"}}\n\n| <>
        frames <>
        ~s|event: message_delta\ndata: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":1}}\n\n| <>
        ~s|event: message_stop\ndata: {"type":"message_stop"}\n\n|

    {state, intents, directives} = Parser.parse_chunk(Parser.init(), stream)
    {summary, trailing} = Parser.finalize(state)

    assert intents == []
    out = for {:forward, b} <- directives ++ trailing, into: "", do: b
    assert out == stream
    assert summary.events_unhandled == 0
    assert summary.intent_count == 0
    assert summary.stop_reason == "end_turn"
  end
end
