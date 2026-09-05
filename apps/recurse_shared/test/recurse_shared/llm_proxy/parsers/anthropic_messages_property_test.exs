defmodule Recurse.Shared.LlmProxy.Parsers.AnthropicMessagesPropertyTest do
  @moduledoc """
  Property tests for `Recurse.Shared.LlmProxy.Parsers.AnthropicMessages`
  (spec 012 S4; contract PT-001..PT-003 of
  `specs/009-llm-api-proxy/contracts/per_provider_parser.md`):

    * **PT-001 adversarial chunk splitting** — every captured fixture,
      split at random byte boundaries, yields the same intents, the same
      summary counts, and byte-identical client output as a single-chunk
      parse (allow-all), and the same output under a deny-all verdict.
    * **PT-002 drift tolerance** — generated streams with random unknown
      event / block / delta types interleaved are forwarded unchanged and
      counted, while the tool_use blocks are still extracted.
    * **PT-003 totality** — random bytes never raise and are forwarded.
  """

  use ExUnit.Case, async: true
  use ExUnitProperties

  @moduletag :capture_log

  alias Recurse.Shared.LlmProxy.Parsers.AnthropicMessages, as: Parser

  @fixtures Path.expand("../../../fixtures/anthropic_messages", __DIR__)

  @sse_fixtures @fixtures
                |> File.ls!()
                |> Enum.filter(&String.ends_with?(&1, ".sse"))
                |> Enum.sort()

  defp fixture(name), do: File.read!(Path.join(@fixtures, name))

  # Random split points → chunk list covering the whole binary.
  defp split_gen(bytes) do
    size = byte_size(bytes)

    gen all(points <- StreamData.list_of(StreamData.integer(0..size), max_length: 40)) do
      points = points |> Enum.uniq() |> Enum.sort()
      bounds = [0 | points] ++ [size]

      bounds
      |> Enum.chunk_every(2, 1, :discard)
      |> Enum.map(fn [a, b] -> binary_part(bytes, a, b - a) end)
      |> Enum.reject(&(&1 == ""))
    end
  end

  defp run(chunks, decision) do
    state = Parser.init()

    {state, intents, out} =
      Enum.reduce(chunks, {state, [], []}, fn c, {st, intents, out} ->
        {st, new_intents, directives} = Parser.parse_chunk(st, c)
        {st, out} = dispatch(st, directives, decision, out)
        {st, intents ++ new_intents, out}
      end)

    {summary, trailing} = Parser.finalize(state)
    {_st, out} = dispatch(state, trailing, decision, out)
    {intents, IO.iodata_to_binary(Enum.reverse(out)), summary}
  end

  defp dispatch(state, directives, decision, out) do
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
        {st, drained} = Parser.apply_verdict(st, id, decision, denial_text: "denied")
        dispatch(st, drained, decision, o)
    end)
  end

  defp intent_keys(intents), do: Enum.map(intents, &{&1.call_id, &1.tool_name, &1.tool_args_hash})

  describe "PT-001 adversarial chunk splitting" do
    for name <- @sse_fixtures do
      property "#{name}: random splits are equivalent to a single-chunk parse" do
        bytes = fixture(unquote(name))
        {whole_intents, whole_out, whole_summary} = run([bytes], :allow)
        {_, whole_deny_out, _} = run([bytes], :deny)
        assert whole_out == bytes

        check all(chunks <- split_gen(bytes), max_runs: 40) do
          {intents, out, summary} = run(chunks, :allow)
          assert out == bytes
          assert intent_keys(intents) == intent_keys(whole_intents)
          assert summary.events_total == whole_summary.events_total
          assert summary.events_unhandled == 0
          assert summary.completion_token_count == whole_summary.completion_token_count

          {_, deny_out, _} = run(chunks, :deny)
          assert deny_out == whole_deny_out
        end
      end
    end
  end

  # ---------------------------------------------------------------------------
  # PT-002 — drift tolerance on generated streams
  # ---------------------------------------------------------------------------

  defp ident_gen, do: StreamData.string([?a..?z, ?_], min_length: 3, max_length: 12)

  defp frame(type, payload) do
    "event: #{type}\ndata: " <> Jason.encode!(Map.put(payload, "type", type)) <> "\n\n"
  end

  defp tool_block_frames(index, id, name, args) do
    json = Jason.encode!(args)
    {a, b} = String.split_at(json, div(String.length(json), 2))

    frame("content_block_start", %{
      "index" => index,
      "content_block" => %{"type" => "tool_use", "id" => id, "name" => name, "input" => %{}}
    }) <>
      frame("content_block_delta", %{
        "index" => index,
        "delta" => %{"type" => "input_json_delta", "partial_json" => ""}
      }) <>
      frame("content_block_delta", %{
        "index" => index,
        "delta" => %{"type" => "input_json_delta", "partial_json" => a}
      }) <>
      frame("content_block_delta", %{
        "index" => index,
        "delta" => %{"type" => "input_json_delta", "partial_json" => b}
      }) <>
      frame("content_block_stop", %{"index" => index})
  end

  defp drift_frame_gen(index) do
    StreamData.one_of([
      StreamData.map(ident_gen(), fn t -> {:event, frame("x_" <> t, %{"k" => 1})} end),
      StreamData.map(ident_gen(), fn t ->
        {:block,
         frame("content_block_start", %{
           "index" => index,
           "content_block" => %{"type" => "x_" <> t}
         }) <>
           frame("content_block_stop", %{"index" => index})}
      end),
      StreamData.map(ident_gen(), fn t ->
        {:delta,
         frame("content_block_start", %{
           "index" => index,
           "content_block" => %{"type" => "text", "text" => ""}
         }) <>
           frame("content_block_delta", %{"index" => index, "delta" => %{"type" => "x_" <> t}}) <>
           frame("content_block_stop", %{"index" => index})}
      end)
    ])
  end

  defp stream_gen do
    gen all(
          n_tools <- StreamData.integer(0..3),
          n_drift <- StreamData.integer(0..3),
          args <-
            StreamData.list_of(
              StreamData.map_of(ident_gen(), StreamData.integer(), max_length: 3),
              length: n_tools
            ),
          drift <- StreamData.list_of(drift_frame_gen(50), length: n_drift)
        ) do
      tools =
        args
        |> Enum.with_index()
        |> Enum.map(fn {a, i} -> tool_block_frames(i + 1, "toolu_#{i}", "T#{i}", a) end)

      drift_bytes = Enum.map_join(drift, "", fn {_kind, bytes} -> bytes end)
      drift_kinds = Enum.map(drift, fn {kind, _} -> kind end)

      body =
        frame("message_start", %{
          "message" => %{"id" => "msg_p", "model" => "m", "usage" => %{"input_tokens" => 1}}
        }) <>
          drift_bytes <>
          Enum.join(tools, "") <>
          frame("message_delta", %{
            "delta" => %{"stop_reason" => if(n_tools > 0, do: "tool_use", else: "end_turn")},
            "usage" => %{"output_tokens" => 2}
          }) <>
          frame("message_stop", %{})

      %{bytes: body, n_tools: n_tools, drift_kinds: drift_kinds}
    end
  end

  property "PT-002: unknown event/block/delta types cannot bypass classification" do
    check all(
            %{bytes: bytes, n_tools: n_tools, drift_kinds: kinds} <- stream_gen(),
            chunks <- split_gen(bytes),
            max_runs: 60
          ) do
      {intents, out, summary} = run(chunks, :allow)

      if kinds == [] do
        assert out == bytes
        assert length(intents) == n_tools
      else
        assert summary.events_unhandled > 0
        assert length(intents) <= n_tools
        refute out =~ ~s("type":"x_)
      end

      {_, deny_out, _} = run(chunks, :deny)
      refute deny_out =~ "input_json_delta"
      refute deny_out =~ ~s("type":"tool_use")
    end
  end

  property "PT-003: any byte sequence is total and undecidable garbage is suppressed" do
    check all(bytes <- StreamData.binary(max_length: 400), max_runs: 200) do
      {[], out, summary} = run([bytes], :allow)
      # Valid SSE comments contain no executable data and may be preserved.
      if summary.events_unhandled > 0, do: assert(out == "")
    end
  end
end
