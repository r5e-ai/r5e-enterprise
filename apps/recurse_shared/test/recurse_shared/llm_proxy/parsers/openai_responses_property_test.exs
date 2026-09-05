defmodule Recurse.Shared.LlmProxy.Parsers.OpenaiResponsesPropertyTest do
  @moduledoc """
  Property tests for `Recurse.Shared.LlmProxy.Parsers.OpenaiResponses`,
  covering the three properties enumerated in
  `specs/009-llm-api-proxy/contracts/per_provider_parser.md`:

    * **PT-001 — adversarial chunk-splitting** — for any random N-way
      chunk split of a well-formed Responses-API stream, the union of
      emitted intents equals the intents from a single-chunk parse.
    * **PT-002 — drift tolerance** — adding random unknown fields to
      events does not break extraction of known fields.
    * **PT-003 — totality** — for any byte sequence (even random
      garbage), `parse_chunk/2` returns `{state, intents, [_ | _]}`
      without raising.

  Per `stream-data-thinking`: generators build values IN the target
  space (well-formed Responses-API streams) rather than filtering
  arbitrary bytes — so shrinks point at minimal failing structures
  (one event, one tool call, one delta), not random garbage.
  """

  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Recurse.Shared.LlmProxy.Parsers.OpenaiResponses

  # ---------------------------------------------------------------------------
  # Generators — well-formed Responses-API streams
  # ---------------------------------------------------------------------------

  # Plain ASCII printable for tool args / names — keeps the JSON encoder
  # free of escape edge cases that would belong to a separate UTF-8 test.
  defp tool_name_gen,
    do: StreamData.string(:alphanumeric, min_length: 1, max_length: 12)

  defp call_id_gen,
    do:
      StreamData.bind(StreamData.integer(0..1_000_000), fn n ->
        StreamData.constant("call_#{n}")
      end)

  defp tool_args_gen do
    StreamData.map_of(
      StreamData.string(:alphanumeric, min_length: 1, max_length: 8),
      StreamData.one_of([
        StreamData.string(:alphanumeric, max_length: 16),
        StreamData.integer(),
        StreamData.boolean()
      ]),
      max_length: 4
    )
  end

  defp function_call_gen do
    gen all call_id <- call_id_gen(),
            name <- tool_name_gen(),
            args <- tool_args_gen() do
      %{call_id: call_id, name: name, args: args}
    end
  end

  defp response_gen do
    gen all calls <- StreamData.list_of(function_call_gen(), min_length: 0, max_length: 4) do
      # Dedup by call_id — the provider never reuses a call_id within one
      # response.
      Enum.uniq_by(calls, & &1.call_id)
    end
  end

  # Render a list of function calls into a well-formed Responses-API
  # SSE byte stream. Each call gets a sequence:
  #
  #   response.output_item.added (function_call)
  #   response.function_call.arguments.delta (one or two)
  #   response.function_call.completed
  #
  # Plus a `response.created` opener and `response.completed` closer.
  defp render_response(calls) do
    events = [%{"type" => "response.created", "response" => %{"id" => "resp_test"}}]

    {events_with_calls, _} =
      Enum.reduce(calls, {events, 0}, fn call, {acc, idx} ->
        item = %{
          "type" => "function_call",
          "id" => "fc_#{idx}",
          "call_id" => call.call_id,
          "name" => call.name,
          "arguments" => ""
        }

        added = %{
          "type" => "response.output_item.added",
          "output_index" => idx,
          "item" => item
        }

        # Split the JSON-encoded args into two halves to exercise the
        # delta accumulator.
        full = Jason.encode!(call.args)
        half = div(byte_size(full), 2)
        first = :binary.part(full, 0, half)
        second = :binary.part(full, half, byte_size(full) - half)

        delta1 = %{
          "type" => "response.function_call.arguments.delta",
          "item_id" => "fc_#{idx}",
          "call_id" => call.call_id,
          "delta" => first
        }

        delta2 = %{
          "type" => "response.function_call.arguments.delta",
          "item_id" => "fc_#{idx}",
          "call_id" => call.call_id,
          "delta" => second
        }

        completed = %{
          "type" => "response.function_call.completed",
          "item_id" => "fc_#{idx}",
          "call_id" => call.call_id
        }

        {acc ++ [added, delta1, delta2, completed], idx + 1}
      end)

    closer = %{"type" => "response.completed", "response" => %{"id" => "resp_test"}}
    events = events_with_calls ++ [closer]

    events
    |> Enum.map(&("data: " <> Jason.encode!(&1) <> "\n\n"))
    |> IO.iodata_to_binary()
  end

  # Split `bytes` into a list of N chunks of arbitrary size whose
  # concatenation is `bytes`. Generated bottom-up via random split
  # offsets — shrinks toward fewer chunks.
  defp chunked_split_gen(bytes) do
    size = byte_size(bytes)

    if size == 0 do
      StreamData.constant([])
    else
      gen all offsets <- StreamData.list_of(StreamData.integer(0..size), max_length: 12) do
        offsets
        |> Enum.uniq()
        |> Enum.sort()
        |> then(&(&1 ++ [size]))
        |> Enum.reduce({0, []}, fn off, {prev, acc} ->
          {off, [:binary.part(bytes, prev, off - prev) | acc]}
        end)
        |> elem(1)
        |> Enum.reverse()
      end
    end
  end

  # Helper: parse a list of chunks through SSE-mode parser, return
  # accumulated intents.
  defp parse_chunks(chunks) do
    state = OpenaiResponses.init(transport: :sse)

    {final_state, all_intents} =
      Enum.reduce(chunks, {state, []}, fn chunk, {st, acc} ->
        {st2, ints, _dirs} = OpenaiResponses.parse_chunk(st, chunk)
        {st2, acc ++ ints}
      end)

    {_summary, _} = OpenaiResponses.finalize(final_state)
    all_intents
  end

  # Project an intent down to the load-bearing fields for chunk-boundary
  # comparison: byte spans WILL differ between split shapes (the byte
  # offset of an event depends on what arrived before it), so compare
  # only the canonical fields.
  defp project(intent) do
    {intent.call_id, intent.tool_name, intent.tool_args, intent.tool_args_hash,
     intent.parallel_index}
  end

  # ---------------------------------------------------------------------------
  # PT-001 — adversarial chunk-splitting
  # ---------------------------------------------------------------------------

  property "PT-001: any chunked split produces the same intents as a single-chunk parse" do
    check all calls <- response_gen(),
              chunks <- chunked_split_gen(render_response(calls)),
              max_runs: 100 do
      bytes = render_response(calls)
      single = parse_chunks([bytes])
      multi = parse_chunks(chunks)

      assert Enum.map(single, &project/1) == Enum.map(multi, &project/1)
    end
  end

  property "PT-001b: byte-by-byte feeding produces the same intents as one chunk" do
    check all calls <- response_gen(), max_runs: 25 do
      bytes = render_response(calls)
      whole = parse_chunks([bytes])

      byte_chunks = for <<b <- bytes>>, do: <<b>>
      bytewise = parse_chunks(byte_chunks)

      assert Enum.map(whole, &project/1) == Enum.map(bytewise, &project/1)
    end
  end

  # ---------------------------------------------------------------------------
  # PT-002 — drift tolerance: unknown fields in events
  # ---------------------------------------------------------------------------

  defp inject_unknown_fields(json_string) do
    case Jason.decode(json_string) do
      {:ok, map} when is_map(map) ->
        polluted = Map.put(map, "_unknown_field_x_42", %{"nested" => "garbage"})
        Jason.encode!(polluted)

      _ ->
        json_string
    end
  end

  defp render_response_with_drift(calls) do
    bytes = render_response(calls)

    bytes
    |> String.split("\n\n", trim: false)
    |> Enum.map(fn block ->
      case block do
        "data: " <> rest ->
          "data: " <> inject_unknown_fields(rest)

        other ->
          other
      end
    end)
    |> Enum.join("\n\n")
  end

  property "PT-002: unknown fields injected into every event do not break intent extraction" do
    check all calls <- response_gen(), max_runs: 50 do
      clean = parse_chunks([render_response(calls)])
      polluted = parse_chunks([render_response_with_drift(calls)])

      assert Enum.map(clean, &project/1) == Enum.map(polluted, &project/1)
    end
  end

  # ---------------------------------------------------------------------------
  # PT-003 — totality: random byte sequences never raise
  # ---------------------------------------------------------------------------

  property "PT-003: arbitrary byte input never raises (Phase 6 totality)" do
    check all chunk <- StreamData.binary(max_length: 1024), max_runs: 200 do
      state = OpenaiResponses.init(transport: :sse)

      # Phase 6 contract: parse_chunk MUST NOT raise on arbitrary input.
      # The OLD contract (forward bytes == chunk bytes) is RELAXED:
      # bytes that don't form a complete SSE event are absorbed by the
      # SSE buffer and only emerge as forward directives once the
      # `\n\n` terminator arrives (or never, if the upstream closed
      # mid-event). This is correct: SSE clients don't see partial
      # events anyway. The proxy-level invariant (no client-visible
      # bytes leak past a Cedar deny) is verified by the Phase 6
      # apply_verdict tests, not this property.
      {_state2, intents, dirs} = OpenaiResponses.parse_chunk(state, chunk)

      assert is_list(dirs)
      assert is_list(intents)

      # All directives are well-formed.
      Enum.each(dirs, fn
        {:forward, b} when is_binary(b) -> :ok
        {:suppress, b} when is_binary(b) -> :ok
        {:cedar_eval, call_id} when is_binary(call_id) -> :ok
        :flush_pending -> :ok
        {:parser_error, reason} when is_atom(reason) -> :ok
        other -> flunk("unexpected directive: #{inspect(other)}")
      end)
    end
  end

  property "PT-003b: arbitrary chunked feeding never raises" do
    check all chunks <- StreamData.list_of(StreamData.binary(max_length: 64), max_length: 8),
              max_runs: 100 do
      state = OpenaiResponses.init(transport: :sse)

      Enum.reduce(chunks, state, fn chunk, st ->
        {st2, _intents, _dirs} = OpenaiResponses.parse_chunk(st, chunk)
        st2
      end)
    end
  end

  property "PT-003c: WS-mode arbitrary frames never raise" do
    check all frames <- StreamData.list_of(StreamData.binary(max_length: 256), max_length: 8),
              max_runs: 100 do
      state = OpenaiResponses.init(transport: :ws)

      Enum.reduce(frames, state, fn frame, st ->
        {st2, _intents, _dirs} = OpenaiResponses.parse_chunk(st, frame)
        st2
      end)
    end
  end

  # ---------------------------------------------------------------------------
  # Bonus: I-003 — exactly-once intent emission (no duplicates / no misses)
  # ---------------------------------------------------------------------------

  property "I-003: intent count equals function-call count regardless of split" do
    check all calls <- response_gen(),
              chunks <- chunked_split_gen(render_response(calls)),
              max_runs: 50 do
      intents = parse_chunks(chunks)
      assert length(intents) == length(calls)

      # Every emitted call_id exists in the input.
      input_ids = MapSet.new(calls, & &1.call_id)

      for intent <- intents do
        assert MapSet.member?(input_ids, intent.call_id)
      end
    end
  end
end
