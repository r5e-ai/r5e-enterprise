defmodule Recurse.Shared.LlmProxy.Parsers.SharedPropertyTest do
  @moduledoc """
  Property tests for `Recurse.Shared.LlmProxy.Parsers.Shared`. Substrate
  for PT-001 (adversarial chunk-splitting) — the per-provider parsers in
  Phase 3 build on this guarantee: if the SHARED helpers are
  chunk-boundary-stable, the per-provider state machines stacked on top
  inherit that property.

  Two properties:

    * **chunk-boundary stability** (oracle-style) — for any well-formed
      SSE byte stream, splitting it into N random chunks and feeding
      them sequentially to `sse_buffer_push/2` produces the same event
      list as feeding the whole stream in one chunk.
    * **totality** (Invariant I-001) — `sse_buffer_push/2`, `json_buffer_push/2`,
      and `json_buffer_try_decode/1` never raise for any byte input.

  Per `stream-data-thinking`: we generate the data IN THE TARGET SPACE
  rather than filtering — the SSE-stream generator builds a list of
  events first, formats them into bytes, then splits randomly. This
  shrinks well: a counterexample shrinks toward fewer/simpler events
  + fewer/larger chunks, both of which are debugger-friendly.
  """

  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Recurse.Shared.LlmProxy.Parsers.Shared

  # =========================================================================
  # Generators
  # =========================================================================

  # Bytes legal inside a single SSE data: line — no \r, no \n. Keep
  # to printable ASCII so we don't conflate the test's edge cases
  # with UTF-8-related ones (those are covered by separate tests).
  defp sse_data_line_byte_gen do
    StreamData.filter(StreamData.integer(0x20..0x7E), &(&1 not in [?\r, ?\n]))
  end

  defp sse_data_value_gen do
    StreamData.bind(StreamData.list_of(sse_data_line_byte_gen(), max_length: 60), fn bytes ->
      StreamData.constant(:binary.list_to_bin(bytes))
    end)
  end

  # Build a single well-formed SSE event with optional event: field
  # and exactly one data: line.
  defp sse_event_gen do
    gen all event_field <- StreamData.one_of([StreamData.constant(nil), sse_data_value_gen()]),
            data <- sse_data_value_gen() do
      %{event: event_field, data: data}
    end
  end

  defp render_sse_event(%{event: nil, data: data}), do: "data: " <> data <> "\n\n"
  defp render_sse_event(%{event: ev, data: data}),
    do: "event: " <> ev <> "\n" <> "data: " <> data <> "\n\n"

  defp sse_stream_gen do
    gen all events <- StreamData.list_of(sse_event_gen(), max_length: 8) do
      bytes = events |> Enum.map(&render_sse_event/1) |> IO.iodata_to_binary()
      {events, bytes}
    end
  end

  # Split `bytes` into N chunks at `n` random byte offsets in [0, byte_size].
  # Generator yields a list of binary chunks whose concatenation == bytes.
  defp chunked_split_gen(bytes) do
    size = byte_size(bytes)

    if size == 0 do
      StreamData.constant([])
    else
      gen all offsets <- StreamData.list_of(StreamData.integer(0..size), max_length: 10) do
        offsets
        |> Enum.uniq()
        |> Enum.sort()
        |> then(&(&1 ++ [size]))
        |> Enum.reduce({0, []}, fn off, {prev, acc} ->
          chunk = :binary.part(bytes, prev, off - prev)
          {off, [chunk | acc]}
        end)
        |> elem(1)
        |> Enum.reverse()
      end
    end
  end

  # =========================================================================
  # PT-001 substrate: chunk-boundary stability
  # =========================================================================

  property "SSE: any chunked split produces the same events as a single-chunk parse" do
    check all {events_in, bytes} <- sse_stream_gen(),
              chunks <- chunked_split_gen(bytes),
              max_runs: 200 do
      single = parse_all(Shared.sse_buffer_new(), [bytes])
      multi = parse_all(Shared.sse_buffer_new(), chunks)

      # The events emitted MUST match — same order, same data + event fields.
      # We strip :raw because byte-equality of `raw` is not the property we
      # are testing here (raw IS preserved per-event but the surrounding
      # accumulation may concat across boundaries — the higher-level
      # invariant is data + event field equality).
      expected = Enum.map(events_in, &Map.take(&1, [:data, :event]))
      observed_single = Enum.map(single, &Map.take(&1, [:data, :event]))
      observed_multi = Enum.map(multi, &Map.take(&1, [:data, :event]))

      assert observed_single == expected
      assert observed_multi == expected
    end
  end

  defp parse_all(buf, chunks) do
    {final_buf, events} =
      Enum.reduce(chunks, {buf, []}, fn chunk, {buf, acc} ->
        {buf2, evs} = Shared.sse_buffer_push(buf, chunk)
        {buf2, acc ++ evs}
      end)

    {_, trailing} = Shared.sse_buffer_flush(final_buf)
    events ++ trailing
  end

  # =========================================================================
  # I-001 totality: never raises for arbitrary bytes
  # =========================================================================

  property "sse_buffer_push: arbitrary byte input never raises" do
    check all chunk <- StreamData.binary(), max_runs: 300 do
      buf = Shared.sse_buffer_new()
      {_, _events} = Shared.sse_buffer_push(buf, chunk)
    end
  end

  property "sse_buffer_push: byte-by-byte feeding never raises" do
    check all input <- StreamData.binary(max_length: 256), max_runs: 100 do
      Enum.reduce(:binary.bin_to_list(input), Shared.sse_buffer_new(), fn b, buf ->
        {buf2, _evs} = Shared.sse_buffer_push(buf, <<b>>)
        buf2
      end)
    end
  end

  property "json_buffer: arbitrary push + try_decode never raises" do
    check all chunks <- StreamData.list_of(StreamData.binary(), max_length: 8),
              max_runs: 300 do
      buf = Enum.reduce(chunks, Shared.json_buffer_new(), &Shared.json_buffer_push(&2, &1))
      result = Shared.json_buffer_try_decode(buf)

      assert match?({:ok, _}, result) or
               match?({:partial, _}, result) or
               match?({:error, _}, result)
    end
  end

  # JSON roundtrip: any value Jason can encode + decode survives a chunked
  # accumulator. This is the property the per-provider parsers depend on
  # for `arguments.delta` / `input_json_delta` accumulation.
  property "json_buffer: chunked-feed of Jason-encoded value decodes back to value" do
    check all value <- json_value_gen(),
              chunks <- chunks_of_jason(value),
              max_runs: 200 do
      buf = Enum.reduce(chunks, Shared.json_buffer_new(), &Shared.json_buffer_push(&2, &1))
      assert {:ok, ^value} = Shared.json_buffer_try_decode(buf)
    end
  end

  defp json_value_gen do
    StreamData.tree(
      StreamData.one_of([
        StreamData.boolean(),
        StreamData.integer(),
        StreamData.string(:printable, max_length: 12),
        StreamData.constant(nil)
      ]),
      fn child ->
        StreamData.one_of([
          StreamData.list_of(child, max_length: 4),
          StreamData.map_of(StreamData.string(:alphanumeric, min_length: 1, max_length: 6), child,
            max_length: 4
          )
        ])
      end
    )
  end

  defp chunks_of_jason(value) do
    bytes = Jason.encode!(value)
    size = byte_size(bytes)

    if size == 0 do
      StreamData.constant([""])
    else
      gen all offsets <- StreamData.list_of(StreamData.integer(0..size), max_length: 10) do
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
end
