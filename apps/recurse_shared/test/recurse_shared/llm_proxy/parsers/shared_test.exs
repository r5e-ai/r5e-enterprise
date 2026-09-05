defmodule Recurse.Shared.LlmProxy.Parsers.SharedTest do
  @moduledoc """
  Unit tests for `Recurse.Shared.LlmProxy.Parsers.Shared` — the
  transport-agnostic helpers used by all four per-provider parsers.

  Spec source: `specs/009-llm-api-proxy/contracts/per_provider_parser.md`
  ("Shared utilities" + Invariant I-001 totality).

  These tests cover:
    * SSE chunk-boundary splitting (events that span N chunks)
    * partial-JSON accumulation across N chunks
    * empty-chunk handling
    * malformed-input total-function guarantee (I-001)
    * WS frame collector behavior + unexpected-binary handling

  Property tests for the same surface (PT-001 substrate — random
  N-way chunk splits) live in `shared_property_test.exs`.
  """

  use ExUnit.Case, async: true

  alias Recurse.Shared.LlmProxy.Parsers.Shared

  # =========================================================================
  # SSE event-line splitter
  # =========================================================================

  describe "SSE: single-chunk extraction" do
    test "extracts a single complete event" do
      chunk = ~s(data: hello\n\n)
      buf = Shared.sse_buffer_new()
      assert {_, [%{data: "hello", event: nil}]} = Shared.sse_buffer_push(buf, chunk)
    end

    test "extracts multiple events in one chunk" do
      chunk = ~s(data: a\n\ndata: b\n\ndata: c\n\n)
      buf = Shared.sse_buffer_new()
      {_, events} = Shared.sse_buffer_push(buf, chunk)
      assert [%{data: "a"}, %{data: "b"}, %{data: "c"}] = events
    end

    test "preserves trailing partial event in buffer" do
      chunk = ~s(data: a\n\ndata: b)
      buf = Shared.sse_buffer_new()
      {buf2, events} = Shared.sse_buffer_push(buf, chunk)
      assert [%{data: "a"}] = events
      # The "data: b" is held in buffer state; second chunk completes it.
      {_, events2} = Shared.sse_buffer_push(buf2, "\n\n")
      assert [%{data: "b"}] = events2
    end

    test "handles event: + data: lines together" do
      chunk = ~s(event: tool_use\ndata: {"id":"1"}\n\n)
      buf = Shared.sse_buffer_new()
      {_, [event]} = Shared.sse_buffer_push(buf, chunk)
      assert event.event == "tool_use"
      assert event.data == ~s({"id":"1"})
    end

    test "skips comment lines and unknown fields per SSE spec" do
      chunk = ~s(:keepalive\nid: 42\nretry: 100\ndata: hello\n\n)
      buf = Shared.sse_buffer_new()
      {_, [%{data: "hello"}]} = Shared.sse_buffer_push(buf, chunk)
    end

    test "joins multi-line data: with \\n per spec" do
      chunk = ~s(data: line1\ndata: line2\n\n)
      buf = Shared.sse_buffer_new()
      {_, [%{data: data}]} = Shared.sse_buffer_push(buf, chunk)
      assert data == "line1\nline2"
    end

    test "strips one leading space after the colon per spec" do
      chunk = ~s(data: hello\n\n)
      buf = Shared.sse_buffer_new()
      {_, [%{data: "hello"}]} = Shared.sse_buffer_push(buf, chunk)
    end

    test "preserves leading spaces beyond the first" do
      # SSE strips ONE leading space; subsequent ones survive.
      chunk = ~s(data:  two-leading-spaces\n\n)
      buf = Shared.sse_buffer_new()
      {_, [%{data: " two-leading-spaces"}]} = Shared.sse_buffer_push(buf, chunk)
    end

    test "handles \\r\\n\\r\\n terminator per spec" do
      chunk = "data: hello\r\n\r\n"
      buf = Shared.sse_buffer_new()
      {_, [%{data: "hello"}]} = Shared.sse_buffer_push(buf, chunk)
    end

    test "discards blocks with no data: lines (SSE: dispatch only when data buffer non-empty)" do
      # event: foo by itself with no data: lines should NOT dispatch.
      chunk = ~s(event: ping\n\ndata: real\n\n)
      buf = Shared.sse_buffer_new()
      {_, events} = Shared.sse_buffer_push(buf, chunk)
      assert [%{data: "real"}] = events
    end
  end

  describe "SSE: chunk-boundary handling" do
    test "byte-by-byte feeding produces the same events as single-chunk" do
      payload = ~s(data: alpha\n\ndata: beta\n\ndata: gamma\n\n)
      expected = [%{data: "alpha"}, %{data: "beta"}, %{data: "gamma"}]

      {_, all_events} =
        Enum.reduce(:binary.bin_to_list(payload), {Shared.sse_buffer_new(), []}, fn b,
                                                                                    {buf, acc} ->
          {buf2, evs} = Shared.sse_buffer_push(buf, <<b>>)
          {buf2, acc ++ evs}
        end)

      assert Enum.map(all_events, &Map.take(&1, [:data])) ==
               Enum.map(expected, &Map.take(&1, [:data]))
    end

    test "splits in the middle of the terminator survive" do
      # Boundary lands between the two \n bytes of the terminator.
      buf = Shared.sse_buffer_new()
      {buf, []} = Shared.sse_buffer_push(buf, "data: a\n")
      {_, [%{data: "a"}]} = Shared.sse_buffer_push(buf, "\n")
    end

    test "boundary inside a data field" do
      buf = Shared.sse_buffer_new()
      {buf, []} = Shared.sse_buffer_push(buf, "data: he")
      {buf, []} = Shared.sse_buffer_push(buf, "llo")
      {_, [%{data: "hello"}]} = Shared.sse_buffer_push(buf, "\n\n")
    end
  end

  describe "SSE: empty-chunk + flush handling" do
    test "empty chunk is a no-op" do
      buf = Shared.sse_buffer_new()
      assert {^buf, []} = Shared.sse_buffer_push(buf, "")
    end

    test "flush on empty buffer returns no events" do
      buf = Shared.sse_buffer_new()
      assert {_, []} = Shared.sse_buffer_flush(buf)
    end

    test "flush on partial buffer with complete fields emits the trailing event" do
      # Some upstreams omit the final \n\n on close; we still want to flush.
      buf = Shared.sse_buffer_new()
      {buf, []} = Shared.sse_buffer_push(buf, "data: tail")
      {_, [%{data: "tail"}]} = Shared.sse_buffer_flush(buf)
    end

    test "flush on partial buffer with no data: lines returns no events" do
      buf = Shared.sse_buffer_new()
      {buf, []} = Shared.sse_buffer_push(buf, ":just a comment")
      {_, []} = Shared.sse_buffer_flush(buf)
    end
  end

  describe "SSE: malformed-input totality (I-001)" do
    test "random bytes never raise; produce buffer state" do
      garbage = :crypto.strong_rand_bytes(2048)
      buf = Shared.sse_buffer_new()
      {_, _events} = Shared.sse_buffer_push(buf, garbage)
    end

    test "embedded null bytes don't crash" do
      chunk = <<"data: pre", 0, "post\n\n">>
      buf = Shared.sse_buffer_new()
      {_, [_event]} = Shared.sse_buffer_push(buf, chunk)
    end

    test "non-binary input is a no-op (defensive — public API uses guards)" do
      buf = Shared.sse_buffer_new()
      assert {^buf, []} = Shared.sse_buffer_push(buf, :not_a_binary)
    end

    test "very long line without terminator is buffered, not raised" do
      buf = Shared.sse_buffer_new()
      huge = String.duplicate("x", 10_000)
      assert {_buf2, []} = Shared.sse_buffer_push(buf, "data: " <> huge)
    end
  end

  # =========================================================================
  # WebSocket frame collector
  # =========================================================================

  describe "WS frame buffer" do
    test "text frames pass through verbatim" do
      buf = Shared.ws_frame_buffer_new()
      {_, [{:text, "hello"}]} = Shared.ws_frame_buffer_push(buf, {:text, "hello"})
    end

    test "binary frames surface as :unexpected_binary AND accumulate" do
      buf = Shared.ws_frame_buffer_new()
      {buf, [{:unexpected_binary, <<1, 2, 3>>}]} =
        Shared.ws_frame_buffer_push(buf, {:binary, <<1, 2, 3>>})

      {buf, [{:unexpected_binary, <<4>>}]} =
        Shared.ws_frame_buffer_push(buf, {:binary, <<4>>})

      assert [<<1, 2, 3>>, <<4>>] = Shared.ws_frame_buffer_unexpected(buf)
    end

    test "control frames / unknown shapes are no-ops" do
      buf = Shared.ws_frame_buffer_new()
      assert {^buf, []} = Shared.ws_frame_buffer_push(buf, {:ping, ""})
      assert {^buf, []} = Shared.ws_frame_buffer_push(buf, :close)
      assert {^buf, []} = Shared.ws_frame_buffer_push(buf, "not a frame tuple")
    end
  end

  # =========================================================================
  # Partial-JSON accumulator
  # =========================================================================

  describe "JSON buffer" do
    test "complete value decodes" do
      buf = Shared.json_buffer_new() |> Shared.json_buffer_push(~s({"a":1}))
      assert {:ok, %{"a" => 1}} = Shared.json_buffer_try_decode(buf)
    end

    test "partial value reports :partial" do
      buf = Shared.json_buffer_new() |> Shared.json_buffer_push(~s({"a":1))
      assert {:partial, _} = Shared.json_buffer_try_decode(buf)
    end

    test "accumulates across N chunks; final probe decodes" do
      chunks = ["{", ~s("cmd":), ~s("ls -la"), ",", ~s("force":true), "}"]

      buf =
        Enum.reduce(chunks, Shared.json_buffer_new(), fn c, acc ->
          # Sanity: every intermediate state is partial.
          {ok_or_partial, _} =
            case Shared.json_buffer_try_decode(acc) do
              {:ok, _} = ok -> ok
              {:partial, _} = p -> p
              {:error, _} = e -> e
            end

          assert ok_or_partial in [:ok, :partial]
          Shared.json_buffer_push(acc, c)
        end)

      assert {:ok, %{"cmd" => "ls -la", "force" => true}} =
               Shared.json_buffer_try_decode(buf)
    end

    test "empty buffer reports :partial" do
      assert {:partial, ""} = Shared.json_buffer_try_decode(Shared.json_buffer_new())
    end

    test "unbalanced closer (more } than {) is :error, not :partial" do
      buf = Shared.json_buffer_new() |> Shared.json_buffer_push(~s({}}))
      assert {:error, _} = Shared.json_buffer_try_decode(buf)
    end

    test "string with unclosed quote is :partial" do
      buf = Shared.json_buffer_new() |> Shared.json_buffer_push(~s({"a":"unter))
      assert {:partial, _} = Shared.json_buffer_try_decode(buf)
    end

    test "escaped quote inside string doesn't end the string" do
      raw = ~s({"a":"he said \\"hi\\""})
      buf = Shared.json_buffer_new() |> Shared.json_buffer_push(raw)
      assert {:ok, %{"a" => "he said \"hi\""}} = Shared.json_buffer_try_decode(buf)
    end

    test "garbage bytes don't raise; reported as :error or :partial" do
      buf = Shared.json_buffer_new() |> Shared.json_buffer_push(<<0, 1, 2, 0xFF, 0xFE>>)
      result = Shared.json_buffer_try_decode(buf)
      assert match?({:error, _}, result) or match?({:partial, _}, result)
    end

    test "raw + reset round-trip" do
      buf = Shared.json_buffer_new() |> Shared.json_buffer_push("hello")
      assert Shared.json_buffer_raw(buf) == "hello"
      assert Shared.json_buffer_raw(Shared.json_buffer_reset(buf)) == ""
    end

    test "non-binary push is a no-op" do
      buf = Shared.json_buffer_new() |> Shared.json_buffer_push("ok")
      assert ^buf = Shared.json_buffer_push(buf, :not_a_binary)
    end
  end
end
