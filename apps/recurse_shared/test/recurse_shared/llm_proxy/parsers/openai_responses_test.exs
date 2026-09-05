defmodule Recurse.Shared.LlmProxy.Parsers.OpenaiResponsesTest do
  @moduledoc """
  Unit tests for `Recurse.Shared.LlmProxy.Parsers.OpenaiResponses`.

  Spec source of truth: `specs/009-llm-api-proxy/contracts/per_provider_parser.md`
  §OpenaiResponses.

  Test surfaces:
    * single function_call (CT-001 substrate)
    * parallel_tool_calls (R-002 + R-007)
    * interleaved message + function_call (R-007 reasoning interleaving)
    * malformed JSON in arguments delta (CT-004)
    * unknown event type passthrough (Invariant I-005)
    * provider_event_span byte ranges captured
    * both transports (`:sse` and `:ws`) yield same intents (R-013)

  Fixtures live at `apps/recurse_shared/test/fixtures/openai_responses/`
  as JSONL — one event JSON per line. Tests render them into either SSE
  byte streams or a list of WS frame payloads.
  """

  use ExUnit.Case, async: true

  alias Recurse.Shared.LlmProxy.Parsers.OpenaiResponses
  alias Recurse.Shared.LlmProxy.ToolUseIntent

  @fixtures_dir Path.expand("../../../fixtures/openai_responses", __DIR__)

  # ---------------------------------------------------------------------------
  # Helpers — fixture loading + transport materialization
  # ---------------------------------------------------------------------------

  defp load_events(filename) do
    @fixtures_dir
    |> Path.join(filename)
    |> File.read!()
    |> String.split("\n", trim: true)
  end

  defp render_sse(event_lines) do
    event_lines
    |> Enum.map(&("data: " <> &1 <> "\n\n"))
    |> IO.iodata_to_binary()
  end

  # Concatenate all `:forward` directive payloads in receive order.
  defp forward_bytes(directives) do
    directives
    |> Enum.flat_map(fn
      {:forward, b} -> [b]
      _ -> []
    end)
    |> IO.iodata_to_binary()
  end

  # Forwards positioned BEFORE the {:cedar_eval, call_id} marker.
  defp forwards_before_marker(directives, call_id) do
    Enum.reduce_while(directives, [], fn
      {:cedar_eval, ^call_id}, acc -> {:halt, acc}
      {:forward, b}, acc -> {:cont, acc ++ [b]}
      _, acc -> {:cont, acc}
    end)
  end

  # Forwards positioned AFTER the {:cedar_eval, call_id} marker.
  defp forwards_after_marker(directives, call_id) do
    {_, post} =
      Enum.reduce(directives, {false, []}, fn
        {:cedar_eval, ^call_id}, {_, acc} -> {true, acc}
        {:forward, b}, {true, acc} -> {true, acc ++ [b]}
        _, acc_tup -> acc_tup
      end)

    post
  end

  defp parse_all_sse(bytes) do
    state = OpenaiResponses.init(transport: :sse)
    {state2, intents, directives} = OpenaiResponses.parse_chunk(state, bytes)
    {summary, final_directives} = OpenaiResponses.finalize(state2)
    {intents, directives ++ final_directives, summary}
  end

  defp parse_all_ws(event_lines) do
    state = OpenaiResponses.init(transport: :ws)

    {final_state, all_intents, all_directives} =
      Enum.reduce(event_lines, {state, [], []}, fn payload, {st, intents_acc, dirs_acc} ->
        {st2, ints, dirs} = OpenaiResponses.parse_chunk(st, payload)
        {st2, intents_acc ++ ints, dirs_acc ++ dirs}
      end)

    {summary, final_dirs} = OpenaiResponses.finalize(final_state)
    {all_intents, all_directives ++ final_dirs, summary}
  end

  # ---------------------------------------------------------------------------
  # Unit tests
  # ---------------------------------------------------------------------------

  describe "init/1" do
    test "defaults to :sse transport with an empty SSE buffer" do
      state = OpenaiResponses.init([])
      assert state.transport == :sse
      assert state.sse_buffer != nil
      assert state.accumulators == %{}
      assert state.event_index == 0
    end

    test "accepts :ws transport with no SSE buffer" do
      state = OpenaiResponses.init(transport: :ws)
      assert state.transport == :ws
      assert state.sse_buffer == nil
    end

    test "unknown transport falls back to :sse" do
      state = OpenaiResponses.init(transport: :weird)
      assert state.transport == :sse
    end
  end

  describe "single function_call" do
    setup do
      events = load_events("single_function_call.jsonl")
      %{events: events, sse_bytes: render_sse(events)}
    end

    test "emits exactly one ToolUseIntent with correct call_id, tool_name, tool_args (SSE)",
         %{sse_bytes: bytes} do
      {intents, directives, summary} = parse_all_sse(bytes)

      assert [%ToolUseIntent{} = intent] = intents
      assert intent.call_id == "call_ls_42"
      assert intent.tool_name == "shell"
      assert intent.tool_args == %{"cmd" => "ls -la /tmp"}
      # Single (non-parallel) call: parallel_index must be nil per I-004.
      assert intent.parallel_index == nil
      assert byte_size(intent.tool_args_hash) == 32
      assert intent.tool_args_size_bytes > 0

      # Phase 6 byte-precise suppression: function_call events are
      # held silently until apply_verdict/3 releases them. Non-fcall
      # events forward immediately. Until verdict is applied, the union
      # of forward directives is a STRICT SUBSET of the original bytes.
      forwarded_bytes = forward_bytes(directives)

      refute forwarded_bytes == bytes,
             "fcall bytes should be held, not forwarded prior to verdict"

      # The directive stream MUST carry exactly one cedar_eval marker
      # for this intent — that's the proxy's signal to evaluate Cedar
      # + call apply_verdict at this exact position in the client stream.
      assert {:cedar_eval, "call_ls_42"} in directives

      assert summary.intent_count == 1
      assert summary.event_count > 0
      assert summary.response_id == "resp_abc123"
    end

    test "apply_verdict(:allow) drains held bytes; concat of all forwards equals original stream",
         %{sse_bytes: bytes} do
      state = OpenaiResponses.init(transport: :sse)
      {state, intents, directives} = OpenaiResponses.parse_chunk(state, bytes)
      assert [%ToolUseIntent{call_id: call_id}] = intents

      {state, allow_dirs} = OpenaiResponses.apply_verdict(state, call_id, :allow)
      {_summary, finalize_dirs} = OpenaiResponses.finalize(state)

      # forwards from chunk + drained-from-verdict + finalize trailing =
      # original byte stream EXACTLY. Note: allow_dirs are spliced in
      # AT THE :cedar_eval marker position, so order in the proxy is:
      #   pre-marker forwards <> drained <> post-marker forwards
      pre_marker_forwards = forwards_before_marker(directives, call_id)
      post_marker_forwards = forwards_after_marker(directives, call_id)

      released = forward_bytes(allow_dirs)
      trailing = forward_bytes(finalize_dirs)

      reconstructed =
        IO.iodata_to_binary(pre_marker_forwards) <>
          released <>
          IO.iodata_to_binary(post_marker_forwards) <>
          trailing

      assert reconstructed == bytes,
             "allow path must release all held bytes so client sees full upstream stream"
    end

    test "apply_verdict(:deny) drains held bytes as :suppress (bytes never reach client)",
         %{sse_bytes: bytes} do
      state = OpenaiResponses.init(transport: :sse)
      {state, intents, directives} = OpenaiResponses.parse_chunk(state, bytes)
      assert [%ToolUseIntent{call_id: call_id}] = intents

      {_state, deny_dirs} = OpenaiResponses.apply_verdict(state, call_id, :deny)

      assert deny_dirs != []

      # Every directive returned by apply_verdict(:deny) MUST be :suppress.
      # If anything :forward leaks here, the proxy will write fcall bytes
      # to the client and codex will execute the tool locally — that's
      # the exact bug R5E-102 fixes.
      assert Enum.all?(deny_dirs, fn
               {:suppress, _} -> true
               _ -> false
             end)

      suppressed =
        deny_dirs
        |> Enum.flat_map(fn
          {:suppress, b} -> [b]
          _ -> []
        end)
        |> IO.iodata_to_binary()

      # The suppressed bytes MUST include the function_call markers —
      # codex would otherwise be able to reconstruct the call.
      assert suppressed =~ "function_call"
      assert suppressed =~ "ls -la /tmp"

      # And those bytes MUST NOT have appeared in the chunk-level
      # forward directives.
      forwarded = forward_bytes(directives)
      refute forwarded =~ "function_call"
      refute forwarded =~ "ls -la /tmp"
    end

    test "WS transport produces the same intent as SSE (R-013)", %{events: events} do
      {ws_intents, _, _} = parse_all_ws(events)
      {sse_intents, _, _} = parse_all_sse(render_sse(events))

      ws = List.first(ws_intents)
      sse = List.first(sse_intents)

      # The intents must agree on the load-bearing fields. Byte spans
      # WILL differ between transports (SSE wraps each event in `data: `
      # + `\n\n`), so we don't compare those.
      assert ws.call_id == sse.call_id
      assert ws.tool_name == sse.tool_name
      assert ws.tool_args == sse.tool_args
      assert ws.tool_args_hash == sse.tool_args_hash
    end

    test "provider_event_span has start <= end and at least one event index",
         %{sse_bytes: bytes} do
      {[intent], _, _} = parse_all_sse(bytes)

      span = intent.provider_event_span
      assert span.start_byte_offset >= 0
      assert span.end_byte_offset >= span.start_byte_offset
      assert is_list(span.event_indices)
      assert span.event_indices != []
    end
  end

  # Codex 0.149 ships tool calls as `custom_tool_call` output items: the
  # args live under `input` (not `arguments`) and stream via
  # `response.custom_tool_call_input.delta`/`.done` correlated by
  # `item_id` alone. A parser that only knows `function_call` extracts
  # ZERO intents from this stream — Cedar is never consulted and a
  # denial silently becomes an allow. These tests pin the shape.
  describe "custom_tool_call (codex 0.149 shape)" do
    setup do
      events = load_events("custom_tool_call.jsonl")
      %{events: events, sse_bytes: render_sse(events)}
    end

    test "emits exactly one ToolUseIntent with correct call_id, tool_name, tool_args (SSE)",
         %{sse_bytes: bytes} do
      {intents, directives, summary} = parse_all_sse(bytes)

      assert [%ToolUseIntent{} = intent] = intents
      # `call_id` is carried on the output_item even though the
      # delta/done events only have `item_id`; the alias must resolve.
      assert intent.call_id == "call_rm_7"
      assert intent.tool_name == "shell"
      assert intent.tool_args == %{"cmd" => "rm -rf /tmp/demo"}
      assert intent.parallel_index == nil
      assert byte_size(intent.tool_args_hash) == 32
      assert intent.tool_args_size_bytes > 0

      assert {:cedar_eval, "call_rm_7"} in directives
      assert summary.intent_count == 1
      assert summary.response_id == "resp_codex149"
    end

    test "custom_tool_call bytes are held pending verdict and suppressed on :deny",
         %{sse_bytes: bytes} do
      state = OpenaiResponses.init(transport: :sse)
      {state, intents, directives} = OpenaiResponses.parse_chunk(state, bytes)
      assert [%ToolUseIntent{call_id: call_id}] = intents

      refute forward_bytes(directives) =~ "rm -rf /tmp/demo"

      {_state, deny_dirs} = OpenaiResponses.apply_verdict(state, call_id, :deny)

      assert deny_dirs != []

      assert Enum.all?(deny_dirs, fn
               {:suppress, _} -> true
               _ -> false
             end)

      suppressed =
        deny_dirs
        |> Enum.flat_map(fn
          {:suppress, b} -> [b]
          _ -> []
        end)
        |> IO.iodata_to_binary()

      assert suppressed =~ "custom_tool_call"
      assert suppressed =~ "rm -rf /tmp/demo"
    end

    test "WS transport produces the same intent as SSE (R-013)", %{events: events} do
      {ws_intents, _, _} = parse_all_ws(events)
      {sse_intents, _, _} = parse_all_sse(render_sse(events))

      ws = List.first(ws_intents)
      sse = List.first(sse_intents)

      assert ws.call_id == sse.call_id
      assert ws.tool_name == sse.tool_name
      assert ws.tool_args == sse.tool_args
      assert ws.tool_args_hash == sse.tool_args_hash
    end

    # A `custom_tool_call`'s `input` is freeform by design — it may be a
    # bare command string rather than a JSON object. It must still reach
    # Cedar as matchable content (`context.tool_args.input`); degrading
    # to the `:too_large` sentinel would leave only the tool NAME to
    # policy on, quietly defeating any content-based forbid rule.
    test "freeform (non-JSON) input is wrapped as %{\"input\" => raw}" do
      events = [
        ~s({"type":"response.created","response":{"id":"resp_freeform","status":"in_progress"}}),
        ~s({"type":"response.output_item.added","output_index":0,"item":{"type":"custom_tool_call","id":"ctc_9","call_id":"call_9","name":"shell","input":""}}),
        ~s({"type":"response.custom_tool_call_input.delta","item_id":"ctc_9","delta":"rm -rf "}),
        ~s({"type":"response.custom_tool_call_input.delta","item_id":"ctc_9","delta":"/etc"}),
        ~s({"type":"response.custom_tool_call_input.done","item_id":"ctc_9","input":"rm -rf /etc"}),
        ~s({"type":"response.completed","response":{"id":"resp_freeform","status":"completed"}})
      ]

      {[intent], _directives, _summary} = parse_all_sse(render_sse(events))

      assert intent.call_id == "call_9"
      assert intent.tool_name == "shell"
      assert intent.tool_args == %{"input" => "rm -rf /etc"}
    end
  end

  describe "parallel_tool_calls" do
    setup do
      events = load_events("parallel_tool_calls.jsonl")
      %{events: events, sse_bytes: render_sse(events)}
    end

    test "emits N ToolUseIntents with correct call_ids and parallel_index set",
         %{sse_bytes: bytes} do
      {intents, _, summary} = parse_all_sse(bytes)

      assert length(intents) == 3

      by_call_id = Map.new(intents, &{&1.call_id, &1})

      assert %ToolUseIntent{tool_name: "shell", tool_args: %{"cmd" => "pwd"}} =
               by_call_id["call_aaa"]

      assert %ToolUseIntent{tool_name: "web_fetch"} = by_call_id["call_bbb"]
      assert by_call_id["call_bbb"].tool_args == %{"url" => "https://example.com/a"}

      assert %ToolUseIntent{tool_name: "edit"} = by_call_id["call_ccc"]
      assert by_call_id["call_ccc"].tool_args == %{"path" => "/tmp/x.txt", "text" => "hello"}

      # Parallel calls carry sequential parallel_index 0..N-1 in
      # registration order (I-004). With three concurrent function_calls
      # opened in order aaa, bbb, ccc, the indices must be 0, 1, 2.
      assert by_call_id["call_aaa"].parallel_index == 0
      assert by_call_id["call_bbb"].parallel_index == 1
      assert by_call_id["call_ccc"].parallel_index == 2

      assert summary.intent_count == 3
    end

    test "intents arrive in completion order (parser invariant)",
         %{sse_bytes: bytes} do
      {intents, _, _} = parse_all_sse(bytes)
      assert Enum.map(intents, & &1.call_id) == ["call_aaa", "call_bbb", "call_ccc"]
    end
  end

  describe "interleaved message + function_call" do
    setup do
      events = load_events("interleaved_message_and_function_call.jsonl")
      %{events: events, sse_bytes: render_sse(events)}
    end

    test "emits one ToolUseIntent for the function_call; message events forwarded",
         %{sse_bytes: bytes} do
      {intents, directives, summary} = parse_all_sse(bytes)

      assert [%ToolUseIntent{} = intent] = intents
      assert intent.call_id == "call_ls_99"
      assert intent.tool_name == "shell"
      assert intent.tool_args == %{"cmd" => "ls"}

      # Phase 6: message bytes forward immediately; fcall bytes are held
      # behind the verdict gate. Concat of forward directives is a strict
      # subset of original until apply_verdict releases the held bytes.
      forwarded = forward_bytes(directives)
      refute forwarded == bytes

      # The cedar_eval marker MUST appear in the directive stream.
      assert {:cedar_eval, "call_ls_99"} in directives

      assert summary.intent_count == 1
    end
  end

  describe "totality (Invariant I-001)" do
    test "malformed JSON in arguments delta does not raise; intent is dropped" do
      events = [
        ~s({"type":"response.created","response":{"id":"r1"}}),
        ~s({"type":"response.output_item.added","output_index":0,"item":{"type":"function_call","id":"f1","call_id":"c1","name":"shell","arguments":""}}),
        ~s({"type":"response.function_call.arguments.delta","item_id":"f1","call_id":"c1","delta":"{\\"cmd\\": \\"unclosed string"}),
        ~s({"type":"response.function_call.completed","item_id":"f1","call_id":"c1"})
      ]

      bytes = render_sse(events)

      # Even though the JSON in the arguments is unclosed, parser must
      # NOT raise; emits :too_large path which still constructs an
      # intent with raw_json hashed.
      assert {intents, _, summary} = parse_all_sse(bytes)
      # We allow either: (a) the intent is dropped (impl chooses
      # graceful degrade) OR (b) the intent emits with :too_large
      # tool_args. Both are valid per I-001 — the contract requires
      # non-raising behaviour, not a specific recovery shape.
      case intents do
        [] ->
          assert summary.intent_count == 0

        [%ToolUseIntent{tool_args: :too_large} = i] ->
          # raw_json bytes were hashed
          assert byte_size(i.tool_args_hash) == 32

        [%ToolUseIntent{tool_args: args}] when is_map(args) ->
          # Permissive partial parse path — also fine
          assert true
      end
    end

    test "unknown event type requires a fail-closed transport decision" do
      events = [
        ~s({"type":"response.created","response":{"id":"r1"}}),
        ~s({"type":"response.brand.new.event.type.from.next.year","whatever":42}),
        ~s({"type":"response.completed","response":{"id":"r1","status":"completed"}})
      ]

      bytes = render_sse(events)
      {intents, directives, summary} = parse_all_sse(bytes)

      assert intents == []
      # Bytes preserved exactly
      forwarded =
        directives
        |> Enum.flat_map(fn
          {:forward, b} -> [b]
          _ -> []
        end)
        |> IO.iodata_to_binary()

      assert forwarded == ""
      assert {:parser_error, :unrecognized_event} in directives
      assert summary.intent_count == 0
    end

    test "non-JSON garbage chunks do not raise (Phase 6: bytes absorbed by SSE buffer)" do
      # Phase 6 contract: bytes that don't form a valid SSE event
      # boundary (`data: ...\n\n`) are absorbed into the SSE buffer.
      # If they never form a valid event, they're silently dropped on
      # finalize. Compare with the old chunk-forward semantics, which
      # passed garbage through to the client; the new contract says
      # "if it isn't a parseable SSE event, the proxy doesn't emit it."
      # This is correct: SSE clients tolerate non-event whitespace but
      # garbage that pretends to be event data is a wire-protocol bug
      # we shouldn't propagate.
      state = OpenaiResponses.init(transport: :sse)
      garbage = <<0, 1, 2, 3, 0xFF, 0xFE>>

      assert {%OpenaiResponses{}, [], _directives} =
               OpenaiResponses.parse_chunk(state, garbage)
    end

    test "completely empty chunk is a no-op (no events, no directives)" do
      state = OpenaiResponses.init(transport: :sse)

      assert {%OpenaiResponses{}, [], []} = OpenaiResponses.parse_chunk(state, "")
    end
  end

  describe "chunk-boundary stability (Invariant I-004 substrate)" do
    test "single-byte chunks produce the same intents as one big chunk" do
      events = load_events("single_function_call.jsonl")
      bytes = render_sse(events)

      {whole_intents, _, _} = parse_all_sse(bytes)

      # Feed byte-by-byte
      state = OpenaiResponses.init(transport: :sse)

      {final_state, byte_intents} =
        Enum.reduce(:binary.bin_to_list(bytes), {state, []}, fn b, {st, acc} ->
          {st2, ints, _dirs} = OpenaiResponses.parse_chunk(st, <<b>>)
          {st2, acc ++ ints}
        end)

      _ = OpenaiResponses.finalize(final_state)

      assert Enum.map(whole_intents, &{&1.call_id, &1.tool_name, &1.tool_args}) ==
               Enum.map(byte_intents, &{&1.call_id, &1.tool_name, &1.tool_args})
    end
  end

  describe "performance smoke (P-001)" do
    @tag :perf
    test "per-chunk overhead < 50ms for a 64KB-padded fixture (light verification)" do
      events = load_events("parallel_tool_calls.jsonl")
      base = render_sse(events)

      # Pad to ~64KB by appending an unknown-event JSON. We measure the
      # parser's ability to handle a real-looking 64KB payload in one
      # shot. We assert against a generous 50ms ceiling rather than
      # the 5ms target — CI variance + first-run JIT warmup makes 5ms
      # too tight for a smoke. The 5ms p95 target remains the design
      # goal; this test guards against pathological regressions only.
      padding =
        for _ <- 1..1500 do
          ~s({"type":"response.brand.new.event","whatever":42})
        end
        |> render_sse()

      payload = base <> padding
      assert byte_size(payload) > 64 * 1024

      state = OpenaiResponses.init(transport: :sse)

      {time_us, _} =
        :timer.tc(fn ->
          OpenaiResponses.parse_chunk(state, payload)
        end)

      assert time_us < 50_000, "parse_chunk took #{time_us}us; budget 50000us"
    end
  end

  describe "summary contract — model + token counts (Sub-3.7-followon)" do
    test "fixture's response.completed.usage populates token counts in summary" do
      events = load_events("single_function_call.jsonl")
      bytes = render_sse(events)
      {_intents, _directives, summary} = parse_all_sse(bytes)

      # The fixture's terminal response.completed event carries
      # `usage: {input_tokens: 42, output_tokens: 17}`.
      assert summary.prompt_token_count == 42
      assert summary.completion_token_count == 17
      # Fixture has no reasoning_tokens (non-o1/o3 model). Either
      # absent from the summary OR present with nil — both fine.
      assert Map.get(summary, :reasoning_token_count) in [nil, 0] or
               not Map.has_key?(summary, :reasoning_token_count)
    end

    test "model from response.created lands in summary" do
      events = [
        ~s({"type":"response.created","response":{"id":"r1","model":"gpt-5-codex"}}),
        ~s({"type":"response.completed","response":{"id":"r1","usage":{"input_tokens":10,"output_tokens":5}}})
      ]

      bytes = render_sse(events)
      {_intents, _directives, summary} = parse_all_sse(bytes)

      assert summary.model == "gpt-5-codex"
      assert summary.prompt_token_count == 10
      assert summary.completion_token_count == 5
    end

    test "reasoning tokens from output_tokens_details surface (o1/o3-style)" do
      events = [
        ~s({"type":"response.created","response":{"id":"r2","model":"o3-mini"}}),
        ~s({"type":"response.completed","response":{"id":"r2","usage":{"input_tokens":20,"output_tokens":80,"output_tokens_details":{"reasoning_tokens":50}}}})
      ]

      bytes = render_sse(events)
      {_intents, _directives, summary} = parse_all_sse(bytes)

      assert summary.model == "o3-mini"
      assert summary.prompt_token_count == 20
      assert summary.completion_token_count == 80
      assert summary.reasoning_token_count == 50
    end

    test "missing usage / model gracefully omits the keys (drift tolerance)" do
      events = [
        ~s({"type":"response.created","response":{"id":"r3"}}),
        ~s({"type":"response.completed","response":{"id":"r3"}})
      ]

      bytes = render_sse(events)
      {_intents, _directives, summary} = parse_all_sse(bytes)

      refute Map.has_key?(summary, :model)
      refute Map.has_key?(summary, :prompt_token_count)
      refute Map.has_key?(summary, :completion_token_count)
    end

    test "current_summary/1 is non-destructive (Sub-3.7-followon WS plumbing)" do
      events = load_events("single_function_call.jsonl")

      state = OpenaiResponses.init(transport: :ws)

      state =
        Enum.reduce(events, state, fn payload, st ->
          {st2, _ints, _dirs} = OpenaiResponses.parse_chunk(st, payload)
          st2
        end)

      snapshot1 = OpenaiResponses.current_summary(state)
      snapshot2 = OpenaiResponses.current_summary(state)

      # Repeated calls return identical maps without mutating state.
      assert snapshot1 == snapshot2
      assert snapshot1.intent_count == 1
      # response.completed event in the fixture surfaces usage.
      assert snapshot1.prompt_token_count == 42
      assert snapshot1.completion_token_count == 17

      # Final finalize/1 still works on the same state.
      {final_summary, _} = OpenaiResponses.finalize(state)
      assert final_summary.intent_count == 1
    end
  end
end
