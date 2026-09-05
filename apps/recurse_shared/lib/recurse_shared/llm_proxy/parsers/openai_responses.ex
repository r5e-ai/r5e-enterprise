defmodule Recurse.Shared.LlmProxy.Parsers.OpenaiResponses do
  @moduledoc """
  Streaming parser for the OpenAI **Responses API** event taxonomy
  (the protocol Codex CLI uses against `chatgpt.com` and `api.openai.com`).

  Spec source of truth: `specs/009-llm-api-proxy/contracts/per_provider_parser.md`
  §OpenaiResponses + `research.md` R-002 (event taxonomy) + R-013 (WS-frame
  payload format identical to SSE-event payload).

  Codex CLI talks WSS first to `wss://chatgpt.com/backend-api/codex/responses`
  and falls back to HTTPS+SSE on the same path. Both transports carry the
  **same** event payload shape — Responses-API events as JSON. This parser
  consumes either transport via the `:transport` init option:

    * `:sse` — the proxy feeds raw upstream byte chunks via
      `parse_chunk/2`; an internal `Shared.sse_buffer` reassembles
      `data: {...}\\n\\n` SSE events across chunk boundaries.
    * `:ws`  — the proxy feeds one already-extracted text-frame payload
      per `parse_chunk/2` call (each frame is one event JSON).

  ## Event taxonomy (per R-002 / contract)

    * `response.created` → state init
    * `response.output_item.added` (item.type == `function_call`)
        → start a new accumulator keyed by `item.call_id`
    * `response.output_item.added` (item.type ∈ `message`, `reasoning`)
        → forward unchanged
    * `response.function_call.arguments.delta` → append `delta` to the
      matching call_id's accumulator
    * `response.function_call.completed` → emit `ToolUseIntent`; close the
      accumulator
    * `response.output_text.delta` / `response.output_text.completed`
        → forward unchanged
    * `response.completed` → emit summary on `finalize/1`
    * **Unknown event types** → forward unchanged (Invariant I-005)

  Reasoning items can interleave with function_calls (R-007 edge case);
  the per-call_id accumulator design is naturally robust to that.

  Parallel tool calls (`parallel_tool_calls: true`) appear as multiple
  concurrent `function_call` items with distinct `call_id` values. Each
  emits its own `ToolUseIntent` (Invariant I-003).

  ## Forward directives — Phase 6 byte-precise suppression

  Per-event directives, NOT per-chunk:

    * Non-function_call events → `{:forward, raw_event_bytes}` immediately.
    * Function_call events while verdict is `:pending` → silently buffered
      in `call_states[call_id].byte_buffer`. NO directive emitted; the
      proxy MUST NOT see these bytes until the verdict applies.
    * Function_call events after `apply_verdict(:allow)` → `{:forward, raw}`
      directly (no buffering; the call is already allowed).
    * Function_call events after `apply_verdict(:deny)` → `{:suppress, raw}`
      directly (no buffering; the call is already denied; bytes NEVER
      reach the client).

  When `function_call_arguments.done` (or older `function_call.completed`)
  fires, a `ToolUseIntent` is emitted to the proxy. The proxy evaluates
  Cedar, then calls `apply_verdict(state, intent.call_id, :allow | :deny)`
  which DRAINS the `byte_buffer` for that call_id and returns either
  `[{:forward, b}, ...]` or `[{:suppress, b}, ...]` — one directive per
  buffered event. Subsequent same-call_id events bypass buffering and
  go through the verdict-aware fast path above.

  ### Why per-event (not per-chunk) directives?

  Phase 3 emitted `{:forward, chunk}` regardless: every byte the upstream
  sent went out the door. Synthetic denial events were APPENDED after the
  original function_call frames, so codex saw both the real tool_use
  request AND the denial — and codex executed the tool locally before
  noticing the denial. That's not enforcement.

  Per-event directives let us **drop the original function_call frames
  entirely** when Cedar denies. Codex never sees the tool_use; it sees
  only the synthetic denial message. Local execution is prevented at
  the byte level (Constitution Principle V — Containment-Aware Provenance).

  ## Totality (Invariant I-001)

  `parse_chunk/2` is total: any byte input — including malformed JSON,
  truncated SSE blocks, control characters, unknown event types —
  returns `{state, [...], [...]}` without raising. JSON decode failures
  degrade gracefully: the offending event's bytes are forwarded
  unchanged; the buffer for an in-progress accumulator is left intact
  so subsequent deltas can still complete.

  ## `provider_event_span` capture

  Each emitted `ToolUseIntent` carries a `provider_event_span` with:

    * `start_byte_offset` — byte offset of the `output_item.added` for
      this `call_id` in the accumulated upstream stream
    * `end_byte_offset`   — byte offset just past the
      `function_call.completed` event for this `call_id`
    * `event_indices`     — the ordinal positions (0-based, in the order
      received) of every event that mentioned this `call_id`

  The injector reads this span to know exactly which raw events to
  suppress when translating a deny decision into a synthetic message
  rewrite.
  """

  @behaviour Recurse.Shared.LlmProxy.Parsers.Parser

  alias Recurse.Shared.LlmProxy.Parsers.Parser
  alias Recurse.Shared.LlmProxy.Parsers.Shared
  alias Recurse.Shared.LlmProxy.ToolUseIntent

  # Output-item types that carry a tool invocation. OpenAI has shipped
  # three shapes for the same thing across Codex releases, and the
  # tool-call shape is the ONE thing this parser exists to find — miss
  # it and no intent is extracted, Cedar is never consulted, and a
  # denial silently becomes an allow.
  #
  #   "function_call"     — pre-0.125 and 0.125+ (args in `arguments`,
  #                         streamed via response.function_call*)
  #   "custom_tool_call"  — codex 0.149 (args in `input`, streamed via
  #                         response.custom_tool_call_input.*). Confirmed
  #                         empirically 2026-08-25 against codex-cli
  #                         0.149.1 through the local proxy; the item
  #                         carries call_id/id/name/input/status.
  #
  # `local_shell_call` is NOT here: we have never observed it on the
  # wire, and guessing at its arg shape would be worse than the
  # `unhandled output_item type=` warning that surfaces it.
  @tool_call_item_types ["function_call", "custom_tool_call"]

  # Spec 012 S4 — recognizer identity recorded on every attestation
  # (plan §11): the SHA-256 (first 16 hex chars) of this source file
  # concatenated with `parsers/shared.ex` (the SSE / JSON framing this
  # parser's recognition depends on), computed at compile time, and the
  # wire-format name. `@external_resource` makes a shared.ex edit
  # recompile this module so the hash never goes stale.
  @shared_source Path.join(Path.dirname(__ENV__.file), "shared.ex")
  @external_resource @shared_source
  @source_version [__ENV__.file, @shared_source]
                  |> Enum.map(&File.read!/1)
                  |> IO.iodata_to_binary()
                  |> then(&:crypto.hash(:sha256, &1))
                  |> Base.encode16(case: :lower)
                  |> binary_part(0, 16)

  @format_name "openai_responses"
  @sample_max_bytes 200

  @typedoc """
  Per-`call_id` accumulator state. We hold the partial JSON arguments
  buffer + the event indices + byte span until `function_call.completed`
  fires (Invariants I-002, I-003).
  """
  @type accumulator :: %{
          call_id: String.t(),
          tool_name: String.t(),
          registration_index: non_neg_integer(),
          json_buffer: term(),
          start_byte_offset: non_neg_integer(),
          event_indices: [non_neg_integer()]
        }

  @typedoc """
  Per-call_id byte-routing state machine for Phase 6 suppression.

    * `byte_buffer` — list of raw event-bytes (one per held event), in
      receive order. Drained by `apply_verdict/3`.
    * `verdict` — `:pending` while Cedar hasn't decided; `:allowed` /
      `:denied` after. Subsequent same-call_id events bypass the buffer
      and emit forward/suppress directives directly.
  """
  @type call_state :: %{
          byte_buffer: [binary()],
          verdict: :pending | :allowed | :denied
        }

  @type t :: %__MODULE__{
          transport: :sse | :ws,
          sse_buffer: term(),
          accumulators: %{optional(String.t()) => accumulator()},
          call_states: %{optional(String.t()) => call_state()},
          item_to_call: %{optional(String.t()) => String.t()},
          event_index: non_neg_integer(),
          byte_offset: non_neg_integer(),
          intent_count: non_neg_integer(),
          function_calls_opened: non_neg_integer(),
          events_unhandled: non_neg_integer(),
          unhandled_types: MapSet.t(),
          unhandled_samples: map(),
          summary: map()
        }

  defstruct transport: :sse,
            failed?: false,
            sse_buffer: nil,
            accumulators: %{},
            call_states: %{},
            emitted_intents: %{},
            terminal_events: [],
            terminal_trailers: [],
            item_to_call: %{},
            event_index: 0,
            byte_offset: 0,
            intent_count: 0,
            function_calls_opened: 0,
            events_unhandled: 0,
            unhandled_types: MapSet.new(),
            unhandled_samples: %{},
            summary: %{}

  @doc """
  SHA-256 (first 16 hex chars) of this module's source concatenated with
  `parsers/shared.ex`, computed at compile time.
  """
  @spec version() :: String.t()
  def version, do: @source_version

  @doc "The wire-format name this parser is exhaustive for (`openai_responses`)."
  @spec format(keyword()) :: String.t()
  def format(_opts \\ []), do: @format_name

  # ---------------------------------------------------------------------------
  # Behaviour callbacks
  # ---------------------------------------------------------------------------

  @impl Parser
  @spec init(keyword()) :: t()
  def init(opts \\ []) do
    transport =
      case Keyword.get(opts, :transport, :sse) do
        :ws -> :ws
        _ -> :sse
      end

    %__MODULE__{
      transport: transport,
      sse_buffer: if(transport == :sse, do: Shared.sse_buffer_new(), else: nil),
      accumulators: %{},
      call_states: %{},
      item_to_call: %{},
      event_index: 0,
      byte_offset: 0,
      intent_count: 0,
      function_calls_opened: 0,
      summary: %{}
    }
  end

  @impl Parser
  @spec parse_chunk(t(), binary()) ::
          {t(), [ToolUseIntent.t()], [Parser.forward_directive()]}
  def parse_chunk(%__MODULE__{failed?: true} = state, _chunk),
    do: {state, [], [{:parser_error, :failed}]}

  def parse_chunk(%__MODULE__{} = state, chunk) when is_binary(chunk) do
    {next, intents, directives} = consume_chunk(state, chunk)

    cond do
      next.events_unhandled > state.events_unhandled ->
        {%{next | failed?: true}, intents, [{:parser_error, :unrecognized_event}]}

      Enum.any?(directives, &match?({:parser_error, _}, &1)) ->
        {%{next | failed?: true}, intents, directives}

      true ->
        {next, intents, directives}
    end
  rescue
    # I-001 totality safety net. consume_chunk/2 is internally defensive
    # but we belt-and-suspenders here so any unforeseen pattern path
    # never breaks the upstream byte stream.
    _ -> {state, [], [{:parser_error, :raised}]}
  catch
    _, _ -> {state, [], [{:parser_error, :failed}]}
  end

  # I-001: non-binary input returns forward-unchanged with empty chunk.
  def parse_chunk(%__MODULE__{} = state, _other) do
    {state, [], [{:forward, ""}]}
  end

  @impl Parser
  @spec finalize(t()) :: {Parser.summary(), [Parser.forward_directive()]}
  def finalize(%__MODULE__{failed?: true} = state),
    do: {build_summary(state), [{:parser_error, :failed}]}

  def finalize(%__MODULE__{transport: :sse, sse_buffer: buf} = state) when buf != nil do
    {_buf2, trailing} = Shared.sse_buffer_flush(buf)
    {state2, intents, trailing_directives} = handle_sse_events(state, trailing)

    unsafe? =
      intents != [] or state2.events_unhandled > state.events_unhandled or
        Enum.any?(state2.call_states, fn {_id, call} -> call.verdict == :pending end)

    {build_summary(state2),
     if(unsafe?,
       do: [{:parser_error, :incomplete_stream}],
       else: trailing_directives ++ terminal_directives(state2)
     )}
  end

  def finalize(%__MODULE__{} = state) do
    pending? = Enum.any?(state.call_states, fn {_id, call} -> call.verdict == :pending end)

    {build_summary(state),
     if(pending?, do: [{:parser_error, :incomplete_stream}], else: terminal_directives(state))}
  end

  @doc """
  Apply Cedar's verdict for `call_id`'s buffered tool-call bytes.

  This is THE byte-precise enforcement primitive (R5E-102):

    * `:allow` → drains the byte buffer + returns `[{:forward, ev_bytes}, ...]`
      one directive per held event, in receive order. The proxy dispatches
      each as it would any non-function_call forward — codex sees the
      original tool_use frames and proceeds normally.
    * `:deny` → drains the byte buffer + returns `[{:suppress, ev_bytes}, ...]`
      one directive per held event. The proxy MUST drop these bytes; codex
      never sees the tool_use frames. The proxy will then inject synthetic
      denial events (a complete assistant `message` turn) so the agent
      loop sees a coherent stream and continues iteration.

  Subsequent same-call_id events that arrive AFTER `apply_verdict/3` are
  routed through the verdict-aware fast path (no buffering): allowed
  → `{:forward, raw}`; denied → `{:suppress, raw}`. This handles the
  trailing `output_item.done` for a function_call whose
  `function_call_arguments.done` already triggered the verdict.

  If `call_id` is unknown (drift / typo / already-drained), returns
  `{state, []}` — total, no raise.
  """
  @spec apply_verdict(t(), String.t(), :allow | :deny) ::
          {t(), [Parser.forward_directive()]}
  def apply_verdict(%__MODULE__{} = state, call_id, decision)
      when is_binary(call_id) and decision in [:allow, :deny] do
    case Map.fetch(state.call_states, call_id) do
      {:ok, %{byte_buffer: buf}} ->
        new_verdict =
          case decision do
            :allow -> :allowed
            :deny -> :denied
          end

        directive_kind =
          case decision do
            :allow -> :forward
            :deny -> :suppress
          end

        directives =
          buf
          |> Enum.reverse()
          |> Enum.map(fn bytes -> {directive_kind, bytes} end)

        # Keep the call_state entry around with verdict applied + buffer
        # cleared so trailing same-call_id events route via the verdict-
        # aware fast path. We never garbage-collect call_states mid-stream
        # — the count is bounded by the number of function_calls in one
        # response, which is small.
        new_call_state = %{byte_buffer: [], verdict: new_verdict}

        new_state = %{
          state
          | call_states: Map.put(state.call_states, call_id, new_call_state)
        }

        {new_state, directives}

      :error ->
        # Unknown call_id (drift). Total, no raise.
        {state, []}
    end
  end

  def apply_verdict(%__MODULE__{} = state, _call_id, _decision), do: {state, []}

  @doc """
  Non-destructive snapshot of the current parser summary.

  Sub-3.7-followon (US1 plumbing) — the WS-bridge attestation emit
  fires from `terminate/2`, after the upstream has closed; but the
  proxy needs `model` + token counts as soon as the
  `response.created` / `response.completed` events flow through. WS
  transport doesn't buffer (each frame is one event) so we can read
  the summary mid-stream without flushing anything.

  Same shape as `finalize/1`'s first tuple element. Does NOT modify
  state. The SSE-mode caller would still call `finalize/1` to ensure
  trailing buffer drain; this accessor is for transports that consume
  events whole.
  """
  @spec current_summary(t()) :: Parser.summary()
  def current_summary(%__MODULE__{} = state), do: build_summary(state)

  defp build_summary(
         %__MODULE__{
           intent_count: intent_count,
           event_index: event_index,
           summary: summary
         } = state
       ) do
    Map.merge(summary, %{
      intent_count: intent_count,
      event_count: event_index,
      events_total: event_index,
      events_unhandled: state.events_unhandled,
      unhandled_types: state.unhandled_types |> MapSet.to_list() |> Enum.sort(),
      unhandled_samples: state.unhandled_samples,
      format: @format_name
    })
  end

  # Spec 012 S4 — drift accounting shared with the AnthropicMessages
  # parser: count the event, remember the discriminator, keep a
  # keys-only sample (never payload content) for the drift store.
  defp record_unhandled(state, discriminator, payload) do
    keys = if is_map(payload), do: payload |> Map.keys() |> Enum.sort(), else: []
    sample = "keys=" <> Enum.join(keys, ",")

    sample =
      if byte_size(sample) > @sample_max_bytes,
        do: binary_part(sample, 0, @sample_max_bytes),
        else: sample

    %{
      state
      | events_unhandled: state.events_unhandled + 1,
        unhandled_types: MapSet.put(state.unhandled_types, discriminator),
        unhandled_samples: Map.put_new(state.unhandled_samples, discriminator, sample)
    }
  end

  # ---------------------------------------------------------------------------
  # Internal — chunk consumption
  # ---------------------------------------------------------------------------

  defp consume_chunk(%__MODULE__{transport: :sse, sse_buffer: buf} = state, chunk) do
    {buf2, events} = Shared.sse_buffer_push(buf, chunk)
    state = %{state | sse_buffer: buf2}
    handle_sse_events(state, events)
  end

  defp consume_chunk(%__MODULE__{transport: :ws} = state, chunk) do
    # WS-mode: each parse_chunk call is one frame's payload (R-013).
    # An empty frame is a no-op.
    case chunk do
      "" ->
        {state, [], []}

      payload when is_binary(payload) ->
        handle_event_payload(state, payload, payload, byte_size(payload))
    end
  end

  # Walk the list of SSE events extracted by the buffer, threading state
  # and accumulating emitted intents + per-event directives. The raw
  # event bytes WITH terminator (`ev.raw <> "\n\n"`) are the unit the
  # proxy will eventually emit as a single Plug.Conn.chunk/2 — so a
  # direct concat of all `:forward` directive bytes equals what the
  # client would see.
  defp handle_sse_events(state, events) do
    Enum.reduce(events, {state, [], []}, fn ev, {st, intents_acc, directives_acc} ->
      raw_size = byte_size(ev.raw) + 2
      raw_bytes = ev.raw <> "\n\n"

      {st2, new_intents, new_directives} =
        handle_event_payload(st, ev.data, raw_bytes, raw_size)

      {st2, intents_acc ++ new_intents, directives_acc ++ new_directives}
    end)
  end

  # Decode one event payload (a JSON object as a string), classify its
  # routing (fcall vs non-fcall), dispatch state-mutation, and emit the
  # right directive for its raw bytes.
  #
  # When dispatch_event emits an intent, we ALSO emit a
  # `{:cedar_eval, call_id}` marker AT THIS POSITION in the directive
  # stream. The proxy uses the marker as a synchronous hand-off point:
  # it evaluates Cedar, calls apply_verdict/3, and dispatches the
  # returned directives inline, before moving past the marker. That's
  # how stream order is preserved (the held fcall bytes are inserted
  # back into the client stream at the exact point the upstream emitted
  # them — modulo the slight reorder of "all held bytes for this call
  # arrive together" instead of interleaved with co-temporal
  # non-fcall events).
  defp handle_event_payload(%__MODULE__{} = state, payload, raw_bytes, payload_byte_size) do
    case decode_event(payload) do
      {:ok, %{"type" => type} = event} ->
        state = bump_indices(state, payload_byte_size)
        {classification, state} = classify_event(state, type, event)

        {state, intents} =
          case classification do
            {:invalid_tool, _reason} -> {state, []}
            _ -> dispatch_event(state, type, event)
          end

        {state, byte_directives} = route_event_bytes(state, classification, raw_bytes)
        eval_markers = Enum.map(intents, fn intent -> {:cedar_eval, intent.call_id} end)
        {state, intents, byte_directives ++ eval_markers}

      _ ->
        state = bump_indices(state, payload_byte_size)
        # SSE comments and the conventional end marker carry no executable item.
        cond do
          payload not in [nil, "", "[DONE]"] ->
            {state, [], [{:parser_error, :malformed_event}]}

          state.summary[:completion_seen?] == true ->
            {%{state | terminal_trailers: [raw_bytes | state.terminal_trailers]}, [], []}

          true ->
            {state, [], [{:forward, raw_bytes}]}
        end
    end
  end

  # Final response objects repeat executable items. They must carry exactly
  # the intent already admitted, and a denied item must not reappear here.
  # Delay these objects until finalize, after the transport applies verdicts.
  defp terminal_directives(state) do
    terminal =
      Enum.flat_map(Enum.reverse(state.terminal_events), &terminal_event_directives(state, &1))

    terminal ++ Enum.map(Enum.reverse(state.terminal_trailers), &{:forward, &1})
  end

  defp terminal_event_directives(state, {event, raw}) do
    output = get_in(event, ["response", "output"]) || []

    pending? =
      Enum.any?(output, fn item ->
        if item["type"] in @tool_call_item_types do
          id = item["call_id"] || item["id"]

          not match?(
            %{verdict: verdict} when verdict in [:allowed, :denied],
            state.call_states[id]
          )
        else
          false
        end
      end)

    if pending? do
      [{:parser_error, :unadmitted_terminal_output}]
    else
      visible =
        Enum.reject(output, fn item ->
          id = item["call_id"] || item["id"]

          item["type"] in @tool_call_item_types and
            match?(%{verdict: :denied}, state.call_states[id])
        end)

      if visible == output do
        [{:forward, raw}]
      else
        json = event |> put_in(["response", "output"], visible) |> Jason.encode!()
        bytes = terminal_frame(state.transport, json)
        [{:forward, bytes}]
      end
    end
  end

  defp terminal_frame(:ws, json), do: json
  defp terminal_frame(_transport, json), do: "data: " <> json <> "\n\n"

  defp item_matches_intent?(_item, nil), do: false

  defp item_matches_intent?(item, intent) do
    args = if item["type"] == "custom_tool_call", do: item["input"], else: item["arguments"]
    item["name"] == intent.tool_name and args_match?(args, intent)
  end

  defp args_match?(args, intent) when is_binary(args) do
    case Jason.decode(args) do
      {:ok, decoded} when is_map(decoded) -> decoded == intent.tool_args
      _ -> intent.tool_args == %{"input" => args}
    end
  end

  defp args_match?(_, _), do: false

  defp repeated_completion_matches?(intent, type, event) do
    not String.ends_with?(type, ".delta") and
      (is_nil(event["name"]) or event["name"] == intent.tool_name) and
      case event["arguments"] || event["input"] do
        nil -> true
        args -> args_match?(args, intent)
      end
  end

  # The completed representation may repeat streamed arguments, but may not
  # replace them with a different operation. Those earlier bytes are released
  # under this very same admission decision.
  defp accumulated_completion_matches?(nil, _type, _event), do: false

  defp accumulated_completion_matches?(acc, type, event) do
    same_name = is_nil(event["name"]) or event["name"] == acc.tool_name
    key = Map.get(acc, :args_key, "arguments")
    completed = event[key]
    streamed = Shared.json_buffer_raw(acc.json_buffer)

    same_name and
      (String.ends_with?(type, ".delta") or is_nil(completed) or
         (is_binary(completed) and
            (streamed == "" or equal_argument_representations?(streamed, completed, key))))
  end

  defp equal_argument_representations?(left, right, "input"), do: left == right

  defp equal_argument_representations?(left, right, _key) do
    case {Jason.decode(left), Jason.decode(right)} do
      {{:ok, a}, {:ok, b}} when is_map(a) and is_map(b) -> a == b
      _ -> false
    end
  end

  defp decode_event(payload) when is_binary(payload) do
    case Jason.decode(payload) do
      {:ok, value} when is_map(value) -> {:ok, value}
      _ -> :error
    end
  end

  defp decode_event(_), do: :error

  defp bump_indices(%__MODULE__{event_index: ei, byte_offset: bo} = state, n)
       when is_integer(n) and n >= 0 do
    %{state | event_index: ei + 1, byte_offset: bo + n}
  end

  # ---------------------------------------------------------------------------
  # Event classification — fcall vs non-fcall + call_id resolution
  # ---------------------------------------------------------------------------

  # Returns `{classification, state}` where classification is either
  # `:non_fcall` or `{:fcall, call_id}`. Side effect: opens a new
  # call_state on `output_item.added` for a function_call item, and
  # registers the item_id → call_id alias.
  defp classify_event(%{summary: %{completion_seen?: true}} = state, _type, _event),
    do: {{:invalid_tool, :event_after_terminal}, state}

  defp classify_event(state, "response.output_item.added", event) do
    item = Map.get(event, "item", %{})

    case Map.get(item, "type") do
      type when type in @tool_call_item_types ->
        call_id = Map.get(item, "call_id") || Map.get(item, "id")
        item_id = Map.get(item, "id")

        args_key = if type == "custom_tool_call", do: "input", else: "arguments"

        if is_binary(call_id) and not Map.has_key?(state.call_states, call_id) and
             is_binary(Map.get(item, args_key, "")) do
          call_states =
            Map.put_new(state.call_states, call_id, %{byte_buffer: [], verdict: :pending})

          item_to_call = register_item_alias(state.item_to_call, item_id, call_id)

          new_state = %{state | call_states: call_states, item_to_call: item_to_call}
          {{:fcall, call_id}, new_state}
        else
          {{:invalid_tool, :missing_call_id}, state}
        end

      _ ->
        {:non_fcall, state}
    end
  end

  # Both old (call_id-correlated) and new (item_id-correlated) shapes.
  defp classify_event(state, type, event)
       when type in [
              "response.function_call_arguments.delta",
              "response.function_call_arguments.done",
              "response.function_call.arguments.delta",
              "response.function_call.arguments.completed",
              "response.function_call.completed",
              # Codex 0.149 (custom-tool shape) — see @tool_call_item_types.
              "response.custom_tool_call_input.delta",
              "response.custom_tool_call_input.done"
            ] do
    {resolved, state} = resolve_call_id_from_event(state, event)

    case resolved do
      nil ->
        {{:invalid_tool, :missing_call_id}, state}

      cid ->
        classify_resolved_arguments(state, cid, type, event)
    end
  end

  defp classify_event(state, type, event)
       when type in [
              "response.output_item.done",
              "response.output_item.completed"
            ] do
    item = Map.get(event, "item", %{})

    case Map.get(item, "type") do
      type when type in @tool_call_item_types ->
        # The item carries `id` (== item_id) + `call_id`. Same resolution
        # logic as the delta/done events.
        synthetic = %{
          "item_id" => Map.get(item, "id"),
          "call_id" => Map.get(item, "call_id")
        }

        {resolved, state} = resolve_call_id_from_event(state, synthetic)

        classify_resolved_item(state, resolved, item)

      _ ->
        {:non_fcall, state}
    end
  end

  defp classify_event(state, "response.completed", event) do
    output = get_in(event, ["response", "output"]) || []

    unsafe? =
      not is_list(output) or
        Enum.any?(output, fn
          %{"type" => type} = item when type in @tool_call_item_types ->
            id = item["call_id"] || item["id"]
            not item_matches_intent?(item, state.emitted_intents[id])

          %{"type" => type} when type in ["message", "reasoning"] ->
            false

          _ ->
            true
        end)

    if unsafe?,
      do: {{:invalid_tool, :unadmitted_terminal_output}, state},
      else: {{:terminal_output, event}, state}
  end

  defp classify_event(state, _type, _event), do: {:non_fcall, state}

  # Resolve an event's `call_id` by checking, in order: explicit
  # `call_id` field that we already opened, `item_id` alias to a known
  # call_id, raw `call_id` field as last resort, or raw `item_id` as
  # very-last resort. nil if nothing resolves.
  defp resolve_call_id_from_event(state, event) do
    item_id = Map.get(event, "item_id")
    call_id = Map.get(event, "call_id")

    cond do
      is_binary(call_id) and Map.has_key?(state.call_states, call_id) ->
        {call_id, state}

      is_binary(item_id) and is_map_key(state.item_to_call, item_id) ->
        {Map.fetch!(state.item_to_call, item_id), state}

      is_binary(call_id) ->
        {call_id, state}

      is_binary(item_id) ->
        {item_id, state}

      true ->
        {nil, state}
    end
  end

  # ---------------------------------------------------------------------------
  # Byte routing — fcall events go through call_state verdict gate;
  # non-fcall events forward immediately.
  # ---------------------------------------------------------------------------

  defp route_event_bytes(state, {:invalid_tool, reason}, _raw_bytes),
    do: {state, [{:parser_error, reason}]}

  defp route_event_bytes(state, {:terminal_output, event}, raw_bytes),
    do: {%{state | terminal_events: [{event, raw_bytes} | state.terminal_events]}, []}

  defp route_event_bytes(state, :non_fcall, raw_bytes) do
    {state, [{:forward, raw_bytes}]}
  end

  defp route_event_bytes(state, {:fcall, call_id}, raw_bytes) do
    case Map.get(state.call_states, call_id) do
      nil ->
        {state, [{:parser_error, :orphan_tool_event}]}

      %{verdict: :pending, byte_buffer: buf} = cs ->
        # Hold silently; emit no directive. apply_verdict/3 will release
        # these bytes once Cedar evaluates.
        new_cs = %{cs | byte_buffer: [raw_bytes | buf]}
        new_state = %{state | call_states: Map.put(state.call_states, call_id, new_cs)}
        {new_state, []}

      %{verdict: :allowed} ->
        # Verdict already applied. Trailing same-call_id events go
        # through unchanged (codex sees the full function_call sequence
        # as if no proxy were in the path).
        {state, [{:forward, raw_bytes}]}

      %{verdict: :denied} ->
        # Verdict already applied. Trailing same-call_id events are
        # suppressed at the byte level — codex never sees them. The
        # synthetic denial message has already been injected by the
        # proxy following the apply_verdict drain.
        {state, [{:suppress, raw_bytes}]}
    end
  end

  # ---------------------------------------------------------------------------
  # Event dispatch — state-mutation only (no directive emission;
  # routing is handled by route_event_bytes/3).
  # ---------------------------------------------------------------------------

  defp dispatch_event(state, "response.created", event) do
    response = Map.get(event, "response", %{})
    response_id = Map.get(response, "id")
    model = Map.get(response, "model")

    summary_updates =
      %{}
      |> maybe_put(:response_id, response_id)
      |> maybe_put(:model, model)

    {%{state | summary: Map.merge(state.summary, summary_updates)}, []}
  end

  defp dispatch_event(state, "response.output_item.added", event) do
    item = Map.get(event, "item", %{})

    case Map.get(item, "type") do
      "function_call" ->
        start_function_call_accumulator(state, item, "arguments")

      # Codex 0.149 custom-tool shape: same lifecycle, different field.
      "custom_tool_call" ->
        start_function_call_accumulator(state, item, "input")

      type when type in ["message", "reasoning"] ->
        {state, []}

      other ->
        # Diagnostic logging — surfaces item.type values the parser
        # doesn't currently handle (e.g. `local_shell_call` from codex
        # 0.125+, `web_search_call`, `code_interpreter_call`, etc.)
        # so we know what to wire up next. Sampled at debug level so
        # production hot-path doesn't spam logs.
        require Logger

        Logger.warning(fn ->
          "OpenaiResponses parser: unhandled output_item type=#{inspect(other)} keys=#{inspect(Map.keys(item))}"
        end)

        {record_unhandled(state, "output_item:" <> stringify_type(other), item), []}
    end
  end

  # Function-call argument streaming. OpenAI's Responses API has emitted
  # these under TWO names across releases:
  #
  #   * `response.function_call.arguments.delta` / `.completed`
  #     (older taxonomy our spec was originally written against; circa
  #     gpt-4o + early codex).
  #   * `response.function_call_arguments.delta` / `.done`
  #     (codex 0.125+ / gpt-5.5 — confirmed empirically 2026-05-08 by
  #     `Logger.warning` diagnostic against audit-dev's proxy stream).
  #
  # We dispatch BOTH so the parser is robust across OpenAI's silent wire
  # rev. See R5E-100 + R5E-101 for the long-term observability + self-
  # healing-inference plan; this is the immediate fix.
  defp dispatch_event(state, "response.function_call_arguments.delta", event),
    do: {append_function_call_delta(state, event), []}

  defp dispatch_event(state, "response.function_call.arguments.delta", event),
    do: {append_function_call_delta(state, event), []}

  # `response.function_call_arguments.done` (codex 0.125+) carries the
  # FULL arguments JSON inlined as `event.arguments`. We override the
  # accumulator's buffer with the canonical args (defense against any
  # delta-stream parsing mishap), then finalize.
  defp dispatch_event(state, "response.function_call_arguments.done", event),
    do: finalize_function_call_with_inline_args(state, event)

  defp dispatch_event(state, "response.function_call.completed", event),
    do: finalize_function_call(state, event)

  # Codex 0.149 custom-tool streaming. Correlated by `item_id` (there is
  # no `call_id` on these two events), and `.done` inlines the canonical
  # full payload under `input` rather than `arguments`.
  defp dispatch_event(state, "response.custom_tool_call_input.delta", event),
    do: {append_function_call_delta(state, event), []}

  defp dispatch_event(state, "response.custom_tool_call_input.done", event),
    do: finalize_function_call_with_inline_args(state, event, "input")

  # Reasoning, message, output_text — forward unchanged, no state change
  # beyond index/offset bumps already applied.
  defp dispatch_event(state, "response.in_progress", _event), do: {state, []}
  defp dispatch_event(state, "response.output_text.delta", _event), do: {state, []}
  defp dispatch_event(state, "response.output_text.done", _event), do: {state, []}
  defp dispatch_event(state, "response.output_text.completed", _event), do: {state, []}
  defp dispatch_event(state, "response.content_part.added", _event), do: {state, []}
  defp dispatch_event(state, "response.content_part.done", _event), do: {state, []}
  defp dispatch_event(state, "response.reasoning.delta", _event), do: {state, []}
  defp dispatch_event(state, "response.reasoning.done", _event), do: {state, []}

  # `response.output_item.done` (codex 0.125+) and `.completed` (older)
  # — defense-in-depth finalizer for function_call items in case the
  # arguments-completion event was missed. Non-function_call items are
  # forwarded unchanged.
  defp dispatch_event(state, "response.output_item.done", event),
    do: maybe_finalize_function_call_on_item_done(state, event)

  defp dispatch_event(state, "response.output_item.completed", event),
    do: maybe_finalize_function_call_on_item_done(state, event)

  defp dispatch_event(state, "response.completed", event) do
    response = Map.get(event, "response", %{})
    usage = Map.get(response, "usage", %{})

    # `response.model` MAY appear here too (some upstream variants emit
    # it on completed but not created); honor whichever event surfaced
    # it first. `response.created` is the canonical source per R-002.
    model = Map.get(response, "model")

    {prompt_tokens, completion_tokens, reasoning_tokens} = extract_usage(usage)

    summary_updates =
      %{completion_seen?: true}
      |> maybe_put(:usage, if(is_map(usage) and usage != %{}, do: usage, else: nil))
      |> maybe_put(:prompt_token_count, prompt_tokens)
      |> maybe_put(:completion_token_count, completion_tokens)
      |> maybe_put(:reasoning_token_count, reasoning_tokens)
      |> maybe_put(:model, if(Map.has_key?(state.summary, :model), do: nil, else: model))

    {%{state | summary: Map.merge(state.summary, summary_updates)}, []}
  end

  # I-005 drift tolerance: unknown event types just bump indices and
  # forward. The chunk is already in `[{:forward, chunk}]` from
  # parse_chunk/2.
  defp dispatch_event(state, unknown, event) do
    # Diagnostic logging — surfaces event-name renames silently shipped
    # by upstream API providers (e.g., OpenAI Responses API renamed
    # `response.function_call.completed` → `response.function_call_arguments.done`
    # in some 2025-26 codex releases). Sampled at debug level so we
    # don't spam logs in steady-state.
    require Logger

    Logger.warning(fn ->
      keys = if is_map(event), do: Map.keys(event) |> inspect(limit: 8), else: "n/a"
      "OpenaiResponses parser: unhandled event type=#{inspect(unknown)} keys=#{keys}"
    end)

    {record_unhandled(state, "event:" <> stringify_type(unknown), event), []}
  end

  defp stringify_type(t) when is_binary(t), do: t
  defp stringify_type(nil), do: "nil"
  defp stringify_type(t), do: inspect(t)

  # Extract OpenAI Responses-API token-usage fields. `nil` for any
  # field the upstream omitted (R-002 schema is documented but the
  # exact shape varies by model — o1/o3 carry
  # `output_tokens_details.reasoning_tokens`; gpt-4o doesn't).
  defp extract_usage(usage) when is_map(usage) do
    prompt = Map.get(usage, "input_tokens")
    completion = Map.get(usage, "output_tokens")
    reasoning = get_in(usage, ["output_tokens_details", "reasoning_tokens"])

    {normalize_token_count(prompt), normalize_token_count(completion),
     normalize_token_count(reasoning)}
  end

  defp extract_usage(_), do: {nil, nil, nil}

  defp normalize_token_count(n) when is_integer(n) and n >= 0, do: n
  defp normalize_token_count(_), do: nil

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)

  # ---------------------------------------------------------------------------
  # function_call accumulator lifecycle
  # ---------------------------------------------------------------------------

  defp start_function_call_accumulator(state, item, args_key) do
    call_id = Map.get(item, "call_id")
    item_id = Map.get(item, "id")
    tool_name = Map.get(item, "name")

    # Older OpenAI Responses streams correlated subsequent
    # function_call.arguments.delta / .completed events by `call_id`.
    # Codex 0.125+ uses `item_id` (= `item.id`, distinct from `call_id`)
    # as the correlation key on delta + done events. We index the
    # accumulator under BOTH so either lookup pattern works without a
    # rewrite of the lookup helpers.
    primary_key = item_id || call_id

    if is_binary(primary_key) and is_binary(tool_name) do
      # Pre-populate any inline args field (some providers ship the full
      # args object up-front; deltas refine it). The field is `arguments`
      # for function_call items and `input` for custom_tool_call ones.
      initial_args = Map.get(item, args_key, "")

      json_buffer =
        Shared.json_buffer_new()
        |> Shared.json_buffer_push(if is_binary(initial_args), do: initial_args, else: "")

      accumulator = %{
        # `call_id` is what ToolUseIntent emission requires (it's the
        # stable agent-side correlation token; survives across requests).
        # When the upstream omits `call_id` (some lightweight item shapes),
        # fall back to `item_id` so we still emit something.
        call_id: call_id || item_id,
        item_id: item_id,
        tool_name: tool_name,
        args_key: args_key,
        registration_index: state.function_calls_opened,
        json_buffer: json_buffer,
        start_byte_offset: state.byte_offset,
        event_indices: [state.event_index - 1]
      }

      accumulators =
        state.accumulators
        |> Map.put(primary_key, accumulator)
        |> maybe_alias_accumulator(item_id, call_id, accumulator)

      new_state = %{
        state
        | accumulators: accumulators,
          function_calls_opened: state.function_calls_opened + 1
      }

      {new_state, []}
    else
      # Drift: function_call missing required fields. Skip; upstream
      # event is still forwarded by the parse_chunk wrapper.
      {state, []}
    end
  end

  # When both `item_id` and `call_id` are present and distinct, index the
  # accumulator under both keys so subsequent events can use either as
  # the correlation token.
  defp maybe_alias_accumulator(map, nil, _, _), do: map
  defp maybe_alias_accumulator(map, _, nil, _), do: map
  defp maybe_alias_accumulator(map, k, k, _), do: map

  defp maybe_alias_accumulator(map, item_id, call_id, accumulator) do
    map
    |> Map.put(item_id, accumulator)
    |> Map.put(call_id, accumulator)
  end

  # I-004: per the contract, `parallel_index` is the position in the
  # parallel_tool_calls array when parallelism is in play; null otherwise.
  # The Responses API doesn't ship a per-item parallel_index field, so we
  # derive it from registration order. The "non-parallel" classification
  # uses a CONSERVATIVE heuristic: if the response only ever opened one
  # function_call (`function_calls_opened == 1`) AND that single call is
  # the one whose intent we are emitting (`registration_index == 0`),
  # we set `parallel_index: nil`. As soon as a SECOND function_call is
  # opened, the first one's intent (whether already emitted or not) is
  # in a parallel context, and we use registration_index. This matches
  # the contract test expectation: single-call → nil; N-call → 0,1,...,N-1.
  defp resolve_parallel_index(%{registration_index: idx}, %__MODULE__{
         function_calls_opened: opened
       }) do
    if opened <= 1 and idx == 0, do: nil, else: idx
  end

  defp append_function_call_delta(state, event) do
    call_id = Map.get(event, "call_id") || Map.get(event, "item_id")
    delta = Map.get(event, "delta", "")

    case Map.fetch(state.accumulators, call_id) do
      {:ok, acc} when is_binary(delta) ->
        new_buffer = Shared.json_buffer_push(acc.json_buffer, delta)

        new_acc = %{
          acc
          | json_buffer: new_buffer,
            event_indices: [state.event_index - 1 | acc.event_indices]
        }

        accumulators =
          state.accumulators
          |> Map.put(call_id, new_acc)
          |> maybe_alias_accumulator(acc.item_id, acc.call_id, new_acc)

        %{state | accumulators: accumulators}

      _ ->
        # Delta for an unknown call_id (drift) or non-binary delta —
        # forward unchanged, do not raise.
        state
    end
  end

  defp finalize_function_call(state, event) do
    lookup_key = Map.get(event, "call_id") || Map.get(event, "item_id")

    case Map.fetch(state.accumulators, lookup_key) do
      {:ok, acc} ->
        end_byte_offset = state.byte_offset
        event_indices = Enum.reverse([state.event_index - 1 | acc.event_indices])

        span = %{
          start_byte_offset: acc.start_byte_offset,
          end_byte_offset: end_byte_offset,
          event_indices: event_indices
        }

        {tool_args, raw_json_opt} =
          decode_accumulator_args(acc.json_buffer, Map.get(acc, :args_key, "arguments"))

        intent_input =
          %{
            call_id: acc.call_id,
            tool_name: acc.tool_name,
            tool_args: tool_args,
            parallel_index: resolve_parallel_index(acc, state),
            provider_event_span: span
          }
          |> maybe_put_raw_json(raw_json_opt)

        accumulators_after = drop_accumulator_keys(state.accumulators, acc, lookup_key)

        case ToolUseIntent.new(intent_input) do
          {:ok, intent} ->
            new_state = %{
              state
              | accumulators: accumulators_after,
                intent_count: state.intent_count + 1,
                emitted_intents: Map.put(state.emitted_intents, intent.call_id, intent)
            }

            {new_state, [intent]}

          {:error, _} ->
            # Could not construct a valid intent (e.g. raw_json was
            # empty). Drop the accumulator without raising; forward the
            # original bytes unchanged.
            {%{state | accumulators: accumulators_after}, []}
        end

      :error ->
        # Completion for an unknown call_id (drift). Skip.
        {state, []}
    end
  end

  # The accumulator may be indexed under both `item_id` and `call_id` (codex 0.125+
  # uses `item_id` on delta/done events; older streams use `call_id`). Delete
  # under both so we don't leak a stale alias after finalization.
  defp drop_accumulator_keys(accumulators, acc, lookup_key) do
    keys =
      [lookup_key, Map.get(acc, :item_id), Map.get(acc, :call_id)]
      |> Enum.filter(&is_binary/1)
      |> Enum.uniq()

    Enum.reduce(keys, accumulators, fn k, m -> Map.delete(m, k) end)
  end

  # Codex 0.125+'s `response.function_call_arguments.done` carries the
  # complete arguments JSON inlined as `event.arguments`. Classification
  # requires agreement with accumulated bytes before this representation can
  # be used for admission and release.
  defp finalize_function_call_with_inline_args(state, event, args_key \\ "arguments") do
    lookup_key = Map.get(event, "item_id") || Map.get(event, "call_id")
    args = Map.get(event, args_key)

    case Map.fetch(state.accumulators, lookup_key) do
      {:ok, acc} when is_binary(args) ->
        canonical_buffer =
          Shared.json_buffer_new()
          |> Shared.json_buffer_push(args)

        updated_acc = %{acc | json_buffer: canonical_buffer}

        # Re-index the accumulator under all of its registered keys so
        # the downstream finalize_function_call lookup finds the
        # buffer-overridden version.
        accumulators =
          [Map.get(acc, :item_id), Map.get(acc, :call_id), lookup_key]
          |> Enum.filter(&is_binary/1)
          |> Enum.uniq()
          |> Enum.reduce(state.accumulators, fn k, m -> Map.put(m, k, updated_acc) end)

        finalize_function_call(%{state | accumulators: accumulators}, %{
          "item_id" => lookup_key
        })

      _ ->
        # Drift: `arguments.done` for an unknown lookup_key, or args is
        # not a binary. Skip without raising — the upstream chunk is
        # forwarded by the outer parse_chunk wrapper regardless.
        {state, []}
    end
  end

  # `response.output_item.done` (codex 0.125+) and `response.output_item.completed`
  # (older) BOTH route here. For function_call items, this is a defense-in-depth
  # finalizer in case `function_call_arguments.{done,completed}` was missed
  # (paranoid but cheap — if the accumulator was already finalized we no-op).
  # For non-function_call items the dispatch is a no-op.
  defp maybe_finalize_function_call_on_item_done(state, event) do
    item = Map.get(event, "item", %{})

    case Map.get(item, "type") do
      type when type in @tool_call_item_types ->
        lookup_key = Map.get(item, "id") || Map.get(item, "call_id")

        if is_binary(lookup_key) and Map.has_key?(state.accumulators, lookup_key) do
          finalize_known_item(state, type, item, lookup_key)
        else
          {state, []}
        end

      _ ->
        {state, []}
    end
  end

  defp maybe_put_raw_json(input, nil), do: input
  defp maybe_put_raw_json(input, raw), do: Map.put(input, :raw_json, raw)

  defp register_item_alias(aliases, item_id, call_id) when is_binary(item_id),
    do: Map.put(aliases, item_id, call_id)

  defp register_item_alias(aliases, _item_id, _call_id), do: aliases

  defp classify_resolved_arguments(state, cid, type, event) do
    case state.emitted_intents[cid] do
      nil ->
        if accumulated_completion_matches?(state.accumulators[cid], type, event),
          do: {{:fcall, cid}, state},
          else: {{:invalid_tool, :inconsistent_tool_arguments}, state}

      intent ->
        if repeated_completion_matches?(intent, type, event),
          do: {{:fcall, cid}, state},
          else: {{:invalid_tool, :changed_tool_after_intent}, state}
    end
  end

  defp classify_resolved_item(state, nil, _item),
    do: {{:invalid_tool, :missing_call_id}, state}

  defp classify_resolved_item(state, cid, item) do
    if (is_nil(state.emitted_intents[cid]) and
          accumulated_completion_matches?(state.accumulators[cid], "item.done", item)) or
         item_matches_intent?(item, state.emitted_intents[cid]),
       do: {{:fcall, cid}, state},
       else: {{:invalid_tool, :changed_tool_after_intent}, state}
  end

  defp finalize_known_item(state, type, item, lookup_key) do
    key = if type == "custom_tool_call", do: "input", else: "arguments"

    if is_binary(item[key]) do
      finalize_function_call_with_inline_args(state, Map.put(item, "item_id", lookup_key), key)
    else
      finalize_function_call(state, %{"item_id" => lookup_key})
    end
  end

  # Decode the JSON buffer; on success return the decoded map.
  # On partial / decode failure, return the `:too_large`-style sentinel
  # path so the caller can still emit an intent with the raw bytes
  # hashed (per ToolUseIntent I-001). For an EMPTY buffer, signal an
  # error to the caller via {:too_large, ""}; ToolUseIntent.new/1 will
  # reject the missing :raw_json and we drop the intent gracefully.
  defp decode_accumulator_args(json_buffer, args_key) do
    raw = Shared.json_buffer_raw(json_buffer)

    case Shared.json_buffer_try_decode(json_buffer) do
      {:ok, value} when is_map(value) ->
        {value, nil}

      _ ->
        undecodable_args(raw, args_key)
    end
  end

  # A `function_call`'s arguments are always a JSON object, so anything
  # that fails to decode is genuine drift/truncation and keeps the
  # `:too_large` sentinel (the gate then policies on the args HASH only).
  #
  # A `custom_tool_call`'s `input` is freeform by design — it may be a
  # bare string rather than an object. Falling through to `:too_large`
  # there would mean Cedar never sees the command text and could only
  # match on tool name, which would quietly defeat any content-based
  # forbid rule. Wrap it so policies can match `context.tool_args.input`.
  defp undecodable_args(raw, "input") when is_binary(raw) and raw != "",
    do: {%{"input" => raw}, nil}

  defp undecodable_args(raw, _args_key), do: {:too_large, raw}
end
