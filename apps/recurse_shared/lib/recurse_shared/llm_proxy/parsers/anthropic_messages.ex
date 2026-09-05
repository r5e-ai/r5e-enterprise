defmodule Recurse.Shared.LlmProxy.Parsers.AnthropicMessages do
  @moduledoc """
  Streaming parser for the Anthropic **Messages API** (`POST /v1/messages`),
  the protocol Claude Code speaks through `ANTHROPIC_BASE_URL`.

  Spec sources: `specs/009-llm-api-proxy/contracts/per_provider_parser.md`
  §AnthropicMessages, `specs/012-compose-quickstart/plan.md` §5 S4 / §9 /
  §11, and the captured fixtures in
  `apps/recurse_shared/test/fixtures/anthropic_messages/` (Claude Code
  2.1.223, `anthropic-version: 2023-06-01`; see `spike-s0.md`).

  ## Wire shape (streaming)

      event: message_start        data: {message: {id, model, usage, ...}}
      event: content_block_start  data: {index, content_block: {type, ...}}
      event: ping
      event: content_block_delta  data: {index, delta: {type, ...}}
      event: content_block_stop   data: {index}
      event: message_delta        data: {delta: {stop_reason}, usage: {output_tokens}}
      event: message_stop

  Content blocks are keyed by `index`. A client tool call is a
  `tool_use` block: `content_block_start` carries `id` (`toolu_…`) and
  `name`, the `input_json_delta` fragments carry the JSON input split at
  arbitrary character boundaries (the first fragment is always `""`),
  and the input is only decodable at `content_block_stop`. `data:` lines
  carry trailing whitespace padding; every payload is trimmed before
  decoding. `stop_reason` appears only in `message_delta`, whose `usage`
  is authoritative for `output_tokens`.

  ## Non-streaming bodies

  Claude Code's `side_query` request has no `stream` key and the upstream
  answers with one JSON message. `accepts_json_body?/0` tells the proxy
  not to bypass this parser for non-SSE responses; the first
  non-whitespace byte selects the mode (`{` → JSON message held until it
  decodes; SSE otherwise; anything else is passed through untouched and
  counted as `stream:unparsed`, see below).

  ## Enforcement (byte-precise suppression)

  A `tool_use` block's frames are held from `content_block_start` to
  `content_block_stop`; at the stop a `ToolUseIntent` is emitted with a
  `{:cedar_eval, id}` marker. The proxy evaluates Cedar and calls
  `apply_verdict/4`:

    * `:allow` releases the held frames unchanged;
    * `:deny` suppresses them and emits `:flush_pending` at their exact
      stream position so the proxy injects the replacement `text` block
      there (same `index` as the suppressed block, so indices stay
      contiguous whichever blocks of a parallel call are denied).

  While any verdict is pending every later frame (`message_delta`,
  `message_stop`, a following block) is queued behind it and released in
  order once the verdict lands, so the client always sees the stream in
  upstream order. When every `tool_use` block of the message was denied,
  `message_delta.delta.stop_reason` is rewritten from `tool_use` to
  `end_turn` so the client does not wait for a tool result (that single
  frame is re-encoded; everything else is forwarded byte-for-byte). In
  JSON mode the denied `tool_use` blocks are replaced in the decoded
  message with `text` blocks carrying the `denial_text:` the proxy passes
  to `apply_verdict/4`, and the re-encoded body is forwarded once.

  ## What is recognised (the format this parser is exhaustive for)

  Events: `message_start`, `content_block_start`, `content_block_delta`,
  `content_block_stop`, `message_delta`, `message_stop`, `ping`, `error`.
  Content blocks: `text`, `thinking`, `redacted_thinking`, `tool_use`,
  and the server-side block types (`server_tool_use`, `mcp_tool_use`,
  `mcp_tool_result`, `web_search_tool_result`, `web_fetch_tool_result`,
  `code_execution_tool_result`, `bash_code_execution_tool_result`,
  `text_editor_code_execution_tool_result`, `tool_search_tool_result`,
  `compaction`). Deltas: `text_delta`, `input_json_delta`,
  `thinking_delta`, `signature_delta`, `citations_delta`.

  `server_tool_use` / `mcp_tool_use` are tool calls the upstream executes
  itself before the response reaches this parser; they are recognised
  (not drift) and recorded in the summary under `:server_tool_uses`, but
  they are NOT `ToolUseIntent`s: a Cedar deny could not prevent an
  execution that already happened, and suppressing the block while its
  result block streams through would corrupt the client's view.

  Anything else is forwarded unmodified (Invariant I-005), logged as
  `AnthropicMessages parser: unhandled … type=…`, and counted: the
  summary's `events_total` / `events_unhandled` / `unhandled_types` are
  what the attestation records as recognition completeness (plan §11).
  `version/0` is the SHA-256 (first 16 hex chars) of this file and
  `parsers/shared.ex` together, computed at compile time, so a record
  names the exact recognizer that read it. The `anthropic-beta` header
  is reported separately as `betas_requested` (what the client asked
  for, not what the upstream honoured); `format/1` carries the version
  only.

  ## Nothing is dropped silently (S4 review)

  Every path that leaves bytes unclassified counts toward
  `events_unhandled`, so §11's downgrade fires instead of the record
  claiming "no tool calls":

    * `stream:unparsed` — bytes that were neither JSON nor SSE (passed
      through), a JSON body that never decoded, or an SSE tail with no
      `data:` at EOF;
    * `stream:trailing_bytes` — bytes after a complete JSON message
      (forwarded, counted once);
    * `parser:raised` — the parser raised; the raising chunk and
      everything after it are passed through unread, after what was
      held has been drained (queued frames released in order, unverdicted
      `tool_use` blocks suppressed, the SSE buffer's tail forwarded);
    * `block:tool_use_unterminated` — a `tool_use` block whose
      `content_block_stop` never arrived: its held frames are SUPPRESSED
      at EOF, never forwarded unevaluated;
    * `block:tool_use_unevaluated` — an intent was emitted but no verdict
      was ever applied (the proxy resolves markers synchronously, so
      only direct callers can reach this); suppressed at EOF;
    * `block:duplicate_index` — a second `content_block_start` at an index
      whose `tool_use` block is still held: both blocks are suppressed
      (held frames, the new start, and every later frame at that index).

  An integral-float `index` (`0.0`) is normalised to the integer.
  """

  @behaviour Recurse.Shared.LlmProxy.Parsers.Parser

  alias Recurse.Shared.LlmProxy.Parsers.Parser
  alias Recurse.Shared.LlmProxy.Parsers.Shared
  alias Recurse.Shared.LlmProxy.ToolUseIntent

  require Logger

  # `@external_resource` makes a shared.ex edit recompile this module so
  # the hash never goes stale.
  @shared_source Path.join(Path.dirname(__ENV__.file), "shared.ex")
  @external_resource @shared_source
  @source_version [__ENV__.file, @shared_source]
                  |> Enum.map(&File.read!/1)
                  |> IO.iodata_to_binary()
                  |> then(&:crypto.hash(:sha256, &1))
                  |> Base.encode16(case: :lower)
                  |> binary_part(0, 16)

  @format_name "anthropic_messages"

  @known_events ~w(message_start content_block_start content_block_delta content_block_stop
                   message_delta message_stop ping error)

  @client_tool_block "tool_use"
  @server_tool_blocks ~w(server_tool_use mcp_tool_use)
  @passive_blocks ~w(text thinking redacted_thinking mcp_tool_result web_search_tool_result
                     web_fetch_tool_result code_execution_tool_result
                     bash_code_execution_tool_result text_editor_code_execution_tool_result
                     tool_search_tool_result compaction)

  @known_deltas ~w(text_delta input_json_delta thinking_delta signature_delta citations_delta)

  @sample_max_bytes 200

  # Text put in place of a tool_use block that was suppressed without a
  # policy verdict (JSON mode; SSE mode suppresses the frames outright).
  @suppressed_text "Tool call suppressed: no policy verdict was obtained for it."

  @typedoc "Per-`index` content-block state."
  @type block :: %{
          index: non_neg_integer(),
          type: String.t(),
          call_id: String.t() | nil,
          tool_name: String.t() | nil,
          json_buffer: term(),
          frames: [binary()],
          verdict: :none | :pending | :allowed | :denied | :suppressed,
          registration_index: non_neg_integer() | nil,
          start_byte_offset: non_neg_integer(),
          event_indices: [non_neg_integer()]
        }

  @type t :: %__MODULE__{}

  defstruct mode: :undetected,
            sse_buffer: nil,
            json_body: "",
            format: @format_name,
            betas_requested: [],
            blocks: %{},
            call_index: %{},
            pending: [],
            post_buffer: [],
            event_index: 0,
            byte_offset: 0,
            tool_use_opened: 0,
            intent_count: 0,
            denied_count: 0,
            events_total: 0,
            events_unhandled: 0,
            unhandled_types: MapSet.new(),
            unhandled_samples: %{},
            server_tool_uses: [],
            summary: %{}

  # ---------------------------------------------------------------------------
  # Identity
  # ---------------------------------------------------------------------------

  @doc """
  SHA-256 (first 16 hex chars) of this module's source concatenated with
  `parsers/shared.ex`, computed at compile time.
  """
  @spec version() :: String.t()
  def version, do: @source_version

  @doc """
  The wire format + version string this parser is exhaustive for, from
  the request headers: `anthropic_messages/<anthropic-version>`. The
  `anthropic-beta` header is not folded in: it names what the client
  requested, not what the upstream honoured, and is recorded separately
  (`betas_requested/1`, surfaced in the summary).
  """
  @spec format(keyword()) :: String.t()
  def format(opts \\ []) do
    case nonempty(Keyword.get(opts, :anthropic_version)) do
      nil -> @format_name
      version -> @format_name <> "/" <> version
    end
  end

  @doc "The request's `anthropic-beta` header as a list of beta names (`[]` when absent)."
  @spec betas_requested(keyword()) :: [String.t()]
  def betas_requested(opts \\ []) do
    case nonempty(Keyword.get(opts, :anthropic_beta)) do
      nil -> []
      betas -> betas |> String.split(",") |> Enum.map(&String.trim/1) |> Enum.reject(&(&1 == ""))
    end
  end

  @doc "The proxy must feed this parser non-SSE (JSON) response bodies too."
  @spec accepts_json_body?() :: true
  def accepts_json_body?, do: true

  # ---------------------------------------------------------------------------
  # Behaviour callbacks
  # ---------------------------------------------------------------------------

  @impl Parser
  @spec init(keyword()) :: t()
  def init(opts \\ []) do
    %__MODULE__{
      sse_buffer: Shared.sse_buffer_new(),
      format: format(opts),
      betas_requested: betas_requested(opts)
    }
  end

  @impl Parser
  @spec parse_chunk(t(), binary()) :: {t(), [ToolUseIntent.t()], [Parser.forward_directive()]}
  def parse_chunk(%__MODULE__{mode: :failed} = state, _chunk),
    do: {state, [], [{:parser_error, :failed}]}

  def parse_chunk(%__MODULE__{} = state, chunk) when is_binary(chunk) do
    {next, intents, directives} = consume_chunk(state, chunk)

    if next.events_unhandled > state.events_unhandled,
      do: {%{next | mode: :failed}, intents, [{:parser_error, :unrecognized_event}]},
      else: {next, intents, directives}
  rescue
    # Exceptions leave no classification capable of authorizing raw bytes.
    e ->
      Logger.warning(fn ->
        "AnthropicMessages parser: raised #{inspect(e)} at #{inspect(__STACKTRACE__, limit: 6)}; suppressing the rest of the stream"
      end)

      fail_closed(state)
  catch
    kind, reason ->
      Logger.warning(fn ->
        "AnthropicMessages parser: #{kind} #{inspect(reason)}; suppressing the rest of the stream"
      end)

      fail_closed(state)
  end

  def parse_chunk(%__MODULE__{} = state, _other), do: {state, [], [{:forward, ""}]}

  @impl Parser
  @spec finalize(t()) :: {Parser.summary(), [Parser.forward_directive()]}
  def finalize(%__MODULE__{mode: :sse} = state) do
    {_buf, trailing} = Shared.sse_buffer_flush_all(state.sse_buffer)
    state = count_unparsed_tail(state, trailing)
    {state, intents, directives} = handle_sse_events(state, trailing)
    {state, tail} = suppress_unevaluated(state)
    unsafe? = intents != [] or MapSet.member?(state.unhandled_types, "stream:unparsed")

    {build_summary(state),
     if(unsafe?, do: [{:parser_error, :incomplete_stream}], else: directives ++ tail)}
  end

  def finalize(%__MODULE__{mode: :json} = state) do
    # Held tool_use blocks (verdict never applied) are suppressed and the
    # rewritten body retained; an undecodable body is refused at EOF.
    {state, tail} = suppress_unevaluated(state)

    if state.summary[:json_forwarded?] == true do
      {build_summary(state), tail}
    else
      state = record_unhandled(state, "stream:unparsed", %{})
      {build_summary(state), [{:parser_error, :incomplete_json}]}
    end
  end

  def finalize(%__MODULE__{mode: :undetected} = state) do
    # Whitespace-only is nothing; a prefix that never became JSON or SSE
    # (`"dat"`) was not recognised.
    state =
      if String.trim(state.json_body) == "",
        do: state,
        else: record_unhandled(state, "stream:unparsed", %{})

    {build_summary(state),
     if(String.trim(state.json_body) == "", do: [], else: [{:parser_error, :unrecognized_stream}])}
  end

  def finalize(%__MODULE__{} = state), do: {build_summary(state), []}

  @doc "Non-destructive snapshot of the summary (mid-stream accessor)."
  @spec current_summary(t()) :: Parser.summary()
  def current_summary(%__MODULE__{} = state), do: build_summary(state)

  @doc """
  Per-intent options for the denial injector: the `index` of the
  suppressed `tool_use` block, so the replacement `text` block reuses it.
  """
  @spec denial_opts(t(), String.t()) :: keyword()
  def denial_opts(%__MODULE__{} = state, call_id) do
    case lookup_block(state, call_id) do
      {:ok, block} -> [output_index: block.index]
      :error -> []
    end
  end

  @doc """
  Apply Cedar's verdict for `call_id`. See the module doc for the
  release / suppress / `:flush_pending` semantics. `opts` may carry
  `denial_text:` (used in JSON mode, where the parser rewrites the body
  itself and emits no `:flush_pending`).
  """
  @spec apply_verdict(t(), String.t(), :allow | :deny, keyword()) ::
          {t(), [Parser.forward_directive()]}
  def apply_verdict(state, call_id, decision, opts \\ [])

  def apply_verdict(%__MODULE__{mode: :json} = state, call_id, decision, opts)
      when is_binary(call_id) and decision in [:allow, :deny] do
    case lookup_block(state, call_id) do
      {:ok, %{verdict: :pending} = block} ->
        verdict = if decision == :deny, do: :denied, else: :allowed

        block =
          Map.merge(block, %{verdict: verdict, denial_text: Keyword.get(opts, :denial_text)})

        state = %{
          state
          | blocks: Map.put(state.blocks, block.index, block),
            pending: List.delete(state.pending, call_id),
            denied_count: state.denied_count + if(decision == :deny, do: 1, else: 0)
        }

        if state.pending == [] do
          state = %{state | summary: Map.put(state.summary, :json_forwarded?, true)}
          # Trailing bytes queued behind the held body follow it in order.
          {state, tail} = maybe_flush_post_buffer(state)
          {state, [{:forward, render_json_body(state)} | tail]}
        else
          {state, []}
        end

      _ ->
        {state, []}
    end
  end

  def apply_verdict(%__MODULE__{} = state, call_id, decision, _opts)
      when is_binary(call_id) and decision in [:allow, :deny] do
    case lookup_block(state, call_id) do
      {:ok, %{verdict: :pending} = block} ->
        {verdict, kind} =
          if decision == :deny, do: {:denied, :suppress}, else: {:allowed, :forward}

        held = block.frames |> Enum.reverse() |> Enum.map(&{kind, &1})
        held = if decision == :deny, do: held ++ [:flush_pending], else: held

        block = %{block | verdict: verdict, frames: []}

        state = %{
          state
          | blocks: Map.put(state.blocks, block.index, block),
            pending: List.delete(state.pending, call_id),
            denied_count: state.denied_count + if(decision == :deny, do: 1, else: 0)
        }

        {state, tail} = maybe_flush_post_buffer(state)
        {state, held ++ tail}

      _ ->
        # Unknown / already-decided call_id (drift). Total, no raise.
        {state, []}
    end
  end

  def apply_verdict(%__MODULE__{} = state, _call_id, _decision, _opts), do: {state, []}

  # ---------------------------------------------------------------------------
  # Chunk consumption — mode detection
  # ---------------------------------------------------------------------------

  defp consume_chunk(%__MODULE__{mode: :undetected} = state, chunk) do
    case detect_mode(state.json_body <> chunk) do
      :undetected ->
        {%{state | json_body: state.json_body <> chunk}, [], []}

      :json ->
        consume_chunk(%{state | mode: :json}, chunk)

      :sse ->
        consume_chunk(%{state | mode: :sse}, chunk)

      :passthrough ->
        # Neither JSON nor SSE: forwarded untouched, and counted so the
        # record cannot claim the response was read.
        state = record_unhandled(state, "stream:unparsed", %{})

        {%{state | mode: :passthrough, json_body: ""}, [],
         forward_if_nonempty(state.json_body <> chunk)}
    end
  end

  defp consume_chunk(%__MODULE__{mode: :passthrough} = state, chunk),
    do: {state, [], [{:forward, chunk}]}

  defp consume_chunk(%__MODULE__{mode: :sse} = state, chunk) do
    # Bytes that arrived before the mode was known are only whitespace.
    prefix = state.json_body
    {buf, events} = Shared.sse_buffer_push_all(state.sse_buffer, prefix <> chunk)
    handle_sse_events(%{state | sse_buffer: buf, json_body: ""}, events)
  end

  defp consume_chunk(%__MODULE__{mode: :json} = state, chunk) do
    cond do
      state.summary[:json_forwarded?] == true ->
        # Trailing bytes after a complete message (never seen in
        # practice): forwarded as they arrive, counted once.
        {count_once(state, "stream:trailing_bytes"), [], forward_if_nonempty(chunk)}

      state.pending != [] ->
        # Same, while the decoded body is still held for a verdict: queued
        # behind it so the client sees upstream order.
        state = count_once(state, "stream:trailing_bytes")
        {%{state | post_buffer: [{:raw, chunk} | state.post_buffer]}, [], []}

      true ->
        body = state.json_body <> chunk

        case Shared.json_buffer_new()
             |> Shared.json_buffer_push(body)
             |> Shared.json_buffer_try_decode() do
          {:ok, message} when is_map(message) ->
            handle_json_message(%{state | json_body: body}, message)

          {:partial, _} ->
            {%{state | json_body: body}, [], []}

          _ ->
            state = record_unhandled(state, "stream:unparsed", %{})
            {%{state | mode: :passthrough, json_body: ""}, [], forward_if_nonempty(body)}
        end
    end
  end

  # Parser bug (a raise inside `consume_chunk/2`): the rest of the stream
  # is passed through unread. What was being held is drained first so the
  # client stream stays consistent — unverdicted tool_use blocks are
  # suppressed and counted, frames queued behind them released in order,
  # and the bytes consumed but not yet forwarded (the SSE buffer's
  # partial block, an undecoded JSON prefix) precede the chunk that
  # raised. `parser:raised` is counted so the record cannot claim the
  # stream was fully recognised. Total: a failure here falls back to the
  # bare forward.
  defp fail_closed(state) do
    {%{record_unhandled(state, "parser:raised", %{}) | mode: :failed}, [],
     [{:parser_error, :raised}]}
  end

  # An SSE tail at EOF that carries no `data:` line and is not a comment
  # or whitespace was cut mid-block (`event: message_st`): unparsed.
  defp count_unparsed_tail(state, items) do
    Enum.reduce(items, state, fn
      %{data: nil, raw: raw}, st ->
        case String.trim(raw) do
          "" -> st
          ":" <> _ -> st
          _ -> record_unhandled(st, "stream:unparsed", %{})
        end

      _, st ->
        st
    end)
  end

  defp count_once(state, discriminator) do
    if MapSet.member?(state.unhandled_types, discriminator),
      do: state,
      else: record_unhandled(state, discriminator, %{})
  end

  # The first non-whitespace bytes decide: `{` is a JSON body, an SSE
  # field name (or comment) is a stream, anything else passes through
  # untouched. Too few bytes to tell (a prefix of a field name) → wait.
  @sse_field_prefixes ["event:", "data:", "retry:", "id:"]

  defp detect_mode(buffer) do
    case String.trim_leading(buffer) do
      "" ->
        :undetected

      <<"{", _::binary>> ->
        :json

      <<":", _::binary>> ->
        :sse

      head ->
        cond do
          Enum.any?(@sse_field_prefixes, &String.starts_with?(head, &1)) -> :sse
          Enum.any?(@sse_field_prefixes, &String.starts_with?(&1, head)) -> :undetected
          true -> :passthrough
        end
    end
  end

  defp forward_if_nonempty(""), do: []
  defp forward_if_nonempty(bytes), do: [{:forward, bytes}]

  # ---------------------------------------------------------------------------
  # SSE event handling
  # ---------------------------------------------------------------------------

  # Every block is reproduced with the exact terminator that closed it
  # (byte-faithful); data-less blocks (comments, keep-alives) are not
  # events — they are forwarded in stream order and not counted.
  defp handle_sse_events(state, events) do
    Enum.reduce(events, {state, [], []}, fn ev, {st, intents_acc, directives_acc} ->
      raw = ev.raw <> ev.terminator

      {st, intents, directives} =
        case ev.data do
          nil -> route_normal(st, raw)
          data -> handle_event_payload(st, data, raw)
        end

      {st, intents_acc ++ intents, directives_acc ++ directives}
    end)
  end

  defp handle_event_payload(state, payload, raw) do
    state = bump_indices(state, byte_size(raw))

    case decode_event(payload) do
      {:ok, %{"type" => type} = event} when is_binary(type) ->
        state = %{state | events_total: state.events_total + 1}
        dispatch_event(state, type, event, raw)

      _ ->
        # Malformed JSON / non-object / missing type: drift-tolerant forward.
        state = %{state | events_total: state.events_total + 1}
        state = record_unhandled(state, "event:undecodable", %{})
        route_normal(state, raw)
    end
  end

  defp decode_event(payload) when is_binary(payload) do
    case Jason.decode(String.trim(payload)) do
      {:ok, value} when is_map(value) -> {:ok, value}
      _ -> :error
    end
  end

  defp bump_indices(state, n),
    do: %{state | event_index: state.event_index + 1, byte_offset: state.byte_offset + n}

  # --- message lifecycle -----------------------------------------------------

  defp valid_block_identity?(index, type), do: is_integer(index) and is_binary(type)

  defp invalid_client_input?(type, block),
    do: type == @client_tool_block and not is_map(Map.get(block, "input"))

  defp passive_delta?(type),
    do: is_binary(type) and type in @known_deltas and type != "input_json_delta"

  defp dispatch_event(state, "message_start", event, raw) do
    message = Map.get(event, "message") || %{}
    usage = Map.get(message, "usage")

    summary =
      state.summary
      |> maybe_put(:model, string_or_nil(Map.get(message, "model")))
      |> maybe_put(:response_id, string_or_nil(Map.get(message, "id")))
      |> merge_usage(usage)

    route_normal(%{state | summary: summary}, raw)
  end

  defp dispatch_event(state, "message_delta", event, raw) do
    delta = Map.get(event, "delta") || %{}
    usage = Map.get(event, "usage")

    summary =
      state.summary
      |> maybe_put(:stop_reason, string_or_nil(Map.get(delta, "stop_reason")))
      |> merge_usage(usage)

    state = %{state | summary: summary}
    route_message_delta(state, raw, event)
  end

  defp dispatch_event(state, "message_stop", _event, raw),
    do: route_normal(%{state | summary: Map.put(state.summary, :completion_seen?, true)}, raw)

  defp dispatch_event(state, "ping", _event, raw), do: route_normal(state, raw)

  defp dispatch_event(state, "error", event, raw) do
    error = Map.get(event, "error") || %{}
    summary = maybe_put(state.summary, :error_type, string_or_nil(Map.get(error, "type")))
    route_normal(%{state | summary: summary}, raw)
  end

  # --- content blocks --------------------------------------------------------

  defp dispatch_event(state, "content_block_start", event, raw) do
    index = normalize_index(Map.get(event, "index"))
    block = Map.get(event, "content_block") || %{}
    type = Map.get(block, "type")

    cond do
      not valid_block_identity?(index, type) ->
        state = record_unhandled(state, "event:content_block_start", event)
        route_normal(state, raw)

      match?(%{type: @client_tool_block, verdict: :pending}, Map.get(state.blocks, index)) ->
        suppress_duplicate_index(state, index, raw)

      invalid_client_input?(type, block) ->
        state = record_unhandled(state, "block:invalid_tool_input", block)
        route_normal(state, raw)

      type == @client_tool_block ->
        open_tool_use_block(state, index, block, raw)

      type in @server_tool_blocks ->
        entry = %{
          type: type,
          name: string_or_nil(Map.get(block, "name")),
          id: string_or_nil(Map.get(block, "id")),
          index: index
        }

        state = %{state | server_tool_uses: state.server_tool_uses ++ [entry]}
        route_normal(register_passive_block(state, index, type), raw)

      type in @passive_blocks ->
        route_normal(register_passive_block(state, index, type), raw)

      true ->
        state = record_unhandled(state, "block:" <> type, block)
        route_normal(register_passive_block(state, index, type), raw)
    end
  end

  defp dispatch_event(state, "content_block_delta", event, raw) do
    index = normalize_index(Map.get(event, "index"))
    delta = Map.get(event, "delta") || %{}
    delta_type = Map.get(delta, "type")

    case Map.get(state.blocks, index) do
      %{type: @client_tool_block, verdict: :pending} = block ->
        {state, block} = append_tool_use_delta(state, block, delta_type, delta, raw)
        {%{state | blocks: Map.put(state.blocks, index, block)}, [], []}

      %{type: @client_tool_block, verdict: :suppressed} ->
        {state, [], [{:suppress, raw}]}

      %{type: @client_tool_block} ->
        state = record_unhandled(state, "delta:after_tool_admission", delta)
        route_normal(state, raw)

      %{type: type} when type in @server_tool_blocks and delta_type == "input_json_delta" ->
        # Arguments for an explicitly recognized upstream-executed tool are
        # observations, not executable client tool bytes awaiting admission.
        route_normal(state, raw)

      _ ->
        state =
          if passive_delta?(delta_type) do
            state
          else
            record_unhandled(state, "delta:" <> stringify(delta_type), delta)
          end

        route_normal(state, raw)
    end
  end

  defp dispatch_event(state, "content_block_stop", event, raw) do
    index = normalize_index(Map.get(event, "index"))

    case Map.get(state.blocks, index) do
      %{type: @client_tool_block, verdict: :pending} = block ->
        block = %{
          block
          | frames: [raw | block.frames],
            event_indices: [state.event_index - 1 | block.event_indices]
        }

        close_tool_use_block(state, block)

      %{type: @client_tool_block, verdict: :suppressed} ->
        {state, [], [{:suppress, raw}]}

      _ ->
        route_normal(state, raw)
    end
  end

  # --- drift -----------------------------------------------------------------

  defp dispatch_event(state, type, event, raw) when type not in @known_events do
    state = record_unhandled(state, "event:" <> type, event)
    route_normal(state, raw)
  end

  # `index` is an integer on the wire; an integral float (`0.0`, as some
  # JSON encoders emit) names the same block.
  defp normalize_index(i) when is_integer(i), do: i

  defp normalize_index(f) when is_float(f) and f >= 0 and f < 1.0e15 do
    if f == Float.floor(f), do: trunc(f), else: f
  end

  defp normalize_index(other), do: other

  # A second content_block_start at an index whose tool_use block is
  # still held: the stream contradicts itself, so neither block can be
  # trusted. The held frames, this start and every later frame at the
  # index (until its stop) are suppressed; counted as
  # `block:duplicate_index`.
  defp suppress_duplicate_index(state, index, raw) do
    block = Map.fetch!(state.blocks, index)
    state = record_unhandled(state, "block:duplicate_index", %{})
    frames = block.frames |> Enum.reverse() |> Enum.map(&{:suppress, &1})

    block =
      block
      |> Map.merge(%{verdict: :suppressed, frames: []})
      |> Map.put(:denial_text, @suppressed_text)

    state = %{
      state
      | blocks: Map.put(state.blocks, index, block),
        pending: List.delete(state.pending, block.call_id),
        denied_count: state.denied_count + 1
    }

    {state, tail} = maybe_flush_post_buffer(state)
    {state, [], frames ++ [{:suppress, raw}] ++ tail}
  end

  # ---------------------------------------------------------------------------
  # tool_use block lifecycle
  # ---------------------------------------------------------------------------

  defp open_tool_use_block(state, index, content_block, raw) do
    call_id = string_or_nil(Map.get(content_block, "id"))
    tool_name = string_or_nil(Map.get(content_block, "name"))

    initial_input =
      case Map.get(content_block, "input") do
        input when is_map(input) and map_size(input) > 0 -> Jason.encode!(input)
        _ -> ""
      end

    block = %{
      index: index,
      type: @client_tool_block,
      call_id: call_id,
      tool_name: tool_name,
      json_buffer: Shared.json_buffer_new() |> Shared.json_buffer_push(initial_input),
      frames: [raw],
      verdict: :pending,
      registration_index: state.tool_use_opened,
      start_byte_offset: state.byte_offset - byte_size(raw),
      event_indices: [state.event_index - 1]
    }

    state = %{
      state
      | blocks: Map.put(state.blocks, index, block),
        call_index:
          if(call_id, do: Map.put(state.call_index, call_id, index), else: state.call_index),
        tool_use_opened: state.tool_use_opened + 1
    }

    {state, [], []}
  end

  defp append_tool_use_delta(state, block, "input_json_delta", delta, raw) do
    partial = Map.get(delta, "partial_json")

    buffer =
      if is_binary(partial),
        do: Shared.json_buffer_push(block.json_buffer, partial),
        else: block.json_buffer

    block = %{
      block
      | json_buffer: buffer,
        frames: [raw | block.frames],
        event_indices: [state.event_index - 1 | block.event_indices]
    }

    {state, block}
  end

  defp append_tool_use_delta(state, block, delta_type, delta, raw) do
    # An unexpected delta on a tool_use block still belongs to the block
    # (it is held and released with it); it is counted as drift.
    state = record_unhandled(state, "delta:" <> stringify(delta_type), delta)

    block = %{
      block
      | frames: [raw | block.frames],
        event_indices: [state.event_index - 1 | block.event_indices]
    }

    {state, block}
  end

  defp close_tool_use_block(state, block) do
    state = %{state | blocks: Map.put(state.blocks, block.index, block)}

    case build_intent(state, block) do
      {:ok, intent} ->
        state = %{
          state
          | intent_count: state.intent_count + 1,
            pending: state.pending ++ [intent.call_id],
            call_index: Map.put(state.call_index, intent.call_id, block.index)
        }

        {state, [intent], [{:cedar_eval, intent.call_id}]}

      :error ->
        # No usable intent (missing id / name): release the block as
        # observed and count it as drift so the record says so.
        Logger.warning(fn ->
          "AnthropicMessages parser: tool_use block index=#{block.index} without id/name; requiring transport refusal"
        end)

        state = record_unhandled(state, "block:tool_use_without_id", %{})
        held = Enum.reverse(block.frames)
        block = %{block | verdict: :allowed, frames: []}
        state = %{state | blocks: Map.put(state.blocks, block.index, block)}

        Enum.reduce(held, {state, [], []}, fn raw, {st, i, d} ->
          {st, i2, d2} = route_normal(st, raw)
          {st, i ++ i2, d ++ d2}
        end)
    end
  end

  defp build_intent(state, block) do
    raw = Shared.json_buffer_raw(block.json_buffer)

    {tool_args, raw_json} =
      case Shared.json_buffer_try_decode(block.json_buffer) do
        {:ok, args} when is_map(args) -> {args, nil}
        _ when raw == "" -> {%{}, nil}
        _ -> {:too_large, raw}
      end

    input =
      %{
        call_id: block.call_id,
        tool_name: block.tool_name,
        tool_args: tool_args,
        parallel_index: resolve_parallel_index(block, state),
        provider_event_span: %{
          start_byte_offset: block.start_byte_offset,
          end_byte_offset: state.byte_offset,
          event_indices: Enum.reverse(block.event_indices),
          block_index: block.index
        }
      }
      |> then(fn m -> if raw_json, do: Map.put(m, :raw_json, raw_json), else: m end)

    case ToolUseIntent.new(input) do
      {:ok, intent} -> {:ok, intent}
      {:error, _} -> :error
    end
  end

  # Single tool_use → nil; the ordinal among tool_use blocks otherwise. A
  # block that closes before a sibling opens gets nil (the stream has not
  # revealed the parallelism yet); JSON mode sees the whole message.
  defp resolve_parallel_index(%{registration_index: idx}, %__MODULE__{tool_use_opened: opened}) do
    if opened <= 1 and idx == 0, do: nil, else: idx
  end

  defp register_passive_block(state, index, type) do
    block = %{
      index: index,
      type: type,
      call_id: nil,
      tool_name: nil,
      json_buffer: nil,
      frames: [],
      verdict: :none,
      registration_index: nil,
      start_byte_offset: 0,
      event_indices: []
    }

    %{state | blocks: Map.put(state.blocks, index, block)}
  end

  defp lookup_block(state, call_id) do
    case Map.fetch(state.call_index, call_id) do
      {:ok, index} -> Map.fetch(state.blocks, index)
      :error -> :error
    end
  end

  # ---------------------------------------------------------------------------
  # Byte routing — order preservation behind pending verdicts
  # ---------------------------------------------------------------------------

  defp route_normal(%{pending: []} = state, raw), do: {state, [], [{:forward, raw}]}

  defp route_normal(state, raw),
    do: {%{state | post_buffer: [{:raw, raw} | state.post_buffer]}, [], []}

  defp route_message_delta(%{pending: []} = state, raw, event),
    do: {state, [], [{:forward, maybe_rewrite_message_delta(state, raw, event)}]}

  defp route_message_delta(state, raw, event),
    do: {%{state | post_buffer: [{:message_delta, raw, event} | state.post_buffer]}, [], []}

  defp maybe_flush_post_buffer(%{pending: []} = state) do
    directives =
      state.post_buffer
      |> Enum.reverse()
      |> Enum.map(fn
        {:raw, raw} -> {:forward, raw}
        {:message_delta, raw, event} -> {:forward, maybe_rewrite_message_delta(state, raw, event)}
      end)

    {%{state | post_buffer: []}, directives}
  end

  defp maybe_flush_post_buffer(state), do: {state, []}

  # Fail-CLOSED at EOF (and on a parser raise): a tool_use block still
  # without a verdict is never forwarded unevaluated. Its held frames are
  # suppressed and the block counted — `block:tool_use_unterminated` when
  # its content_block_stop never arrived, `block:tool_use_unevaluated`
  # when the intent was emitted but no verdict was applied. Frames queued
  # behind the verdicts are then released in order; in JSON mode the held
  # body is forwarded with those blocks rewritten as text.
  defp suppress_unevaluated(state) do
    open =
      state.blocks
      |> Map.values()
      |> Enum.filter(&(&1.type == @client_tool_block and &1.verdict == :pending))
      |> Enum.sort_by(& &1.index)

    {state, held} =
      Enum.reduce(open, {state, []}, fn block, {st, acc} ->
        discriminator =
          if block.call_id != nil and block.call_id in st.pending,
            do: "block:tool_use_unevaluated",
            else: "block:tool_use_unterminated"

        st = record_unhandled(st, discriminator, %{})
        frames = block.frames |> Enum.reverse() |> Enum.map(&{:suppress, &1})

        block =
          block
          |> Map.merge(%{verdict: :suppressed, frames: []})
          |> Map.put(:denial_text, @suppressed_text)

        st = %{
          st
          | blocks: Map.put(st.blocks, block.index, block),
            pending: List.delete(st.pending, block.call_id),
            denied_count: st.denied_count + 1
        }

        {st, acc ++ frames}
      end)

    state = %{state | pending: []}
    {state, tail} = maybe_flush_post_buffer(state)
    {state, body} = maybe_forward_rendered_json(state, open != [])
    {state, held ++ body ++ tail}
  end

  defp maybe_forward_rendered_json(%{mode: :json} = state, true) do
    if state.summary[:json_forwarded?] == true or state.summary[:json_message] == nil do
      {state, []}
    else
      {%{state | summary: Map.put(state.summary, :json_forwarded?, true)},
       [{:forward, render_json_body(state)}]}
    end
  end

  defp maybe_forward_rendered_json(state, _), do: {state, []}

  # When every tool_use block of the message was denied, the client must
  # not wait for a tool result: stop_reason tool_use → end_turn. This is
  # the one frame that is re-encoded rather than forwarded verbatim.
  defp maybe_rewrite_message_delta(state, raw, event) do
    if all_denied?(state) and get_in(event, ["delta", "stop_reason"]) == "tool_use" do
      rewritten = put_in(event, ["delta", "stop_reason"], "end_turn")
      "event: message_delta\ndata: " <> Jason.encode!(rewritten) <> "\n\n"
    else
      raw
    end
  end

  defp all_denied?(%{tool_use_opened: opened, denied_count: denied}),
    do: opened > 0 and denied == opened

  # ---------------------------------------------------------------------------
  # JSON (non-streaming) mode
  # ---------------------------------------------------------------------------

  defp handle_json_message(state, %{"type" => "message"} = message) do
    content = List.wrap(Map.get(message, "content"))

    summary =
      state.summary
      |> maybe_put(:model, string_or_nil(Map.get(message, "model")))
      |> maybe_put(:response_id, string_or_nil(Map.get(message, "id")))
      |> maybe_put(:stop_reason, string_or_nil(Map.get(message, "stop_reason")))
      |> merge_usage(Map.get(message, "usage"))
      |> Map.put(:json_message, message)
      |> Map.put(:completion_seen?, true)

    state = %{
      state
      | summary: summary,
        events_total: 1 + length(content),
        event_index: 1 + length(content)
    }

    tool_use_count =
      Enum.count(content, &(is_map(&1) and Map.get(&1, "type") == @client_tool_block))

    {state, intents} =
      content
      |> Enum.with_index()
      |> Enum.reduce({state, []}, fn {block, index}, {st, acc} ->
        classify_json_block(st, block, index, tool_use_count, acc)
      end)

    if intents == [] do
      {%{state | summary: Map.put(state.summary, :json_forwarded?, true)}, [],
       [{:forward, state.json_body}]}
    else
      markers = Enum.map(intents, &{:cedar_eval, &1.call_id})
      {state, intents, markers}
    end
  end

  defp handle_json_message(state, %{"type" => type} = body) do
    # `{"type":"error",...}` (HTTP 4xx/5xx) or anything else: one
    # recognised-or-not top-level object, forwarded as is.
    state = %{state | events_total: 1, event_index: 1}

    state =
      case type do
        "error" ->
          error = Map.get(body, "error") || %{}

          %{
            state
            | summary:
                maybe_put(state.summary, :error_type, string_or_nil(Map.get(error, "type")))
          }

        other ->
          record_unhandled(state, "event:" <> stringify(other), body)
      end

    {%{state | summary: Map.put(state.summary, :json_forwarded?, true)}, [],
     [{:forward, state.json_body}]}
  end

  defp handle_json_message(state, body) do
    state = %{state | events_total: 1, event_index: 1}
    state = record_unhandled(state, "event:untyped_object", body)

    {%{state | summary: Map.put(state.summary, :json_forwarded?, true)}, [],
     [{:forward, state.json_body}]}
  end

  defp classify_json_block(
         state,
         %{"type" => @client_tool_block} = block,
         index,
         tool_use_count,
         acc
       ) do
    call_id = string_or_nil(Map.get(block, "id"))
    tool_name = string_or_nil(Map.get(block, "name"))
    input = Map.get(block, "input")
    args = if is_map(input), do: input, else: nil

    parallel_index = if tool_use_count > 1, do: state.tool_use_opened, else: nil

    intent_input = %{
      call_id: call_id,
      tool_name: tool_name,
      tool_args: args,
      parallel_index: parallel_index,
      provider_event_span: %{
        start_byte_offset: 0,
        end_byte_offset: byte_size(state.json_body),
        event_indices: [index + 1],
        block_index: index
      }
    }

    case ToolUseIntent.new(intent_input) do
      {:ok, intent} ->
        entry = %{
          index: index,
          type: @client_tool_block,
          call_id: call_id,
          tool_name: tool_name,
          json_buffer: nil,
          frames: [],
          verdict: :pending,
          registration_index: state.tool_use_opened,
          start_byte_offset: 0,
          event_indices: [index + 1]
        }

        state = %{
          state
          | blocks: Map.put(state.blocks, index, entry),
            call_index: Map.put(state.call_index, call_id, index),
            tool_use_opened: state.tool_use_opened + 1,
            intent_count: state.intent_count + 1,
            pending: state.pending ++ [call_id]
        }

        {state, acc ++ [intent]}

      {:error, _} ->
        {record_unhandled(state, "block:tool_use_without_id", %{}), acc}
    end
  end

  defp classify_json_block(state, %{"type" => type} = block, index, _count, acc)
       when is_binary(type) do
    state =
      cond do
        type in @server_tool_blocks ->
          entry = %{
            type: type,
            name: string_or_nil(Map.get(block, "name")),
            id: string_or_nil(Map.get(block, "id")),
            index: index
          }

          %{state | server_tool_uses: state.server_tool_uses ++ [entry]}

        type in @passive_blocks ->
          state

        true ->
          record_unhandled(state, "block:" <> type, block)
      end

    {state, acc}
  end

  defp classify_json_block(state, _block, _index, _count, acc),
    do: {record_unhandled(state, "block:untyped", %{}), acc}

  # Rewrite the decoded message: denied tool_use blocks become text
  # blocks carrying the denial; all denied → stop_reason end_turn. No
  # denials → the original bytes, untouched.
  defp render_json_body(%{denied_count: 0} = state), do: state.json_body

  defp render_json_body(state) do
    message = state.summary.json_message
    content = List.wrap(Map.get(message, "content"))

    content =
      content
      |> Enum.with_index()
      |> Enum.map(fn {block, index} ->
        case Map.get(state.blocks, index) do
          %{verdict: v} = b when v in [:denied, :suppressed] ->
            %{"type" => "text", "text" => b[:denial_text] || "Tool call blocked by org policy."}

          _ ->
            block
        end
      end)

    message = Map.put(message, "content", content)

    message =
      if all_denied?(state) and Map.get(message, "stop_reason") == "tool_use",
        do: Map.put(message, "stop_reason", "end_turn"),
        else: message

    Jason.encode!(message)
  end

  # ---------------------------------------------------------------------------
  # Drift accounting
  # ---------------------------------------------------------------------------

  defp record_unhandled(state, discriminator, payload) do
    keys = if is_map(payload), do: Map.keys(payload) |> Enum.sort(), else: []

    Logger.warning(fn ->
      "AnthropicMessages parser: unhandled #{describe(discriminator)} keys=#{inspect(keys, limit: 12)}"
    end)

    sample = ("keys=" <> Enum.join(keys, ",")) |> binary_part_safe(@sample_max_bytes)

    %{
      state
      | events_unhandled: state.events_unhandled + 1,
        unhandled_types: MapSet.put(state.unhandled_types, discriminator),
        unhandled_samples: Map.put_new(state.unhandled_samples, discriminator, sample)
    }
  end

  defp describe("event:" <> t), do: "event type=#{inspect(t)}"
  defp describe("block:" <> t), do: "content_block type=#{inspect(t)}"
  defp describe("delta:" <> t), do: "delta type=#{inspect(t)}"
  defp describe("stream:" <> t), do: "stream #{t}"
  defp describe("parser:" <> t), do: "parser #{t}"
  defp describe(other), do: "type=#{inspect(other)}"

  defp binary_part_safe(bin, max) when byte_size(bin) <= max, do: bin
  defp binary_part_safe(bin, max), do: binary_part(bin, 0, max)

  # ---------------------------------------------------------------------------
  # Summary
  # ---------------------------------------------------------------------------

  defp build_summary(state) do
    summary = Map.drop(state.summary, [:json_message, :json_forwarded?])
    usage = Map.get(summary, :usage, %{})

    Map.merge(summary, %{
      intent_count: state.intent_count,
      event_count: state.events_total,
      events_total: state.events_total,
      events_unhandled: state.events_unhandled,
      unhandled_types: state.unhandled_types |> MapSet.to_list() |> Enum.sort(),
      unhandled_samples: state.unhandled_samples,
      format: state.format,
      betas_requested: state.betas_requested,
      tool_use_count: state.tool_use_opened,
      denied_count: state.denied_count,
      server_tool_uses: state.server_tool_uses,
      prompt_token_count: token(Map.get(usage, "input_tokens")),
      completion_token_count: token(Map.get(usage, "output_tokens")),
      reasoning_token_count: token(get_in(usage, ["output_tokens_details", "thinking_tokens"])),
      model: Map.get(summary, :model),
      response_id: Map.get(summary, :response_id)
    })
  end

  # `message_start.usage` is the first sighting; `message_delta.usage`
  # (or the whole-message usage in JSON mode) is authoritative for
  # every key it carries. Keys are merged so `input_tokens` from
  # message_start survives a message_delta that omits it.
  defp merge_usage(summary, usage) when is_map(usage) do
    merged = Map.merge(Map.get(summary, :usage, %{}), usage)
    Map.put(summary, :usage, merged)
  end

  defp merge_usage(summary, _), do: summary

  defp token(n) when is_integer(n) and n >= 0, do: n
  defp token(_), do: nil

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)

  defp string_or_nil(s) when is_binary(s) and s != "", do: s
  defp string_or_nil(_), do: nil

  defp nonempty(s) when is_binary(s) do
    case String.trim(s) do
      "" -> nil
      t -> t
    end
  end

  defp nonempty(_), do: nil

  defp stringify(s) when is_binary(s), do: s
  defp stringify(nil), do: "nil"
  defp stringify(other), do: inspect(other)
end
