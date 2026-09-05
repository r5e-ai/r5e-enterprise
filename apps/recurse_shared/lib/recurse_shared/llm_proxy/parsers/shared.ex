defmodule Recurse.Shared.LlmProxy.Parsers.Shared do
  @moduledoc """
  Transport-agnostic helpers used by all four per-provider parsers
  (`OpenaiResponses`, `OpenaiChatCompletions`, `AnthropicMessages`,
  `GoogleGemini`) in the LLM proxy.

  Spec source of truth: `specs/009-llm-api-proxy/contracts/per_provider_parser.md`
  ("Shared utilities" subsection).

  Per R-013, the WebSocket-frame payload format is identical to the
  SSE-event payload format for these APIs — so once a transport-specific
  framer extracts a single "event" worth of bytes, the per-provider
  parser sees the same shape regardless of whether it arrived over
  HTTPS+SSE or WSS.

  Three primitives:

    * `sse_buffer_*` — accumulator for `data: ...\\n\\n`-delimited SSE
      events. Handles event boundaries that span N chunks; handles
      multi-line `data:` payloads (RFC says concat with `\\n`, but the
      LLM-API providers all emit one-line-per-event so we keep both
      shapes correct just in case).
    * `ws_frame_buffer_*` — accumulator for WebSocket text frames. Each
      text frame IS one event; binary frames are unexpected and are
      surfaced to the caller as `{:unexpected_binary, frame}` so the
      parser can decide policy (drop / forward / log).
    * `json_buffer_*` — accumulator for JSON values streamed as deltas
      across N chunks (Anthropic's `input_json_delta`, OpenAI Responses'
      `function_call.arguments.delta`). Caller appends deltas; can probe
      `try_decode/1` at any time to see if the buffer is now a complete
      JSON value.

  ## Totality (Invariant I-001)

  Every public function in this module is **total** over byte input —
  it accepts any binary, including random garbage, partial multibyte
  UTF-8 sequences, embedded null bytes, etc., and returns a valid state
  + a list of items extracted so far. Functions NEVER raise.

  Garbage input is reflected in the output — for example,
  `sse_buffer_push/2` returns events even for malformed `data:` lines
  (the parser then `Jason.decode/1`s them and routes the decode failure
  per its own policy). This is by design: we preserve the upstream byte
  stream so the proxy can forward it unchanged on parser failure
  (per the contract's failure-mode table).
  """

  # =========================================================================
  # SSE event-line accumulator
  # =========================================================================

  @typedoc """
  Opaque accumulator state for SSE events. Keep this in your parser
  state; thread through `sse_buffer_push/2`.
  """
  @opaque sse_buffer :: %{__struct__: SseBuffer, partial: binary()}

  defmodule SseBuffer do
    @moduledoc false
    defstruct partial: ""
  end

  @typedoc """
  One SSE event extracted from the byte stream. `data` is the
  concatenated `data:` field bytes (multi-line `data:` payloads are
  joined with `\\n` per the SSE spec). `event` is the optional
  `event:` field (most LLM APIs don't use it; nil when absent).
  `raw` is the exact byte slice that constituted this event in the
  upstream stream — used by the denial injector to compute
  `provider_event_span` byte offsets.
  """
  @type sse_event :: %{
          data: binary(),
          event: String.t() | nil,
          raw: binary()
        }

  @doc "Initialize an empty SSE buffer."
  @spec sse_buffer_new() :: sse_buffer()
  def sse_buffer_new, do: %SseBuffer{}

  @doc """
  Append a chunk to the SSE buffer. Returns the new buffer plus any
  complete events extracted (zero-or-more — chunks can carry multiple
  events, half an event, or just whitespace).

  Total over byte input.
  """
  @spec sse_buffer_push(sse_buffer(), binary()) :: {sse_buffer(), [sse_event()]}
  def sse_buffer_push(%SseBuffer{partial: partial} = _buf, chunk) when is_binary(chunk) do
    combined = partial <> chunk
    {events, leftover} = extract_sse_events(combined, [], false)
    {%SseBuffer{partial: leftover}, events}
  end

  def sse_buffer_push(%SseBuffer{} = buf, _not_binary), do: {buf, []}

  @typedoc """
  One SSE block as `sse_buffer_push_all/2` yields it: like `t:sse_event/0`
  but `data` is `nil` for blocks that carried no `data:` line (comments,
  keep-alives, unknown fields), and `terminator` is the exact separator
  that closed the block (`"\n\n"`, `"\r\n\r\n"` or `"\r\r"`; `""` for the
  unterminated tail returned by `sse_buffer_flush_all/1`). `raw <>
  terminator` over every item reproduces the upstream bytes exactly.
  """
  @type sse_item :: %{
          data: binary() | nil,
          event: String.t() | nil,
          raw: binary(),
          terminator: binary()
        }

  @doc """
  Like `sse_buffer_push/2` but byte-faithful: every block is returned,
  including data-less ones (as `data: nil`), each with the terminator
  that closed it. Parsers that must reproduce the upstream stream
  exactly (spec 012 S4 `AnthropicMessages`) use this; `sse_buffer_push/2`
  keeps dropping comment-only blocks for the callers that never needed
  them.
  """
  @spec sse_buffer_push_all(sse_buffer(), binary()) :: {sse_buffer(), [sse_item()]}
  def sse_buffer_push_all(%SseBuffer{partial: partial} = _buf, chunk) when is_binary(chunk) do
    combined = partial <> chunk
    {items, leftover} = extract_sse_events(combined, [], true)
    {%SseBuffer{partial: leftover}, items}
  end

  def sse_buffer_push_all(%SseBuffer{} = buf, _not_binary), do: {buf, []}

  @doc """
  Byte-faithful flush: the unterminated tail (if any) comes back as one
  item with `terminator: ""` — parsed as an event when it has `data:`
  lines, `data: nil` otherwise — so no byte is ever dropped at EOF.
  """
  @spec sse_buffer_flush_all(sse_buffer()) :: {sse_buffer(), [sse_item()]}
  def sse_buffer_flush_all(%SseBuffer{partial: ""} = buf), do: {buf, []}

  def sse_buffer_flush_all(%SseBuffer{partial: partial}) do
    {%SseBuffer{}, [block_item(partial, "")]}
  end

  @doc """
  Flush whatever's left in the buffer at stream end. Returns any
  trailing event whose terminator was elided by the upstream + the empty
  buffer. Most well-formed SSE streams will return `[]` here (the
  terminating `\\n\\n` was sent before close).
  """
  @spec sse_buffer_flush(sse_buffer()) :: {sse_buffer(), [sse_event()]}
  def sse_buffer_flush(%SseBuffer{partial: ""} = buf), do: {buf, []}

  def sse_buffer_flush(%SseBuffer{partial: partial}) do
    case parse_one_sse_block(partial) do
      {:ok, ev} -> {%SseBuffer{}, [ev]}
      :empty -> {%SseBuffer{}, []}
    end
  end

  # Walk `binary` extracting events delimited by `\n\n` (also tolerates
  # `\r\n\r\n` and CR-only `\r\r` per the SSE spec, which admits all three
  # line endings). Returns {events_in_order, leftover}.
  # With `keep_empty?` data-less blocks are returned as `data: nil` items
  # and every item carries its `terminator` (byte-faithful mode).
  defp extract_sse_events(binary, acc, keep_empty?) do
    case find_sse_terminator(binary) do
      :not_found ->
        {Enum.reverse(acc), binary}

      {block, sep, rest} ->
        case {parse_one_sse_block(block), keep_empty?} do
          {{:ok, ev}, true} ->
            extract_sse_events(rest, [Map.put(ev, :terminator, sep) | acc], true)

          {{:ok, ev}, false} ->
            extract_sse_events(rest, [ev | acc], false)

          {:empty, true} ->
            extract_sse_events(rest, [block_item(block, sep) | acc], true)

          {:empty, false} ->
            extract_sse_events(rest, acc, false)
        end
    end
  end

  defp block_item(block, sep) do
    case parse_one_sse_block(block) do
      {:ok, ev} -> Map.put(ev, :terminator, sep)
      :empty -> %{data: nil, event: nil, raw: block, terminator: sep}
    end
  end

  # Returns {block_with_terminator_stripped, terminator, remainder} or
  # :not_found. All three separators are searched and the earliest wins,
  # so a stream that mixes LF, CRLF and CR blocks splits at the right
  # place.
  defp find_sse_terminator(binary) do
    [
      {"\n\n", :binary.match(binary, "\n\n")},
      {"\r\n\r\n", :binary.match(binary, "\r\n\r\n")},
      {"\r\r", :binary.match(binary, "\r\r")}
    ]
    |> Enum.reject(fn {_sep, m} -> m == :nomatch end)
    |> Enum.min_by(fn {_sep, {start, _len}} -> start end, fn -> nil end)
    |> case do
      nil ->
        :not_found

      {sep, {start, len}} ->
        prefix = :binary.part(binary, 0, start)
        suffix = :binary.part(binary, start + len, byte_size(binary) - start - len)
        {prefix, sep, suffix}
    end
  end

  # Parse one SSE block (the bytes BEFORE the terminator) into an event.
  # Returns :empty for blocks consisting only of comments / blanks / unknown
  # fields with no `data:` lines (the SSE spec says: dispatch only when the
  # data buffer is non-empty).
  defp parse_one_sse_block(""), do: :empty

  defp parse_one_sse_block(block) when is_binary(block) do
    # `:binary.matches/2` picks the longest pattern at a position, so a
    # CRLF pair never splits into an empty CR-terminated line.
    lines = String.split(block, ["\r\n", "\n", "\r"])

    {data_lines, event_field} =
      Enum.reduce(lines, {[], nil}, fn line, {data_acc, event_acc} ->
        case parse_sse_line(line) do
          {:data, value} -> {[value | data_acc], event_acc}
          {:event, value} -> {data_acc, value}
          # comments, unknown fields, blank lines
          :skip -> {data_acc, event_acc}
        end
      end)

    case data_lines do
      [] ->
        :empty

      _ ->
        data = data_lines |> Enum.reverse() |> Enum.join("\n")
        # `raw` reconstructs the on-wire block bytes (without the terminator).
        # The denial injector uses this to compute byte offsets; preserving
        # the exact source helps when upstream uses `\r\n` vs `\n`.
        {:ok, %{data: data, event: event_field, raw: block}}
    end
  end

  # SSE line dispatch:
  #   ":..."         → comment, skip.
  #   "field: value" → {field, value} where field ∈ {:data, :event, ...}
  #                    Per SSE: a single leading space after the colon is
  #                    stripped. Other fields (id, retry) are skipped here
  #                    because LLM APIs don't use them.
  #   ""             → blank line; the only blank-line case INSIDE a block
  #                    happens before our terminator hits; effectively a no-op.
  #   anything else  → field name with no colon — SSE spec says treat as
  #                    `field: ""`. Skipped (no useful field for us).
  defp parse_sse_line(""), do: :skip
  defp parse_sse_line(":" <> _comment), do: :skip

  defp parse_sse_line(line) do
    case :binary.split(line, ":", []) do
      [field, value] ->
        # Strip ONE leading space from value per spec.
        value = strip_one_leading_space(value)

        case field do
          "data" -> {:data, value}
          "event" -> {:event, value}
          # SSE 'id' / 'retry' / unknown fields — irrelevant for LLM APIs.
          _ -> :skip
        end

      [_no_colon] ->
        :skip
    end
  end

  defp strip_one_leading_space(<<" ", rest::binary>>), do: rest
  defp strip_one_leading_space(other), do: other

  # =========================================================================
  # WebSocket text-frame collector
  # =========================================================================

  @typedoc """
  Opaque WS-frame buffer. Frames arrive as discrete units from the
  WebSocket stack — there is no chunk-boundary problem, but we accumulate
  unexpected binary frames separately so the parser can decide what to
  do with them.
  """
  @opaque ws_frame_buffer :: %{__struct__: WsFrameBuffer, unexpected: [binary()]}

  defmodule WsFrameBuffer do
    @moduledoc false
    defstruct unexpected: []
  end

  @typedoc """
  A WebSocket frame as seen by the parser. Per R-013, text frames carry
  the same payload format as SSE event `data:` lines, so per-provider
  parsers can reuse the same JSON decoder for both transports.
  """
  @type ws_frame ::
          {:text, binary()}
          | {:unexpected_binary, binary()}

  @doc "Initialize an empty WS frame buffer."
  @spec ws_frame_buffer_new() :: ws_frame_buffer()
  def ws_frame_buffer_new, do: %WsFrameBuffer{}

  @doc """
  Push a single WS frame. Text frames are returned verbatim; binary
  frames are accumulated under `:unexpected` for later inspection
  (LLM APIs don't use binary frames; the proxy should log + forward
  but not parse).

  Total over input.
  """
  @spec ws_frame_buffer_push(ws_frame_buffer(), {:text, binary()} | {:binary, binary()} | term()) ::
          {ws_frame_buffer(), [ws_frame()]}
  def ws_frame_buffer_push(%WsFrameBuffer{} = buf, {:text, payload}) when is_binary(payload) do
    {buf, [{:text, payload}]}
  end

  def ws_frame_buffer_push(%WsFrameBuffer{unexpected: prev} = buf, {:binary, payload})
      when is_binary(payload) do
    {%WsFrameBuffer{buf | unexpected: [payload | prev]}, [{:unexpected_binary, payload}]}
  end

  # Anything else — control frames, malformed input, etc. — is a no-op.
  def ws_frame_buffer_push(%WsFrameBuffer{} = buf, _other), do: {buf, []}

  @doc "Returns the list of unexpected binary frames seen so far (oldest-first)."
  @spec ws_frame_buffer_unexpected(ws_frame_buffer()) :: [binary()]
  def ws_frame_buffer_unexpected(%WsFrameBuffer{unexpected: u}), do: Enum.reverse(u)

  # =========================================================================
  # Partial-JSON accumulator
  # =========================================================================

  @typedoc """
  Opaque JSON buffer state. Append delta strings via `json_buffer_push/2`;
  call `json_buffer_try_decode/1` to probe whether the buffer is now a
  complete JSON value.
  """
  @opaque json_buffer :: %{__struct__: JsonBuffer, raw: binary()}

  defmodule JsonBuffer do
    @moduledoc false
    defstruct raw: ""
  end

  @doc "Initialize an empty JSON buffer."
  @spec json_buffer_new() :: json_buffer()
  def json_buffer_new, do: %JsonBuffer{}

  @doc """
  Append a delta to the JSON buffer. No parsing happens here; the buffer
  just accumulates bytes. Total over byte input.
  """
  @spec json_buffer_push(json_buffer(), binary()) :: json_buffer()
  def json_buffer_push(%JsonBuffer{raw: raw} = buf, delta) when is_binary(delta) do
    %JsonBuffer{buf | raw: raw <> delta}
  end

  def json_buffer_push(%JsonBuffer{} = buf, _not_binary), do: buf

  @doc """
  Try to decode the buffer as a complete JSON value. Returns
  `{:ok, decoded}` if the buffer is currently a complete JSON value,
  `{:partial, _}` if more bytes are needed, `{:error, _}` for malformed
  input. Does NOT mutate the buffer; caller decides whether to reset
  it after a successful decode.

  Total over byte input — wraps `Jason.decode/1` and never raises.
  """
  @spec json_buffer_try_decode(json_buffer()) ::
          {:ok, term()} | {:partial, binary()} | {:error, term()}
  def json_buffer_try_decode(%JsonBuffer{raw: ""}), do: {:partial, ""}

  def json_buffer_try_decode(%JsonBuffer{raw: raw}) do
    case Jason.decode(raw) do
      {:ok, value} ->
        {:ok, value}

      {:error, %Jason.DecodeError{} = err} ->
        # Heuristic: classify "unexpected end of input" / unclosed-string /
        # unclosed-object as :partial; all others as :error. We don't have
        # a reliable typed signal from Jason for this, so we recompute by
        # checking bracket-balance with string awareness.
        if json_looks_partial?(raw) do
          {:partial, raw}
        else
          {:error, err}
        end
    end
  end

  @doc "Return the raw buffer contents (used by callers that need to hash/forward the bytes)."
  @spec json_buffer_raw(json_buffer()) :: binary()
  def json_buffer_raw(%JsonBuffer{raw: raw}), do: raw

  @doc "Reset the buffer to empty."
  @spec json_buffer_reset(json_buffer()) :: json_buffer()
  def json_buffer_reset(%JsonBuffer{}), do: %JsonBuffer{}

  # Cheap structural-balance check that distinguishes partial JSON from
  # malformed JSON. Walks the bytes once tracking:
  #   * brace/bracket depth
  #   * inside-string state (with escape awareness)
  # If at end-of-input we're still inside a string OR depth > 0, the input
  # is partial — more bytes could complete it. If depth < 0 (more closers
  # than openers), the input is genuinely malformed. If depth == 0 and
  # not in a string, but Jason still failed to decode, it's malformed
  # (e.g. trailing garbage, bad number literal).
  defp json_looks_partial?(<<>>), do: true
  defp json_looks_partial?(raw) when is_binary(raw), do: scan_json(raw, 0, false, false)

  # scan_json(rest, depth, in_string?, escape?)
  defp scan_json(<<>>, depth, in_string?, _escape?) do
    in_string? or depth > 0
  end

  defp scan_json(<<_c, rest::binary>>, depth, true, true),
    do: scan_json(rest, depth, true, false)

  defp scan_json(<<?\\, rest::binary>>, depth, true, false),
    do: scan_json(rest, depth, true, true)

  defp scan_json(<<?", rest::binary>>, depth, true, false),
    do: scan_json(rest, depth, false, false)

  defp scan_json(<<_c, rest::binary>>, depth, true, false),
    do: scan_json(rest, depth, true, false)

  defp scan_json(<<?", rest::binary>>, depth, false, _),
    do: scan_json(rest, depth, true, false)

  defp scan_json(<<c, rest::binary>>, depth, false, _) when c in [?{, ?[],
    do: scan_json(rest, depth + 1, false, false)

  defp scan_json(<<c, rest::binary>>, depth, false, _) when c in [?}, ?]] do
    if depth <= 0 do
      # More closers than openers — malformed, not partial.
      false
    else
      scan_json(rest, depth - 1, false, false)
    end
  end

  defp scan_json(<<_c, rest::binary>>, depth, false, _),
    do: scan_json(rest, depth, false, false)
end
