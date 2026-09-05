defmodule Recurse.Shared.LlmProxy.Parsers.Parser do
  @moduledoc """
  Behaviour contract for per-API-format streaming parsers in the LLM proxy.

  Spec source of truth: `specs/009-llm-api-proxy/contracts/per_provider_parser.md`.

  All four per-provider parsers (`OpenaiResponses`, `OpenaiChatCompletions`,
  `AnthropicMessages`, `GoogleGemini`) implement this behaviour. The proxy
  core feeds them upstream byte chunks one at a time and they:

    1. accumulate state across chunks (the JSON / SSE event boundary may not
       align with the chunk boundary — see
       `Recurse.Shared.LlmProxy.Parsers.Shared`);
    2. emit zero-or-more `Recurse.Shared.LlmProxy.ToolUseIntent.t()` values
       once a full tool-use intent has been observed; and
    3. return `forward_directive`s that tell the proxy what to do with the
       upstream bytes — forward unchanged, suppress (the denial injector
       will splice in synthetic content), or flush queued synthetic content.

  ## Invariants (from contract)

    * **I-001** — `parse_chunk/2` is **total** over byte input. It MUST
      NEVER raise. Unparseable input emits `{:parser_error, reason}`.
      The proxy interrupts the stream, suppresses held executable bytes,
      and records `parser_failure`; EOF cannot release the held bytes.
    * **I-002** — For any well-formed response stream, the union of forward
      directives across all `parse_chunk/2` calls equals the original byte
      stream (modulo `:suppress` spans, which are paired with explicit
      replacements by the denial injector in Phase 4).
    * **I-003** — `ToolUseIntent` is emitted exactly once per logical
      tool-use intent, regardless of how the chunks are split.
    * **I-004** — Adversarial chunk-splitting (random byte boundaries) does
      NOT cause duplicate or missed intents.
    * **I-005** — Unknown fields within recognized, non-executable events
      may be forwarded. Unknown executable block types or incomplete tool
      frames fail closed. Drift counters describe the observed uncertainty.

  ## Lifecycle

      state0 = MyParser.init(opts)
      {state1, intents1, forwards1} = MyParser.parse_chunk(state0, chunk1)
      {state2, intents2, forwards2} = MyParser.parse_chunk(state1, chunk2)
      ...
      {summary, final_forwards} = MyParser.finalize(stateN)

  `init/1` opts are parser-specific. `finalize/1` is invoked by the proxy
  when the upstream stream closes; it lets the parser flush any
  unfinished accumulators and return a summary map (token counts, intent
  count, etc.) that the attestation emitter records on the parent
  `:llm_call_attested` predicate.

  ## Forward directives

  Parsers emit a list of `t:forward_directive/0` per chunk. The proxy
  applies them in order to its outbound stream:

    * `{:forward, bytes}` — write `bytes` to the client unchanged.
    * `{:suppress, span}` — drop `span` from the client stream. The denial
      injector queues a synthetic replacement (Phase 4) before the next
      `:forward` resumes.
    * `:flush_pending` — request the injector to flush any queued
      synthetic content NOW (used at intent boundaries).

  ## See also

    * `Recurse.Shared.LlmProxy.Parsers.Shared` — transport-agnostic SSE +
      WebSocket-frame helpers used by all four implementations.
    * `Recurse.Shared.LlmProxy.ToolUseIntent` — the canonical struct
      parsers emit.
  """

  alias Recurse.Shared.LlmProxy.ToolUseIntent

  @typedoc """
  Opaque per-implementation state. Threaded through `parse_chunk/2`; the
  proxy MUST NOT inspect or mutate it directly.
  """
  @type state :: term()

  @typedoc """
  A single forward directive emitted per chunk. See module doc.

    * `{:forward, bytes}` — write `bytes` to the client unchanged.
    * `{:suppress, bytes}` — drop `bytes` from the client stream.
    * `{:parser_error, reason}` — stop forwarding: these bytes cannot be
      classified safely. The transport must fail closed, including EOF.
    * `:flush_pending` — request the injector to flush any queued
      synthetic content NOW.
    * `{:cedar_eval, call_id}` — Phase 6 byte-precise suppression
      marker. Emitted at the point in the stream where a `ToolUseIntent`
      was fully observed. The proxy MUST treat this as a synchronous
      hand-off: evaluate Cedar for the matching intent, call
      `apply_verdict/3` on the parser, dispatch the returned directives
      inline (preserving stream order), and only then continue
      processing subsequent directives. This is what gives codex the
      illusion of a transparent proxy while letting us drop the
      function_call frames entirely on deny.
  """
  @type forward_directive ::
          {:forward, binary()}
          | {:suppress, binary()}
          | :flush_pending
          | {:cedar_eval, call_id :: String.t()}
          | {:parser_error, reason :: atom()}

  @typedoc """
  Summary returned by `finalize/1`.

  Per-parser (each implementation records the metrics natural to its
  API format), but the keys below form the **canonical contract** the
  proxy threads into `Recurse.Gateway.LlmProxy.AttestationEmitter.call_state`.
  Phase-6 multi-provider parsers (Anthropic / Gemini / ChatCompletions)
  MUST populate the same keys when the upstream surfaces the
  equivalent value, and `nil` (or omit) when the field is unknown.

    * `:intent_count` — number of `ToolUseIntent` emitted across the
      whole call.
    * `:event_count` — number of upstream events / frames consumed.
    * `:model` — the model identifier string the upstream returned in
      its first / created event (e.g. `"gpt-5-codex"`,
      `"claude-3-5-sonnet-20241022"`). The request-side model param
      is NOT authoritative; the upstream may resolve `"gpt-4o"` to a
      specific version. Parsers MUST emit the upstream-resolved value.
    * `:prompt_token_count` — non-negative integer; from the
      provider's terminal-event usage shape (OpenAI:
      `usage.input_tokens`; Anthropic: `usage.input_tokens`; Gemini:
      `usageMetadata.promptTokenCount`).
    * `:completion_token_count` — same, output tokens.
    * `:reasoning_token_count` — non-negative integer | nil. OpenAI o1/
      o3/codex models report this in
      `usage.output_tokens_details.reasoning_tokens`. nil when the
      model doesn't surface separate reasoning tokens.
    * `:response_id` — provider-side response identifier (OpenAI
      `response.id`). Useful for cross-system correlation.

  Other fields are parser-specific (e.g. OpenaiResponses adds the raw
  `:usage` map for debugging).
  """
  @type summary :: %{
          optional(:intent_count) => non_neg_integer(),
          optional(:event_count) => non_neg_integer(),
          optional(:model) => String.t() | nil,
          optional(:prompt_token_count) => non_neg_integer() | nil,
          optional(:completion_token_count) => non_neg_integer() | nil,
          optional(:reasoning_token_count) => non_neg_integer() | nil,
          optional(:response_id) => String.t() | nil,
          optional(atom()) => term()
        }

  @doc """
  Initialize parser state from impl-specific options.
  """
  @callback init(opts :: keyword()) :: state()

  @doc """
  Consume one byte chunk from the upstream stream.

  Returns the next state, any intents fully observed during this chunk,
  and the list of forward directives the proxy should apply.

  MUST NOT raise (Invariant I-001). On unparseable input, return
  `{state, [], [{:forward, chunk}]}`.
  """
  @callback parse_chunk(state(), chunk :: binary()) ::
              {state(), [ToolUseIntent.t()], [forward_directive()]}

  @doc """
  Called when the upstream stream closes cleanly. Flushes any pending
  state and returns a summary plus any final forward directives.
  """
  @callback finalize(state()) :: {summary(), [forward_directive()]}
end
