# Contract: Per-Provider Parser

**Module**: `Recurse.Shared.LlmProxy.Parsers.{Parser, OpenaiResponses, OpenaiChatCompletions, AnthropicMessages, GoogleGemini, Shared}`
**Owner phase**: Phase 1
**Consumed by**: Phase 2 (streaming proxy invokes parser per chunk/frame), Phase 3 (Cedar gate consumes ToolUseIntent), Phase 4 (denial injector references intent span)

## Purpose

Per-API-format streaming state machine that consumes SSE events / WebSocket frames and emits `ToolUseIntent` events as it identifies them. Shared across HTTPS+SSE and WebSocket transports — payload shape is identical between transports per R-013.

## Behaviour

```elixir
defmodule Recurse.Shared.LlmProxy.Parsers.Parser do
  @callback init(opts :: keyword()) :: state :: term()
  @callback parse_chunk(state :: term(), chunk :: binary()) ::
              {state :: term(), [Recurse.Shared.LlmProxy.ToolUseIntent.t()], [forward_directive()]}
  @callback finalize(state :: term()) :: {summary :: map(), [forward_directive()]}

  @type forward_directive ::
          {:forward, binary()}                            # forward this byte sequence to client unchanged
        | {:suppress, span :: binary()}                  # suppress this byte sequence (will be replaced by injector)
        | {:flush_pending}                                # request injector to flush any queued synthetic content
end
```

## Per-impl scope

### `Recurse.Shared.LlmProxy.Parsers.OpenaiResponses` (CRITICAL — Codex CLI primary path)

Handles the OpenAI Responses API event taxonomy:

- `response.created` → state init
- `response.output_item.added` (item.type == "function_call") → start a new function_call accumulator keyed by `item.call_id`
- `response.output_item.added` (item.type == "message" | "reasoning") → forward unchanged
- `response.function_call.arguments.delta` → append delta to the matching call_id's accumulator
- `response.function_call.completed` → emit `ToolUseIntent`; finalize the accumulator
- `response.output_text.delta`, `response.output_text.completed` → forward unchanged
- `response.completed` → emit summary + flush state
- Unknown event types → forward unchanged (per drift-tolerance in R-007)

Handles BOTH SSE-event encoding (`data: {...}\n\n`) and WebSocket-frame encoding (one event per frame). The shared utilities (`Recurse.Shared.LlmProxy.Parsers.Shared`) handle the transport detail; the `OpenaiResponses` parser sees decoded events.

Parallel function calls: multiple `function_call` items concurrent in the response (different `call_id`s). Each emits its own `ToolUseIntent`. The injector handles the response stream rewriting case-by-case if any are denied.

### `Recurse.Shared.LlmProxy.Parsers.OpenaiChatCompletions`

Legacy Chat Completions API (NOT Codex; used by other OpenAI-targeting clients):
- SSE events with `data: {...}` payloads, `data: [DONE]` terminator
- `delta.tool_calls[]` array; per-element `index`, `id`, `function.name`, `function.arguments`
- Legacy `function_call` (singleton) — degenerate case
- Parallel: multiple entries in `tool_calls[]`

### `Recurse.Shared.LlmProxy.Parsers.AnthropicMessages`

- Typed SSE events: `message_start`, `content_block_start`, `content_block_delta`, `content_block_stop`, `message_delta`, `message_stop`
- Tool use: `content_block_start` with `content_block.type == "tool_use"`, carrying `id`, `name`, `input`
- `input` accumulates via `content_block_delta` events with `delta.type == "input_json_delta"`, `delta.partial_json`
- Multiple tool uses: distinct `index`

### `Recurse.Shared.LlmProxy.Parsers.GoogleGemini`

- SSE chunks; each carries a candidate response payload
- Tool calls in `candidates[0].content.parts[]` where `part.functionCall: { name, args }`
- `args` is JSON object (not string)

### `Recurse.Shared.LlmProxy.Parsers.Shared`

- SSE event-line splitter (`data: ...\n\n` → discrete events)
- WebSocket frame collector (text frames are events; binary frames are unexpected for these APIs)
- Partial-JSON accumulator (handles JSON spanning N chunks/frames)

## Invariants

- **I-001**: `parse_chunk/2` is total over byte input; never raises. Returns `{state, [], [forward_unchanged]}` for unparseable input.
- **I-002**: For any well-formed response stream, the union of `forward_directive` byte sequences emitted across all `parse_chunk` calls equals the original byte stream (modulo suppressions which are paired with explicit replacements).
- **I-003**: `ToolUseIntent` is emitted exactly once per logical tool_use intent in the response, regardless of how the chunks are split.
- **I-004**: Adversarial chunk-splitting (random byte boundaries within an event) does NOT cause duplicate or missed intents.
- **I-005**: Unknown fields/event types in input are forwarded unmodified — provider drift tolerance.

## Test contracts

- **CT-001**: For the official Responses API sample stream from openai/codex tests, the parser extracts the expected `ToolUseIntent` list with correct `call_id`, `tool_name`, `tool_args`.
- **CT-002**: For Anthropic's `messages` streaming sample with two parallel tool uses, both intents extracted with correct `id`/`name`/`input`.
- **CT-003**: For Gemini's streaming `functionCall` sample, intent extracted with correct `name`/`args`.
- **CT-004**: For a malformed payload (truncated JSON, missing fields), parser returns `{state, [], [forward_unchanged]}` and does NOT raise.

## Property tests

- **PT-001**: Adversarial chunk-splitting — for any random N-way chunk split of a well-formed payload, the union of emitted intents equals the intents from a single-chunk parse.
- **PT-002**: Drift-tolerance — adding random unknown fields to events does not break extraction of known fields.
- **PT-003**: Parser is total — for any byte sequence (even random garbage), `parse_chunk/2` returns `{state, [], [_]}` without raising.

## Performance contracts

- **P-001**: Per-chunk parser overhead < 5ms p95 for chunks up to 64KB.
- **P-002**: 1000 chunks/sec sustained throughput single BEAM node.

## Dependencies

- `Jason` — JSON parsing
- `:crypto.hash(:sha256, _)` — for `tool_args_hash`
- No new Hex deps
