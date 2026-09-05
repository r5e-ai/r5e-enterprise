defmodule Recurse.Shared.LlmProxy do
  @moduledoc """
  LLM API proxy — provider-agnostic shared types and parsers.

  Spec: `specs/009-llm-api-proxy/`
  Linear epic filter: `from-speckit:009-llm-api-proxy`

  This namespace hosts the **provider-agnostic** primitives that both the
  Gateway proxy (`Recurse.Gateway.LlmProxy.*`) and audit-side consumers
  depend on:

  * `#{inspect(__MODULE__)}.ToolUseIntent` — canonical struct extracted
    from streaming responses (per-API parsers converge into this shape).
    See `contracts/tool_use_intent.md`.

  * `#{inspect(__MODULE__)}.Parsers.Parser` — the behaviour that all 4
    per-API streaming parsers (OpenaiResponses, OpenaiChatCompletions,
    AnthropicMessages, GoogleGemini) implement.

  * `#{inspect(__MODULE__)}.Parsers.Shared` — transport-agnostic helpers
    (SSE event-line splitter, WebSocket text-frame collector,
    partial-JSON accumulator) used by all 4 parsers.

  Implementation lives under `Recurse.Gateway.LlmProxy.*` (proxy +
  routing + Cedar gate + denial injector + attestation emitter).

  See `specs/009-llm-api-proxy/plan.md` for the 6-phase build plan
  and `tasks.md` for the 128-task work breakdown.
  """
end
