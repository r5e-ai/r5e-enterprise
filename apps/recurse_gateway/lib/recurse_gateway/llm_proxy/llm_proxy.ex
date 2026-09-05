defmodule Recurse.Gateway.LlmProxy do
  @moduledoc """
  LLM API proxy — Gateway-side wiring (Data Plane).

  Spec: `specs/009-llm-api-proxy/`
  Linear epic filter: `from-speckit:009-llm-api-proxy`

  This namespace hosts the **wire-level** Gateway-side primitives:

  * `#{inspect(__MODULE__)}.ProxyRouter` — Plug router; matches on
    `(host_header, request_path)` against `LlmProviderConfig` entries.
    Dispatches to `WebSocketBridge` or `StreamingProxy` based on
    Upgrade header.

  * `#{inspect(__MODULE__)}.StreamingProxy` — HTTPS+SSE bidirectional
    flow with per-chunk parser inspection. NO buffering.

  * `#{inspect(__MODULE__)}.WebSocketBridge` — WebSocket bidirectional
    flow via `WebSockAdapter` inbound + `Mint.WebSocket` outbound.
    Codex CLI's primary transport for `wss://chatgpt.com`.

  * `#{inspect(__MODULE__)}.UpstreamResolver` — looks up
    `LlmProviderConfig` for `(tenant_id, host_header)`.

  * `#{inspect(__MODULE__)}.BypassDnsResolver` — resolves upstream
    hostnames to their REAL IPs even when corp DNS points those names
    back at recurse-gateway (the customer's routing primitive).

  * `#{inspect(__MODULE__)}.CedarToolUseGate` — the per-call gate context
    both proxies build, and the argument-inlining threshold. The Cedar
    decision it once made here is gone: a tool is authorized by
    `Recurse.Gateway.Fold.Admission.admit_tool/3` and the kernel.

  * `#{inspect(__MODULE__)}.TokenEstimator` — proxy-side token estimator
    feeding `gate_context.estimated_completion_tokens` for FR-011 budget
    enforcement.

  * `#{inspect(__MODULE__)}.DenialInjector` — behaviour + per-API impls
    (`Denial.OpenaiResponses`, etc.) that rewrite the response stream
    when Cedar denies a tool_use intent.

  * `#{inspect(__MODULE__)}.AttestationEmitter` — DSSE-signs one
    `:llm_call_attested` per call + one `:tool_use_denied` per denied
    intent. Last step before connection close (invariant I-004).

  Provider-agnostic types live under `Recurse.Shared.LlmProxy.*`.

  See `specs/009-llm-api-proxy/plan.md` for the 6-phase build plan,
  `contracts/` for per-module specs, and `tasks.md` for the 128-task
  work breakdown.
  """
end
