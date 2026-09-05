# Contract: Streaming Proxy + WebSocket Bidirectional Bridge

**Module**: `Recurse.Gateway.LlmProxy.{ProxyRouter, StreamingProxy, WebSocketBridge, UpstreamResolver}`
**Owner phase**: Phase 2
**Consumed by**: Phase 3 (Cedar gate hooks per intent), Phase 4 (denial injector hooks via forward_directive), Phase 5 (attestation emitter on close)

## Purpose

Bidirectional streaming proxy that:
1. Accepts client connections (HTTPS or WebSocket) at recurse-gateway
2. Looks up `LlmProviderConfig` for tenant + Host header
3. Opens corresponding upstream connection (WSS or HTTPS+SSE)
4. Streams request body up; streams response body down with per-chunk parser inspection
5. Preserves all required headers per R-012
6. Closes both sides on either-side close

## Routing

```
POST /v1/llm-proxy/{provider}/{path...}                   ← logical path; not used by Codex
GET  /backend-api/codex/responses (WS upgrade or HTTPS)   ← Codex's actual path; Host: chatgpt.com
POST /v1/responses                                         ← OpenAI API-key path; Host: api.openai.com
POST /v1/messages                                          ← Anthropic; Host: api.anthropic.com
POST /v1beta/models/.../streamGenerateContent             ← Gemini; Host: generativelanguage.googleapis.com
GET  /oauth/authorize, POST /oauth/token, etc.             ← auth.openai.com flows
```

The proxy's Plug router matches on `(Host header, request path)` against `LlmProviderConfig` entries. Customer's DNS override ensures these Host headers actually arrive at recurse-gateway.

## Header preservation (CRITICAL — R-012)

ALL of the following MUST be forwarded unchanged on every proxied request:

- `Authorization: Bearer <jwt>` — bearer token
- `chatgpt-account-id: <uuid>` — required for ChatGPT-plan auth
- `OpenAI-Beta: responses=v1` — feature flag
- `originator: codex_cli_rs` — client identifier
- `session_id: <uuid>` — Codex session id
- `User-Agent: ...` — client diagnostics
- `Content-Type`, `Accept`, `Accept-Encoding`
- All `Sec-WebSocket-*` headers on WS upgrade
- All `x-anthropic-*` headers for Anthropic
- All `x-goog-*` headers for Gemini

The proxy MAY add: `X-Recurse-Trace-Id: <uuid>`, `X-Recurse-Tenant-Id: <ulid>`. The proxy MUST NOT remove any client-supplied headers.

## WebSocket bidirectional flow

```
Client (Codex CLI)        Recurse-gateway (this module)     Upstream (chatgpt.com)
────────────────          ─────────────────────────────     ──────────────────────
1. TLS connect (DNS=recurse-gateway)
2. HTTP/1.1 GET /backend-api/codex/responses
   Upgrade: websocket
   ... (all R-012 headers) ...
                          3. Validate token (basic) + tenant lookup
                          4. Open own WS to real chatgpt.com
                             (using bypass DNS resolver)
                          5. Send upgrade with all headers preserved
                                                           6. 101 Switching Protocols
                          7. Forward 101 to client
8. WS established (bidirectional)
9. Client sends text frame: request payload (JSON)
                          10. Forward frame upstream
                                                           11. Begins streaming response frames
                          12. Receive frame; parser.parse_chunk(state, frame)
                          13. {new_state, intents, [forward_directives]}
                          14. For each intent: Cedar gate (Phase 3)
                              On allow: forward original frame (forward_directive)
                              On deny: queue suppression + injector synthesizes replacement frames (Phase 4)
                          15. Send forward_directives as WS frames downstream
16. Client receives frames (original or synthesized)
... (repeat 11-16 throughout response) ...
                                                           17. Sends final completion frame
                          18. Forward; emit attestation (Phase 5)
                          19. Close downstream WS
20. Client receives close
```

## HTTPS+SSE flow (mostly identical)

Same structure but:
- Step 1-7: HTTP/1.1 or HTTP/2 connection (no WS upgrade)
- Step 9-16: SSE event frames (`data: {...}\n\n` separators) instead of WS frames
- Same parser; same Cedar; same denial injection

## Upstream connection

`Req` library with:
- Custom DNS resolver bypassing corp DNS override (recurse-gateway needs to actually reach upstream)
- Connection pooling per upstream host (avoids TLS handshake per call)
- `into: :self` for streaming response into the calling process's mailbox
- Timeout: 5min idle (long-lived streams expected)

For WebSocket: `Mint.WebSocket` with manual DNS resolution via `:inet_res.lookup/4` against the upstream resolver.

## UpstreamResolver

```elixir
@spec resolve(tenant_id :: String.t(), host_header :: String.t()) ::
        {:ok, %LlmProviderConfig{}} | {:error, :not_configured | :not_allowed}
```

Looks up the `LlmProviderConfig` for `(tenant_id, upstream_host = host_header)`. Returns the config or an error explaining why the request can't be proxied (not configured, disabled, etc.).

## Auth flow special cases

`auth.openai.com` traffic is proxied with NO parser invocation (no tool_use intents in OAuth flow). Just byte-for-byte forwarding with header preservation. Logged but not Cedar-gated in v1 (Phase 2 enhancement: Cedar-gate the login itself).

## Failure modes

| Failure | Handling |
|---|---|
| Upstream connection fails | Return 503 to client; emit `:llm_call_attested` with `error_kind: "upstream_connection_failed"` |
| Upstream auth rejects (401) | Forward 401 to client unmodified; signs attestation with `upstream_status_code: 401` |
| Upstream rate limit (429) | Forward 429 with `Retry-After` header preserved; same |
| Parser failure mid-stream | Set `error_kind: "parser_failure"`; forward subsequent chunks unchanged (fail-open on parsing — better to forward unparsed than break the stream) |
| Cedar evaluation failure | Set `error_kind: "policy_evaluation_failure"`; **fail-closed** — block the call with HTTP 503 + `:llm_call_attested` carrying the failure |
| Recurse-gateway crash mid-stream | Client connection terminated; client retries per its own logic; no half-attestation (only emit on clean call completion) |

## Test contracts

- **CT-001**: WS upgrade against a `Bypass`-mocked upstream completes with 101 Switching Protocols and bidirectional frame relay works
- **CT-002**: HTTPS+SSE roundtrip with a 100KB streaming response forwards intact (no buffering observed via memory profiling)
- **CT-003**: All R-012 headers preserved on forwarded request (verified by `Bypass`-side header capture)
- **CT-004**: Parallel WS connections (50 concurrent) all run independently without head-of-line blocking

## Performance contracts

- **P-001**: WS upgrade handshake added latency p95 < 50ms (TLS + WS upgrade + upstream WS open)
- **P-002**: Per-frame forward latency p95 < 10ms (parser + Cedar inline)
- **P-003**: 100 concurrent streams sustained per BEAM node without measurable degradation

## Dependencies

- `bandit` (existing) — HTTP server with WS support via WebSockAdapter
- `plug` (existing) — router
- `req` (existing) — outbound HTTP
- `Mint.WebSocket` (NEW Hex dep — `mint_web_socket`) — outbound WS client
- `WebSockAdapter` (existing for Phoenix; usable with Bandit) — inbound WS handler
