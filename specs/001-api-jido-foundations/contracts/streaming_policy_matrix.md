# Streaming Policy Matrix (Deliverable G — FR-012)

Authoritative endpoint → streaming-kind mapping for Recurse Enterprise v1.0.
Every endpoint in `openapi.yaml` (T049) appears here with its streaming
classification, cancellation semantics, and terminal-frame shape. This file
is the single source of truth referenced by Gateway ingress, SSE pipe
construction, and client-side SDK code generation.

**Streaming kinds (FR-012):**

- **`sync`** — single request / single response. No streaming. The client
  receives the complete payload in the HTTP response body.
- **`sse`** — Server-Sent Events. HTTP response `Content-Type: text/event-stream`.
  The server emits a sequence of `event:`/`data:` frames terminated by either
  a natural `completed` frame, a `completed_with_denial` frame (FR-016f), or a
  `cancellation` frame (FR-029).
- **`ws`** — WebSocket. **Not used in v1.0.** Reserved for future protocols that
  legitimately require bidirectional binary framing (not LLM / MCP). Any `ws`
  endpoint would require a changelog entry per FR-006.

**Cancellation semantics (FR-029):**

- Sync endpoints — the client aborts the HTTP request (TCP RST or HTTP/2
  RST_STREAM). Server best-effort cancels in-flight upstream work; no terminal
  frame (there is no stream to close).
- SSE endpoints — two paths:
  - **Client-side close**: the client closes the TCP connection. The Gateway
    emits a `cancellation` frame on the disconnecting stream (best-effort; may
    be lost if the peer has already RST'd) AND records a `cancellation` event
    in the session chain. Session transitions to `cancelled` per FR-044.
  - **Control Plane DELETE / explicit cancel**: the client calls
    `/v1/orchestrator/sessions/{session_id}/cancel` (or equivalent operation
    resource). The Runtime emits a terminal `cancellation` frame on every
    in-flight SSE stream for that session before closing, then transitions the
    session to `cancelled`.

## Matrix

| Plane        | Method | Path                                                   | Streaming | Cancellation semantics                                                                                                    | Terminal frame shape                                                                                 |
|--------------|--------|--------------------------------------------------------|-----------|---------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------|
| Observability| GET    | `/healthz`                                             | `sync`    | n/a — response completes in milliseconds                                                                                  | n/a                                                                                                  |
| Observability| GET    | `/readyz`                                              | `sync`    | n/a                                                                                                                       | n/a                                                                                                  |
| Observability| GET    | `/metrics`                                             | `sync`    | n/a                                                                                                                       | n/a                                                                                                  |
| Data         | POST   | `/v1/chat/completions`                                 | `sse`*    | Client close → `cancellation` frame best-effort; Runtime-initiated cancel via Control Plane → `cancellation` frame guaranteed | `completed` \| `completed_with_denial` (FR-016f) \| `cancellation` (FR-029) — OpenAI-shaped delta with `finish_reason` |
| Data         | POST   | `/v1/embeddings`                                       | `sync`    | n/a                                                                                                                       | n/a                                                                                                  |
| Data         | GET    | `/v1/models`                                           | `sync`    | n/a                                                                                                                       | n/a                                                                                                  |
| Data         | GET    | `/v1/mcp/{server_name}/sse`                            | `sse`     | Client close → `cancellation` MCP error frame best-effort; cancel endpoint → guaranteed                                   | MCP-protocol `finished` frame on normal completion; `error` frame with `policy_canonical_hash` on FR-016a/f denial; `cancellation` on FR-029 |
| Data         | POST   | `/v1/mcp/{server_name}/messages`                       | `sync`    | n/a                                                                                                                       | n/a                                                                                                  |
| Control      | POST   | `/v1/orchestrator/spawn`                               | `sync`    | n/a (returns 202 immediately; lifecycle observed via session endpoints)                                                   | n/a                                                                                                  |
| Control      | GET    | `/v1/orchestrator/sessions`                            | `sync`    | n/a                                                                                                                       | n/a                                                                                                  |
| Control      | POST   | `/v1/orchestrator/sessions/{session_id}/cancel`        | `sync`    | n/a (this IS the cancel trigger for Data Plane SSE streams)                                                               | n/a                                                                                                  |
| Control      | GET    | `/v1/version`                                          | `sync`    | n/a                                                                                                                       | n/a                                                                                                  |
| Governance   | POST   | `/v1/governance/policy/bundle`                         | `sync`    | n/a                                                                                                                       | n/a                                                                                                  |
| Governance   | GET    | `/v1/governance/policy/bundle`                         | `sync`    | n/a                                                                                                                       | n/a                                                                                                  |
| Governance   | GET    | `/v1/governance/policy/{policy_bundle_digest}`         | `sync`    | n/a                                                                                                                       | n/a                                                                                                  |
| Governance   | POST   | `/v1/governance/policy/simulate`                       | `sync`    | deferred to T085; will be `sync`                                                                                          | n/a                                                                                                  |
| Governance   | POST   | `/v1/governance/policy/propose-from-event`             | `sync`    | deferred to T085; will be `sync`                                                                                          | n/a                                                                                                  |
| Governance   | POST   | `/v1/governance/policy/blast-radius`                   | `sync`    | deferred to T085; will be `sync` (large replays chunk via pagination, NOT SSE)                                            | n/a                                                                                                  |
| Audit        | GET    | `/v1/audit/receipts`                                   | `sync`    | n/a                                                                                                                       | n/a                                                                                                  |
| Audit        | GET    | `/v1/audit/receipts/{run_id}/{step_id}`                | `sync`    | n/a                                                                                                                       | n/a                                                                                                  |
| Audit        | GET    | `/v1/audit/sessions/{session_id}`                      | `sync`    | n/a                                                                                                                       | n/a                                                                                                  |
| Audit        | GET    | `/v1/audit/broker/{payload_uri_hash}`                  | `sync`    | n/a (payloads stream within the HTTP response body but are single-payload, not framed SSE)                                | n/a                                                                                                  |
| Audit        | POST   | `/v1/audit/export`                                     | `sync`    | deferred to T089; will be `sync` returning a one-shot `.zip`                                                              | n/a                                                                                                  |
| Audit        | POST   | `/v1/audit/forward`                                    | `sync`    | deferred to T089; will be `sync` (NDJSON emission is operator-side, not an SSE stream)                                    | n/a                                                                                                  |

\* `/v1/chat/completions` is `sse` when `stream: true` is present in the request
body; otherwise it is `sync`. Protocol-native — matches OpenAI semantics.

## Terminal frame schemas (SSE endpoints only)

### OpenAI-compatible — `/v1/chat/completions`

Natural completion: OpenAI's own `data: {"choices":[{"index":0,"finish_reason":"stop",...}]}` followed by `data: [DONE]`.

FR-016f mid-stream denial — synthetic delta carrying denial metadata followed
by `data: [DONE]`:

```
data: {"choices":[{"index":0,"delta":{"role":"assistant","content":null,"tool_calls":[]},"finish_reason":"content_filter","x_recurse":{"event":"completed_with_denial","policy_canonical_hash":"<hex>","correlation_id":"<ulid>"}}]}

data: [DONE]
```

FR-029 cancellation — synthetic delta with `finish_reason: "cancelled"` and
`x_recurse.event: "cancellation"` followed by `data: [DONE]`:

```
data: {"choices":[{"index":0,"delta":{},"finish_reason":"cancelled","x_recurse":{"event":"cancellation","reason":"client_disconnect","correlation_id":"<ulid>"}}]}

data: [DONE]
```

### MCP SSE — `/v1/mcp/{server_name}/sse`

Natural completion: a protocol-shaped `finished` notification on the MCP
response channel.

Denial (FR-016a initial denial, FR-016f mid-stream flip): MCP-protocol `error`
frame with error-data carrying:

```json
{
  "event": "deny",
  "policy_canonical_hash": "<hex>",
  "matched_rules": ["<rule-id>"],
  "correlation_id": "<ulid>",
  "message": "tool call denied by Cedar policy"
}
```

Cancellation (FR-029): MCP-protocol `error` frame or `cancelled` notification
with data:

```json
{
  "event": "cancellation",
  "reason": "client_disconnect" | "client_delete" | "operator_abort",
  "correlation_id": "<ulid>",
  "session_id": "<ulid>"
}
```

Both the OpenAI and MCP terminal-denial frames correspond to the
`DeniedCallFrame` component schema in `openapi.yaml`. The cancellation frames
correspond to `CancellationFrame`.

## Non-HTTP-protocol streams

The session chain is NOT a public API stream; it is an internal Runtime
durable-WAL + commit pipeline (per FR-036 / FR-037 / FR-040). Auditors do not
subscribe to it — they query the Audit Plane endpoints above.

## Cross-references

- `openapi.yaml` — declares `x-recurse-streaming` on every endpoint matching
  this table.
- `error_codes.md` — the FR-010 codes referenced by non-Data-Plane responses.
- `session_lifecycle.md` (T078, Deliverable L) — state machine for `cancelled`
  transition triggered by FR-029.
