# Contract: Live-tail Transport (WebSocket)

**Feature**: F004 | **Spec**: FR-013, Edge Case "Live-tail reconnection" | **Research**: D2 | **Glossary**: Live-tail

This contract defines the WebSocket transport that delivers newly-committed receipts to authenticated audit-console browsers in real time. Per D2, WebSocket (not SSE) is the chosen primary transport because client-side filter changes are bidirectional and must update the server-side filter without re-establishing the connection.

---

## Endpoint

**HTTP upgrade**: `GET /admin/live-tail` — handled by the Bandit WebSocket adapter.

**Authentication**: Session Cookie ONLY. The cookie is `Path=/admin`, so it accompanies the WebSocket upgrade automatically. The handler validates the cookie at upgrade time:

1. Extract `r5e_session` cookie from the upgrade request.
2. Decrypt + validate per `browser_oidc_flow.md`.
3. Run Cedar evaluation: `(principal, Recurse::Action::"DashboardQuery", Resource::ConsoleSurface, ctx)`. Deny → `HTTP 403` upgrade rejection + emit `:policy_denied` receipt.
4. Allow → upgrade succeeds; emit `:ui_session` `event: "live_tail_open"` receipt.

**No bearer-auth path**: Live-tail is browser-only. API clients that want a real-time receipt stream get a future endpoint under `/v1/*` (deferred).

---

## Connection state

Per-connection in-memory state:

```elixir
%LiveTailState{
  principal_subject: binary(),
  tenant_id: binary(),
  browser_session_id: binary(),
  filter: %{
    event_kind: [String.t()] | :any,
    policy_decision: :allow | :deny | :any,
    principal_subject: binary() | :any,
    tool_name: binary() | :any,
    since: DateTime.t() | :any
  },
  last_seen_run_id: Ecto.UUID.t() | nil,
  last_seen_committed_at: DateTime.t() | nil,
  last_client_ping_at: DateTime.t(),
  last_server_ping_at: DateTime.t(),
  pubsub_topic: "recurse:attestation_first_committed",
  filter_compiled: (Attestation.t() -> boolean())
}
```

The `filter_compiled` field is a closure built from the filter struct; the connection-process uses it in the `handle_info({:pubsub, attestation}, state)` callback to decide whether to forward the receipt.

---

## PubSub subscription

The handler subscribes to the existing F002 topic `recurse:attestation_first_committed` (broadcast by `PostgresMerkleLedger.commit_attestation/2` on first commit). The Gateway already broadcasts every attestation's first-commit event; F004 just adds per-connection filtering.

```elixir
@impl true
def handle_connect(conn, state) do
  Phoenix.PubSub.subscribe(Recurse.PubSub, state.pubsub_topic)
  {:ok, state}
end

@impl true
def handle_info({:attestation_first_committed, attestation}, state) do
  cond do
    attestation.tenant_id != state.tenant_id ->
      {:ok, state}  # cross-tenant filter

    state.filter_compiled.(attestation) ->
      frame = encode_attestation_frame(attestation)
      new_state = %{state | last_seen_run_id: attestation.run_id, last_seen_committed_at: attestation.committed_at}
      {:push, frame, new_state}

    true ->
      {:ok, state}
  end
end
```

At sustained 50 QPS Data Plane → ~50 attestations/sec arriving at every connection's filter; 50 filter-evals/conn/sec is trivial CPU.

---

## Frame protocol

All frames are JSON text frames; binary frames are not used.

### Server → Client frames

#### `attestation` frame (the primary frame)

```json
{
  "type": "attestation",
  "run_id": "uuid",
  "tenant_id": "string",
  "session_id": "uuid",
  "event_kind": "ui_query",
  "policy_decision": "allow",
  "principal_subject": "auth0|alice",
  "committed_at": "2026-04-24T10:05:00Z",
  "summary": "GET /v1/audit/receipts?...",
  "verification_level": "global_inclusion_verified"
}
```

The frame is the slim "row shape" used by the Dashboard's TanStack Table — same fields the table renders. Full receipt detail requires a separate `GET /v1/audit/receipts/{run_id}` (or audit-agent `fetch_receipt_detail`).

#### `filter_acknowledged` frame

Sent in response to a client `set_filter` control frame.

```json
{"type": "filter_acknowledged", "filter": {...echoed-filter-shape...}, "applied_at": "..."}
```

#### `backfill_summary` frame

Sent at connection-resume after reconnect (see Reconnection below).

```json
{
  "type": "backfill_summary",
  "from_run_id": "uuid",
  "to_run_id": "uuid",
  "delivered_count": 47,
  "truncated": false
}
```

If `truncated: true`, the gap exceeded the 1,000-receipt backfill bound and the client should display a "Some receipts may be missing — refresh to see the full window" toast.

#### `error` frame

For recoverable errors (e.g., filter validation failed):

```json
{"type": "error", "code": "invalid_filter", "message": "tool_name must be string"}
```

Recoverable errors do NOT close the connection.

#### `ping` frame

```json
{"type": "ping", "ts": "..."}
```

Server sends every 60 seconds.

#### Connection-closing close frame

WebSocket close codes:
- `1000` normal closure
- `4001` cookie expired (idle / absolute timeout)
- `4002` cross-tenant access attempt (Cedar denied a runtime check)
- `4003` server shutting down (gateway draining)
- `4408` client missed heartbeats

### Client → Server control frames

#### `set_filter` frame

```json
{
  "type": "set_filter",
  "filter": {
    "event_kind": ["chat_completion", "policy_denied"],
    "policy_decision": "deny"
  }
}
```

The server compiles the new filter into a closure, replies with `filter_acknowledged`, applies on the next emission. Filter validation failures emit an `error` frame and the previous filter remains active.

Allowed filter keys: `event_kind` (array of strings), `policy_decision` (`"allow"|"deny"|"any"`), `principal_subject` (string), `tool_name` (string), `since` (ISO 8601 timestamp). Unknown keys → `error` frame `code: "unknown_filter_key"`.

#### `pong` frame

```json
{"type": "pong", "ts": "..."}
```

Sent in response to server ping.

#### `ping` frame (client-initiated heartbeat)

```json
{"type": "ping", "ts": "..."}
```

Server replies with `pong`.

---

## Heartbeat protocol

- **Client pings every 30 seconds**. Server replies with `pong` immediately.
- **Server pings every 60 seconds**. Client replies with `pong` immediately.
- **Missed heartbeat policy**: if the server hasn't received any frame (ping, pong, or set_filter) from the client in 90 seconds, the server closes the connection with code `4408`. Symmetric on the client side: if the client hasn't received a ping/pong in 120 seconds, it auto-reconnects.

---

## Reconnection + bounded backfill

When a client reconnects (via `?last_seen_run_id=uuid` query parameter on the upgrade URL):

1. Server validates the cookie + Cedar permission as for a fresh connection.
2. Server queries the audit log for receipts with `tenant_id = state.tenant_id AND committed_at > last_seen.committed_at AND filter_match` ordered by `committed_at` ascending, **bounded to 1,000 receipts**.
3. Server emits each backfilled receipt as an `attestation` frame in chronological order.
4. Server emits a `backfill_summary` frame after the backfill completes.
5. If the gap exceeded 1,000 receipts (i.e., the 1,001st-onwards receipts were not emitted), `backfill_summary.truncated: true`.
6. After backfill, server transitions to live PubSub subscription for new receipts.

**Why 1,000-receipt bound?** Backfill is intended for short network blips, not long disconnections. A user closing their laptop overnight should see "refresh to see the full window" rather than the server replaying tens of thousands of receipts.

**Reconnection cursor security**: `last_seen_run_id` is validated to belong to `state.tenant_id` before backfill. A forged UUID from another tenant returns an empty backfill (no leakage) and the connection proceeds with live PubSub only.

---

## Backpressure

If the client's send buffer fills (slow client), the server applies backpressure:

1. After 100 unacked frames in the send queue, the server stops calling `Phoenix.PubSub.subscribe` for new attestations (effectively pausing the stream for this client).
2. After 30 seconds of no client receive activity, the server emits a `backpressure_warning` frame (a recoverable `error` frame with `code: "backpressure"`).
3. After 60 seconds, the server closes the connection with code `4408` (treating slow client as stalled).

This prevents one slow consumer from filling the WebSocket process's mailbox unboundedly.

At the SPA layer, the eviction loop described in §"SPA row cap and eviction" below
absorbs sustained 50 QPS without growing TanStack Table state unboundedly: at 50
attestations/sec the SPA evicts ~50 rows/sec to maintain the cap. Eviction is O(1) at the
tail end of the in-memory list (drop-from-back), so steady-state row-cap maintenance is
free in CPU terms; the only cost is React re-render of the visible window, which TanStack
Table already virtualizes (per D8). Server-side backpressure (1.–3. above) and SPA-side
row-cap eviction are independent mechanisms and compose: server backpressure protects the
WebSocket process mailbox; SPA row-cap eviction protects the browser's heap.

---

## SPA row cap and eviction

The SPA's TanStack Table state caps at **5,000 rows by default**. This prevents the
"walk-away tab" pathology: at sustained 50 QPS Data Plane → 50 frames/sec into the SPA, an
hour-long idle tab would otherwise accumulate ~180,000 rows in React state, causing RAM
blow-up, render lag, and eventual browser tab termination.

### Cap parameters

- **Default cap**: 5,000 rows.
- **Configurable per-tenant** via tier-config: `console.live_tail_max_rows`. Operators with
  high-end hardware and short retention windows MAY raise the cap; operators with thin
  clients (low-RAM auditors) MAY lower it. The cap is purely a client-side soft limit;
  the server enforces no equivalent.
- **Independent of the WebSocket backfill cap (1,000)**. Backfill on reconnect can refill
  up to 1,000 most recent missed receipts (per §"Reconnection + bounded backfill"); the
  SPA cap (5,000) bounds total in-memory rows regardless of backfill. Eviction on backfill
  follows the same rules below.

### Eviction policy

When a new `attestation` frame arrives and the in-memory row count is already at the cap,
the SPA drops the **oldest non-pinned row** before prepending the new row. "Pinned" rows
survive eviction; pin status comes from any of:

1. **User-selected**: rows the operator has selected (multi-select for bulk action — e.g.,
   "build a draft from these N receipts").
2. **User-favorited**: rows the operator has explicitly starred for later review (the
   `pinned: true` checkbox in the Receipt Detail drawer).
3. **In the current scroll-position window**: rows currently visible in the TanStack Table
   virtualization viewport, plus the buffer rows above and below (~30 rows total per the
   D8 prefetch buffer). Rows in this window are pinned for the duration the operator has
   the row in view, so scrolling-while-stream-flows doesn't yank rows out from under the
   cursor.

If all 5,000 rows are pinned (operator has selected the entire viewport), eviction
**stalls**: incoming attestations are dropped (not appended to the table), and the SPA
shows a sustained "Live-tail paused — clear selection to resume" toast until the operator
unpins or scrolls.

### User feedback

When eviction first fires in a session, the SPA shows a one-time toast:

> "Live-tail trimmed older rows (showing latest 5,000); use the time-range filter to view
> earlier receipts."

The toast is dismissable and does not re-fire for subsequent evictions in the same SPA
session. The "Live-tail paused" toast (the all-pinned stall case) re-fires every 30
seconds until pin pressure is released.

### Cross-reference (frontend implementation)

The TanStack Table state shape, the `useInfiniteQuery` hook that backs it, and the
eviction logic itself live in the SPA frontend; the source-of-truth implementation is
documented in `frontend_architecture.md` §"TanStack Table eviction" (owned by SA2 — the
hook description includes the row-cap eviction integration with the live-tail WebSocket
client). The numbers in this contract (5,000 cap, eviction order) are the authority that
`frontend_architecture.md` references.

---

## Cross-tenant safety

Every emitted `attestation` frame's `tenant_id` is checked against `state.tenant_id`. If a runtime configuration error leaks a foreign-tenant attestation through PubSub (shouldn't happen in single-tenant-per-BEAM Phase-1), the per-emission filter rejects it. This is defense-in-depth; the primary tenant boundary is the BEAM-per-tenant deployment shape.

---

## Property-test surface

(Tested in F004 catalog Surface "Live-tail filter correctness" + reused F002 Surface R for receipt-source.)

- **Filter-compile correctness**: a generated `filter` shape compiles to a closure that returns true for matching attestations and false otherwise. 1,000 iterations of `(filter, attestation_or_no_match)`.
- **Reconnect backfill bound**: with N=1,500 receipts in the gap window, exactly 1,000 are delivered + `truncated: true`.
- **Cross-tenant rejection**: forging `last_seen_run_id` from a different tenant yields zero backfilled receipts.
- **Heartbeat-driven close**: a client that stops sending pings for 91+ seconds is closed with code `4408`.

---

## Out of scope

- Server-Sent Events (SSE) fallback. WebSocket is sole transport. Browsers behind aggressive proxies that block WS may need to use the Dashboard's polling-fallback view (Day-2+).
- Compression (`permessage-deflate`). Bandit supports it; F004 disables to keep the wire encoding simple to diagnose during verification.
- Subprotocols. The default subprotocol is empty; future versions may negotiate `r5e-live-tail-v2`.
- Multiplexed live-tail across tenants for an operator with cross-tenant role. Not in F004 (single-tenant deployment).
