# Contract: F004 Audit API Extensions

**Feature**: F004 | **Spec**: FRs 008–046 | **Research**: D2, D5, D8 | **Extends**: F002 `/v1/audit/*` surface

This contract defines every new HTTP endpoint F004 adds to the `:recurse_gateway` OTP application on top of the F002 audit-API surface. All endpoints live under the same Bandit port / TLS cert / Docker image as the F002 Data Plane (`/v1/*` same-origin). Authentication for **browser** flows is the signed-encrypted **Session Cookie** (per `browser_oidc_flow.md`); authentication for **API** flows is the F002 `Authorization: Bearer <X-Observed-Identity-JWT>` header; both resolve identically through `JwtValidator` after `BrowserSessionPlug` lifts cookie → header.

**Canonical names**: every Cedar action and `event_kind` referenced in this
contract MUST match the canonical action / `event_kind` / lifecycle matrix at
`data-model.md` §0 verbatim. If this document and the matrix disagree, the
matrix wins; fix this document.

All error responses use the **canonical flat error envelope** shape (per
`apps/recurse_gateway/priv/schemas/error_envelope.json`, built by
`Recurse.Gateway.AuditPlane.ErrorEnvelope.build/3`):

```json
{
  "error": "ERR_UPPER_SNAKE_CODE",
  "error_description": "human-readable explanation",
  "correlation_id": "uuid-v4",
  "attested_run_id": "uuid-v4-of-denial-receipt|null"
}
```

> **Note** — F001-nested envelope retired in MR !31; canonical shape is now
> flat per `priv/schemas/error_envelope.json` (issue #30 / Task L). Earlier
> revisions of this contract referenced an "F001 error envelope" — that
> label survives only as the historical name for what is now the flat shape
> documented above.

Every endpoint's authorization is gated by a named Cedar action; see `cedar_entity_schema_extensions.md` for the full role-to-action allowlist. Every endpoint emits at least one attested `event_kind` per successful invocation and (when Cedar denies) one additional `:policy_denied`-class receipt per FR-006.

---

## Auth introspection

### `GET /v1/auth/me` — current-session principal info

Lightweight endpoint that returns the authenticated request's principal info derived from the BrowserSessionPlug-lifted JWT. Does NOT expose the JWT itself or any cookie content. Used by the SPA's `useAuth` hook to render user-info UI (avatar letter, role pill, sign-out button) without re-decoding the cookie client-side.

- **Authorization**: any authenticated principal (no Cedar gate; reading your own identity is implicit).
- **Request**: `GET /v1/auth/me`. No body. Authenticated via session cookie.
- **Response (200, application/json)**:
  ```json
  {
    "principal_subject": "alice@corp",
    "recurse_role": "tenant_auditor",
    "tenant_id": "01HQZN5K7J8M9N0P1Q2R3S4T5V",
    "browser_session_id": "01J9X4...",
    "session_expires_at": "2026-04-25T00:32:18Z",
    "session_idle_timeout_at": "2026-04-24T17:32:18Z"
  }
  ```
- **Response (401)**: no/expired cookie. SPA reacts by redirecting to `/login/start`.
- **`event_kind` emitted**: NONE. Reading your own identity does not produce a receipt (avoiding noise on every SPA boot). The browser session itself is already attested at `:ui_login` time.
- **Schema**: `/v1/schemas/auth_me.json`.

This is the only F004 endpoint that does not emit a receipt per call. The rationale is documented in `cedar_entity_schema_extensions.md`'s "Implicit-self actions" section: introspecting one's own session is not a governance-class action.

---

## Session timeline

### `GET /v1/audit/sessions/{session_id}` — session-grouped receipt view

Returns all receipts belonging to `session_id`, ordered by `sequence` ascending (chronological).

**Path params**: `session_id` (UUID).

**Query params** (optional):
- `cursor` (opaque b64, per D8) — resume after this sequence
- `limit` (integer, default 100, max 500) — page size

**Response (200)**:

```json
{
  "session_id": "uuid",
  "tenant_id": "string",
  "started_at": "2026-04-24T10:00:00Z",
  "last_seen_at": "2026-04-24T10:05:00Z",
  "epoch_count": 3,
  "receipts": [
    {
      "run_id": "uuid",
      "sequence": 1,
      "event_kind": "chat_completion",
      "policy_decision": "allow",
      "matched_policy": "platform_roles.cedar:42",
      "verification_level": "global_inclusion_verified",
      "principal_subject": "auth0|alice@corp",
      "summary": "POST /v1/chat/completions model=gpt-4o"
    }
  ],
  "next_cursor": "b64-or-null"
}
```

**Status codes**: 200 ok | 401 cookie/JWT invalid | 403 not authorized for tenant | 404 session not found | 500 internal.

**Cedar action**: `Recurse::Action::"DashboardQuery"` (session timeline is a dashboard surface; reuses dashboard action).

**event_kind emitted**: `:ui_query` with `query_kind: "session_timeline"`.

---

## Policy simulation

### `POST /v1/policy/simulate` — run Cedar source against synthetic input

Evaluates an arbitrary Cedar source against a caller-supplied synthetic `(principal, action, resource, context)` tuple. Used by the Policy Simulator "Simulate" mode.

**Request body** (`Content-Type: application/json`):

```json
{
  "cedar_source": "permit(principal, action, resource) when { ... };",
  "principal": {"kind": "Principal::Human", "id": "alice", "attrs": {...}},
  "action": "Recurse::Action::\"ChatCompletion\"",
  "resource": {"kind": "Resource::LLMEndpoint", "id": "openai/gpt-4o", "attrs": {...}},
  "context": {"tenant_id": "...", "correlation_id": "...", "timestamp": 1714000000, "client_ip": "..."}
}
```

**Response (200)**:

```json
{
  "decision": "allow|deny",
  "matched_policies": [{"id": "policy0", "effect": "permit", "line_start": 1, "line_end": 5}],
  "reasoning": "policy0 matched because principal.recurse_role == \"platform_operator\"",
  "attested_run_id": "uuid"
}
```

**Status codes**: 200 ok | 400 invalid Cedar source (parse error with line/col) | 401 auth | 403 role not allowed | 422 synthetic input invalid against Cedar Entity Schema | 500 internal.

**Cedar action**: `Recurse::Action::"PolicySimulate"`.

**event_kind emitted**: `:ui_policy_simulate`.

### `POST /v1/policy/replay/{run_id}` — replay a past receipt against deployed policy

Takes a historical `run_id`, extracts its `(principal, action, resource)` from `attestation.signed_predicate`, and evaluates against the currently-deployed Cedar bundle.

**Path params**: `run_id` (UUID of target receipt).

**Request body** (optional; allows overriding the deployed source):

```json
{
  "override_cedar_source": "permit(principal, action, resource) when { ... };" // optional
}
```

**Response (200)**:

```json
{
  "run_id": "uuid",
  "original_decision": "deny",
  "replayed_decision": "allow",
  "decision_changed": true,
  "matched_policies": [...],
  "reasoning": "...",
  "cedar_source_hash": "sha256:...",
  "attested_run_id": "uuid"
}
```

**Status codes**: 200 ok | 401 auth | 403 role not allowed | 404 run_id not found | 500 internal.

**Cedar action**: `Recurse::Action::"PolicyReplay"`.

**event_kind emitted**: `:ui_policy_replay` (a distinct event_kind from
`:ui_policy_simulate` per data-model.md §0; replay is a separate action class
because it evaluates against a real past receipt, not a synthetic input).

---

## Policy drafts

### `GET /v1/policy/drafts` — list drafts

**Query params**:
- `status` (enum: `draft|adopted_as_draft|archived`, default `draft`) — values
  match `policy_drafts.status` per data-model.md §1.1. `adopted` (deploy-pipeline
  state) is reserved for F005+ and is not currently a valid value.
- `author_principal_subject` (string, optional filter)
- `cursor`, `limit` (D8 pagination)

**Response (200)**:

```json
{
  "drafts": [
    {
      "id": "uuid",
      "tenant_id": "string",
      "author_principal_subject": "auth0|alice",
      "source_receipt_run_id": "uuid-or-null",
      "cedar_source_excerpt": "permit(principal == Principal::Human::\"alice\", ...)",
      "status": "draft",
      "created_at": "...",
      "updated_at": "...",
      "last_blast_radius_summary": {"total_affected": 47, "matches_intent": 45, "unintended": 2, "would_have_allowed": 0, "no_change": 8432}
    }
  ],
  "next_cursor": "b64-or-null"
}
```

### `POST /v1/policy/drafts` — create draft

**Request body**:

```json
{
  "cedar_source": "permit(...) when {...};",
  "scope_metadata": {"kind": "principal|role|group|tenant", "value": "..."},
  "condition_metadata": [{"attr": "tool_name", "op": "eq", "value": "bash_exec"}],
  "source_receipt_run_id": "uuid-or-null"
}
```

**Response (201)**: full draft envelope (same shape as GET item).

### `GET /v1/policy/drafts/{id}` — fetch single draft

**Response (200)**: full draft envelope, including `cedar_source` (not just excerpt).

### `PATCH /v1/policy/drafts/{id}` — edit draft

**Request body**: any subset of `{cedar_source, scope_metadata, condition_metadata}`.

**Response (200)**: updated draft.

### `DELETE /v1/policy/drafts/{id}` — soft-archive draft

Sets `status = "archived"`; draft remains readable for retention window per `retention_lifecycle.md`.

**Response (204)** — no content.

### `POST /v1/policy/drafts/from-receipt` — skeleton from receipt

**Request body**: `{"source_receipt_run_id": "uuid"}`

Generates a Cedar skeleton matching the source receipt's `(principal, action, resource)` shape; returns the draft as if created via `POST /v1/policy/drafts`.

**Response (201)**: draft envelope.

### `POST /v1/policy/drafts/{id}/dry-run` — Blast Radius computation

Per `blast_radius_algorithm.md`. Returns **synchronously** for windows ≤10K receipts; returns **202 Accepted + Oban job ID** for larger windows.

**Request body** (optional):

```json
{
  "window_days": 30,
  "async": false // default false; set true to force async
}
```

**Response (200)** (sync):

```json
{
  "draft_id": "uuid",
  "window_days": 30,
  "total_receipts_in_window": 8552,
  "total_affected": 120,
  "matches_intent": 115,
  "unintended": 5,
  "would_have_allowed": 0,
  "no_change": 8432,
  "sample_receipts": [{"run_id": "...", "classification": "unintended"}],
  "computed_at": "2026-04-24T...",
  "attested_run_id": "uuid"
}
```

**Four-cell classification** (per `blast_radius_algorithm.md` and spec FR-026):

- `matches_intent` — proposed=deny, original=deny. Rule would have correctly fired.
- `unintended` — proposed=deny, original=allow. Rule would have blocked legitimate work. **Primary risk signal.**
- `would_have_allowed` — proposed=allow, original=deny. Rule would have permitted previously-denied calls. Secondary advisory; surfaced when non-zero.
- `no_change` — proposed=allow, original=allow. Not surfaced by default in the UI; available via "show all" toggle.

Sample receipts in the response prefer `unintended` first, then `would_have_allowed`, capped at 20 entries.

**Response (202)** (async):

```json
{
  "draft_id": "uuid",
  "job_id": "oban-job-uuid",
  "poll_url": "/v1/policy/drafts/uuid/dry-run/oban-job-uuid"
}
```

**Cedar actions (per draft endpoint, per data-model.md §0)**:

| Endpoint | Cedar action | `event_kind` emitted |
|---|---|---|
| `POST /v1/policy/drafts` | `PolicyDraftCreate` | `:ui_policy_draft_created` |
| `POST /v1/policy/drafts/from-receipt` | `PolicyDraftCreate` | `:ui_policy_draft_created` |
| `GET /v1/policy/drafts` / `GET /v1/policy/drafts/{id}` | `DashboardQuery` | `:ui_query` (`query_kind: "policy_drafts"`) |
| `PATCH /v1/policy/drafts/{id}` | `PolicyDraftEdit` | `:ui_policy_draft_edited` |
| `DELETE /v1/policy/drafts/{id}` | `PolicyDraftArchive` | `:ui_policy_draft_archived` |
| `POST /v1/policy/drafts/{id}/dry-run` | `PolicyDraftDryRun` | `:ui_policy_draft_dry_run` |

**Removed from earlier drafts** (per data-model.md §0): `PolicyDraftSave` and
`:ui_policy_draft_saved` — these were dead schema; `:created` and `:edited`
cover all writes.

---

## Policy suggestions

### `GET /v1/policy/suggestions` — list suggestions

**Query params**: `source` (`heuristic|llm|any`), `status` (`active|adopted_as_draft|dismissed`, default `active`), `cursor`, `limit`. Values match `policy_suggestions.status` per data-model.md §1.2.

**Response (200)**: array of suggestion envelopes:

```json
{
  "suggestions": [
    {
      "id": "uuid",
      "source": "heuristic",
      "confidence": 87,
      "pattern_summary": "alice@corp invoked search_kb 423 times in 30 days with 0 denies",
      "proposed_cedar": "permit(...);",
      "blast_radius_snapshot": {"total": 423, "matches_intent": 423, "unintended": 0},
      "status": "active",
      "generated_at": "..."
    }
  ],
  "next_cursor": "b64-or-null"
}
```

### `GET /v1/policy/suggestions/{id}` — fetch single suggestion (operator opens in UI)

Returns the full suggestion envelope. Distinct from list (`GET /v1/policy/suggestions`) because opening a suggestion in the UI is the operator-visible governance action that gets attested as `:ui_policy_suggestion_viewed` per the canonical matrix; the list query is a generic dashboard read.

**Response (200)**: the same suggestion-envelope shape as a list-result element, plus `proposed_cedar` (full body, not excerpted) and `blast_radius_snapshot` (full).

**Status codes**: 200 ok | 401 auth | 403 role not allowed | 404 not found.

**Cedar action**: `Recurse::Action::"PolicySuggestionView"`.

**event_kind emitted**: `:ui_policy_suggestion_viewed`.

### `POST /v1/policy/suggestions/{id}/adopt` — adopt as draft

Creates a new `policy_drafts` row with the suggestion's `proposed_cedar` pre-populated; marks the suggestion `status = "adopted_as_draft"` with `adopted_as_draft_id` back-reference (per data-model.md §1.2 lifecycle).

**Response (201)**: `{"draft_id": "uuid", "suggestion_id": "uuid"}`.

### `POST /v1/policy/suggestions/{id}/dismiss` — dismiss

**Request body** (optional): `{"reason": "free-form"}`.

**Response (204)** — no content.

### `POST /v1/policy/suggestions/refresh` — manual refresh

Kicks the heuristic + LLM engines outside their regular cadence. Rate-limited per FR-030a (default 6/hour/tenant per Q5).

**Request body** (optional): `{"sources": ["heuristic", "llm"]}` (default: both).

**Response (202)**: `{"run_id": "uuid", "sources_triggered": ["heuristic", "llm"]}`.

**Status codes**: 202 accepted | 401 auth | 403 role not allowed | 429 rate-limited (includes `Retry-After` header).

**Cedar actions (per suggestion endpoint, per data-model.md §0)**:

| Endpoint | Cedar action | `event_kind` emitted |
|---|---|---|
| `GET /v1/policy/suggestions` (list) | `DashboardQuery` | `:ui_query` (`query_kind: "policy_suggestions"`) |
| `GET /v1/policy/suggestions/{id}` (open one in UI) | `PolicySuggestionView` | `:ui_policy_suggestion_viewed` |
| `POST /v1/policy/suggestions/{id}/adopt` | `PolicySuggestionAdopt` | `:ui_policy_suggestion_adopted` |
| `POST /v1/policy/suggestions/{id}/dismiss` | `PolicySuggestionDismiss` | `:ui_policy_suggestion_dismissed` |
| `POST /v1/policy/suggestions/refresh` (manual trigger) | `PolicySuggestionRefresh` | `:ui_policy_suggestion_refresh_requested` |
| Suggestion engine (system principal; Oban) | `PolicySuggestionGenerate` | `:ui_policy_suggestion_generated` |

`PolicySuggestionGenerate` fires from the engine (system principal), NOT from
the manual `POST /refresh` endpoint — `/refresh` emits `Refresh` and enqueues a
new run; the run's per-suggestion emissions then carry `Generate`.

---

## Chat (Audit Agent)

### `POST /v1/chat/messages` — send chat message (SSE-streamed response)

**Important**: this endpoint uses **Server-Sent Events** (`Content-Type: text/event-stream`) to stream the agent's response tokens + tool-call records. This is **distinct from the WebSocket** used by Live-tail (`GET /admin/live-tail`) — SSE is unidirectional (server → client) and fits the agent-response shape; Live-tail needs bidirectional control frames.

**Request body**:

```json
{
  "conversation_id": "uuid-or-null",
  "content": "Why was Alice's last bash_exec denied?"
}
```

If `conversation_id` is `null`, a new conversation is created.

**Response** (`Content-Type: text/event-stream`):

```
event: conversation_id
data: {"conversation_id": "uuid"}

event: agent_token
data: {"delta": "The deny fired because..."}

event: tool_call_start
data: {"tool_name": "fetch_receipt_detail", "args": {"run_id": "..."}, "attested_run_id": "..."}

event: tool_call_result
data: {"tool_name": "fetch_receipt_detail", "result": {...}, "attested_run_id": "..."}

event: agent_token
data: {"delta": " the matched policy was..."}

event: message_complete
data: {"message_id": "uuid", "attested_run_id": "uuid"}
```

**Status codes (initial response headers)**: 200 stream started | 401 auth | 403 role not allowed | 404 conversation_id not owned by caller | 500 internal.

Per-event errors are delivered as `event: error\ndata: {flat error envelope}\n\n` in-stream without closing the connection on recoverable failures; fatal errors close the stream after emitting `event: error`. The envelope shape matches `priv/schemas/error_envelope.json` (canonical post-MR-!31 / issue #30 Task L; replaces the earlier "F001 envelope" label).

**Cedar action**: `Recurse::Action::"ChatDrawerQuery"` (plus per-tool Cedar actions per `audit_agent_tools.md`).

**event_kind emitted**: `:ui_chat` for the message itself + one `:ui_chat_skill_invoked_<tool>` per tool call.

### `GET /v1/chat/conversations` — list conversations

**Query params**: `cursor`, `limit`.

**Response (200)**:

```json
{
  "conversations": [
    {
      "id": "uuid",
      "started_at": "...",
      "last_message_at": "...",
      "last_user_message_excerpt": "Why was Alice's..."
    }
  ],
  "next_cursor": "b64-or-null"
}
```

### `GET /v1/chat/conversations/{id}` — conversation detail

**Response (200)**:

```json
{
  "id": "uuid",
  "started_at": "...",
  "messages": [
    {
      "id": "uuid",
      "role": "user|agent",
      "content": "...",
      "tool_calls": [{"tool_name": "...", "args": {...}, "result": {...}, "attested_run_id": "..."}],
      "attested_run_id": "uuid",
      "sequence": 1,
      "created_at": "..."
    }
  ]
}
```

**Status codes**: 200 ok | 401 auth | 403 conversation not owned by caller's principal | 404 not found.

**Cedar action**: `Recurse::Action::"ChatDrawerQuery"`.

**event_kind emitted**: `:ui_query` with `query_kind: "chat_history"`.

---

## Live-tail (WebSocket)

### `GET /admin/live-tail` — WebSocket upgrade

Per `live_tail_transport.md` (D2). Auth via **Session Cookie only** (cookie is `Path=/admin` scoped; API-bearer flow does not apply — if API clients want a live-tail stream, a future endpoint will be added under `/v1/*`).

**Handshake**: standard WebSocket upgrade (`Upgrade: websocket`, `Connection: Upgrade`, `Sec-WebSocket-Version: 13`). Server validates the Session Cookie at upgrade time; rejects with `401` if invalid.

**Frames**: see `live_tail_transport.md` for the control-frame protocol + heartbeat rules.

**Cedar action**: `Recurse::Action::"DashboardQuery"` (live-tail is a dashboard capability).

**event_kind emitted**: `:ui_session` with `session_kind: "live_tail_open"` at connect; `:ui_session` with `session_kind: "live_tail_close"` at disconnect.

---

## Cross-cutting rules

- All endpoints return the canonical flat error envelope (per `priv/schemas/error_envelope.json`; issue #30 Task L) on 4xx/5xx.
- All endpoints emit their attested receipt before sending the 200 response body (per FR-042 / SC-009: 2-second receipt-visibility guarantee).
- All endpoints include `X-Correlation-Id` response header echoing the request's `correlation_id` (or a fresh one if absent).
- All endpoints honor the `tenant_id` derived from the authenticated JWT; cross-tenant reads are rejected with 403 + attested `:policy_denied` receipt per Edge Case "cross-tenant access attempt."
- Pagination cursors are opaque server-signed (D8); tampered cursors are rejected with 400.

## Out of scope (deferred to F005+)

- `POST /v1/policy/deploy` — deploying a draft to production. F004 ships drafts + adopt + suggestions, NOT deploy. See spec Out of Scope.
- Mutation of F002 `/v1/audit/*` endpoints. F004 strictly extends; no existing endpoint semantics change.
- Batch draft operations (`POST /v1/policy/drafts/batch`). Deferred.
- WebSocket-based chat streaming. Chat uses SSE; WebSocket is Live-tail only.
