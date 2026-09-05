# Contract: Audit Console "LLM Calls" View

**Modules**: `ui/src/pages/LlmCalls.tsx`, `ui/src/components/audit/LlmCallRow.tsx`, `ui/src/components/audit/LlmCallDrawer.tsx`, `ui/src/lib/llmCallsApi.ts`, plus a new audit-plane endpoint `GET /v1/audit/llm-calls`
**Owner phase**: Phase 6
**Consumed by**: customer's CISO + security team (audit + governance)

## Purpose

CISO-facing audit surface for LLM calls. Filterable list of `LlmCallRecord` entries; per-call drill-in showing prompt hash, response hash, tool-use intents, decisions, tokens, latency, model, principal.

## API endpoint

```
GET /v1/audit/llm-calls
  ?tenant_id=<ulid>
  &principal_id=<id>     (optional)
  &model=<model>          (optional)
  &decision=<allow|deny|mixed>   (optional)
  &tool_name=<tool>       (optional)
  &session_id=<uuid>      (optional)
  &since=<iso8601>         (optional; default last 7 days)
  &until=<iso8601>         (optional)
  &cursor=<paging-cursor>  (optional)
  &limit=<int>             (optional; default 50, max 200)

Response:
{
  "calls": [LlmCallRecord, ...],
  "next_cursor": "...",
  "total_count": 12345
}
```

```
GET /v1/audit/llm-calls/:run_id
  → returns the full LlmCallRecord + nested ToolUseIntentRecord[]
  + the canonical predicate (signed) + recurse-verify-readable signature material
```

## Components

### `LlmCalls.tsx` (page)

- Filter bar: principal, model, decision, tool, session, time range
- Table of `LlmCallRow` entries (paginated; 50/page default)
- Sort: `started_at DESC` default; user can re-sort by latency, tokens, decision_summary

### `LlmCallRow.tsx`

- One row per call with summary: timestamp, principal (truncated), model, decision summary, tokens, latency, "open drawer" link
- Visual badge for decision: green (all allow) / yellow (mixed) / red (any deny)

### `LlmCallDrawer.tsx`

- Per-call detail drawer (modal/slide-in)
- Shows:
  - Header: call ID, principal, session ID, started/completed times
  - Tabs: Overview / Tool Use Intents / Receipt / Raw Predicate
  - **Overview**: model, provider, transport, tokens (prompt/completion/reasoning), latency, decision summary
  - **Tool Use Intents**: list of all intents in the call; each shows tool_name, args (truncated; expandable), decision, rule_id (for deny), reason (for deny)
  - **Receipt**: prompt_hash, response_hash, cedar_bundle_hash, link to fetch raw payload (via existing payload broker), link to verify with recurse-verify
  - **Raw Predicate**: the JCS-canonical predicate JSON, syntax-highlighted

## Performance

- **P-001**: First-paint of `LlmCalls.tsx` < 500ms with default filters
- **P-002**: Drawer open < 200ms
- **P-003**: Pagination via cursor (no offset-based skip — large tenants will have millions of rows)

## Test contracts

- **CT-001** (Vitest): `LlmCalls.tsx` renders with mock data; filters apply correctly
- **CT-002** (Vitest): `LlmCallDrawer.tsx` renders all tabs correctly
- **CT-003** (Playwright): end-to-end — generate proxy traffic → verify call appears in LlmCalls view within 5s

## Dependencies

- F004 component library (existing; reuse drawer scaffolding, filter primitives, table)
- Existing audit-plane endpoints + auth
- TanStack Query (existing) for state
