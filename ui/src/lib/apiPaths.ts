// Single source of truth for backend API path strings used by the SPA.
//
// Per S-2 in `docs/superpowers/plans/2026-04-29-audit-pass-resolver-consolidation.md`:
// every hardcoded `/v1/...` and `/admin/...` API path string in the SPA
// consolidates into the typed object map below. The eventual property test
// (P-3) will cross-reference this map against the backend's
// `Router.__routes__/0` table to catch drift.
//
// SPA-internal route paths (`/admin/login`, `/admin/dashboard`, etc.) live in
// `~/lib/routes.ts` and are NOT mirrored here — those are router-only paths,
// not backend API endpoints.

export const apiPaths = {
  auth: {
    me: "/v1/auth/me",
    loginStart: "/admin/login/start",
    logout: "/admin/logout",
  },
  audit: {
    receipts: "/v1/audit/receipts",
    receiptDetail: (runId: string) =>
      `/v1/audit/receipts/${encodeURIComponent(runId)}`,
    verify: (runId: string) =>
      `/v1/audit/receipts/${encodeURIComponent(runId)}/verify`,
    payload: (runId: string) =>
      `/v1/audit/payload?run_id=${encodeURIComponent(runId)}`,
    // Export-evidence flow: `POST /v1/audit/export` is synchronous — body
    // carries `{run_ids: [...]}` (max 100) and the response is the zip
    // bytes themselves with `Content-Type: application/zip`. There is NO
    // status-poll endpoint; the previous `/v1/audit/exports/:id` helper
    // pointed to a route that never existed. Per `router.ex` line 261 +
    // `audit_plane/export_handler.ex`. DO NOT use /v1/audit/receipts/
    // :run_id/export — that path doesn't exist either (GAN review fix
    // on !31).
    export: "/v1/audit/export",
    sessions: (sessionId: string) =>
      `/v1/audit/sessions/${encodeURIComponent(sessionId)}`,
    // Spec 012 S4 — parser drift rows (event types the LLM-proxy parsers
    // could not classify). `GET`, cookie-gated, `DashboardQuery`.
    parserDrift: "/v1/audit/parser-drift",
  },
  policy: {
    drafts: "/v1/policy/drafts",
    draftDetail: (id: string) => `/v1/policy/drafts/${encodeURIComponent(id)}`,
    fromReceipt: "/v1/policy/drafts/from-receipt",
    dryRun: (id: string) => `/v1/policy/drafts/${encodeURIComponent(id)}/dry-run`,
    simulate: "/v1/policy/simulate",
    replay: (runId: string) =>
      `/v1/policy/replay/${encodeURIComponent(runId)}`,
  },
  suggestions: {
    list: "/v1/policy/suggestions",
    detail: (id: string) =>
      `/v1/policy/suggestions/${encodeURIComponent(id)}`,
    adopt: (id: string) =>
      `/v1/policy/suggestions/${encodeURIComponent(id)}/adopt`,
    dismiss: (id: string) =>
      `/v1/policy/suggestions/${encodeURIComponent(id)}/dismiss`,
    // Manual rerun (rate-limited per FR-030a). GAN review fix on !31:
    // was previously computed inline in usePolicySuggestions.ts as
    // `${SUGGESTIONS_PATH}/refresh`; consolidating here.
    refresh: "/v1/policy/suggestions/refresh",
  },
  chat: {
    messages: "/v1/chat/messages",
    conversations: "/v1/chat/conversations",
    conversationDetail: (id: string) =>
      `/v1/chat/conversations/${encodeURIComponent(id)}`,
  },
  liveTail: "/admin/live-tail",
} as const;
