// Canonical event_kind enum — the SPA's source of truth, MIRRORS the
// 34-atom backend enum at:
//   - apps/recurse_shared/lib/recurse_shared/attestation/signed_predicate.ex
//     (`@event_kinds`)
//   - apps/recurse_providers/lib/recurse_providers/impls/postgres_merkle_ledger/
//     schemas/attestation.ex (`Ecto.Enum`)
//   - apps/recurse_gateway/priv/schemas/attestation.json (`enum`)
//
// Issue #44 (2026-04-30) — the audit-log left-rail Event Kind picker
// rendered hardcoded values that drifted from this enum (had stale
// `chat_completion`, `ui_logout`; missing `llm_call`, `ui_session`,
// `ui_evidence_export`). The picker now derives its values from the
// FACET COUNTS the backend returns + this canonical list as the
// 0-count baseline so every kind is selectable even when none have
// landed in the current filter window.
//
// When a new event_kind atom lands in the backend, append it here
// AND update the Histogram's `colorClassForKind` semantic anchors at
// `ui/src/components/audit/Histogram.tsx`. There is no codegen for
// this list yet (a future schema-driven type would catch drift via
// `pnpm gen:types`; tracked as the F2 punch-list item — wire-shape
// schemas missing for several response shapes).

/** The canonical 34 atoms accepted by the backend's `Attestation` Ecto.Enum. */
export const CANONICAL_EVENT_KINDS = [
  // F002 base (5)
  "llm_call",
  "tool_call",
  "egress_denied",
  "policy_denied",
  "session_abort",
  // F004 UI session lifecycle (3)
  "ui_login",
  "ui_session",
  "ui_query",
  // F004 Policy Simulator (2)
  "ui_policy_simulate",
  "ui_policy_replay",
  // F004 Policy Draft lifecycle (4)
  "ui_policy_draft_created",
  "ui_policy_draft_edited",
  "ui_policy_draft_archived",
  "ui_policy_draft_dry_run",
  // F004 Policy Suggestion lifecycle (5)
  "ui_policy_suggestion_generated",
  "ui_policy_suggestion_viewed",
  "ui_policy_suggestion_adopted",
  "ui_policy_suggestion_dismissed",
  "ui_policy_suggestion_refresh_requested",
  // F004 Chat drawer (1)
  "ui_chat",
  // F004 Audit-agent six-tool vocabulary (6)
  "ui_chat_skill_invoked_query_receipts",
  "ui_chat_skill_invoked_fetch_receipt_detail",
  "ui_chat_skill_invoked_explain_denial",
  "ui_chat_skill_invoked_find_similar_receipts",
  "ui_chat_skill_invoked_simulate_policy_dryrun",
  "ui_chat_skill_invoked_suggest_policy_pattern",
  // F004 reused-action UI surfaces (2)
  "ui_payload_access",
  "ui_evidence_export",
  // F004 retention purge (1)
  "ui_retention_purge",
  // MCP/Trusted-Registry vertical slice (2)
  "mcp_tool_call",
  "ui_mcp_quarantine",
  // !119 OCI policy provider (1)
  "policy_bundle_activated",
  // 009 LLM-proxy tool governance (2)
  "llm_call_attested",
  "tool_use_denied",
] as const;

/** Type-narrow string union derived from the canonical list. */
export type CanonicalEventKind = (typeof CANONICAL_EVENT_KINDS)[number];

/** policy_decision atoms — Cedar verdict surface. */
export const CANONICAL_POLICY_DECISIONS = ["allow", "deny"] as const;
export type CanonicalPolicyDecision = (typeof CANONICAL_POLICY_DECISIONS)[number];

/** verification_level atoms — RFC 9162 inclusion ladder. */
export const CANONICAL_VERIFICATION_LEVELS = [
  "signed",
  "local_inclusion_verified",
  "global_inclusion_verified",
] as const;
export type CanonicalVerificationLevel =
  (typeof CANONICAL_VERIFICATION_LEVELS)[number];

/**
 * Build a row list for the dashboard's left-rail FilterFacet picker.
 *
 * - `canonical` is the source of truth for WHICH chips render (so 0-count
 *   kinds are still selectable).
 * - `serverCounts` is the SQL `GROUP BY` payload from `?facets=true` over
 *   the FULL filtered universe; absent kinds become `0`.
 * - Any kind in `serverCounts` that's NOT in `canonical` is appended at
 *   the bottom (forward-compat: the backend gained an atom this client
 *   doesn't yet know about; we still render it rather than hiding it).
 *
 * Issue #44 (2026-04-30): the prior inline implementation in
 * `Dashboard.tsx` derived counts from `rows.filter(...).length` (the
 * paginated page) and the canonical list was a wrong + drifting
 * hardcode. Both bugs go away when the picker reads server-computed
 * counts against this canonical baseline.
 */
export function buildFacetRows(
  canonical: readonly string[],
  // Issue #48: codegen'd `ReceiptsFacets` axes are typed as
  // `{[k: string]: number | undefined}` (TS strictIndexSignatures); the
  // function below already coalesces `undefined → 0`, so we accept the
  // wider type and produce the narrower one out the back. Explicit
  // `undefined` handling keeps the contract honest.
  serverCounts: Record<string, number | undefined> | undefined,
): { value: string; label: string; count: number }[] {
  const counts = serverCounts ?? {};
  const seen = new Set<string>();
  const out: { value: string; label: string; count: number }[] = [];
  for (const v of canonical) {
    seen.add(v);
    out.push({ value: v, label: v, count: counts[v] ?? 0 });
  }
  for (const [v, n] of Object.entries(counts)) {
    if (seen.has(v)) continue;
    out.push({ value: v, label: v, count: n ?? 0 });
  }
  return out;
}
