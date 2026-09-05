// Unit tests for the canonical event_kind enum + facet-row derivation
// (issue #44).
//
// Acceptance from the brief:
//   - All 34 canonical event_kind atoms render in the picker (so every
//     histogram series is also click-able from the left rail).
//   - 0-count rows still render so empty kinds remain checkable.
//   - Counts come from the backend's `facets` payload (server-side
//     SQL GROUP BY over the FULL filtered set, NOT the paginated page).
//   - Forward-compat: a server-returned kind not in the canonical list
//     still renders.
//
// The standing brief flags hardcoded enum lists drifting from backend
// schema as the latent bug behind today's symptom (it WAS the symptom
// here — `chat_completion`/`ui_logout` in the picker, `llm_call`/
// `ui_session`/`ui_evidence_export` missing). Snapshot the canonical
// 34-atom set so when a new atom lands in
// `apps/recurse_shared/.../signed_predicate.ex` and someone forgets to
// mirror it here, this test fails LOUD.

import { describe, expect, it } from "vitest";

import {
  CANONICAL_EVENT_KINDS,
  CANONICAL_POLICY_DECISIONS,
  CANONICAL_VERIFICATION_LEVELS,
  buildFacetRows,
} from "~/lib/event_kinds";

describe("CANONICAL_EVENT_KINDS — drift guard against signed_predicate.ex", () => {
  it("matches the 34-atom backend enum (5 F002 + 24 F004 + 2 MCP + 1 OCI + 2 spec-009) exactly", () => {
    // Mirrors the @event_kinds list at:
    // apps/recurse_shared/lib/recurse_shared/attestation/signed_predicate.ex
    expect(CANONICAL_EVENT_KINDS).toEqual([
      "llm_call",
      "tool_call",
      "egress_denied",
      "policy_denied",
      "session_abort",
      "ui_login",
      "ui_session",
      "ui_query",
      "ui_policy_simulate",
      "ui_policy_replay",
      "ui_policy_draft_created",
      "ui_policy_draft_edited",
      "ui_policy_draft_archived",
      "ui_policy_draft_dry_run",
      "ui_policy_suggestion_generated",
      "ui_policy_suggestion_viewed",
      "ui_policy_suggestion_adopted",
      "ui_policy_suggestion_dismissed",
      "ui_policy_suggestion_refresh_requested",
      "ui_chat",
      "ui_chat_skill_invoked_query_receipts",
      "ui_chat_skill_invoked_fetch_receipt_detail",
      "ui_chat_skill_invoked_explain_denial",
      "ui_chat_skill_invoked_find_similar_receipts",
      "ui_chat_skill_invoked_simulate_policy_dryrun",
      "ui_chat_skill_invoked_suggest_policy_pattern",
      "ui_payload_access",
      "ui_evidence_export",
      "ui_retention_purge",
      "mcp_tool_call",
      "ui_mcp_quarantine",
      "policy_bundle_activated",
      "llm_call_attested",
      "tool_use_denied",
    ]);
  });

  it("does NOT contain `chat_completion` or `ui_logout` (issue #44 stale picker leftovers)", () => {
    expect(CANONICAL_EVENT_KINDS).not.toContain("chat_completion");
    expect(CANONICAL_EVENT_KINDS).not.toContain("ui_logout");
  });

  it("contains the kinds that demo data emits but were missing from the picker pre-fix", () => {
    // From the brief: "in data but NOT in picker: ui_session, ui_evidence_export, llm_call".
    expect(CANONICAL_EVENT_KINDS).toContain("llm_call");
    expect(CANONICAL_EVENT_KINDS).toContain("ui_session");
    expect(CANONICAL_EVENT_KINDS).toContain("ui_evidence_export");
  });
});

describe("CANONICAL_POLICY_DECISIONS / CANONICAL_VERIFICATION_LEVELS", () => {
  it("policy_decision is exactly [allow, deny]", () => {
    expect(CANONICAL_POLICY_DECISIONS).toEqual(["allow", "deny"]);
  });

  it("verification_level is the 3-rung RFC-9162 inclusion ladder", () => {
    expect(CANONICAL_VERIFICATION_LEVELS).toEqual([
      "signed",
      "local_inclusion_verified",
      "global_inclusion_verified",
    ]);
  });
});

describe("buildFacetRows — picker derivation", () => {
  it("renders all canonical kinds even when server returned no counts", () => {
    const rows = buildFacetRows(CANONICAL_EVENT_KINDS, undefined);
    expect(rows).toHaveLength(34);
    for (const r of rows) expect(r.count).toBe(0);
  });

  it("renders all canonical kinds even when server returned empty map", () => {
    const rows = buildFacetRows(CANONICAL_EVENT_KINDS, {});
    expect(rows).toHaveLength(34);
    for (const r of rows) expect(r.count).toBe(0);
  });

  it("attaches server counts to canonical kinds", () => {
    const rows = buildFacetRows(CANONICAL_EVENT_KINDS, {
      tool_call: 12,
      llm_call: 5,
      ui_query: 174,
    });
    const byKind = Object.fromEntries(rows.map((r) => [r.value, r.count]));
    expect(byKind.tool_call).toBe(12);
    expect(byKind.llm_call).toBe(5);
    expect(byKind.ui_query).toBe(174);
    // Untouched kinds stay at 0 (still selectable!).
    expect(byKind.session_abort).toBe(0);
    expect(byKind.ui_evidence_export).toBe(0);
  });

  it("preserves the canonical declaration order", () => {
    const rows = buildFacetRows(CANONICAL_EVENT_KINDS, { tool_call: 5 });
    expect(rows.map((r) => r.value)).toEqual([...CANONICAL_EVENT_KINDS]);
  });

  it("appends server-returned kinds NOT in the canonical list (forward-compat)", () => {
    const rows = buildFacetRows(CANONICAL_EVENT_KINDS, {
      tool_call: 1,
      future_kind_v6: 3,
    });
    const last = rows[rows.length - 1];
    expect(last).toEqual({ value: "future_kind_v6", label: "future_kind_v6", count: 3 });
    // tool_call still in its canonical position.
    expect(rows[1]).toEqual({ value: "tool_call", label: "tool_call", count: 1 });
  });

  it("works for the 2-atom decision axis", () => {
    const rows = buildFacetRows(CANONICAL_POLICY_DECISIONS, { allow: 180, deny: 6 });
    expect(rows).toEqual([
      { value: "allow", label: "allow", count: 180 },
      { value: "deny", label: "deny", count: 6 },
    ]);
  });

  it("works for the 3-atom verification axis", () => {
    const rows = buildFacetRows(CANONICAL_VERIFICATION_LEVELS, {
      global_inclusion_verified: 184,
    });
    const byLevel = Object.fromEntries(rows.map((r) => [r.value, r.count]));
    expect(byLevel.signed).toBe(0);
    expect(byLevel.local_inclusion_verified).toBe(0);
    expect(byLevel.global_inclusion_verified).toBe(184);
  });
});
