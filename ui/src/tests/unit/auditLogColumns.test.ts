// Pure-module tests for the audit-log columns + sort + page-math helpers
// (#31, #32, #33).
//
// Asserts the contract pieces that the components + Dashboard rely on:
//   - sort-cycle (ASC → DESC → null), with column-switch resetting cycle
//   - row sort comparators are stable + handle null timestamps without
//     crashing
//   - column-visibility toggle respects required columns
//   - page-math (slice + nav entries) handles the boundary cases
//     (single page, single ellipsis, double ellipsis)

import { describe, expect, it } from "vitest";

import {
  AUDIT_LOG_COLUMNS,
  AUDIT_LOG_COLUMN_IDS,
  AUDIT_LOG_PAGE_SIZE,
  buildPageNav,
  columnCountLabel,
  defaultColumnVisibility,
  getAuditLogColumn,
  nextSortState,
  normalizeColumnVisibility,
  pageSlice,
  sortRows,
  toggleColumnVisibility,
  type AuditLogColumnId,
} from "~/lib/auditLogColumns";
import type { ReceiptRow } from "~/hooks/useReceipts";

function makeRow(
  runId: string,
  overrides: Partial<{
    timestamp: string | null;
    event_kind: string | null;
    principal: unknown;
    decision: "allow" | "deny" | null;
    verification_level:
      | "signed"
      | "local_inclusion_verified"
      | "global_inclusion_verified"
      | null;
  }> = {},
): ReceiptRow {
  // NOTE: explicit `key in overrides` checks (not `??`) so callers can pass
  // `null` to override a default — `null ?? default` returns the default
  // and silently drops the test's intent.
  const timestamp =
    "timestamp" in overrides ? overrides.timestamp! : "2026-04-29T12:00:00.000Z";
  const eventKind =
    "event_kind" in overrides ? overrides.event_kind! : "tool_call";
  const principal =
    "principal" in overrides ? overrides.principal : "alice@example.com";
  const decision: "allow" | "deny" | null =
    "decision" in overrides ? overrides.decision! : "allow";
  const verificationLevel =
    "verification_level" in overrides ? overrides.verification_level! : "signed";

  return {
    run_id: runId,
    signed_predicate: {
      run_id: runId,
      session_id: null,
      turn_id: null,
      event_kind: eventKind,
      machine_identity: null,
      principal: principal as ReceiptRow["signed_predicate"]["principal"],
      tenant_id: "t1",
      policy_canonical_hash: null,
      payload_hash: null,
      payload_uri: "recurse://x",
      correlation_id: null,
      signer_kms_key_id: null,
      signer_key_version: null,
      timestamp,
      tool_name: null,
      tool_summary: null,
    },
    outer_container: {
      verification_level: verificationLevel,
      tier_completeness_advisory: "partial",
      session_chain_epoch: 0,
      session_chain_root: null,
      policy_decision: decision,
      outcome: "ok",
      upstream_status_code: null,
      commit_retry_exhausted: false,
      tags: null,
    },
  };
}

// ---------------------------------------------------------------------------
// Column registry
// ---------------------------------------------------------------------------

describe("auditLogColumns — registry", () => {
  it("exports a non-empty ordered column list including triplet + legacy togglables", () => {
    expect(AUDIT_LOG_COLUMNS.length).toBeGreaterThan(0);
    expect(AUDIT_LOG_COLUMN_IDS).toContain("timestamp");
    // Triplet (default-visible policy-natural axes per Pencil's
    // comp/receipts-table-v2):
    expect(AUDIT_LOG_COLUMN_IDS).toContain("tool");
    expect(AUDIT_LOG_COLUMN_IDS).toContain("command");
    expect(AUDIT_LOG_COLUMN_IDS).toContain("subject");
    // Legacy togglables retained for users who prefer them:
    expect(AUDIT_LOG_COLUMN_IDS).toContain("summary");
    expect(AUDIT_LOG_COLUMN_IDS).toContain("event_kind");
  });

  it("marks ONLY timestamp as required after the triplet split", () => {
    expect(getAuditLogColumn("timestamp").required).toBe(true);
    // Post-triplet: summary is togglable (off by default), not required.
    expect(getAuditLogColumn("summary").required).toBe(false);
    // Triplet pieces are individually togglable (the picker exposes each).
    expect(getAuditLogColumn("tool").required).toBe(false);
    expect(getAuditLogColumn("command").required).toBe(false);
    expect(getAuditLogColumn("subject").required).toBe(false);
  });

  it("marks summary + subject as non-sortable (free-form text)", () => {
    expect(getAuditLogColumn("summary").sortable).toBe(false);
    expect(getAuditLogColumn("subject").sortable).toBe(false);
  });

  it("marks the structured + chrome columns as sortable", () => {
    for (const id of [
      "timestamp",
      "decision",
      "event_kind",
      "principal",
      "verification_level",
      "category",
      "tool",
      "command",
    ] as AuditLogColumnId[]) {
      expect(getAuditLogColumn(id).sortable).toBe(true);
    }
  });

  it("default visibility excludes the legacy togglables (summary + event_kind off by default)", () => {
    expect(getAuditLogColumn("summary").defaultVisible).toBe(false);
    expect(getAuditLogColumn("event_kind").defaultVisible).toBe(false);
    // Triplet on by default.
    expect(getAuditLogColumn("tool").defaultVisible).toBe(true);
    expect(getAuditLogColumn("command").defaultVisible).toBe(true);
    expect(getAuditLogColumn("subject").defaultVisible).toBe(true);
  });

  // Live-data regression guard (audit-dev visual verification, May 2026):
  // SUBJECT (and its sibling SUMMARY) cells render whatever the gateway
  // puts in `argument_body`. Live agents stuff entire bash command lines
  // there (until issue #66 lands the broker-resident migration). Without
  // overflow-hidden + max-w on the cell wrapper, the inner SubjectCell's
  // `truncate` is a no-op (the row's `min-w-fit` from the !87 #65 fix
  // propagates fit-content up the tree) and the table extends past
  // 18,000px wide — defeating the dashboard's horizontal-scroll UX.
  // Both flex-1 columns MUST carry the containment classes.
  it("subject + summary widthClass contains overflow-hidden + max-w bound (live-data regression guard)", () => {
    for (const id of ["subject", "summary"] as const) {
      const wc = getAuditLogColumn(id).widthClass;
      expect(wc).toMatch(/overflow-hidden/);
      expect(wc).toMatch(/max-w-\[/);
      expect(wc).toMatch(/min-w-\[/);
      expect(wc).toMatch(/\bflex-1\b/);
    }
  });
});

// ---------------------------------------------------------------------------
// Visibility
// ---------------------------------------------------------------------------

describe("auditLogColumns — visibility", () => {
  it("defaults to columns marked defaultVisible (NOT all columns)", () => {
    const v = defaultColumnVisibility();
    // 8 of 10: timestamp, category, principal, tool, command, subject,
    // decision, verification_level. Off by default: event_kind, summary.
    expect(v.has("timestamp")).toBe(true);
    expect(v.has("category")).toBe(true);
    expect(v.has("tool")).toBe(true);
    expect(v.has("command")).toBe(true);
    expect(v.has("subject")).toBe(true);
    expect(v.has("decision")).toBe(true);
    expect(v.has("verification_level")).toBe(true);
    expect(v.has("principal")).toBe(true);
    // Off by default
    expect(v.has("summary")).toBe(false);
    expect(v.has("event_kind")).toBe(false);
  });

  it("toggleColumnVisibility hides an optional column", () => {
    const v = defaultColumnVisibility();
    const next = toggleColumnVisibility(v, "decision");
    expect(next.has("decision")).toBe(false);
    expect(next.has("timestamp")).toBe(true);
  });

  it("toggleColumnVisibility re-shows a hidden column", () => {
    let v = toggleColumnVisibility(defaultColumnVisibility(), "decision");
    v = toggleColumnVisibility(v, "decision");
    expect(v.has("decision")).toBe(true);
  });

  it("toggleColumnVisibility refuses to hide a required column", () => {
    const v = defaultColumnVisibility();
    const next = toggleColumnVisibility(v, "timestamp");
    expect(next.has("timestamp")).toBe(true);
    // Returns same reference (no-op) so React shallow-compare doesn't re-render.
    expect(next).toBe(v);
  });

  it("normalizeColumnVisibility drops unknown ids and force-adds required", () => {
    const v = normalizeColumnVisibility(["principal", "bogus_col"]);
    // "bogus_col" should be dropped; required columns (timestamp only,
    // post-triplet) should be force-added.
    expect(Array.from(v).sort()).toEqual(
      [...new Set(["principal", "timestamp"])].sort(),
    );
  });

  it("columnCountLabel formats the picker label as 'N of M' over the FULL registry", () => {
    const v = defaultColumnVisibility();
    const total = AUDIT_LOG_COLUMN_IDS.length;
    expect(columnCountLabel(v)).toBe(`${v.size} of ${total} columns`);
    const reduced = toggleColumnVisibility(v, "decision");
    expect(columnCountLabel(reduced)).toBe(`${v.size - 1} of ${total} columns`);
  });
});

// ---------------------------------------------------------------------------
// Sort cycle (#31)
// ---------------------------------------------------------------------------

describe("auditLogColumns — nextSortState (sort cycle)", () => {
  it("first click on a column starts ASC", () => {
    const s = nextSortState(null, "timestamp");
    expect(s).toEqual({ column: "timestamp", direction: "asc" });
  });

  it("second click on the SAME column flips to DESC", () => {
    const s = nextSortState(
      { column: "timestamp", direction: "asc" },
      "timestamp",
    );
    expect(s).toEqual({ column: "timestamp", direction: "desc" });
  });

  it("third click on the SAME column returns to default (null)", () => {
    const s = nextSortState(
      { column: "timestamp", direction: "desc" },
      "timestamp",
    );
    expect(s).toBeNull();
  });

  it("clicking a DIFFERENT column restarts the cycle on that column at ASC", () => {
    const s = nextSortState(
      { column: "timestamp", direction: "desc" },
      "decision",
    );
    expect(s).toEqual({ column: "decision", direction: "asc" });
  });
});

// ---------------------------------------------------------------------------
// Sort comparators
// ---------------------------------------------------------------------------

describe("auditLogColumns — sortRows comparators", () => {
  it("default sort (null) returns rows unchanged (server order preserved)", () => {
    const rows = [makeRow("a"), makeRow("b"), makeRow("c")];
    const sorted = sortRows(rows, null);
    expect(sorted.map((r) => r.run_id)).toEqual(["a", "b", "c"]);
  });

  it("sorts ASC by timestamp", () => {
    const rows = [
      makeRow("c", { timestamp: "2026-04-29T12:00:00.000Z" }),
      makeRow("a", { timestamp: "2026-04-27T12:00:00.000Z" }),
      makeRow("b", { timestamp: "2026-04-28T12:00:00.000Z" }),
    ];
    const sorted = sortRows(rows, { column: "timestamp", direction: "asc" });
    expect(sorted.map((r) => r.run_id)).toEqual(["a", "b", "c"]);
  });

  it("sorts DESC by timestamp", () => {
    const rows = [
      makeRow("c", { timestamp: "2026-04-29T12:00:00.000Z" }),
      makeRow("a", { timestamp: "2026-04-27T12:00:00.000Z" }),
      makeRow("b", { timestamp: "2026-04-28T12:00:00.000Z" }),
    ];
    const sorted = sortRows(rows, { column: "timestamp", direction: "desc" });
    expect(sorted.map((r) => r.run_id)).toEqual(["c", "b", "a"]);
  });

  it("sorts ASC by event_kind alphabetically", () => {
    const rows = [
      makeRow("a", { event_kind: "tool_call" }),
      makeRow("b", { event_kind: "llm_call" }),
      makeRow("c", { event_kind: "policy_denied" }),
    ];
    const sorted = sortRows(rows, { column: "event_kind", direction: "asc" });
    expect(sorted.map((r) => r.signed_predicate.event_kind)).toEqual([
      "llm_call",
      "policy_denied",
      "tool_call",
    ]);
  });

  it("sorts ASC by decision: allow before deny", () => {
    const rows = [
      makeRow("a", { decision: "deny" }),
      makeRow("b", { decision: "allow" }),
    ];
    const sorted = sortRows(rows, { column: "decision", direction: "asc" });
    expect(sorted.map((r) => r.run_id)).toEqual(["b", "a"]);
  });

  it("handles null timestamps without crashing (null < non-null)", () => {
    const rows = [
      makeRow("a", { timestamp: "2026-04-29T12:00:00.000Z" }),
      makeRow("b", { timestamp: null }),
    ];
    const sortedAsc = sortRows(rows, { column: "timestamp", direction: "asc" });
    expect(sortedAsc[0]?.run_id).toBe("b");
    const sortedDesc = sortRows(rows, { column: "timestamp", direction: "desc" });
    expect(sortedDesc[0]?.run_id).toBe("a");
  });

  it("ties break stably by run_id (deterministic)", () => {
    const rows = [
      makeRow("z", { event_kind: "tool_call" }),
      makeRow("a", { event_kind: "tool_call" }),
      makeRow("m", { event_kind: "tool_call" }),
    ];
    const sorted = sortRows(rows, { column: "event_kind", direction: "asc" });
    expect(sorted.map((r) => r.run_id)).toEqual(["a", "m", "z"]);
  });

  it("sorts by principal using displayPrincipal (string subject form)", () => {
    const rows = [
      makeRow("a", { principal: "zoe@example.com" }),
      makeRow("b", { principal: { kind: "user", subject: "alice@example.com" } }),
      makeRow("c", { principal: "bob@example.com" }),
    ];
    const sorted = sortRows(rows, { column: "principal", direction: "asc" });
    expect(sorted.map((r) => r.run_id)).toEqual(["b", "c", "a"]);
  });

  it("does not mutate the input array", () => {
    const rows = [
      makeRow("c", { timestamp: "2026-04-29T12:00:00.000Z" }),
      makeRow("a", { timestamp: "2026-04-27T12:00:00.000Z" }),
    ];
    const original = rows.map((r) => r.run_id);
    sortRows(rows, { column: "timestamp", direction: "asc" });
    expect(rows.map((r) => r.run_id)).toEqual(original);
  });
});

// ---------------------------------------------------------------------------
// Page math (#32)
// ---------------------------------------------------------------------------

describe("auditLogColumns — pageSlice", () => {
  it("returns full page when enough rows exist", () => {
    const { start, end } = pageSlice(150, 1, 50);
    expect(start).toBe(50);
    expect(end).toBe(100);
  });

  it("clamps end to totalLoaded on the last (partial) page", () => {
    const { start, end } = pageSlice(120, 2, 50);
    expect(start).toBe(100);
    expect(end).toBe(120);
  });

  it("returns empty range past loaded window", () => {
    const { start, end } = pageSlice(50, 5, 50);
    expect(end - start).toBe(0);
  });

  it("uses AUDIT_LOG_PAGE_SIZE by default", () => {
    expect(AUDIT_LOG_PAGE_SIZE).toBe(50);
    const { start, end } = pageSlice(100, 0);
    expect(start).toBe(0);
    expect(end).toBe(50);
  });
});

describe("auditLogColumns — buildPageNav", () => {
  it("returns empty for zero pages", () => {
    expect(buildPageNav(0, 0)).toEqual([]);
  });

  it("returns single page entry for 1 total", () => {
    expect(buildPageNav(1, 0)).toEqual([{ kind: "page", index: 0 }]);
  });

  it("returns first + last with no ellipsis when small", () => {
    const e = buildPageNav(3, 1);
    // 1 [2] 3 → indices 0, 1, 2 (no ellipsis needed; window covers all)
    expect(e.filter((x) => x.kind === "page").map((x) => x.index)).toEqual([
      0, 1, 2,
    ]);
    expect(e.some((x) => x.kind === "ellipsis")).toBe(false);
  });

  it("inserts trailing ellipsis when current is near start", () => {
    // 17 pages, current=0 → 1 [2] ... 17 (with windowSize=1 the
    // visible cluster is [0,1] then ellipsis then [16])
    const e = buildPageNav(17, 0, 1);
    expect(e[0]).toEqual({ kind: "page", index: 0 });
    expect(e.some((x) => x.kind === "ellipsis")).toBe(true);
    expect(e[e.length - 1]).toEqual({ kind: "page", index: 16 });
  });

  it("inserts double ellipsis when current is in the middle", () => {
    const e = buildPageNav(20, 10, 1);
    // expect: 1 ... 10 [11] 12 ... 20
    const ellipses = e.filter((x) => x.kind === "ellipsis");
    expect(ellipses.length).toBe(2);
  });

  it("first/last anchors are always present (deep-link preserves them)", () => {
    const e = buildPageNav(50, 25, 1);
    expect(e[0]).toEqual({ kind: "page", index: 0 });
    expect(e[e.length - 1]).toEqual({ kind: "page", index: 49 });
  });
});
