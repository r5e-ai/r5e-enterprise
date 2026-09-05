// F10 Investigation Timeline — pure-helper unit tests for `~/lib/timeline`.
//
// Asserts:
//   - `eventFromRow` projects a receipt row into a timeline event with the
//     deny-trumps-category rule applied (R4 Rule 01).
//   - `lanesFromRows` groups events by principal subject, sorts each lane's
//     events ascending by time, and sorts lanes by recency descending.
//   - `densityFromRows` buckets by hour and sums per-category counts.
//   - `filterByScope` honors principal / session_id / correlation_id /
//     since / until filters.
//   - `relatedEvents` ranks by relation: same_correlation > session_adjacent
//     > principal_adjacent.
//   - `tickIntervalMs` returns sensible intervals for each window size.

import { describe, expect, it } from "vitest";

import type { ReceiptRow } from "~/hooks/useReceipts";
import {
  densityFromEvents,
  densityFromRows,
  eventFromRow,
  filterByScope,
  lanesFromEvents,
  lanesFromRows,
  matchesPrincipal,
  relatedEvents,
  relatedEventsFromEvents,
  tickIntervalMs,
  timeWindowToMs,
} from "~/lib/timeline";
import { PRINCIPAL_IDENTITY_KEYS } from "~/lib/displayField";

const T0 = Date.parse("2026-05-01T03:00:00Z");

function mkRow(
  off: number,
  opts: {
    run_id?: string;
    principal?: string;
    session_id?: string;
    correlation_id?: string;
    decision?: "allow" | "deny" | null;
    category?: string;
    summary?: string;
  } = {},
): ReceiptRow {
  const ts = new Date(T0 + off * 1000).toISOString();
  const id = opts.run_id ?? `r-${off}`;
  return {
    run_id: id,
    signed_predicate: {
      run_id: id,
      session_id: opts.session_id ?? "sess-default",
      turn_id: id,
      event_kind: "tool_call",
      machine_identity: null,
      principal: { kind: "obo_human", subject: opts.principal ?? "alice@example.com" },
      tenant_id: "t",
      policy_canonical_hash: null,
      payload_hash: null,
      payload_uri: null,
      correlation_id: opts.correlation_id ?? null,
      signer_kms_key_id: null,
      signer_key_version: null,
      timestamp: ts,
      tool_name: null,
      tool_summary: null,
    },
    outer_container: {
      verification_level: "global_inclusion_verified",
      tier_completeness_advisory: null,
      session_chain_epoch: 0,
      session_chain_root: null,
      policy_decision: opts.decision ?? "allow",
      outcome: null,
      upstream_status_code: null,
      commit_retry_exhausted: false,
      tags: {
        category: opts.category ?? "subprocess_exec",
        display_summary: opts.summary ?? "Bash: ls",
        tool_kind: "bash",
        verb: "ls",
        argument_body: "/",
        scope_kind: null,
        scope_value: null,
        target_resources: [],
        semantic_args: { verb: "ls" },
      },
    },
  } as ReceiptRow;
}

describe("eventFromRow", () => {
  it("returns null when timestamp is missing", () => {
    const row = mkRow(0);
    row.signed_predicate.timestamp = null;
    expect(eventFromRow(row)).toBeNull();
  });

  it("projects principal subject + category onto the event", () => {
    const ev = eventFromRow(mkRow(0, { principal: "agent-1" }))!;
    expect(ev.principal_subject).toBe("agent-1");
    expect(ev.category).toBe("subprocess_exec");
  });

  it("applies deny-trumps-category — denial events read as policy_denied", () => {
    const ev = eventFromRow(
      mkRow(0, { decision: "deny", category: "subprocess_exec" }),
    )!;
    expect(ev.category).toBe("policy_denied");
    expect(ev.policy_decision).toBe("deny");
  });
});

describe("lanesFromRows", () => {
  it("groups by principal subject", () => {
    const rows = [
      mkRow(0, { principal: "alice" }),
      mkRow(60, { principal: "alice" }),
      mkRow(30, { principal: "bob" }),
    ];
    const lanes = lanesFromRows(rows);
    expect(lanes).toHaveLength(2);
    const alice = lanes.find((l) => l.principal_subject === "alice")!;
    expect(alice.events).toHaveLength(2);
  });

  it("sorts each lane's events ascending by timestamp", () => {
    const rows = [
      mkRow(60, { principal: "alice", run_id: "later" }),
      mkRow(0, { principal: "alice", run_id: "earlier" }),
    ];
    const lanes = lanesFromRows(rows);
    expect(lanes[0]!.events.map((e) => e.run_id)).toEqual(["earlier", "later"]);
  });

  it("sorts lanes by most-recent activity descending", () => {
    const rows = [
      mkRow(0, { principal: "old-active" }),
      mkRow(120, { principal: "recent-active" }),
    ];
    const lanes = lanesFromRows(rows);
    expect(lanes.map((l) => l.principal_subject)).toEqual([
      "recent-active",
      "old-active",
    ]);
  });
});

describe("densityFromRows", () => {
  it("buckets events into hourly slots and counts per category", () => {
    const rows = [
      mkRow(0, { category: "subprocess_exec" }),
      mkRow(60, { category: "subprocess_exec" }),
      mkRow(0, { category: "file_read" }),
    ];
    const buckets = densityFromRows(rows);
    expect(buckets).toHaveLength(1);
    expect(buckets[0]!.count_by_category.subprocess_exec).toBe(2);
    expect(buckets[0]!.count_by_category.file_read).toBe(1);
    expect(buckets[0]!.total).toBe(3);
  });

  it("returns sorted ascending by timestamp", () => {
    const rows = [
      mkRow(7200, { category: "subprocess_exec" }), // +2h
      mkRow(0, { category: "subprocess_exec" }),
    ];
    const buckets = densityFromRows(rows);
    expect(buckets[0]!.ts_ms).toBeLessThan(buckets[1]!.ts_ms);
  });
});

describe("event-based adapters (F008 — single eventFromRow projection)", () => {
  const rows = [
    mkRow(0, { principal: "alice", session_id: "s1", correlation_id: "c1" }),
    mkRow(60, { principal: "bob", session_id: "s1", correlation_id: "c1" }),
  ];
  const events = rows
    .map((r) => eventFromRow(r))
    .filter((e): e is NonNullable<ReturnType<typeof eventFromRow>> => e !== null);

  it("lanesFromEvents matches lanesFromRows", () => {
    expect(lanesFromEvents(events).map((l) => l.principal_subject)).toEqual(
      lanesFromRows(rows).map((l) => l.principal_subject),
    );
  });

  it("densityFromEvents matches densityFromRows", () => {
    expect(densityFromEvents(events)).toEqual(densityFromRows(rows));
  });

  it("relatedEventsFromEvents matches relatedEvents", () => {
    expect(relatedEventsFromEvents(events, rows[0]!.run_id)).toEqual(
      relatedEvents(rows, rows[0]!.run_id),
    );
  });
});

describe("matchesPrincipal (Constitution Principle VII — canonical helper)", () => {
  it("matches the canonical display form (subject for obo_human)", () => {
    const principal = { kind: "obo_human", subject: "alice@example.com" };
    expect(matchesPrincipal(principal, "alice@example.com")).toBe(true);
  });

  it("matches the canonical display form (spiffe_id for autonomous)", () => {
    const principal = {
      kind: "autonomous",
      spiffe_id: "spiffe://r5e/agents/llm-agent-01",
    };
    expect(
      matchesPrincipal(principal, "spiffe://r5e/agents/llm-agent-01"),
    ).toBe(true);
  });

  it("matches per-kind identity keys directly (subject / spiffe_id / account_id)", () => {
    // Autonomous principals in the dev-mocks corpus carry BOTH subject
    // and spiffe_id so a chip URL using either form resolves.
    const dual = {
      kind: "autonomous",
      subject: "llm-agent-01",
      spiffe_id: "spiffe://r5e/agents/llm-agent-01",
    };
    expect(matchesPrincipal(dual, "llm-agent-01")).toBe(true);
    expect(matchesPrincipal(dual, "spiffe://r5e/agents/llm-agent-01")).toBe(true);

    const sa = { kind: "service_account", account_id: "svc-build-runner" };
    expect(matchesPrincipal(sa, "svc-build-runner")).toBe(true);
  });

  it("returns false for non-matching identifiers", () => {
    const p = { kind: "obo_human", subject: "alice@example.com" };
    expect(matchesPrincipal(p, "bob@example.com")).toBe(false);
  });

  it("PRINCIPAL_IDENTITY_KEYS covers all three matching keys", () => {
    expect(PRINCIPAL_IDENTITY_KEYS).toEqual(["subject", "account_id", "spiffe_id"]);
  });
});

describe("filterByScope", () => {
  const rows = [
    mkRow(0, { principal: "alice", session_id: "s1", correlation_id: "c1" }),
    mkRow(60, { principal: "bob", session_id: "s1", correlation_id: "c2" }),
    mkRow(120, { principal: "alice", session_id: "s2", correlation_id: "c1" }),
  ];

  it("filters by principal", () => {
    const out = filterByScope(rows, { principal: "alice" });
    expect(out).toHaveLength(2);
  });

  it("filters by session_id", () => {
    const out = filterByScope(rows, { session_id: "s1" });
    expect(out).toHaveLength(2);
  });

  it("filters by correlation_id", () => {
    const out = filterByScope(rows, { correlation_id: "c1" });
    expect(out).toHaveLength(2);
  });

  it("filters by since/until timestamps", () => {
    const sinceIso = new Date(T0 + 30 * 1000).toISOString();
    const untilIso = new Date(T0 + 90 * 1000).toISOString();
    const out = filterByScope(rows, { since: sinceIso, until: untilIso });
    expect(out).toHaveLength(1);
    expect(out[0]!.run_id).toBe("r-60");
  });
});

describe("relatedEvents", () => {
  it("primary signal is same correlation_id", () => {
    // Time gap on `stranger` exceeds principal-adjacency window (5min)
    // AND its correlation differs — it should NOT be related.
    const rows = [
      mkRow(0, { run_id: "target", correlation_id: "shared", principal: "alice" }),
      mkRow(60, { run_id: "sibling", correlation_id: "shared", principal: "carol" }),
      mkRow(60 * 60, { run_id: "stranger", correlation_id: "other", principal: "bob" }),
    ];
    const out = relatedEvents(rows, "target");
    expect(out.map((e) => e.run_id)).toContain("sibling");
    expect(out.map((e) => e.run_id)).not.toContain("stranger");
    expect(out[0]!.relation).toBe("same_correlation");
  });

  it("falls through to session_adjacent when correlation differs", () => {
    const rows = [
      mkRow(0, { run_id: "target", session_id: "s1", correlation_id: "c1" }),
      mkRow(5, { run_id: "neighbor", session_id: "s1", correlation_id: "different" }),
    ];
    const out = relatedEvents(rows, "target");
    expect(out).toHaveLength(1);
    expect(out[0]!.run_id).toBe("neighbor");
    expect(out[0]!.relation).toBe("session_adjacent");
  });

  it("returns empty when target run_id is missing", () => {
    expect(relatedEvents([], "missing")).toEqual([]);
  });

  it("within a single relation rank, sorts newest → oldest", () => {
    // F010: the inspector's RELATED EVENTS panel claims to surface
    // newest-first. Three same_correlation siblings spread across +30s,
    // +60s, +120s should land in DESCENDING ts_ms order.
    const rows = [
      mkRow(0, { run_id: "target", correlation_id: "c1", principal: "alice" }),
      mkRow(30, { run_id: "older", correlation_id: "c1", principal: "alice" }),
      mkRow(60, { run_id: "middle", correlation_id: "c1", principal: "alice" }),
      mkRow(120, { run_id: "newest", correlation_id: "c1", principal: "alice" }),
    ];
    const out = relatedEvents(rows, "target");
    expect(out.map((e) => e.run_id)).toEqual(["newest", "middle", "older"]);
  });

  it("ranks same_correlation before session_adjacent before principal_adjacent", () => {
    const rows = [
      mkRow(0, { run_id: "target", session_id: "s1", correlation_id: "c1", principal: "alice" }),
      mkRow(60, { run_id: "principal-adj", session_id: "s2", correlation_id: "c-other", principal: "alice" }),
      mkRow(5, { run_id: "session-adj", session_id: "s1", correlation_id: "c-other", principal: "bob" }),
      mkRow(30, { run_id: "corr-match", session_id: "s9", correlation_id: "c1", principal: "carol" }),
    ];
    const out = relatedEvents(rows, "target");
    expect(out[0]!.run_id).toBe("corr-match");
    expect(out[0]!.relation).toBe("same_correlation");
    expect(out.map((e) => e.relation)).toEqual([
      "same_correlation",
      "session_adjacent",
      "principal_adjacent",
    ]);
  });
});

describe("tickIntervalMs / timeWindowToMs", () => {
  it("returns 15min for 1h window", () => {
    expect(tickIntervalMs(60 * 60 * 1000)).toBe(15 * 60 * 1000);
  });
  it("returns 1h for 24h window", () => {
    expect(tickIntervalMs(24 * 60 * 60 * 1000)).toBe(60 * 60 * 1000);
  });
  it("returns 1d for 7d window", () => {
    expect(tickIntervalMs(7 * 24 * 60 * 60 * 1000)).toBe(24 * 60 * 60 * 1000);
  });

  it("timeWindowToMs maps the keys to milliseconds", () => {
    expect(timeWindowToMs("1h")).toBe(60 * 60 * 1000);
    expect(timeWindowToMs("24h")).toBe(24 * 60 * 60 * 1000);
    expect(timeWindowToMs("all")).toBeNull();
  });
});
