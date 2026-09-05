// timeline.ts — pure helpers for the F10 Investigation Timeline.
//
// The Timeline is a SEPARATE surface from the Audit Log (R1) — it answers
// "tell me the story of what THIS principal/session/workstream did, in order"
// (Datadog APM / Honeycomb shape) while R1 answers "show me all rows
// matching X across time" (Datadog Logs / SIEM shape).
//
// Backend wire shape per `design/briefs/10-session-trace.md`:
//
//   GET /v1/audit/timeline?{scope params} → TimelineResponse
//   GET /v1/audit/receipts/<run_id>/related → RelatedEventsResponse
//
// For the demo target the dedicated endpoints don't exist server-side yet;
// the SPA derives the timeline shape from the existing `/v1/audit/receipts`
// payload (group-by-principal, derive density-by-hour, infer related events
// from same correlation_id / session_id adjacency). Backend follow-up to
// add proper endpoints is filed in the MR description.
//
// All helpers in this module are pure and unit-tested.

import type { ReceiptRow } from "~/hooks/useReceipts";
import { categoryFromRow, tagsOf, displaySummary, type ReceiptTags } from "~/lib/tags";
import { displayPrincipal } from "~/lib/principal";
import { matchesPrincipal } from "~/lib/displayField";
import {
  PRINCIPAL_ADJACENT_WINDOW_MS,
  SESSION_ADJACENT_WINDOW_MS,
} from "~/lib/timeline-constants";

// Re-export for backwards compatibility with anything that imported the
// helper from `~/lib/timeline`. The implementation now lives in
// `displayField.ts` so the dev-mocks Vite plugin can share it without
// pulling in the React-flavored `~/hooks/useReceipts` module graph.
export { matchesPrincipal };

/** A single event projected onto a timeline lane. */
export interface TimelineEvent {
  run_id: string;
  timestamp: string; // ISO 8601
  /** Unix epoch ms — pre-computed for time-axis math. */
  ts_ms: number;
  category: string;
  display_summary: string;
  policy_decision: "allow" | "deny" | null;
  verification_level: string | null;
  session_id: string | null;
  correlation_id: string | null;
  event_kind: string | null;
  tags: ReceiptTags | null;
  principal_subject: string;
  principal_kind: string;
}

/** A swim lane keyed by principal subject. */
export interface TimelineLane {
  principal_subject: string;
  /** Display label for the lane (subject or account_id). */
  principal_label: string;
  /** Highest precision principal kind we could resolve. */
  principal_kind: string;
  events: TimelineEvent[];
  /** Most-recent event timestamp in ms — used to sort lanes by recency. */
  last_event_ms: number;
}

/** Density-strip bucket: count by category at one timestamp slice. */
export interface DensityBucket {
  ts: string; // ISO 8601 — start of the bucket
  ts_ms: number;
  count_by_category: Record<string, number>;
  total: number;
}

/** Active scope summary used to render <ScopeChips />. */
export interface ActiveScope {
  principal: string | null;
  session_id: string | null;
  correlation_id: string | null;
  run_id: string | null;
  since: string | null;
  until: string | null;
  /** Human label for the time-window pill (e.g., "Last 24h"). */
  time_window_label: string;
}

/** Time-window picker keys. */
export type TimeWindowKey = "1h" | "6h" | "24h" | "7d" | "all";

export const TIME_WINDOWS: ReadonlyArray<{ key: TimeWindowKey; label: string }> = [
  { key: "1h", label: "Last 1h" },
  { key: "6h", label: "Last 6h" },
  { key: "24h", label: "Last 24h" },
  { key: "7d", label: "Last 7d" },
  { key: "all", label: "All" },
];

const HOUR_MS = 60 * 60 * 1000;
const DAY_MS = 24 * HOUR_MS;

/** Convert a TimeWindowKey to milliseconds. `all` returns null. */
export function timeWindowToMs(key: TimeWindowKey): number | null {
  switch (key) {
    case "1h":
      return HOUR_MS;
    case "6h":
      return 6 * HOUR_MS;
    case "24h":
      return 24 * HOUR_MS;
    case "7d":
      return 7 * DAY_MS;
    case "all":
      return null;
  }
}

/** Project a single receipt row to a TimelineEvent. */
export function eventFromRow(row: ReceiptRow): TimelineEvent | null {
  const sp = row.signed_predicate;
  const oc = row.outer_container;
  const ts = sp.timestamp ?? null;
  if (!ts) return null;
  const tsMs = Date.parse(ts);
  if (Number.isNaN(tsMs)) return null;
  const tags = tagsOf(row as { outer_container: { tags: unknown } });
  const category = categoryFromRow({
    signed_predicate: { event_kind: sp.event_kind },
    outer_container: { policy_decision: oc.policy_decision, tags: oc.tags },
  });
  const principalRaw = sp.principal as Record<string, unknown> | null | string;
  const principalSubject = displayPrincipal(principalRaw);
  const principalKind =
    principalRaw && typeof principalRaw === "object"
      ? String((principalRaw as { kind?: unknown }).kind ?? "unknown")
      : "unknown";
  const summary = displaySummary({
    tags,
    toolName: sp.tool_name,
    toolSummary: sp.tool_summary,
    eventKind: sp.event_kind ?? "",
    principal: principalSubject,
    decision: oc.policy_decision,
    upstreamStatusCode: oc.upstream_status_code,
  });
  return {
    run_id: row.run_id,
    timestamp: ts,
    ts_ms: tsMs,
    category,
    display_summary: summary,
    policy_decision: oc.policy_decision,
    verification_level: oc.verification_level,
    session_id: sp.session_id,
    correlation_id: sp.correlation_id,
    event_kind: sp.event_kind,
    tags,
    principal_subject: principalSubject,
    principal_kind: principalKind,
  };
}

/**
 * Group already-projected events into swim lanes keyed by principal subject.
 * Lanes are sorted by last-event timestamp descending (most-active principal
 * at top). Pair with `lanesFromRows` when the caller has rows but not events.
 */
export function lanesFromEvents(events: TimelineEvent[]): TimelineLane[] {
  const byPrincipal = new Map<string, TimelineLane>();
  for (const ev of events) {
    let lane = byPrincipal.get(ev.principal_subject);
    if (!lane) {
      lane = {
        principal_subject: ev.principal_subject,
        principal_label: ev.principal_subject || "(unknown principal)",
        principal_kind: ev.principal_kind,
        events: [],
        last_event_ms: 0,
      };
      byPrincipal.set(ev.principal_subject, lane);
    }
    lane.events.push(ev);
    if (ev.ts_ms > lane.last_event_ms) lane.last_event_ms = ev.ts_ms;
  }
  for (const lane of byPrincipal.values()) {
    lane.events.sort((a, b) => a.ts_ms - b.ts_ms);
  }
  return Array.from(byPrincipal.values()).sort(
    (a, b) => b.last_event_ms - a.last_event_ms,
  );
}

/**
 * Row-shaped wrapper preserved for unit tests + future row-only callers.
 * Most production paths should project to events once at the parent and
 * call `lanesFromEvents` (F008 — eliminates redundant `eventFromRow`
 * walks across lanes/density/related selectors).
 */
export function lanesFromRows(rows: ReceiptRow[]): TimelineLane[] {
  const events = rows
    .map((r) => eventFromRow(r))
    .filter((e): e is TimelineEvent => e !== null);
  return lanesFromEvents(events);
}

/**
 * Bucket already-projected events into density-strip slices by hour.
 * Returns at most ~24 slices for a 24h window, ~168 for 7d. Each bucket
 * sums a category-keyed count map so the strip can render stacked bars
 * (R4 palette).
 */
export function densityFromEvents(
  events: TimelineEvent[],
  bucketMs = HOUR_MS,
): DensityBucket[] {
  const buckets = new Map<number, DensityBucket>();
  for (const ev of events) {
    const slot = Math.floor(ev.ts_ms / bucketMs) * bucketMs;
    let b = buckets.get(slot);
    if (!b) {
      b = {
        ts: new Date(slot).toISOString(),
        ts_ms: slot,
        count_by_category: {},
        total: 0,
      };
      buckets.set(slot, b);
    }
    b.count_by_category[ev.category] = (b.count_by_category[ev.category] ?? 0) + 1;
    b.total += 1;
  }
  return Array.from(buckets.values()).sort((a, b) => a.ts_ms - b.ts_ms);
}

/**
 * Row-shaped wrapper preserved for unit tests + future row-only callers.
 * Most production paths should project to events once at the parent and
 * call `densityFromEvents`.
 */
export function densityFromRows(
  rows: ReceiptRow[],
  bucketMs = HOUR_MS,
): DensityBucket[] {
  const events = rows
    .map((r) => eventFromRow(r))
    .filter((e): e is TimelineEvent => e !== null);
  return densityFromEvents(events, bucketMs);
}

/** Filter rows to the active scope so derived shapes match the UI's chips.
 *
 * Principal matching is intentionally LIBERAL — a chip URL of
 * `?principal=<X>` matches a row when X equals any of:
 *   - the canonical `displayPrincipal()` output for that row, OR
 *   - the row's literal `principal.subject`, `principal.spiffe_id`, or
 *     `principal.account_id`.
 * This makes the URL form canonical (auditors share `spiffe://r5e/agents/...`
 * for autonomous principals — the form `displayPrincipal()` returns for
 * backend-shaped data per `identity_context_builder.ex:215`) while the
 * filter still matches the dev-mocks corpus where autonomous rows carry
 * BOTH `subject` and `spiffe_id`. Without the broader match, F011-style
 * canonical chip URLs return zero lanes against mock data.
 */
export function filterByScope(
  rows: ReceiptRow[],
  scope: {
    principal?: string | null;
    session_id?: string | null;
    correlation_id?: string | null;
    since?: string | null;
    until?: string | null;
  },
): ReceiptRow[] {
  const principal = scope.principal ?? null;
  const sessionId = scope.session_id ?? null;
  const correlationId = scope.correlation_id ?? null;
  const sinceMs = scope.since ? Date.parse(scope.since) : null;
  const untilMs = scope.until ? Date.parse(scope.until) : null;
  return rows.filter((r) => {
    const sp = r.signed_predicate;
    if (principal) {
      if (!matchesPrincipal(sp.principal, principal)) return false;
    }
    if (sessionId && sp.session_id !== sessionId) return false;
    if (correlationId && sp.correlation_id !== correlationId) return false;
    const ts = sp.timestamp ? Date.parse(sp.timestamp) : null;
    if (ts !== null) {
      if (sinceMs !== null && ts < sinceMs) return false;
      if (untilMs !== null && ts > untilMs) return false;
    }
    return true;
  });
}


/**
 * Infer events related to a target receipt — primary signal is matching
 * `correlation_id`; secondary is session adjacency (±N seconds in same
 * session); tertiary is principal adjacency (same principal in window).
 *
 * Returns events tagged by relation kind so the UI can group/sort.
 */
export interface RelatedEvent extends TimelineEvent {
  relation: "same_correlation" | "session_adjacent" | "principal_adjacent";
}

// Adjacency-window constants live in `~/lib/timeline-constants` so the
// dev-mocks Vite plugin (no React deps) can import the same values
// (Constitution Principle VII — Interface-First on Second Consumer).

/** Event-shaped wrapper used by callers that already projected rows
 *  via `eventFromRow` (F008 — TimelinePage projects once at the parent). */
export function relatedEventsFromEvents(
  events: TimelineEvent[],
  targetRunId: string,
): RelatedEvent[] {
  const target = events.find((e) => e.run_id === targetRunId);
  if (!target) return [];

  const out = new Map<string, RelatedEvent>();
  for (const ev of events) {
    if (ev.run_id === targetRunId) continue;
    // Primary: same correlation_id (treat null/empty as no match)
    if (
      target.correlation_id &&
      ev.correlation_id &&
      ev.correlation_id === target.correlation_id
    ) {
      out.set(ev.run_id, { ...ev, relation: "same_correlation" });
      continue;
    }
    // Secondary: same session within adjacency window
    if (
      target.session_id &&
      ev.session_id === target.session_id &&
      Math.abs(ev.ts_ms - target.ts_ms) <= SESSION_ADJACENT_WINDOW_MS
    ) {
      if (!out.has(ev.run_id)) {
        out.set(ev.run_id, { ...ev, relation: "session_adjacent" });
      }
      continue;
    }
    // Tertiary: same principal within wider adjacency window
    if (
      ev.principal_subject === target.principal_subject &&
      Math.abs(ev.ts_ms - target.ts_ms) <= PRINCIPAL_ADJACENT_WINDOW_MS
    ) {
      if (!out.has(ev.run_id)) {
        out.set(ev.run_id, { ...ev, relation: "principal_adjacent" });
      }
    }
  }
  const relationRank: Record<RelatedEvent["relation"], number> = {
    same_correlation: 0,
    session_adjacent: 1,
    principal_adjacent: 2,
  };
  return Array.from(out.values()).sort((a, b) => {
    const r = relationRank[a.relation] - relationRank[b.relation];
    if (r !== 0) return r;
    return b.ts_ms - a.ts_ms;
  });
}

export function relatedEvents(rows: ReceiptRow[], targetRunId: string): RelatedEvent[] {
  const events = rows
    .map((r) => eventFromRow(r))
    .filter((e): e is TimelineEvent => e !== null);
  return relatedEventsFromEvents(events, targetRunId);
}

/**
 * Choose a sensible time-axis tick interval for the given window (in ms).
 * Returns the tick spacing in ms — callers floor each tick to a multiple
 * of this value.
 */
export function tickIntervalMs(windowMs: number): number {
  if (windowMs <= 60 * 60 * 1000) return 15 * 60 * 1000; // 15min for 1h
  if (windowMs <= 6 * 60 * 60 * 1000) return 60 * 60 * 1000; // 1h for 6h
  if (windowMs <= 24 * 60 * 60 * 1000) return 60 * 60 * 1000; // 1h for 24h
  if (windowMs <= 7 * 24 * 60 * 60 * 1000) return 24 * 60 * 60 * 1000; // 1d for 7d
  return 7 * 24 * 60 * 60 * 1000; // 1w for "all"
}

/** Format a tick label for the time axis. */
export function formatTick(tsMs: number, windowMs: number): string {
  const d = new Date(tsMs);
  if (windowMs <= 24 * HOUR_MS) {
    return `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}`;
  }
  return `${d.getUTCMonth() + 1}/${d.getUTCDate()}`;
}

function pad(n: number): string {
  return n < 10 ? `0${n}` : String(n);
}
