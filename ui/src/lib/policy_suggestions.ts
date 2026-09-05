// Pure helpers for the Policy Suggestions surface. Lives outside the
// page module so:
//   1. The page can stay a "components-only" module (eslint react-refresh
//      rule prefers this for HMR boundaries).
//   2. Unit tests can target the helper directly without rendering the page.
//
// Add helpers here when they're stateless + computed-from-rows, not when
// they need React context / hooks.

import type { PolicySuggestion } from "~/hooks/usePolicySuggestions";

/**
 * Single source-of-truth ordering for the suggestions queue —
 * confidence DESC, then time DESC (`inserted_at` falls back to
 * `generated_at` when the wire only carries the latter).
 */
export function sortSuggestions(rows: PolicySuggestion[]): PolicySuggestion[] {
  return rows.slice().sort((a, b) => {
    if (b.confidence !== a.confidence) return b.confidence - a.confidence;
    const aTime = a.inserted_at ?? a.generated_at;
    const bTime = b.inserted_at ?? b.generated_at;
    return bTime.localeCompare(aTime);
  });
}

/**
 * Latest `generated_at` across the list (regardless of confidence).
 *
 * Used for the "Last run" caption — the timestamp must reflect engine
 * recency, not the position of the highest-confidence row. Pre-fix the
 * page derived this from `sortSuggestions(rows)[0].generated_at`, but
 * `sortSuggestions` orders by confidence first; a stale high-confidence
 * row would mask a fresh low-confidence one and mislead operators about
 * engine recency (the exact thing the rate-limit + refresh affordance
 * is built around).
 */
export function latestGeneratedAt(rows: PolicySuggestion[]): string | null {
  if (rows.length === 0) return null;
  let latestMs = -Infinity;
  let latestIso: string | null = null;
  for (const r of rows) {
    const ms = Date.parse(r.generated_at);
    if (Number.isNaN(ms)) continue;
    if (ms > latestMs) {
      latestMs = ms;
      latestIso = r.generated_at;
    }
  }
  return latestIso;
}

/**
 * Lightweight relative-time formatter used by the suggestions page header
 * AND each `<SuggestionCard>` header time so an operator sees one consistent
 * cadence ("2 min ago") inside the viewport instead of the page reading
 * "Last run: 2 min ago" while individual cards still show raw ISO strings
 * (F006 — pre-fix-pass-2 the card stamped `suggestion.generated_at` raw,
 * mixing two formats for the same kind of value).
 *
 * We accept the absolute-time decision boundary at the call site: receipt
 * detail surfaces want full ISO + UTC for forensic citation; dashboard +
 * card surfaces want relative time for at-a-glance recency. This helper
 * powers the latter; receipt-detail uses the raw ISO directly.
 *
 * Returns the input string unchanged when the input doesn't parse as a
 * Date so callers don't have to special-case malformed wire data.
 */
export function relativeFromNow(iso: string, now: Date = new Date()): string {
  const then = Date.parse(iso);
  if (Number.isNaN(then)) return iso;
  const deltaSec = Math.max(0, Math.floor((now.getTime() - then) / 1000));
  if (deltaSec < 60) return "just now";
  const deltaMin = Math.floor(deltaSec / 60);
  if (deltaMin < 60) return `${deltaMin} min ago`;
  const deltaHr = Math.floor(deltaMin / 60);
  if (deltaHr < 24) return `${deltaHr} hr ago`;
  const deltaDay = Math.floor(deltaHr / 24);
  return `${deltaDay} day${deltaDay === 1 ? "" : "s"} ago`;
}
