// Shared, React-free constants for the F10 Investigation Timeline.
//
// These are imported by both the SPA's `~/lib/timeline` (TimelineEvent
// derivation) and the dev-mocks Vite plugin (the stubbed
// /v1/audit/receipts/<run_id>/related endpoint). Keeping them in a tiny
// dedicated module — no React imports — means the dev-mocks plugin can
// pull them in without dragging in the rest of the SPA.
//
// If the SPA tunes these thresholds based on demo feedback, the mock
// shape will follow without anyone having to remember to keep the two
// callsites in sync (Constitution Principle VII — single source of
// truth for cross-consumer values).

/** ±30s same session adjacency window for `relatedEvents`. */
export const SESSION_ADJACENT_WINDOW_MS = 30 * 1000;

/** ±5min same principal adjacency window for `relatedEvents`. */
export const PRINCIPAL_ADJACENT_WINDOW_MS = 5 * 60 * 1000;
