// DraftFromReceiptBanner — small banner above column 01 of the Policy
// Simulator when the auditor arrived from the dashboard's "Draft policy from
// receipt" CTA (URL: `/admin/policy-simulator?mode=draft&run_id=<id>`).
//
// Per `design/briefs/04-policy-simulator.md`:
//
//   DRAFTING FROM RECEIPT
//   a621cbb7-01b7-5781-a06a-f258560402e2 · tool_call         view full receipt →
//
// The banner cites the source receipt by run_id, surfaces the receipt's
// event_kind (when loaded), and exposes a "view full receipt →" link that
// opens the receipt drawer in OVERLAY (does NOT navigate away from the
// simulator). The link is RELATIVE (`receipts/<run_id>`) so it nests under
// whichever parent route mounts the banner — `/admin/policy-simulator`
// for F4 today. Per GAN F005 — an absolute `/admin/dashboard/receipts/<id>`
// would jump to Dashboard, contrary to the brief's "doesn't navigate
// away" mandate.
//
// Constitution Principle VII — extracted from the inline implementation
// previously living inside `PolicySimulator.tsx`. This is the second
// consumer (the source-receipt banner shape may also be reused by the
// Replay mode's "loaded receipt" callout in a future iteration).

import { Link } from "react-router-dom";

import { ApiError } from "~/lib/api";

interface Props {
  /** The source receipt's run_id (UUID-shaped). */
  runId: string;
  /** True while the receipt detail / skeleton is being fetched. */
  loading?: boolean;
  /** Fetch error from the source receipt query. */
  error?: Error | null;
  /** event_kind summary to surface alongside the run_id (e.g. "tool_call"). */
  summary?: string | null;
}

export function DraftFromReceiptBanner({
  runId,
  loading = false,
  error = null,
  summary = null,
}: Props): JSX.Element {
  return (
    <div
      data-testid="draft-from-receipt-banner"
      className="mx-6 mt-3 flex items-center justify-between gap-3 rounded border border-r5e-accent/40 bg-r5e-accent/5 px-3 py-2 text-xs"
    >
      <div className="flex flex-col gap-0.5">
        <span className="text-[10px] font-mono uppercase tracking-wider text-r5e-muted">
          Drafting from receipt
        </span>
        <span className="font-mono text-r5e-text">
          {runId}
          {summary && <span className="text-r5e-muted"> · {summary}</span>}
        </span>
        {loading && (
          <span className="text-[10px] text-r5e-muted">
            Loading skeleton…
          </span>
        )}
        {error && (
          <span className="text-[10px] text-r5e-danger">
            {error instanceof ApiError ? error.error_description : error.message}
          </span>
        )}
      </div>
      {/* Relative `receipts/<run_id>` so the drawer overlays the simulator
          (the parent route). Per F4 brief — must NOT navigate away from
          the simulator. The receipt detail drawer's `close()` uses `..`
          so closing returns to the simulator with all in-flight state
          preserved. */}
      <Link
        to={`receipts/${encodeURIComponent(runId)}`}
        className="text-[11px] text-r5e-accent hover:underline"
      >
        view full receipt →
      </Link>
    </div>
  );
}
