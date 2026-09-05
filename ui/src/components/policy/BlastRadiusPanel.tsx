// BlastRadiusPanel — 4-cell Wiz-pattern matrix for the Policy Simulator
// (T094 — Phase 5 US3, FR-026 + FR-027; F4 redesign per
// `design/briefs/04-policy-simulator.md`).
//
// Wiz wedge layout:
//
//                    Old: ALLOW            Old: DENY
//                  ┌─────────────────────┬─────────────────────┐
//     New: ALLOW   │ NO CHANGE   1,572   │ WOULD HAVE  51      │
//                  │ (allow continued)   │ (now permit)        │
//                  ├─────────────────────┼─────────────────────┤
//     New: DENY    │ UNINTENDED  127     │ MATCHES INTENT 92%  │
//                  │ (NEW BLOCKS)        │ (deny continued)    │
//                  └─────────────────────┴─────────────────────┘
//
// Key brief mandates:
//   - MATCHES INTENT (bottom-right) is the success-green TOP-LINE metric,
//     rendered as a percentage (matches_intent / total_affected*100) so
//     the auditor sees "92%" at a glance, not "matches=2 unintended=127".
//   - UNINTENDED (bottom-left) is solid danger-red — these are NEW BLOCKS
//     the draft would introduce that aren't currently denied. These are
//     the regressions the auditor is hunting for.
//   - WOULD HAVE (top-right) is warning-yellow — currently denied, draft
//     would now permit. Surface but do not emphasize.
//   - NO CHANGE (top-left) is muted — currently allowed, still allowed;
//     no change of behavior.
//   - Sample receipts list ALWAYS sorts UNINTENDED rows to the top.
//   - "view full receipt" links open the drawer in OVERLAY (does not
//     navigate away from the simulator).
//
// SPEC ADVISORIES (per FR-026 + FR-027 — restored in fix-pass-2):
//   - FR-027 — UnintendedAdvisory renders BELOW the matrix whenever
//     `unintended > 0`, with copy that recommends narrowings + a
//     `→ Suggestions` deep-link. The cell ring-highlight is retained as a
//     visual emphasis but the *advisory text* satisfies the spec MUST.
//   - FR-026 (c) — WouldHaveAllowedAdvisory renders below the matrix when
//     `would_have_allowed > 0`. Secondary tone (warning).
//   - FR-026 (d) — `show all (incl. no-change)` toggle filters the
//     sample-receipts list. The 4-cell matrix always renders, but the
//     `no_change` rows in the sample list are hidden by default and
//     revealed by the toggle.
//
// The panel renders one of three states:
//   1. idle      — call-to-action ("Run dry-run") + helper copy
//   2. pending   — spinner skeleton
//   3. complete  — the 4-cell 2x2 + advisories + sample list
//
// Component is purely presentational — parent owns the dry-run trigger.

import { useState } from "react";
import { Link } from "react-router-dom";

import { ErrorState as SharedErrorState } from "~/components/shared/states";
import { routes, stripBasename } from "~/lib/routes";
import {
  type BlastRadiusClassification,
  type BlastRadiusResult,
  type BlastRadiusSampleReceipt,
} from "~/hooks/useBlastRadius";

interface Props {
  result: BlastRadiusResult | null;
  isPending: boolean;
  error: Error | null;
  /** Trigger the dry-run. Component is presentational; parent owns the call. */
  onRun: () => void;
}

// UNINTENDED first per brief — "We surface unintended blocks first so you
// can spot regressions before deploying." Then WOULD HAVE (the warning),
// then MATCHES (correct), then NO CHANGE (the noise).
const CLASSIFICATION_PRIORITY: BlastRadiusClassification[] = [
  "unintended",
  "would_have_allowed",
  "matches_intent",
  "no_change",
];

// Sort sample receipts by classification priority then truncate to 20 — the
// Wiz wedge surfaces UNINTENDED at the top so a single glance reveals
// regression risk. Per FR-026 (d) — `no_change` rows are hidden from the
// sample list by default; the `showAll` toggle reveals them.
function sortSamples(
  samples: BlastRadiusSampleReceipt[],
  showAll: boolean,
): BlastRadiusSampleReceipt[] {
  const filtered = showAll
    ? samples
    : samples.filter((s) => s.classification !== "no_change");
  return filtered
    .slice()
    .sort(
      (a, b) =>
        CLASSIFICATION_PRIORITY.indexOf(a.classification) -
        CLASSIFICATION_PRIORITY.indexOf(b.classification),
    )
    .slice(0, 20);
}

export function BlastRadiusPanel({
  result,
  isPending,
  error,
  onRun,
}: Props): JSX.Element {
  // FR-026 (d) — `show all (incl. no-change)` toggle filters the sample
  // list. `no_change` is the dominant noise class on most rules; hiding
  // it by default keeps the auditor's eye on the regression-revealing
  // UNINTENDED + WOULD-HAVE rows.
  const [showAll, setShowAll] = useState(false);

  return (
    <section
      data-testid="blast-radius-panel"
      aria-label="Blast radius"
      className="flex flex-col gap-3 rounded border border-r5e-border bg-r5e-surface p-4"
    >
      <header className="flex items-center justify-between">
        <h2 className="text-sm font-semibold text-r5e-text">Blast radius</h2>
        <div className="flex items-center gap-3">
          {result && (
            <label
              className="flex items-center gap-1.5 text-[10px] uppercase tracking-wider text-r5e-muted"
              data-testid="blast-radius-show-all-label"
            >
              <input
                type="checkbox"
                checked={showAll}
                onChange={(e) => setShowAll(e.target.checked)}
                className="h-3 w-3 accent-r5e-accent"
                data-testid="blast-radius-show-all"
              />
              Show all (incl. no-change)
            </label>
          )}
          <button
            type="button"
            onClick={onRun}
            disabled={isPending}
            className="rounded border border-r5e-accent bg-r5e-accent/10 px-3 py-1.5 text-[10px] font-semibold uppercase tracking-wider text-r5e-accent hover:bg-r5e-accent/20 disabled:cursor-not-allowed disabled:opacity-50"
            data-testid="blast-radius-run"
          >
            {isPending ? "Running…" : result ? "Re-run dry-run" : "Run dry-run"}
          </button>
        </div>
      </header>

      {error && <ErrorBanner error={error} />}

      {!result && !isPending && !error && <IdleState />}

      {isPending && !result && <PendingSkeleton />}

      {result && (
        <>
          <MatchesIntentTopline result={result} />
          <WizMatrix result={result} />
          {/* FR-027 — primary advisory, surfaced when `unintended > 0`. */}
          {result.unintended > 0 && (
            <UnintendedAdvisory count={result.unintended} />
          )}
          {/* FR-026 (c) — secondary advisory, surfaced when
              `would_have_allowed > 0`. */}
          {result.would_have_allowed > 0 && (
            <WouldHaveAllowedAdvisory count={result.would_have_allowed} />
          )}
          <FooterSummary result={result} />
          <SampleReceiptsList
            samples={sortSamples(result.sample_receipts, showAll)}
          />
        </>
      )}
    </section>
  );
}

// ---------------------------------------------------------------------------
// MATCHES INTENT topline — the headline metric.
// ---------------------------------------------------------------------------
//
// Threshold below which the topline drops the success-green palette. Brief
// mandates "≥ 75% match-rate per brief intent" before painting the topline
// in success-green; below the threshold (or when total_affected = 0) we
// render an empty state instead of a misleading 0%-in-green pill.
const MATCH_RATE_SUCCESS_THRESHOLD = 75;

function MatchesIntentTopline({
  result,
}: {
  result: BlastRadiusResult;
}): JSX.Element {
  // Denominator is the backend-canonical `total_affected`, defined per the
  // `blast_radius_algorithm.md` contract as
  //   total_affected = matches_intent + unintended.
  // (Would-have-allowed is a subset of no_change in the algorithm and is
  // NOT included here.)
  //
  // Two empty-state branches:
  //   1. total_affected === 0 — the rule doesn't fire on any historical
  //      receipt. Render a neutral empty state (NOT 0% in success-green;
  //      see GAN F003 + F006). The auditor needs to see "rule didn't fire,
  //      try again with a wider scope" rather than a false-success metric.
  //   2. pct < MATCH_RATE_SUCCESS_THRESHOLD — the rule fires but the match
  //      rate is below the brief's 75% intent threshold. We still render
  //      a percentage, but in warning-yellow so the auditor knows the
  //      rule needs tightening.
  if (result.total_affected === 0) {
    return (
      <div
        data-testid="matches-intent-topline"
        data-state="empty"
        className="flex items-baseline justify-between rounded border border-r5e-border bg-r5e-bg px-4 py-3"
      >
        <span className="text-[10px] font-mono uppercase tracking-wider text-r5e-muted">
          Matches intent
        </span>
        <span
          className="font-mono text-3xl font-semibold text-r5e-muted"
          data-testid="matches-intent-pct"
        >
          —
        </span>
      </div>
    );
  }

  const pct = Math.round((result.matches_intent / result.total_affected) * 100);
  const aboveThreshold = pct >= MATCH_RATE_SUCCESS_THRESHOLD;
  const palette = aboveThreshold
    ? {
        box: "border-r5e-success/40 bg-r5e-success/10",
        label: "text-r5e-success",
        count: "text-r5e-success",
      }
    : {
        box: "border-r5e-warning/40 bg-r5e-warning/10",
        label: "text-r5e-warning",
        count: "text-r5e-warning",
      };
  return (
    <div
      data-testid="matches-intent-topline"
      data-state={aboveThreshold ? "success" : "warning"}
      className={`flex items-baseline justify-between rounded border px-4 py-3 ${palette.box}`}
    >
      <span className={`text-[10px] font-mono uppercase tracking-wider ${palette.label}`}>
        Matches intent
      </span>
      <span
        className={`font-mono text-3xl font-semibold ${palette.count}`}
        data-testid="matches-intent-pct"
      >
        {pct}%
      </span>
    </div>
  );
}

// ---------------------------------------------------------------------------
// 2x2 Wiz matrix — `Old × New` × `ALLOW × DENY`.
// ---------------------------------------------------------------------------

// Brief mock (xMKo8) shows MATCHES INTENT 92% inside the cell; canonical
// design moves the percentage to the dedicated `<MatchesIntentTopline />`
// pill above the matrix and keeps the cell on raw counts for parity with
// the other three classification cells. Per GAN F008 — defensible visual
// divergence from the brief mock; the topline-as-headline is more legible
// for the SOC-analyst audience at 1440px.
function WizMatrix({ result }: { result: BlastRadiusResult }): JSX.Element {
  return (
    <div
      data-testid="blast-radius-matrix"
      className="flex flex-col gap-1.5"
    >
      {/* Column header axis: Old: ALLOW | Old: DENY */}
      <div
        aria-hidden="true"
        className="grid grid-cols-[80px_1fr_1fr] items-end gap-2"
      >
        <span />
        <span className="text-center text-[10px] uppercase tracking-wider text-r5e-muted">
          Old: Allow
        </span>
        <span className="text-center text-[10px] uppercase tracking-wider text-r5e-muted">
          Old: Deny
        </span>
      </div>

      {/* Row 1: New: ALLOW — NO CHANGE | WOULD HAVE */}
      <div className="grid grid-cols-[80px_1fr_1fr] gap-2">
        <span
          aria-hidden="true"
          className="self-center text-right text-[10px] uppercase tracking-wider text-r5e-muted"
        >
          New: Allow
        </span>
        <Cell
          testId="cell-no-change"
          label="No change"
          hint="Allow continued"
          count={result.no_change}
          tone="neutral"
        />
        <Cell
          testId="cell-would-have-allowed"
          label="Would have"
          hint="Now permit"
          count={result.would_have_allowed}
          tone="warning"
        />
      </div>

      {/* Row 2: New: DENY — UNINTENDED | MATCHES INTENT */}
      <div className="grid grid-cols-[80px_1fr_1fr] gap-2">
        <span
          aria-hidden="true"
          className="self-center text-right text-[10px] uppercase tracking-wider text-r5e-muted"
        >
          New: Deny
        </span>
        <Cell
          testId="cell-unintended"
          label="Unintended"
          hint="New blocks"
          count={result.unintended}
          tone="danger"
          prominent={result.unintended > 0}
        />
        <Cell
          testId="cell-matches-intent"
          label="Matches intent"
          hint="Deny continued"
          count={result.matches_intent}
          tone="success"
        />
      </div>
    </div>
  );
}

type Tone = "success" | "danger" | "warning" | "neutral";

const TONE_CLASSES: Record<Tone, { box: string; label: string; count: string }> = {
  success: {
    box: "border-r5e-success/40 bg-r5e-success/10",
    label: "text-r5e-success",
    count: "text-r5e-success",
  },
  danger: {
    // Solid danger-red per brief — UNINTENDED is the loudest signal.
    box: "border-r5e-danger bg-r5e-danger/15",
    label: "text-r5e-danger",
    count: "text-r5e-danger",
  },
  warning: {
    box: "border-r5e-warning/40 bg-r5e-warning/10",
    label: "text-r5e-warning",
    count: "text-r5e-warning",
  },
  neutral: {
    box: "border-r5e-border bg-r5e-bg",
    label: "text-r5e-muted",
    count: "text-r5e-text",
  },
};

function Cell({
  testId,
  label,
  hint,
  count,
  tone,
  prominent = false,
}: {
  testId: string;
  label: string;
  hint: string;
  count: number;
  tone: Tone;
  prominent?: boolean;
}): JSX.Element {
  const classes = TONE_CLASSES[tone];
  return (
    <div
      data-testid={testId}
      className={`flex flex-col gap-0.5 rounded border p-2.5 ${classes.box} ${
        prominent ? "ring-2 ring-r5e-danger/60" : ""
      }`}
    >
      <span className={`text-[9px] uppercase tracking-wider ${classes.label}`}>
        {label}
      </span>
      <span
        className={`font-mono text-xl font-semibold leading-none ${classes.count}`}
        data-testid={`${testId}-count`}
      >
        {count.toLocaleString()}
      </span>
      {/* Per F4 brief + GAN F011 — hint stays at text-[10px] for SOC analyst
          @ 1440px+ readability. Cell label above can stay at text-[9px]
          for fit since it's uppercase + tracking-wider. */}
      <span className="text-[10px] text-r5e-muted">{hint}</span>
    </div>
  );
}

// ---------------------------------------------------------------------------
// FR-027 unintended advisory + FR-026 (c) would-have-allowed advisory
// ---------------------------------------------------------------------------
//
// Both advisories sit BELOW the 4-cell matrix. They satisfy the spec MUST:
// the cell ring-highlight + tone-coding is a glance-level cue, but the
// advisory carries the recommendation copy ("consider narrowing", "review
// whether this loosening is intentional") and the deep-link to the
// Suggestions queue where the operator can act on the finding.

function UnintendedAdvisory({ count }: { count: number }): JSX.Element {
  return (
    <div
      role="alert"
      data-testid="unintended-block-advisory"
      className="flex items-start gap-3 rounded border border-r5e-danger bg-r5e-danger/10 p-3"
    >
      <WarningIcon className="mt-0.5 h-5 w-5 shrink-0 text-r5e-danger" />
      <div className="flex flex-1 flex-col gap-1 text-xs text-r5e-danger">
        <strong className="text-sm font-semibold">
          {count.toLocaleString()} action{count === 1 ? "" : "s"} would have been
          incorrectly blocked.
        </strong>
        <span>
          Consider narrowing the rule (tighten the scope, add a condition that
          excludes the legitimate cases).
        </span>
        <Link
          to={stripBasename(routes.policySimulatorSuggestions)}
          className="self-start text-r5e-danger underline-offset-2 hover:underline"
          data-testid="unintended-block-advisory-suggestions-link"
        >
          Open suggestions →
        </Link>
      </div>
    </div>
  );
}

function WouldHaveAllowedAdvisory({ count }: { count: number }): JSX.Element {
  return (
    <div
      role="status"
      data-testid="would-have-allowed-advisory"
      className="flex items-start gap-3 rounded border border-r5e-warning/60 bg-r5e-warning/10 p-3"
    >
      <span className="mt-0.5 inline-block h-2 w-2 shrink-0 rounded-full bg-r5e-warning" />
      <div className="flex flex-col gap-1 text-xs text-r5e-warning">
        <strong className="text-sm font-semibold">
          {count.toLocaleString()} previously-denied call
          {count === 1 ? "" : "s"} would now be allowed.
        </strong>
        <span>Review whether this loosening is intentional.</span>
      </div>
    </div>
  );
}

function WarningIcon({ className }: { className?: string }): JSX.Element {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
      aria-hidden="true"
    >
      <path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0Z" />
      <line x1="12" y1="9" x2="12" y2="13" />
      <line x1="12" y1="17" x2="12.01" y2="17" />
    </svg>
  );
}

function FooterSummary({ result }: { result: BlastRadiusResult }): JSX.Element {
  return (
    <div className="grid grid-cols-2 gap-2 text-[10px] text-r5e-muted">
      <span>
        Window: <span className="font-mono text-r5e-text">{result.window_days}d</span>
      </span>
      <span>
        Scanned:{" "}
        <span className="font-mono text-r5e-text">
          {result.total_receipts_in_window.toLocaleString()}
        </span>
      </span>
      <span>
        Affected:{" "}
        <span className="font-mono text-r5e-text">
          {result.total_affected.toLocaleString()}
        </span>
      </span>
      <span>
        Computed: <span className="font-mono text-r5e-text">{result.computed_at}</span>
      </span>
    </div>
  );
}

function SampleReceiptsList({
  samples,
}: {
  samples: BlastRadiusSampleReceipt[];
}): JSX.Element | null {
  if (samples.length === 0) return null;
  return (
    <div className="flex flex-col gap-2" data-testid="sample-receipts">
      <h3 className="text-[10px] uppercase tracking-wider text-r5e-muted">
        Sample receipts ({samples.length})
      </h3>
      <ul className="flex flex-col divide-y divide-r5e-border rounded border border-r5e-border bg-r5e-bg">
        {samples.map((s) => (
          <li
            key={s.run_id}
            className="flex items-center justify-between gap-3 px-3 py-1.5 text-[11px]"
            data-testid={`sample-receipt-${s.classification}`}
          >
            <ClassificationChip kind={s.classification} />
            <span className="flex-1 truncate font-mono text-r5e-text">
              {s.summary || s.run_id}
            </span>
            {/* Relative `receipts/<run_id>` so the drawer overlays the
                CURRENT parent route (Policy Simulator OR Dashboard,
                whichever the auditor is on). Per F4 brief +
                GAN F005 — "doesn't navigate away". An absolute
                `/admin/dashboard/receipts/<id>` would jump to the
                Dashboard host even when called from the simulator. */}
            <Link
              to={`receipts/${encodeURIComponent(s.run_id)}`}
              className="shrink-0 text-r5e-accent hover:underline"
            >
              view full receipt →
            </Link>
          </li>
        ))}
      </ul>
    </div>
  );
}

function ClassificationChip({
  kind,
}: {
  kind: BlastRadiusClassification;
}): JSX.Element {
  const palette: Record<BlastRadiusClassification, string> = {
    matches_intent:
      "border-r5e-success/60 bg-r5e-success/10 text-r5e-success",
    unintended: "border-r5e-danger/60 bg-r5e-danger/10 text-r5e-danger",
    would_have_allowed:
      "border-r5e-warning/60 bg-r5e-warning/10 text-r5e-warning",
    no_change: "border-r5e-border bg-r5e-surface text-r5e-muted",
  };
  const label: Record<BlastRadiusClassification, string> = {
    matches_intent: "matches",
    unintended: "unintended",
    would_have_allowed: "would-allow",
    no_change: "no-change",
  };
  return (
    <span
      className={`inline-block rounded border px-1.5 py-0.5 text-[9px] uppercase tracking-wider ${palette[kind]}`}
    >
      {label[kind]}
    </span>
  );
}

function IdleState(): JSX.Element {
  return (
    <div
      className="flex flex-col gap-1 rounded border border-dashed border-r5e-border bg-r5e-bg p-4 text-center text-xs text-r5e-muted"
      data-testid="blast-radius-idle"
    >
      <span>
        Run a dry-run to see how this draft would have classified the last
        30 days of receipts.
      </span>
      <span className="text-[10px]">
        We surface unintended blocks first so you can spot regressions before
        deploying.
      </span>
    </div>
  );
}

function PendingSkeleton(): JSX.Element {
  return (
    <div
      className="flex items-center gap-2 text-xs text-r5e-muted"
      data-testid="blast-radius-pending"
    >
      <span className="inline-block h-3 w-3 animate-spin rounded-full border-2 border-r5e-accent border-t-transparent" />
      Computing blast radius…
    </div>
  );
}

function ErrorBanner({ error }: { error: Error }): JSX.Element {
  // R5 — shared primitive.
  return (
    <SharedErrorState
      testId="blast-radius-error"
      title="Blast radius failed"
      detail={error.message}
      compact
    />
  );
}
