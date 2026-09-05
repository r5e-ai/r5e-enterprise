// SuggestionCard — single suggestion presenter for the Policy Suggestions
// surface (T136 — Phase 7 US5; redesigned per `design/briefs/05-suggestions.md`).
//
// Layout per brief 05:
//
//   ┌──────────────────────────────────────────────────────────┐
//   │ [HEURISTIC] [HIGH CONFIDENCE]                            │
//   │  Forbid bash subprocess writes outside working directory │
//   │  Auditor pattern: 17 denied bash commands writing to     │
//   │  /etc/* or /tmp/* in the last 24h.                       │
//   │  forbid (...) { ... }              ← collapsible Cedar   │
//   │  Triggered by: 17 receipts → view 5 examples →           │
//   │  Blast radius preview: 12 unintended · 5 matches intent  │
//   │  [ADOPT AS DRAFT] [SIMULATE FIRST] [DISMISS ▾]           │
//   └──────────────────────────────────────────────────────────┘
//
// Pills:
//   - HEURISTIC = outline accent / LLM = solid accent
//   - HIGH = solid success / MEDIUM = solid warning / LOW = outline neutral
//
// Cedar preview: collapsed to ~5 lines by default (reveals first 5 lines of
// the proposed source); "expand" link reveals the full source. We don't
// pull in Monaco for the read-only preview here — a static <pre> with the
// monospace font is faster, smaller, and avoids the lazy-chunk cost on
// every list render. The full Cedar editor in the simulator handles the
// authoring path.
//
// Triggered-by: muted text + clickable link that opens a popover listing
// the example receipts. Each receipt link deep-links to the dashboard's
// receipt drawer overlay.
//
// CTAs:
//   - ADOPT AS DRAFT — parent owns the mutation; on success navigates to
//     `/admin/policy-simulator?mode=draft&suggestion=<id>&draft_id=<id>`
//   - SIMULATE FIRST — sandbox path: navigates to the simulator with
//     `?mode=draft&suggestion=<id>&sandbox=1` without creating a saved
//     draft up front.
//   - DISMISS ▾ — small dropdown surfacing 4 reason buckets:
//       Not relevant / Wrong policy shape / Already covered / Other (with note)
//
// The card is purely presentational — the parent owns the network state
// (adopt/dismiss mutation, post-success navigation). The dismiss reason is
// the only piece of local state on the card.

import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";

import { Pill } from "~/components/shared/Pill";
import {
  type PolicySuggestion,
  type PolicySuggestionBlastRadiusSnapshot,
} from "~/hooks/usePolicySuggestions";
import { relativeFromNow } from "~/lib/policy_suggestions";
import { receiptDetailPath, stripBasename } from "~/lib/routes";

interface Props {
  suggestion: PolicySuggestion;
  /** Trigger adoption. Parent owns the mutation + post-success navigation. */
  onAdopt: () => void;
  /** Trigger sandbox-simulate (no saved draft). Parent owns the navigation. */
  onSimulate?: () => void;
  /** Trigger dismissal with an optional reason. */
  onDismiss: (reason?: string) => void;
  /** True while either mutation is in flight; disables the action buttons. */
  isPending: boolean;
}

const CONFIDENCE_HIGH = 90;
const CONFIDENCE_MEDIUM = 70;
const CEDAR_PREVIEW_LINES = 5;

/** Reasons surfaced in the DISMISS dropdown per brief 05. */
const DISMISS_REASONS: ReadonlyArray<{ key: string; label: string }> = [
  { key: "not_relevant", label: "Not relevant" },
  { key: "wrong_policy_shape", label: "Wrong policy shape" },
  { key: "already_covered", label: "Already covered" },
  { key: "other", label: "Other (with note)" },
];

interface ConfidenceTone {
  label: string;
  tone: "success" | "warning" | "neutral";
  outline: boolean;
}

function confidenceTone(confidence: number): ConfidenceTone {
  if (confidence >= CONFIDENCE_HIGH) {
    return { label: "High confidence", tone: "success", outline: false };
  }
  if (confidence >= CONFIDENCE_MEDIUM) {
    return { label: "Medium confidence", tone: "warning", outline: false };
  }
  return { label: "Low confidence", tone: "neutral", outline: true };
}

interface SourceTone {
  label: string;
  outline: boolean;
}

function sourceTone(source: PolicySuggestion["source"]): SourceTone {
  // Brief 05: HEURISTIC outline-accent / LLM solid-accent — distinguishes the
  // two engine paths at a glance. We use the shared Pill primitive's
  // "accent" tone with the outline flag flipped per source.
  if (source === "heuristic") {
    return { label: "Heuristic", outline: true };
  }
  return { label: "LLM", outline: false };
}

/** Take the first N non-empty lines of the Cedar source for preview. */
function previewLines(cedar: string, n: number): { preview: string; hasMore: boolean } {
  const lines = cedar.split(/\r?\n/);
  if (lines.length <= n) return { preview: cedar, hasMore: false };
  return {
    preview: lines.slice(0, n).join("\n"),
    hasMore: true,
  };
}

export function SuggestionCard({
  suggestion,
  onAdopt,
  onSimulate,
  onDismiss,
  isPending,
}: Props): JSX.Element {
  const [expanded, setExpanded] = useState(false);
  const [showTriggers, setShowTriggers] = useState(false);
  const [dismissOpen, setDismissOpen] = useState(false);
  const [otherNote, setOtherNote] = useState("");
  const [otherInputOpen, setOtherInputOpen] = useState(false);

  const isLowConfidence = suggestion.confidence < CONFIDENCE_MEDIUM;
  const isAdopted = suggestion.status === "adopted_as_draft";
  const isDismissed = suggestion.status === "dismissed";
  const source = sourceTone(suggestion.source);
  const conf = confidenceTone(suggestion.confidence);

  // Brief 05 splits the legacy `pattern_summary` into title (one-liner) +
  // body (longer explanatory paragraph). When the wire only carries
  // `pattern_summary` we surface it as the title and skip the body.
  const title = suggestion.title?.trim() || suggestion.pattern_summary;
  const body = suggestion.body?.trim() || null;

  const { preview, hasMore } = previewLines(
    suggestion.proposed_cedar,
    CEDAR_PREVIEW_LINES,
  );

  return (
    <article
      data-testid={`suggestion-card-${suggestion.id}`}
      data-source={suggestion.source}
      data-status={suggestion.status}
      data-low-confidence={isLowConfidence ? "true" : "false"}
      className={`flex flex-col gap-3 rounded border border-r5e-border bg-r5e-surface p-4 transition-opacity ${
        isLowConfidence ? "opacity-70 hover:opacity-100" : ""
      }`}
    >
      {/* Top row: source pill + confidence pill + status overlay + generated_at */}
      <header className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap items-center gap-2">
          <Pill
            tone="accent"
            outline={source.outline}
            size="sm"
            testId="suggestion-source-pill"
          >
            {source.label}
          </Pill>
          <Pill
            tone={conf.tone}
            outline={conf.outline}
            size="sm"
            testId="suggestion-confidence-pill"
          >
            {conf.label}
          </Pill>
          {isAdopted && (
            <Pill
              tone="success"
              size="sm"
              testId="suggestion-status-adopted"
            >
              Adopted
            </Pill>
          )}
          {isDismissed && (
            <Pill
              tone="muted"
              size="sm"
              testId="suggestion-status-dismissed"
            >
              Dismissed
            </Pill>
          )}
        </div>
        {/* F006 (fix-pass-2) — match the page header's relative format. The
            page reads "Last run: N min ago" while each card previously
            stamped the raw ISO ("2026-04-30T10:00:00Z"), mixing two formats
            for the same kind of value inside one viewport. We keep
            `dateTime={...}` on the element so the a11y / title-tooltip
            still resolves to the absolute timestamp; only the visible text
            switches to the consistent relative cadence. */}
        <time
          dateTime={suggestion.generated_at}
          title={suggestion.generated_at}
          className="font-mono text-[10px] text-r5e-muted"
          data-testid="suggestion-generated-at"
        >
          {relativeFromNow(suggestion.generated_at)}
        </time>
      </header>

      {/* Title + body */}
      <div className="flex flex-col gap-1.5">
        <h3
          data-testid="suggestion-title"
          className="text-sm font-semibold leading-snug text-r5e-text"
        >
          {title}
        </h3>
        {body && (
          <p
            data-testid="suggestion-body"
            className="text-xs leading-relaxed text-r5e-muted"
          >
            {body}
          </p>
        )}
      </div>

      {/* Cedar preview — first 5 lines visible by default; expand for full */}
      <div
        className="flex flex-col gap-1.5"
        data-testid="suggestion-cedar-preview"
      >
        <pre
          data-testid="suggestion-proposed-rule"
          data-expanded={expanded ? "true" : "false"}
          className="overflow-x-auto rounded border border-r5e-border bg-r5e-bg p-3 font-mono text-[11px] leading-relaxed text-r5e-text"
        >
          {expanded ? suggestion.proposed_cedar : preview}
        </pre>
        {hasMore && (
          <button
            type="button"
            onClick={() => setExpanded((v) => !v)}
            aria-expanded={expanded}
            data-testid="suggestion-toggle-rule"
            className="self-start text-[10px] font-semibold uppercase tracking-wider text-r5e-muted hover:text-r5e-accent"
          >
            {expanded ? "Collapse rule" : "Expand rule"}
          </button>
        )}
      </div>

      {/* Triggered-by line + popover */}
      <TriggeredByLine
        suggestion={suggestion}
        open={showTriggers}
        onToggle={() => setShowTriggers((v) => !v)}
        onClose={() => setShowTriggers(false)}
      />

      {/* Inline blast-radius preview — text-only summary per brief 05 */}
      <BlastRadiusInlineSummary snapshot={suggestion.blast_radius_snapshot ?? null} />

      {/* Dismiss reason (when this is a dismissed-tab card) */}
      {isDismissed && suggestion.dismiss_reason && (
        <p
          data-testid="suggestion-dismiss-reason"
          className="text-[11px] italic text-r5e-muted"
        >
          Dismissed: {suggestion.dismiss_reason}
        </p>
      )}

      {/* Bottom row: ADOPT / SIMULATE FIRST / DISMISS ▾ */}
      {!isAdopted && !isDismissed && (
        <footer className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={onAdopt}
              disabled={isPending}
              data-testid="suggestion-adopt"
              className="rounded border border-r5e-accent bg-r5e-accent/15 px-3 py-1.5 text-[11px] font-semibold uppercase tracking-wider text-r5e-accent hover:bg-r5e-accent/25 disabled:cursor-not-allowed disabled:opacity-50"
            >
              Adopt as draft
            </button>
            {onSimulate && (
              <button
                type="button"
                onClick={onSimulate}
                disabled={isPending}
                data-testid="suggestion-simulate"
                className="rounded border border-r5e-border px-3 py-1.5 text-[11px] font-semibold uppercase tracking-wider text-r5e-text hover:border-r5e-accent hover:text-r5e-accent disabled:cursor-not-allowed disabled:opacity-50"
              >
                Simulate first
              </button>
            )}
            <DismissDropdown
              open={dismissOpen}
              onToggle={() => {
                setDismissOpen((v) => !v);
                setOtherInputOpen(false);
              }}
              onClose={() => {
                setDismissOpen(false);
                setOtherInputOpen(false);
              }}
              disabled={isPending}
              otherNote={otherNote}
              otherInputOpen={otherInputOpen}
              onOtherNoteChange={setOtherNote}
              onPickReason={(key, label) => {
                if (key === "other") {
                  if (!otherInputOpen) {
                    setOtherInputOpen(true);
                    return;
                  }
                  const note = otherNote.trim();
                  if (!note) return;
                  onDismiss(`Other: ${note}`);
                  setDismissOpen(false);
                  setOtherInputOpen(false);
                  setOtherNote("");
                  return;
                }
                onDismiss(label);
                setDismissOpen(false);
              }}
            />
          </div>
          <Link
            to={stripBasename(
              `/admin/chat?chat=open&seed=${encodeURIComponent(
                `Explain why suggestion ${suggestion.id} (source=${suggestion.source}, confidence=${suggestion.confidence}) was generated, and how the proposed Cedar would affect the last 30 days of receipts.`,
              )}`,
            )}
            data-testid="suggestion-explain"
            className="text-[11px] text-r5e-accent hover:underline"
          >
            Explain →
          </Link>
        </footer>
      )}
    </article>
  );
}

// ---------------------------------------------------------------------------
// Triggered-by line + popover
// ---------------------------------------------------------------------------

function TriggeredByLine({
  suggestion,
  open,
  onToggle,
  onClose,
}: {
  suggestion: PolicySuggestion;
  open: boolean;
  onToggle: () => void;
  onClose: () => void;
}): JSX.Element | null {
  const ids = suggestion.triggered_by_receipt_ids ?? [];
  const total = suggestion.triggered_by_count ?? ids.length;

  // No trigger metadata at all — skip the line entirely. Keeps cards
  // compact when the wire shape predates the brief redesign.
  if (total === 0 && ids.length === 0) return null;

  const exampleCount = Math.min(ids.length, 5);
  const totalLabel = `${total.toLocaleString()} receipt${total === 1 ? "" : "s"}`;
  const examplesLabel =
    exampleCount > 0
      ? `view ${exampleCount} example${exampleCount === 1 ? "" : "s"} →`
      : null;

  return (
    <div
      className="relative flex flex-col gap-1.5"
      data-testid="suggestion-triggered-by"
    >
      <p className="text-[11px] text-r5e-muted">
        Triggered by: <span className="text-r5e-text">{totalLabel}</span>
        {examplesLabel && ids.length > 0 && (
          <>
            {" · "}
            <button
              type="button"
              onClick={onToggle}
              aria-expanded={open}
              data-testid="suggestion-triggered-by-toggle"
              className="text-r5e-accent hover:underline"
            >
              {examplesLabel}
            </button>
          </>
        )}
      </p>
      {open && ids.length > 0 && (
        <TriggeredByPopover ids={ids.slice(0, 5)} onClose={onClose} />
      )}
    </div>
  );
}

function TriggeredByPopover({
  ids,
  onClose,
}: {
  ids: string[];
  onClose: () => void;
}): JSX.Element {
  // F004 — the popover is anchored absolute over the rest of the card
  // instead of pushing the blast-radius preview + footer down.
  // F007-companion — Escape closes the popover for keyboard-only operators.
  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      if (e.key === "Escape") onClose();
    }
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [onClose]);

  // F006 — receiptDetailPath already calls stripBasename internally
  // (lib/routes.ts), so we pass its output to <Link to> directly. The
  // pre-fix call site wrapped it in another stripBasename which was
  // harmless (idempotent) but diverged from the dashboard audit-log row
  // convention; future callers are less likely to copy a confused
  // double-wrap.
  //
  // F005 (deferred per GAN F005 action=defer): the link still navigates
  // to the dashboard route — making it overlay the suggestions surface
  // instead requires either a nested receipt route under suggestions or
  // a portal-mountable receipt drawer extracted out of Dashboard.tsx.
  // Tracked as a follow-up; not in scope for this fix-pass.
  return (
    <div
      role="dialog"
      aria-label="Trigger receipts"
      data-testid="suggestion-triggered-by-popover"
      className="absolute left-0 top-full z-30 mt-1 flex min-w-[260px] flex-col gap-1 rounded border border-r5e-border bg-r5e-bg p-2 shadow-lg"
    >
      <p className="px-1 pb-1 text-[10px] uppercase tracking-wider text-r5e-muted">
        Example receipts
      </p>
      <ul className="flex flex-col gap-px">
        {ids.map((runId) => (
          <li key={runId}>
            <Link
              to={receiptDetailPath(runId)}
              data-testid={`suggestion-trigger-receipt-${runId}`}
              className="block rounded px-2 py-1 font-mono text-[11px] text-r5e-accent hover:bg-r5e-accent/10 hover:underline"
            >
              {runId}
            </Link>
          </li>
        ))}
      </ul>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Dismiss dropdown
// ---------------------------------------------------------------------------

function DismissDropdown({
  open,
  onToggle,
  onClose,
  disabled,
  onPickReason,
  otherNote,
  otherInputOpen,
  onOtherNoteChange,
}: {
  open: boolean;
  onToggle: () => void;
  onClose: () => void;
  disabled: boolean;
  onPickReason: (key: string, label: string) => void;
  otherNote: string;
  otherInputOpen: boolean;
  onOtherNoteChange: (next: string) => void;
}): JSX.Element {
  const containerRef = useRef<HTMLDivElement | null>(null);

  // Click-outside closes the menu. Escape key also closes — keyboard-only
  // operators tabbing into Dismiss need a fast way out without picking a
  // reason. (F007 — a11y baseline gap on an audit-tool surface where
  // keyboard-driven workflows are common.)
  useEffect(() => {
    if (!open) return;
    function handleClick(e: MouseEvent) {
      if (
        containerRef.current &&
        !containerRef.current.contains(e.target as Node)
      ) {
        onClose();
      }
    }
    function handleKey(e: KeyboardEvent) {
      if (e.key === "Escape") onClose();
    }
    document.addEventListener("mousedown", handleClick);
    document.addEventListener("keydown", handleKey);
    return () => {
      document.removeEventListener("mousedown", handleClick);
      document.removeEventListener("keydown", handleKey);
    };
  }, [open, onClose]);

  return (
    <div ref={containerRef} className="relative">
      <button
        type="button"
        onClick={onToggle}
        disabled={disabled}
        aria-haspopup="menu"
        aria-expanded={open}
        data-testid="suggestion-dismiss"
        className="rounded border border-r5e-border bg-r5e-bg px-3 py-1.5 text-[11px] font-semibold uppercase tracking-wider text-r5e-muted hover:border-r5e-text hover:text-r5e-text disabled:cursor-not-allowed disabled:opacity-50"
      >
        Dismiss <span aria-hidden="true">▾</span>
      </button>
      {open && (
        <div
          role="menu"
          data-testid="suggestion-dismiss-menu"
          className="absolute left-0 top-full z-30 mt-1 flex min-w-[200px] flex-col gap-px rounded border border-r5e-border bg-r5e-bg p-1 shadow-lg"
        >
          {DISMISS_REASONS.map((r) => {
            const isOther = r.key === "other";
            const showOtherInput = isOther && otherInputOpen;
            return (
              <div key={r.key} className="flex flex-col">
                <button
                  type="button"
                  role="menuitem"
                  onClick={() => onPickReason(r.key, r.label)}
                  data-testid={`suggestion-dismiss-reason-${r.key}`}
                  className="rounded px-2 py-1.5 text-left text-[11px] text-r5e-text hover:bg-r5e-accent/10 hover:text-r5e-accent"
                >
                  {r.label}
                </button>
                {showOtherInput && (
                  <div className="flex flex-col gap-1 px-2 py-1">
                    <input
                      type="text"
                      value={otherNote}
                      onChange={(e) => onOtherNoteChange(e.target.value)}
                      onKeyDown={(e) => {
                        // F007 — Enter submits the Other note (matches
                        // operator muscle-memory on form-style inputs);
                        // Escape closes the menu via the document-level
                        // listener installed above.
                        if (e.key === "Enter" && otherNote.trim()) {
                          e.preventDefault();
                          onPickReason("other", "Other");
                        }
                      }}
                      placeholder="Reason note"
                      autoFocus
                      data-testid="suggestion-dismiss-other-note"
                      className="w-full rounded border border-r5e-border bg-r5e-bg px-2 py-1 text-[11px] text-r5e-text outline-none focus:border-r5e-accent"
                    />
                    <button
                      type="button"
                      onClick={() => onPickReason("other", "Other")}
                      disabled={!otherNote.trim()}
                      data-testid="suggestion-dismiss-other-submit"
                      className="self-end rounded border border-r5e-accent px-2 py-1 text-[10px] uppercase tracking-wider text-r5e-accent hover:bg-r5e-accent/15 disabled:cursor-not-allowed disabled:opacity-50"
                    >
                      Submit
                    </button>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Inline blast-radius preview text (brief 05 layout)
// ---------------------------------------------------------------------------

function BlastRadiusInlineSummary({
  snapshot,
}: {
  snapshot: PolicySuggestionBlastRadiusSnapshot | null;
}): JSX.Element | null {
  // F004 (fix-pass-2) — distinguish "engine never ran" from "engine ran,
  // confirmed no impact". Pre-fix both states rendered as `null`, hiding
  // the high-confidence-no-impact signal from operators triaging adopt.
  // When `snapshot === null` the engine hasn't run; we omit the line so
  // cards stay compact. When the snapshot exists but every count is 0 we
  // surface an explicit "Engine ran, no policy delta" — the operator
  // knows the dry-run completed and the rule is safe to adopt.
  if (!snapshot) return null;

  const unintended = snapshot.unintended ?? 0;
  const matches = snapshot.matches_intent ?? 0;
  const wouldHave = snapshot.would_have_allowed ?? 0;
  const totalAffected = snapshot.total_affected ?? unintended + matches + wouldHave;
  const engineRanAt = snapshot.computed_at ?? null;

  if (unintended === 0 && matches === 0 && wouldHave === 0) {
    // Engine ran (snapshot exists) and confirmed zero impact — say so.
    // The wire shape doesn't strictly require `computed_at`, but a
    // snapshot with zero counts is itself proof the engine ran (engines
    // don't emit empty snapshots). We still surface the timestamp when
    // present for operator context.
    if (totalAffected === 0) {
      return (
        <p
          data-testid="suggestion-blast-radius"
          data-engine-ran="true"
          data-empty="true"
          className="text-[11px] text-r5e-muted"
        >
          Blast radius preview:{" "}
          <span
            className="text-r5e-success"
            data-testid="suggestion-blast-no-delta"
          >
            Engine ran, no policy delta
          </span>
          {engineRanAt && (
            <span
              className="ml-1 font-mono text-[10px] text-r5e-muted"
              data-testid="suggestion-blast-computed-at"
            >
              ({engineRanAt})
            </span>
          )}
        </p>
      );
    }
    return null;
  }

  return (
    <p
      data-testid="suggestion-blast-radius"
      className="text-[11px] text-r5e-muted"
    >
      Blast radius preview:{" "}
      <span
        className="text-r5e-danger"
        data-testid="suggestion-blast-unintended"
      >
        {unintended.toLocaleString()} unintended
      </span>
      {" · "}
      <span
        className="text-r5e-success"
        data-testid="suggestion-blast-matches"
      >
        {matches.toLocaleString()} matches intent
      </span>
      {wouldHave > 0 && (
        <>
          {" · "}
          <span
            className="text-r5e-warning"
            data-testid="suggestion-blast-would-have"
          >
            {wouldHave.toLocaleString()} would-have-allowed
          </span>
        </>
      )}
    </p>
  );
}
