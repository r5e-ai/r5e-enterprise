// EventInspector (a.k.a. TimelineRightPanel) — receipt detail + related
// events panel that populates when an event is selected on the Timeline.
//
// Per `design/briefs/10-session-trace.md` right-panel spec:
//   - RECEIPT DATA section — compact key/value summary of the selected
//     event's identity + decision context. "View full Tags →" link opens
//     the R2 drawer over the Timeline (modal — same surface auditors use
//     from the dashboard table click).
//   - SEMANTIC ARGUMENTS section — `tags.semantic_args` rendered as a
//     JSON code block (mono).
//   - RELATED EVENTS section — list of receipts related to the selected
//     one (same correlation_id, session-adjacent, principal-adjacent).
//     Each entry: timestamp + event_kind chip + truncated display_summary
//     + decision indicator. Click → switches selection.
//   - Bottom CTAs: [Draft Policy Rule] [Export Receipt] (same flow as the
//     R2 drawer's matching CTAs).
//
// Always-visible at width ≥1440px per brief; below that the parent renders
// it conditionally.

import { Download, Wand2 } from "lucide-react";
import { useLocation, useNavigate } from "react-router-dom";

import { ExportEvidenceButton } from "~/components/audit/ExportEvidenceButton";
import { CategoryPill } from "~/components/audit/CategoryPill";
import { Pill } from "~/components/shared/Pill";
import type { TimelineEvent, RelatedEvent } from "~/lib/timeline";
import { routes, stripBasename, timelineReceiptDetailPath } from "~/lib/routes";

interface Props {
  selected: TimelineEvent | null;
  related: RelatedEvent[];
  onSelectRelated: (run_id: string) => void;
}

export function EventInspector({
  selected,
  related,
  onSelectRelated,
}: Props): JSX.Element {
  if (!selected) {
    return (
      <div
        data-testid="event-inspector-empty"
        className="flex h-full flex-col items-center justify-center gap-2 px-6 py-8 text-center"
      >
        <span className="text-sm font-semibold text-r5e-text">
          Pick an event
        </span>
        <span className="max-w-[28ch] text-xs text-r5e-muted">
          Click a dot on a swim lane to see receipt detail, semantic
          arguments, and related events.
        </span>
      </div>
    );
  }

  return (
    <div
      data-testid="event-inspector"
      data-run-id={selected.run_id}
      className="flex h-full flex-col overflow-y-auto"
    >
      <ReceiptDataSection event={selected} />
      <SemanticArgumentsSection event={selected} />
      <RelatedEventsSection
        related={related}
        onSelect={onSelectRelated}
      />
      <BottomCtas event={selected} />
    </div>
  );
}

// ---------------------------------------------------------------------------
// RECEIPT DATA
// ---------------------------------------------------------------------------

function ReceiptDataSection({ event }: { event: TimelineEvent }): JSX.Element {
  const navigate = useNavigate();
  const location = useLocation();
  // F008: When the auditor opens the full receipt drawer FROM the
  // Investigation Timeline, ReceiptDetail's close() must route back
  // here rather than to the dashboard — otherwise the investigation
  // context (chips, time window, selected event) is lost. We pass the
  // current timeline URL via location.state.returnTo and ReceiptDetail
  // honors it on close. `pathname + search` keeps the chips intact.
  const returnTo = `${location.pathname}${location.search}`;
  return (
    <section
      data-testid="receipt-data-section"
      className="border-b border-r5e-border px-4 py-3"
    >
      <div className="mb-2 flex items-center justify-between">
        <span className="text-[10px] font-mono uppercase tracking-wider text-r5e-accent">
          Receipt data
        </span>
        <button
          type="button"
          data-testid="open-receipt-drawer"
          onClick={() =>
            navigate(timelineReceiptDetailPath(event.run_id), {
              state: { returnTo },
            })
          }
          className="text-[11px] text-r5e-accent hover:underline"
        >
          View full Tags →
        </button>
      </div>
      <dl className="grid grid-cols-[120px_1fr] gap-x-3 gap-y-1.5 text-xs">
        <Row label="event_kind" value={event.event_kind ?? "—"} />
        <Row label="principal" value={event.principal_subject} />
        <Row label="timestamp" value={event.timestamp} />
        <Row
          label="category"
          render={
            <CategoryPill
              category={event.category}
              forceDenial={event.policy_decision === "deny"}
              size="sm"
            />
          }
        />
        <Row
          label="decision"
          render={
            event.policy_decision === "deny" ? (
              <Pill tone="danger" size="xs">
                deny
              </Pill>
            ) : (
              <Pill tone="success" size="xs" outline>
                allow
              </Pill>
            )
          }
        />
        <Row
          label="verification"
          value={event.verification_level ?? "—"}
        />
        <Row label="run_id" value={event.run_id} mono />
        {event.session_id && <Row label="session_id" value={event.session_id} mono />}
        {event.correlation_id && (
          <Row label="correlation_id" value={event.correlation_id} mono />
        )}
      </dl>
    </section>
  );
}

function Row({
  label,
  value,
  render,
  mono,
}: {
  label: string;
  value?: string;
  render?: JSX.Element;
  mono?: boolean;
}): JSX.Element {
  return (
    <>
      <dt className="text-[10px] font-mono uppercase tracking-wider text-r5e-muted">
        {label}
      </dt>
      <dd
        className={
          mono
            ? "break-all font-mono text-[11px] text-r5e-text"
            : "text-[11px] text-r5e-text"
        }
      >
        {render ?? value ?? "—"}
      </dd>
    </>
  );
}

// ---------------------------------------------------------------------------
// SEMANTIC ARGUMENTS
// ---------------------------------------------------------------------------

function SemanticArgumentsSection({ event }: { event: TimelineEvent }): JSX.Element {
  const args = event.tags?.semantic_args ?? null;
  return (
    <section
      data-testid="semantic-arguments-section"
      className="border-b border-r5e-border px-4 py-3"
    >
      <div className="mb-2 text-[10px] font-mono uppercase tracking-wider text-r5e-accent">
        Semantic arguments
      </div>
      {args && Object.keys(args).length > 0 ? (
        <pre className="max-h-48 overflow-auto rounded border border-r5e-border bg-r5e-bg p-2 font-mono text-[11px] leading-snug text-r5e-text">
          {JSON.stringify(args, null, 2)}
        </pre>
      ) : (
        <span className="text-[11px] text-r5e-muted">
          (no semantic arguments on this receipt)
        </span>
      )}
    </section>
  );
}

// ---------------------------------------------------------------------------
// RELATED EVENTS
// ---------------------------------------------------------------------------

const RELATION_LABEL: Record<RelatedEvent["relation"], string> = {
  same_correlation: "workstream",
  session_adjacent: "session",
  principal_adjacent: "principal",
};

function RelatedEventsSection({
  related,
  onSelect,
}: {
  related: RelatedEvent[];
  onSelect: (run_id: string) => void;
}): JSX.Element {
  return (
    <section
      data-testid="related-events-section"
      className="flex-1 border-b border-r5e-border px-4 py-3"
    >
      <div className="mb-2 flex items-center justify-between">
        <span className="text-[10px] font-mono uppercase tracking-wider text-r5e-accent">
          Related events
        </span>
        <span className="text-[10px] text-r5e-muted">{related.length}</span>
      </div>
      {related.length === 0 ? (
        <span data-testid="related-events-empty" className="text-[11px] text-r5e-muted">
          (no related events found)
        </span>
      ) : (
        <ul className="flex flex-col gap-1">
          {related.map((ev) => (
            <li key={ev.run_id}>
              <button
                type="button"
                data-testid="related-event-row"
                data-run-id={ev.run_id}
                onClick={() => onSelect(ev.run_id)}
                className="flex w-full items-start gap-2 rounded border border-r5e-border/40 px-2 py-1.5 text-left hover:border-r5e-accent hover:bg-r5e-accent/5"
              >
                <span className="shrink-0 font-mono text-[10px] text-r5e-muted">
                  {ev.timestamp.slice(11, 19)}
                </span>
                <span className="shrink-0">
                  {ev.policy_decision === "deny" ? (
                    <Pill tone="danger" size="xs">
                      deny
                    </Pill>
                  ) : (
                    // Brief 10-session-trace.md:140 — "Each entry:
                    // timestamp + event_kind chip + truncated
                    // display_summary + decision indicator." We render
                    // the event_kind as a monospace chip; if a receipt
                    // somehow lacks event_kind we fall back to the
                    // category name so the cell is never blank.
                    <span className="inline-flex items-center rounded border border-r5e-border bg-r5e-surface px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wider text-r5e-muted">
                      {ev.event_kind ?? ev.category}
                    </span>
                  )}
                </span>
                <span
                  className="flex-1 truncate text-[11px] text-r5e-text"
                  title={ev.display_summary}
                >
                  {ev.display_summary}
                </span>
                <span className="shrink-0 text-[10px] uppercase tracking-wider text-r5e-muted">
                  {RELATION_LABEL[ev.relation]}
                </span>
              </button>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

// ---------------------------------------------------------------------------
// Bottom CTAs
// ---------------------------------------------------------------------------

function BottomCtas({ event }: { event: TimelineEvent }): JSX.Element {
  const navigate = useNavigate();
  const draftTarget = `${stripBasename(routes.policySimulator)}?mode=draft&run_id=${encodeURIComponent(event.run_id)}`;
  return (
    <section
      data-testid="event-inspector-ctas"
      className="flex shrink-0 items-center gap-2 border-t border-r5e-border bg-r5e-surface px-4 py-3"
    >
      <button
        type="button"
        data-testid="cta-draft-policy"
        onClick={() => navigate(draftTarget)}
        className="flex h-8 items-center gap-1.5 rounded-md border border-r5e-accent px-3 text-[11px] font-semibold text-r5e-accent hover:bg-r5e-accent/10"
      >
        <Wand2 className="h-3.5 w-3.5" aria-hidden="true" />
        Draft Policy Rule
      </button>
      <ExportEvidenceButton runId={event.run_id} />
      <span className="ml-auto inline-flex items-center text-[10px] text-r5e-muted">
        <Download aria-hidden="true" className="mr-1 h-3 w-3" />
        single-receipt zip
      </span>
    </section>
  );
}
