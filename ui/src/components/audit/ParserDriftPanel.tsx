// ParserDriftPanel — spec 012 S4 (plan §10 "parser drift is a product
// surface").
//
// Lists the event / content-block / delta types the LLM-proxy parsers
// could not classify: discriminator, wire format, count, first/last seen
// and the keys-only sample the parser kept. Hidden entirely while there
// are no rows (or while the request is loading / failed): the panel is a
// signal that a parser needs a patch, not a permanent fixture. It carries
// no caveat about the receipts — those already record the counts in
// `parse.events_unhandled` and the row copy says "N events unrecognized".

import { useParserDrift, type ParserDriftEvent } from "~/hooks/useParserDrift";

function relative(iso: string): string {
  const then = Date.parse(iso);
  if (Number.isNaN(then)) return iso;
  const seconds = Math.max(0, Math.round((Date.now() - then) / 1000));
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 48) return `${hours}h ago`;
  return `${Math.round(hours / 24)}d ago`;
}

export function ParserDriftPanel(): JSX.Element | null {
  const { data, isError, isLoading } = useParserDrift();
  if (isLoading || isError || !data || data.events.length === 0) return null;
  return <ParserDriftPanelView events={data.events} newSinceBoot={data.new_since_boot} />;
}

/** Presentational half — testable without TanStack Query. */
export function ParserDriftPanelView({
  events,
  newSinceBoot,
}: {
  events: ReadonlyArray<ParserDriftEvent>;
  newSinceBoot: number;
}): JSX.Element | null {
  if (events.length === 0) return null;
  return (
    <section
      data-testid="parser-drift-panel"
      aria-label="Parser drift"
      className="border-b border-r5e-border bg-r5e-surface/60 px-4 py-3"
    >
      <div className="flex items-baseline justify-between">
        <h2 className="text-xs font-semibold uppercase tracking-wider text-r5e-muted">
          Parser drift
        </h2>
        <span className="text-xs text-r5e-muted" data-testid="parser-drift-count">
          {events.length} type{events.length === 1 ? "" : "s"}
          {newSinceBoot > 0 ? ` · ${newSinceBoot} new since boot` : ""}
        </span>
      </div>
      <ul className="mt-2 divide-y divide-r5e-border/60 text-xs">
        {events.map((e) => (
          <li
            key={`${e.api_format}:${e.event_type}`}
            data-testid="parser-drift-row"
            className="flex flex-wrap items-baseline gap-x-3 gap-y-1 py-1.5"
          >
            <code className="font-mono text-r5e-text">{e.event_type}</code>
            <span className="text-r5e-muted">{e.api_format}</span>
            <span className="text-r5e-muted">
              ×{e.count} · last {relative(e.last_seen)}
            </span>
            {e.sample_redacted ? (
              <code className="font-mono text-[11px] text-r5e-muted">{e.sample_redacted}</code>
            ) : null}
          </li>
        ))}
      </ul>
    </section>
  );
}
