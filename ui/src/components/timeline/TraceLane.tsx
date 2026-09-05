// TraceLane — one horizontal swim lane for a single principal.
//
// Per `design/briefs/10-session-trace.md` swim-lane spec:
//   - Left: PrincipalLabel (subject or account_id)
//   - Right: LaneEvents (positioned <EventDot /> children along time axis)
//   - Lane height: ~36px so dots have breathing room

import type { TimelineLane } from "~/lib/timeline";
import { EventDot } from "~/components/timeline/EventDot";

interface Props {
  lane: TimelineLane;
  /** Pixel width of the time canvas. */
  canvasWidth: number;
  selectedRunId: string | null;
  onSelect: (run_id: string) => void;
  timeToX: (ms: number) => number;
}

export function TraceLane({
  lane,
  canvasWidth,
  selectedRunId,
  onSelect,
  timeToX,
}: Props): JSX.Element {
  return (
    <div
      data-testid="trace-lane"
      data-principal={lane.principal_subject}
      className="flex items-center gap-3 border-b border-r5e-border/40 py-2"
    >
      <div
        className="w-44 shrink-0 truncate font-mono text-xs text-r5e-text"
        title={lane.principal_label}
      >
        <span className="mr-2 inline-block h-1.5 w-1.5 rounded-full bg-r5e-accent" aria-hidden="true" />
        {lane.principal_label}
        <span className="ml-2 text-[10px] uppercase tracking-wider text-r5e-muted">
          {lane.events.length}
        </span>
      </div>
      <div
        className="relative h-7 shrink-0"
        style={{ width: `${canvasWidth}px` }}
        data-testid="lane-events"
      >
        {/* Lane axis baseline */}
        <div
          aria-hidden="true"
          className="absolute inset-x-0 top-1/2 h-px bg-r5e-border/40"
        />
        {lane.events.map((ev) => (
          <EventDot
            key={ev.run_id}
            event={ev}
            selected={ev.run_id === selectedRunId}
            x={timeToX(ev.ts_ms)}
            onClick={onSelect}
          />
        ))}
      </div>
    </div>
  );
}
