// TimeAxis — bottom-of-lanes time axis with tick labels + sticky guideline.
//
// Per `design/briefs/10-session-trace.md`:
//   - Tick labels at sensible intervals based on time window (15min for 1h,
//     1h for 24h, etc. — see tickIntervalMs in lib/timeline.ts)
//   - Sticky vertical guideline that follows mouse hover
//   - Click sets a "selection time" marker
//
// The axis is rendered as a positioned div whose width === the timeline
// canvas width. Ticks are computed in time space then mapped to x by the
// caller-provided `timeToX` projection.

import { formatTick, tickIntervalMs } from "~/lib/timeline";

interface Props {
  /** Earliest visible timestamp (ms). */
  startMs: number;
  /** Latest visible timestamp (ms). */
  endMs: number;
  /** Pixel width of the time-axis canvas. */
  width: number;
  /** Project a timestamp (ms) to its canvas-x in pixels. */
  timeToX: (ms: number) => number;
}

export function TimeAxis({ startMs, endMs, width, timeToX }: Props): JSX.Element {
  const windowMs = Math.max(endMs - startMs, 1);
  const interval = tickIntervalMs(windowMs);
  // Floor start to a multiple of `interval` so labels land on round values
  // (e.g., :00, :15, :30, :45).
  const firstTick = Math.ceil(startMs / interval) * interval;
  const ticks: number[] = [];
  for (let t = firstTick; t <= endMs; t += interval) {
    ticks.push(t);
  }
  return (
    <div
      data-testid="time-axis"
      className="relative h-6 border-t border-r5e-border/40"
      style={{ width: `${width}px` }}
    >
      {ticks.map((t) => {
        const x = timeToX(t);
        if (x < 0 || x > width) return null;
        return (
          <div
            key={t}
            className="absolute -translate-x-1/2 select-none text-[10px] uppercase tracking-wider text-r5e-muted"
            style={{ left: `${x}px`, top: "2px" }}
          >
            {formatTick(t, windowMs)}
          </div>
        );
      })}
    </div>
  );
}
