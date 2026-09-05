// TraceLanes — container that holds one TraceLane per principal plus the
// shared TimeAxis at the bottom.
//
// Owns the mouse-hover guideline (sticky vertical line that follows the
// cursor across the canvas) AND the click-to-pin selection-time marker
// (F004 — second sticky vertical bar at the clicked x-coord). Both lines
// live above the lanes so an auditor can read the relative spacing
// between two pinned moments.
//
// Per `design/briefs/10-session-trace.md`:
//   "the time axis support 'click sets a selection time marker' in
//    addition to the hover guideline."

import { useCallback, useRef, useState, type MouseEvent as ReactMouseEvent } from "react";

import type { TimelineLane } from "~/lib/timeline";
import { TimeAxis } from "~/components/timeline/TimeAxis";
import { TraceLane } from "~/components/timeline/TraceLane";

interface Props {
  lanes: TimelineLane[];
  startMs: number;
  endMs: number;
  /** Width of the time canvas (px) — Lanes' label column is OUTSIDE this. */
  canvasWidth: number;
  selectedRunId: string | null;
  onSelect: (run_id: string) => void;
  /** F004 — the pinned selection-time marker x-coord (canvas-x px), or
   *  null when the user has not pinned a moment yet. Owned by the
   *  parent so multiple panels (today: just the lanes; tomorrow: the
   *  density strip too) can read the same value. */
  pinnedX?: number | null;
  /** F004 — call when the user clicks the lanes canvas to toggle the
   *  pinned marker. The new x is the canvas-relative x-coord (after the
   *  label column has been subtracted), or null to unpin. */
  onPinX?: (x: number | null) => void;
}

export function TraceLanes({
  lanes,
  startMs,
  endMs,
  canvasWidth,
  selectedRunId,
  onSelect,
  pinnedX = null,
  onPinX,
}: Props): JSX.Element {
  const ref = useRef<HTMLDivElement | null>(null);
  const [hoverX, setHoverX] = useState<number | null>(null);

  // Project a timestamp (ms) onto the canvas-x. Linear, clamped.
  const timeToX = useCallback(
    (ms: number): number => {
      const range = Math.max(endMs - startMs, 1);
      const t = (ms - startMs) / range;
      return Math.max(0, Math.min(canvasWidth, t * canvasWidth));
    },
    [startMs, endMs, canvasWidth],
  );

  function canvasOffsetX(clientX: number): number | null {
    const target = ref.current;
    if (!target) return null;
    const rect = target.getBoundingClientRect();
    const offsetX = clientX - rect.left - LABEL_COL_PX;
    if (offsetX < 0 || offsetX > canvasWidth) return null;
    return offsetX;
  }

  function onMouseMove(e: ReactMouseEvent<HTMLDivElement>): void {
    const x = canvasOffsetX(e.clientX);
    setHoverX(x);
  }

  function onClickLanes(e: ReactMouseEvent<HTMLDivElement>): void {
    if (!onPinX) return;
    // If the click landed on an interactive descendant (event dot,
    // related-event button), let it handle the click — the lanes
    // background only owns "click to pin time".
    const t = e.target as HTMLElement;
    if (t.closest("[data-testid='event-dot']")) return;
    const x = canvasOffsetX(e.clientX);
    if (x === null) return;
    // Clicking the same pinned x un-pins so a second click clears the
    // marker. Within ~3px the click is considered the same column.
    if (pinnedX !== null && Math.abs(pinnedX - x) <= 3) {
      onPinX(null);
    } else {
      onPinX(x);
    }
  }

  return (
    <div
      ref={ref}
      data-testid="trace-lanes"
      className="relative flex flex-col"
      onMouseMove={onMouseMove}
      onMouseLeave={() => setHoverX(null)}
      onClick={onClickLanes}
    >
      {lanes.map((lane) => (
        <TraceLane
          key={lane.principal_subject}
          lane={lane}
          canvasWidth={canvasWidth}
          selectedRunId={selectedRunId}
          onSelect={onSelect}
          timeToX={timeToX}
        />
      ))}

      {/* Time axis at the bottom — aligned with the canvas (offset past the
          label column) by way of an outer wrapper. */}
      <div className="flex items-center gap-3 pl-44">
        {/* spacer for the dot prefix in lane labels (matches the bullet) */}
        <span aria-hidden="true" className="w-0" />
        <TimeAxis
          startMs={startMs}
          endMs={endMs}
          width={canvasWidth}
          timeToX={timeToX}
        />
      </div>

      {/* Hover guideline — vertical line following mouse-x. Renders ONLY
          when hoverX is in range; lives ABOVE lanes via z-index. */}
      {hoverX !== null && (
        <div
          aria-hidden="true"
          data-testid="lane-hover-guideline"
          className="pointer-events-none absolute top-0 bottom-6 w-px bg-r5e-accent/60"
          style={{ left: `${LABEL_COL_PX + hoverX}px` }}
        />
      )}

      {/* F004: click-to-pin selection-time marker — a second sticky
          vertical bar at the user's pinned x. Higher contrast than the
          hover guideline so the two read as distinct. */}
      {pinnedX !== null && (
        <div
          aria-hidden="true"
          data-testid="lane-pinned-marker"
          className="pointer-events-none absolute top-0 bottom-6 w-px bg-r5e-accent"
          style={{ left: `${LABEL_COL_PX + pinnedX}px` }}
        />
      )}
    </div>
  );
}

// Label column width = `w-44` (176px) + `gap-3` (12px) on the lane row.
const LABEL_COL_PX = 176 + 12;
