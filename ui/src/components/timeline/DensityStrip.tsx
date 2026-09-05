// DensityStrip — top mini-histogram (~60px tall) showing receipt count by
// hour, stacked by category (R4 palette).
//
// Per `design/briefs/10-session-trace.md`:
//   - Compact strip — ~60px tall
//   - Stacked-bar by category, R4 palette
//   - Same palette as R1's main histogram, denser/shorter
//   - (Brush-zoom is a Phase-2 nice-to-have; we render the strip + click-set
//     cursor for the demo target. Brush-drag is filed as a follow-up.)

import type { DensityBucket } from "~/lib/timeline";
import { categoryColorToken } from "~/lib/tags";

interface Props {
  buckets: DensityBucket[];
  /** Optional pixel width override; defaults to fill parent. */
  width?: number;
  /** Bar height in px (~60 default). */
  height?: number;
}

const STRIP_CATEGORIES = [
  "subprocess_exec",
  "file_write",
  "file_read",
  "mcp_tool_call",
  "agent_dispatch",
  "network_egress",
  "llm_call",
  "policy_denied",
  "file_search",
  "todo_management",
  "ui_event",
  "unknown",
] as const;

/**
 * Static category → fill class. Tailwind 3 JIT requires literal strings;
 * mirrors EventDot/CategoryPill enumeration approach.
 */
function fillClass(category: string): string {
  const token = categoryColorToken(category);
  switch (token) {
    case "chart-subprocess":
      return "bg-r5e-chart-subprocess";
    case "chart-file-write":
      return "bg-r5e-chart-file-write";
    case "chart-file-read":
      return "bg-r5e-chart-file-read";
    case "chart-network":
      return "bg-r5e-chart-network";
    case "chart-mcp-tool":
      return "bg-r5e-chart-mcp-tool";
    case "chart-agent":
      return "bg-r5e-chart-agent";
    case "chart-llm":
      return "bg-r5e-chart-llm";
    case "chart-denied":
      return "bg-r5e-chart-denied";
    case "chart-ui":
    default:
      return "bg-r5e-chart-ui";
  }
}

export function DensityStrip({ buckets, width, height = 60 }: Props): JSX.Element {
  const hasData = buckets.length > 0;
  const max = hasData ? Math.max(...buckets.map((b) => b.total)) : 0;
  return (
    <div
      data-testid="density-strip"
      className="rounded border border-r5e-border bg-r5e-surface/40 p-2"
      style={width ? { width: `${width}px` } : undefined}
    >
      <div className="mb-1 flex items-center justify-between">
        <span className="text-[10px] uppercase tracking-wider text-r5e-muted">
          Receipt count · density
        </span>
        <span className="text-[10px] text-r5e-muted">
          {buckets.reduce((acc, b) => acc + b.total, 0)} events
        </span>
      </div>
      {!hasData ? (
        <div
          data-testid="density-strip-empty"
          className="flex items-center justify-center text-[10px] text-r5e-muted"
          style={{ height: `${height}px` }}
        >
          No events in window
        </div>
      ) : (
        <div
          data-testid="density-strip-bars"
          className="flex items-end gap-px"
          style={{ height: `${height}px` }}
        >
          {buckets.map((b, i) => {
            const heightPct = max === 0 ? 0 : (b.total / max) * 100;
            return (
              <div
                key={`${b.ts_ms}-${i}`}
                data-testid="density-strip-bar"
                title={`${b.ts.replace("T", " ").replace(/:.+$/, "")} — ${b.total} events`}
                className="relative flex-1 flex flex-col-reverse"
                style={{ height: `${heightPct}%` }}
              >
                {STRIP_CATEGORIES.map((cat) => {
                  const count = b.count_by_category[cat] ?? 0;
                  if (count === 0) return null;
                  const segPct = (count / b.total) * 100;
                  return (
                    <div
                      key={cat}
                      data-testid={`density-segment-${cat}`}
                      className={`${fillClass(cat)} w-full`}
                      style={{ height: `${segPct}%` }}
                    />
                  );
                })}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
