// EventDot — a single colored circle on a timeline lane.
//
// Per `design/briefs/10-session-trace.md` swim-lane spec:
//   - ~10px diameter (selected: ~14px with glow ring)
//   - R4 palette tone by category (deny-trumps-category — denials read red)
//   - Denied events: red ring + Lucide Ban (⊘) overlay
//   - Selected: brighter ring, subtle glow
//   - Hover: tooltip shows display_summary
//   - Click: selects → right panel populates
//
// Tailwind 3 JIT requires LITERAL class strings; we enumerate the chart-*
// utilities the same way CategoryPill does (per shared-systems brief).

import { Ban } from "lucide-react";

import type { TimelineEvent } from "~/lib/timeline";
import { categoryColorToken } from "~/lib/tags";

interface Props {
  event: TimelineEvent;
  selected: boolean;
  /** Center coordinate (px) along the lane's time axis. */
  x: number;
  onClick: (run_id: string) => void;
}

/**
 * Map a category token to the static Tailwind classes for the dot's fill +
 * border. Same enumeration approach as CategoryPill — Tailwind's JIT cannot
 * see dynamic interpolation, so each branch is a literal class string.
 */
function dotClasses(category: string, denied: boolean): { bg: string; border: string; ring: string } {
  if (denied) {
    return {
      bg: "bg-r5e-chart-denied",
      border: "border-r5e-chart-denied",
      ring: "ring-r5e-chart-denied/60",
    };
  }
  const token = categoryColorToken(category);
  switch (token) {
    case "chart-subprocess":
      return { bg: "bg-r5e-chart-subprocess", border: "border-r5e-chart-subprocess", ring: "ring-r5e-chart-subprocess/60" };
    case "chart-file-write":
      return { bg: "bg-r5e-chart-file-write", border: "border-r5e-chart-file-write", ring: "ring-r5e-chart-file-write/60" };
    case "chart-file-read":
      return { bg: "bg-r5e-chart-file-read", border: "border-r5e-chart-file-read", ring: "ring-r5e-chart-file-read/60" };
    case "chart-network":
      return { bg: "bg-r5e-chart-network", border: "border-r5e-chart-network", ring: "ring-r5e-chart-network/60" };
    case "chart-mcp-tool":
      return { bg: "bg-r5e-chart-mcp-tool", border: "border-r5e-chart-mcp-tool", ring: "ring-r5e-chart-mcp-tool/60" };
    case "chart-agent":
      return { bg: "bg-r5e-chart-agent", border: "border-r5e-chart-agent", ring: "ring-r5e-chart-agent/60" };
    case "chart-llm":
      return { bg: "bg-r5e-chart-llm", border: "border-r5e-chart-llm", ring: "ring-r5e-chart-llm/60" };
    case "chart-denied":
      return { bg: "bg-r5e-chart-denied", border: "border-r5e-chart-denied", ring: "ring-r5e-chart-denied/60" };
    case "chart-ui":
    default:
      return { bg: "bg-r5e-chart-ui", border: "border-r5e-chart-ui", ring: "ring-r5e-chart-ui/60" };
  }
}

export function EventDot({ event, selected, x, onClick }: Props): JSX.Element {
  const denied = event.policy_decision === "deny";
  const { bg, border, ring } = dotClasses(event.category, denied);
  const size = selected ? "h-3.5 w-3.5" : "h-2.5 w-2.5";
  const ringClass = selected ? `ring-2 ${ring}` : "";
  const tooltip = `${event.timestamp.replace("T", " ").replace(/\..+$/, "Z")} — ${event.display_summary}`;
  return (
    <button
      type="button"
      data-testid="event-dot"
      data-run-id={event.run_id}
      data-category={event.category}
      data-denied={denied ? "true" : "false"}
      data-selected={selected ? "true" : "false"}
      title={tooltip}
      onClick={() => onClick(event.run_id)}
      className={`absolute -translate-x-1/2 -translate-y-1/2 inline-flex items-center justify-center rounded-full border ${size} ${bg} ${border} ${ringClass} transition-transform hover:scale-125 focus:outline-none focus:ring-2 focus:ring-r5e-accent-glow`}
      style={{ left: `${x}px`, top: "50%" }}
      aria-label={`Event ${event.run_id}: ${event.display_summary}`}
    >
      {denied && (
        <Ban
          aria-hidden="true"
          className="h-full w-full text-r5e-text"
          strokeWidth={3}
        />
      )}
    </button>
  );
}
