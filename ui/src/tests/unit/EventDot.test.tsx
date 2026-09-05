// EventDot — dot rendering, R4 palette, denial overlay, selected glow.
//
// Asserts:
//   - Renders a button at the configured x position (absolute-positioned).
//   - Maps category → R4 chart-* class (Tailwind static enumeration).
//   - Denied events override the category color with chart-denied + render
//     a Lucide Ban (⊘) overlay.
//   - Selected events get a ring + larger size class.
//   - onClick fires with the run_id.

import { render, screen, fireEvent } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { EventDot } from "~/components/timeline/EventDot";
import type { TimelineEvent } from "~/lib/timeline";

function mkEvent(overrides: Partial<TimelineEvent> = {}): TimelineEvent {
  return {
    run_id: "r-1",
    timestamp: "2026-05-01T03:00:00Z",
    ts_ms: Date.parse("2026-05-01T03:00:00Z"),
    category: "subprocess_exec",
    display_summary: "Bash: ls",
    policy_decision: "allow",
    verification_level: "global_inclusion_verified",
    session_id: "s1",
    correlation_id: null,
    event_kind: "tool_call",
    tags: null,
    principal_subject: "alice",
    principal_kind: "obo_human",
    ...overrides,
  };
}

describe("EventDot", () => {
  it("renders a button positioned at the supplied x", () => {
    render(
      <EventDot
        event={mkEvent()}
        selected={false}
        x={120}
        onClick={() => undefined}
      />,
    );
    const dot = screen.getByTestId("event-dot");
    expect(dot.style.left).toBe("120px");
  });

  it("paints the category color for non-denial events", () => {
    render(
      <EventDot
        event={mkEvent({ category: "subprocess_exec" })}
        selected={false}
        x={0}
        onClick={() => undefined}
      />,
    );
    const dot = screen.getByTestId("event-dot");
    expect(dot.className).toMatch(/bg-r5e-chart-subprocess/);
    expect(dot.dataset.denied).toBe("false");
  });

  it("renders a deny ring + Ban overlay when policy_decision === 'deny'", () => {
    render(
      <EventDot
        event={mkEvent({ category: "subprocess_exec", policy_decision: "deny" })}
        selected={false}
        x={0}
        onClick={() => undefined}
      />,
    );
    const dot = screen.getByTestId("event-dot");
    expect(dot.className).toMatch(/bg-r5e-chart-denied/);
    expect(dot.dataset.denied).toBe("true");
    // Lucide Ban renders as an SVG inside the dot; its presence is the
    // visual deny marker.
    expect(dot.querySelector("svg")).not.toBeNull();
  });

  it("paints selected dot with a ring + larger size", () => {
    render(
      <EventDot
        event={mkEvent()}
        selected={true}
        x={0}
        onClick={() => undefined}
      />,
    );
    const dot = screen.getByTestId("event-dot");
    expect(dot.className).toMatch(/ring-2/);
    expect(dot.dataset.selected).toBe("true");
  });

  it("fires onClick with the event run_id", () => {
    const onClick = vi.fn();
    render(
      <EventDot
        event={mkEvent({ run_id: "click-me" })}
        selected={false}
        x={0}
        onClick={onClick}
      />,
    );
    fireEvent.click(screen.getByTestId("event-dot"));
    expect(onClick).toHaveBeenCalledWith("click-me");
  });
});
