// Wave C — CategoryPill render tests.
//
// Asserts:
//   - The pill renders with the chart-* class for each known category
//     (Tailwind static-class enumeration in the component is correct).
//   - forceDenial paints policy_denied colors regardless of the
//     category prop (the row's R4 Rule 01 enforcement path).
//   - sm size variant produces the compact class set.

import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { CategoryPill } from "~/components/audit/CategoryPill";

describe("CategoryPill", () => {
  it("renders the category label and chart-* class for subprocess_exec", () => {
    render(<CategoryPill category="subprocess_exec" />);
    const pill = screen.getByTestId("category-pill");
    expect(pill).toHaveTextContent("subprocess_exec");
    expect(pill.className).toMatch(/text-r5e-chart-subprocess/);
    expect(pill.className).toMatch(/border-r5e-chart-subprocess/);
  });

  it("paints policy_denied colors when forceDenial is true (R4 Rule 01)", () => {
    render(<CategoryPill category="subprocess_exec" forceDenial />);
    const pill = screen.getByTestId("category-pill");
    expect(pill).toHaveTextContent("policy_denied");
    expect(pill.className).toMatch(/text-r5e-chart-denied/);
    expect(pill.className).toMatch(/border-r5e-chart-denied/);
    expect(pill.className).not.toMatch(/text-r5e-chart-subprocess/);
  });

  it("falls back to chart-ui for null category", () => {
    render(<CategoryPill category={null} />);
    const pill = screen.getByTestId("category-pill");
    expect(pill).toHaveTextContent("unknown");
    expect(pill.className).toMatch(/text-r5e-chart-ui/);
  });

  it("size=sm produces compact padding", () => {
    render(<CategoryPill category="network_egress" size="sm" />);
    const pill = screen.getByTestId("category-pill");
    expect(pill.className).toMatch(/text-\[9px\]/);
    expect(pill.className).toMatch(/text-r5e-chart-network/);
  });

  it("each known category gets a distinct text color class", () => {
    const seen = new Set<string>();
    const cats = [
      "subprocess_exec",
      "file_write",
      "file_read",
      "network_egress",
      "mcp_tool_call",
      "agent_dispatch",
      "llm_call",
      "policy_denied",
    ];
    for (const cat of cats) {
      const { unmount } = render(<CategoryPill category={cat} />);
      const pill = screen.getByTestId("category-pill");
      const match = pill.className.match(/text-r5e-chart-[a-z-]+/);
      expect(match).not.toBeNull();
      seen.add(match![0]);
      unmount();
    }
    // 8 categories, but file_write/notebook_edit + file_read/file_search
    // intentionally share — we sent 8 distinct categories above; that
    // should produce 8 distinct color classes.
    expect(seen.size).toBe(cats.length);
  });
});
