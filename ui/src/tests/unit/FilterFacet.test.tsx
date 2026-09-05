// Wave C — FilterFacet collapsed-empty rule tests.
//
// Asserts the redesign's #1 sidebar fix:
//   - Rows with count=0 are HIDDEN by default behind a "+ Show N empty"
//     affordance, addressing the pre-Wave-C clutter where 30 canonical
//     event_kinds rendered with mostly-zero counts.
//   - Active values stay visible regardless of count (so URL state
//     and sidebar can't desync — the operator must always be able to
//     unfilter).
//   - Toggling the affordance flips between "+ Show N empty" and
//     "− Hide N empty" labels and toggles aria-expanded.
//   - The optional getValueColor prop wires R4 palette tokens into
//     the chip's text color class.

import { render, screen, fireEvent } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { FilterFacet } from "~/components/audit/FilterFacet";
import { categoryColorToken } from "~/lib/tags";

describe("FilterFacet — Wave C collapsed-empty rule", () => {
  const values = [
    { value: "subprocess_exec", label: "subprocess_exec", count: 4 },
    { value: "file_write", label: "file_write", count: 1 },
    { value: "network_egress", label: "network_egress", count: 0 },
    { value: "mcp_tool_call", label: "mcp_tool_call", count: 0 },
    { value: "agent_dispatch", label: "agent_dispatch", count: 0 },
  ];

  it("hides 0-count rows by default and shows the affordance", () => {
    render(
      <FilterFacet
        title="Category"
        values={values}
        active={new Set()}
        onToggle={vi.fn()}
        onClear={vi.fn()}
      />,
    );
    expect(screen.getByText("subprocess_exec")).toBeInTheDocument();
    expect(screen.getByText("file_write")).toBeInTheDocument();
    expect(screen.queryByText("network_egress")).not.toBeInTheDocument();
    expect(screen.queryByText("mcp_tool_call")).not.toBeInTheDocument();
    expect(screen.getByTestId("facet-show-empty-category")).toHaveTextContent("+ Show 3 empty");
  });

  it("expands empties on click and updates the toggle label", () => {
    render(
      <FilterFacet
        title="Category"
        values={values}
        active={new Set()}
        onToggle={vi.fn()}
        onClear={vi.fn()}
      />,
    );
    const toggle = screen.getByTestId("facet-show-empty-category");
    expect(toggle).toHaveAttribute("aria-expanded", "false");
    fireEvent.click(toggle);
    expect(screen.getByText("network_egress")).toBeInTheDocument();
    expect(screen.getByText("mcp_tool_call")).toBeInTheDocument();
    expect(toggle).toHaveAttribute("aria-expanded", "true");
    expect(toggle).toHaveTextContent("− Hide 3 empty");
  });

  it("keeps an ACTIVE value visible even when its count is 0", () => {
    render(
      <FilterFacet
        title="Category"
        values={values}
        active={new Set(["network_egress"])} // count=0 but active
        onToggle={vi.fn()}
        onClear={vi.fn()}
      />,
    );
    // network_egress is active → always visible (so user can unfilter)
    expect(screen.getByText("network_egress")).toBeInTheDocument();
    // The remaining 0-count entries (mcp + agent) stay hidden
    expect(screen.queryByText("mcp_tool_call")).not.toBeInTheDocument();
    // Affordance shows count of TRULY hidden rows: 2
    expect(screen.getByTestId("facet-show-empty-category")).toHaveTextContent("+ Show 2 empty");
  });

  it("getValueColor wires the R4 palette token into the chip class", () => {
    render(
      <FilterFacet
        title="Category"
        values={values}
        active={new Set()}
        onToggle={vi.fn()}
        onClear={vi.fn()}
        getValueColor={(v) => categoryColorToken(v)}
      />,
    );
    const subprocChip = screen.getByText("subprocess_exec").closest("button")!;
    expect(subprocChip.className).toMatch(/text-r5e-chart-subprocess/);
    expect(subprocChip).toHaveAttribute("data-color-token", "chart-subprocess");
  });

  it("does NOT render the affordance when there are zero hidden rows", () => {
    render(
      <FilterFacet
        title="Decision"
        values={[
          { value: "allow", label: "allow", count: 5 },
          { value: "deny", label: "deny", count: 2 },
        ]}
        active={new Set()}
        onToggle={vi.fn()}
        onClear={vi.fn()}
      />,
    );
    expect(screen.queryByTestId("facet-show-empty-decision")).not.toBeInTheDocument();
  });
});
