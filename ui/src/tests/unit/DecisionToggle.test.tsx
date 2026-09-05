// DecisionToggle — column 02 DECISION row matching the canonical
// `MdEKl > drawer > midP > decRow` Pencil element.

import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { DecisionToggle } from "~/components/policy/DecisionToggle";

describe("DecisionToggle", () => {
  it("renders Allow + Deny as mutually-exclusive toggle buttons", () => {
    render(<DecisionToggle value="allow" onChange={() => {}} />);
    expect(screen.getByTestId("decision-allow")).toBeInTheDocument();
    expect(screen.getByTestId("decision-deny")).toBeInTheDocument();
  });

  it("aria-pressed reflects the current value", () => {
    render(<DecisionToggle value="deny" onChange={() => {}} />);
    expect(screen.getByTestId("decision-deny")).toHaveAttribute(
      "aria-pressed",
      "true",
    );
    expect(screen.getByTestId("decision-allow")).toHaveAttribute(
      "aria-pressed",
      "false",
    );
  });

  it("clicking emits onChange with the corresponding verdict", () => {
    const onChange = vi.fn();
    render(<DecisionToggle value="allow" onChange={onChange} />);
    fireEvent.click(screen.getByTestId("decision-deny"));
    expect(onChange).toHaveBeenCalledWith("deny");
  });

  it("the SELECTED Deny carries the canonical accent-pink visual cues", () => {
    render(<DecisionToggle value="deny" onChange={() => {}} />);
    const deny = screen.getByTestId("decision-deny");
    expect(deny.className).toMatch(/border-r5e-accent-pink/);
    expect(deny.className).toMatch(/text-r5e-accent-pink/);
  });

  it("the SELECTED Allow carries accent-green visual cues", () => {
    render(<DecisionToggle value="allow" onChange={() => {}} />);
    const allow = screen.getByTestId("decision-allow");
    expect(allow.className).toMatch(/border-r5e-accent-green/);
    expect(allow.className).toMatch(/text-r5e-accent-green/);
  });
});
