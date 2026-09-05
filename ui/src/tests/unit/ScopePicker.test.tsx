// ScopePicker — F4 column 02 SCOPE & CONDITIONS.
//
// Pre-rewrite this exercised a 2x2 segmented control (per the brief at
// design/briefs/04-policy-simulator.md). Post-rewrite it follows the
// canonical `MdEKl > drawer > midP` Pencil frame structure: vertical
// radio list with two stacked sections (WHO + WHAT), inline value
// display when a row is selected, separate text input below.

import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { ScopePicker } from "~/components/policy/ScopePicker";

describe("ScopePicker — canonical WHO + WHAT vertical radio sections", () => {
  it("renders all four WHO scope kinds as radio rows", () => {
    render(<ScopePicker value={null} onChange={() => {}} />);
    expect(screen.getByTestId("scope-kind-principal")).toBeInTheDocument();
    expect(screen.getByTestId("scope-kind-role")).toBeInTheDocument();
    expect(screen.getByTestId("scope-kind-group")).toBeInTheDocument();
    expect(screen.getByTestId("scope-kind-tenant")).toBeInTheDocument();
  });

  it("renders all three WHAT action-scope options as radio rows", () => {
    render(<ScopePicker value={null} onChange={() => {}} />);
    expect(screen.getByTestId("action-scope-exact")).toBeInTheDocument();
    expect(screen.getByTestId("action-scope-kind")).toBeInTheDocument();
    expect(screen.getByTestId("action-scope-explicit_set")).toBeInTheDocument();
  });

  it("changing the WHO kind emits onChange with the previous value preserved", () => {
    const onChange = vi.fn();
    render(
      <ScopePicker
        value={{ scope_kind: "principal", scope_value: "alice" }}
        onChange={onChange}
      />,
    );
    fireEvent.click(screen.getByTestId("scope-kind-role"));
    expect(onChange).toHaveBeenCalledWith({
      scope_kind: "role",
      scope_value: "alice",
    });
  });

  it("editing the value emits onChange with the current kind preserved", () => {
    const onChange = vi.fn();
    render(
      <ScopePicker
        value={{ scope_kind: "tenant", scope_value: "" }}
        onChange={onChange}
      />,
    );
    const input = screen.getByTestId("scope-value");
    fireEvent.change(input, { target: { value: "01H..." } });
    expect(onChange).toHaveBeenCalledWith({
      scope_kind: "tenant",
      scope_value: "01H...",
    });
  });

  it("changing the WHAT action-scope emits onActionScopeChange", () => {
    const onActionScopeChange = vi.fn();
    render(
      <ScopePicker
        value={null}
        onChange={() => {}}
        actionScope="exact"
        onActionScopeChange={onActionScopeChange}
      />,
    );
    fireEvent.click(screen.getByTestId("action-scope-kind"));
    expect(onActionScopeChange).toHaveBeenCalledWith("kind");
  });

  it("inline value display appears next to the selected WHO row", () => {
    render(
      <ScopePicker
        value={{ scope_kind: "principal", scope_value: "alice@corp" }}
        onChange={() => {}}
      />,
    );
    const principalRow = screen.getByTestId("scope-kind-principal");
    expect(principalRow.textContent).toContain("alice@corp");
  });
});
