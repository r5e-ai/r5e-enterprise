// ConditionBuilder — F4 redesign per `design/briefs/04-policy-simulator.md`.
//
// 5 condition kinds (eq / neq / in / time_window / group_member). Adding a
// row appends to the array; removing pops it; updating modifies in place.

import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { ConditionBuilder } from "~/components/policy/ConditionBuilder";

describe("ConditionBuilder — F4 5-kind condition builder", () => {
  it("renders + buttons for all five condition kinds", () => {
    render(<ConditionBuilder value={[]} onChange={() => {}} />);
    expect(screen.getByTestId("add-condition-eq")).toBeInTheDocument();
    expect(screen.getByTestId("add-condition-neq")).toBeInTheDocument();
    expect(screen.getByTestId("add-condition-in")).toBeInTheDocument();
    expect(screen.getByTestId("add-condition-time_window")).toBeInTheDocument();
    expect(screen.getByTestId("add-condition-group_member")).toBeInTheDocument();
  });

  it("clicking + ATTRIBUTE EQUALS appends a new row with kind=eq and a default attr", () => {
    const onChange = vi.fn();
    render(<ConditionBuilder value={[]} onChange={onChange} />);
    fireEvent.click(screen.getByTestId("add-condition-eq"));
    // Wire shape MUST be `{kind, attr, value}` — the backend
    // `validate_condition_metadata_shape/1` requires a `:kind` key per
    // entry; `:op` is rejected with "every entry must be a map with a
    // :kind key".
    expect(onChange).toHaveBeenCalledWith([
      { kind: "eq", attr: "resource.tags.tool_kind", value: "" },
    ]);
  });

  it("clicking + TIME WINDOW appends a row with kind=time_window, range default value, and a context.* default attr", () => {
    const onChange = vi.fn();
    render(<ConditionBuilder value={[]} onChange={onChange} />);
    fireEvent.click(screen.getByTestId("add-condition-time_window"));
    const arg = onChange.mock.calls[0]?.[0];
    expect(arg).toHaveLength(1);
    expect(arg[0].kind).toBe("time_window");
    expect(arg[0].attr).toContain("context.");
    // Default value for a range is `[start, end]` so the chip-list /
    // single-string downstream renderers don't have to coerce.
    expect(arg[0].value).toEqual(["", ""]);
  });

  it("clicking + ATTRIBUTE IN SET appends a row with an empty chip-list value", () => {
    const onChange = vi.fn();
    render(<ConditionBuilder value={[]} onChange={onChange} />);
    fireEvent.click(screen.getByTestId("add-condition-in"));
    const arg = onChange.mock.calls[0]?.[0];
    expect(arg[0].kind).toBe("in");
    expect(arg[0].value).toEqual([]);
  });

  it("removing a row drops it from the array", () => {
    const onChange = vi.fn();
    const rows = [
      { kind: "eq" as const, attr: "a", value: "1" },
      { kind: "neq" as const, attr: "b", value: "2" },
    ];
    render(<ConditionBuilder value={[...rows]} onChange={onChange} />);
    const buttons = screen.getAllByLabelText("Remove condition");
    expect(buttons.length).toBe(2);
    fireEvent.click(buttons[0]!);
    expect(onChange).toHaveBeenCalledWith([rows[1]]);
  });

  it("renders the empty-state hint when no conditions exist", () => {
    render(<ConditionBuilder value={[]} onChange={() => {}} />);
    expect(screen.getByText(/no conditions yet/i)).toBeInTheDocument();
  });

  it("renders chip-list editor for ATTRIBUTE IN SET rows", () => {
    render(
      <ConditionBuilder
        value={[{ kind: "in", attr: "resource.tags.verb", value: ["rm", "sudo"] }]}
        onChange={() => {}}
      />,
    );
    // The chip surface renders a wrapper testid + per-chip testids.
    expect(screen.getByTestId("condition-row-0-chips")).toBeInTheDocument();
    expect(screen.getByTestId("condition-row-0-chip-0").textContent).toContain("rm");
    expect(screen.getByTestId("condition-row-0-chip-1").textContent).toContain("sudo");
  });

  it("pressing Enter in the chip input commits the buffer to the value array", () => {
    const onChange = vi.fn();
    render(
      <ConditionBuilder
        value={[{ kind: "in", attr: "resource.tags.verb", value: [] }]}
        onChange={onChange}
      />,
    );
    const input = screen
      .getByTestId("condition-row-0-chips")
      .querySelector("input")!;
    fireEvent.change(input, { target: { value: "rm" } });
    fireEvent.keyDown(input, { key: "Enter" });
    expect(onChange).toHaveBeenCalledWith([
      { kind: "in", attr: "resource.tags.verb", value: ["rm"] },
    ]);
  });

  it("renders two date-range inputs for TIME WINDOW rows", () => {
    render(
      <ConditionBuilder
        value={[{ kind: "time_window", attr: "context.timestamp", value: ["a", "b"] }]}
        onChange={() => {}}
      />,
    );
    const range = screen.getByTestId("condition-row-0-range");
    const inputs = range.querySelectorAll("input");
    expect(inputs).toHaveLength(2);
    expect((inputs[0] as HTMLInputElement).value).toBe("a");
    expect((inputs[1] as HTMLInputElement).value).toBe("b");
  });
});
