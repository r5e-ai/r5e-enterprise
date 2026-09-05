// ColumnPicker — interaction + a11y tests for the dropdown column toggle
// (#33).

import { fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ColumnPicker } from "~/components/audit/ColumnPicker";
import {
  AUDIT_LOG_COLUMN_IDS,
  defaultColumnVisibility,
  toggleColumnVisibility,
} from "~/lib/auditLogColumns";

describe("ColumnPicker", () => {
  beforeEach(() => {
    window.localStorage.clear();
  });

  afterEach(() => {
    window.localStorage.clear();
  });

  it("renders the count label 'N of M columns' over the default-visible subset", () => {
    // Post-triplet: defaultColumnVisibility() returns the columns marked
    // `defaultVisible: true` (timestamp, category, principal, tool, command,
    // subject, decision, verification_level → 8) over the full registry
    // (10 ids — adds togglable event_kind + summary). The label MUST reflect
    // both numbers so the user knows there are MORE columns available.
    render(
      <ColumnPicker
        visibility={defaultColumnVisibility()}
        onChange={vi.fn()}
      />,
    );
    const trigger = screen.getByTestId("column-picker-trigger");
    const visible = defaultColumnVisibility().size;
    expect(trigger).toHaveTextContent(
      `${visible} of ${AUDIT_LOG_COLUMN_IDS.length} columns`,
    );
  });

  it("the menu is closed by default", () => {
    render(
      <ColumnPicker
        visibility={defaultColumnVisibility()}
        onChange={vi.fn()}
      />,
    );
    expect(screen.queryByTestId("column-picker-menu")).not.toBeInTheDocument();
  });

  it("opens the menu when the trigger is clicked", () => {
    render(
      <ColumnPicker
        visibility={defaultColumnVisibility()}
        onChange={vi.fn()}
      />,
    );
    fireEvent.click(screen.getByTestId("column-picker-trigger"));
    expect(screen.getByTestId("column-picker-menu")).toBeInTheDocument();
    expect(screen.getByTestId("column-picker-trigger")).toHaveAttribute(
      "aria-expanded",
      "true",
    );
  });

  it("renders a menuitemcheckbox for every column with correct aria-checked", () => {
    const v = toggleColumnVisibility(defaultColumnVisibility(), "decision");
    render(<ColumnPicker visibility={v} onChange={vi.fn()} />);
    fireEvent.click(screen.getByTestId("column-picker-trigger"));
    expect(
      screen.getByTestId("column-picker-item-decision"),
    ).toHaveAttribute("aria-checked", "false");
    expect(
      screen.getByTestId("column-picker-item-timestamp"),
    ).toHaveAttribute("aria-checked", "true");
  });

  it("disables only the required columns (timestamp post-triplet)", () => {
    // Post-triplet split: only `timestamp` is `required: true`. The summary
    // column is now togglable (defaultVisible:false) so its checkbox MUST be
    // interactive. Triplet pieces (tool/command/subject) are also togglable.
    render(
      <ColumnPicker
        visibility={defaultColumnVisibility()}
        onChange={vi.fn()}
      />,
    );
    fireEvent.click(screen.getByTestId("column-picker-trigger"));
    expect(
      screen.getByTestId("column-picker-item-timestamp"),
    ).toBeDisabled();
    // Summary is now togglable, not required.
    expect(
      screen.getByTestId("column-picker-item-summary"),
    ).not.toBeDisabled();
    // Triplet pieces are togglable too.
    expect(
      screen.getByTestId("column-picker-item-tool"),
    ).not.toBeDisabled();
    expect(
      screen.getByTestId("column-picker-item-command"),
    ).not.toBeDisabled();
    expect(
      screen.getByTestId("column-picker-item-subject"),
    ).not.toBeDisabled();
    expect(
      screen.getByTestId("column-picker-item-decision"),
    ).not.toBeDisabled();
  });

  it("emits onChange with toggled visibility when an optional column is clicked", () => {
    const onChange = vi.fn();
    render(
      <ColumnPicker
        visibility={defaultColumnVisibility()}
        onChange={onChange}
      />,
    );
    fireEvent.click(screen.getByTestId("column-picker-trigger"));
    fireEvent.click(screen.getByTestId("column-picker-item-decision"));
    expect(onChange).toHaveBeenCalledTimes(1);
    const firstCall = onChange.mock.calls[0];
    expect(firstCall).toBeDefined();
    const next = firstCall![0] as Set<string>;
    expect(next.has("decision")).toBe(false);
    expect(next.has("timestamp")).toBe(true);
  });

  it("does NOT call onChange when a required column is clicked (button is disabled)", () => {
    const onChange = vi.fn();
    render(
      <ColumnPicker
        visibility={defaultColumnVisibility()}
        onChange={onChange}
      />,
    );
    fireEvent.click(screen.getByTestId("column-picker-trigger"));
    fireEvent.click(screen.getByTestId("column-picker-item-timestamp"));
    expect(onChange).not.toHaveBeenCalled();
  });

  it("closes the menu when the user presses Escape", () => {
    render(
      <ColumnPicker
        visibility={defaultColumnVisibility()}
        onChange={vi.fn()}
      />,
    );
    fireEvent.click(screen.getByTestId("column-picker-trigger"));
    expect(screen.getByTestId("column-picker-menu")).toBeInTheDocument();
    fireEvent.keyDown(document, { key: "Escape" });
    expect(screen.queryByTestId("column-picker-menu")).not.toBeInTheDocument();
  });

  it("closes the menu when the user clicks outside", () => {
    render(
      <div>
        <ColumnPicker
          visibility={defaultColumnVisibility()}
          onChange={vi.fn()}
        />
        <button data-testid="outside">outside</button>
      </div>,
    );
    fireEvent.click(screen.getByTestId("column-picker-trigger"));
    expect(screen.getByTestId("column-picker-menu")).toBeInTheDocument();
    fireEvent.mouseDown(screen.getByTestId("outside"));
    expect(screen.queryByTestId("column-picker-menu")).not.toBeInTheDocument();
  });
});
