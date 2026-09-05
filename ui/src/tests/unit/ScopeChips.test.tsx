// ScopeChips — active scope chips + dismiss behavior + time-window picker.
//
// Asserts:
//   - Renders dismiss-able chips for principal / session_id / correlation_id.
//   - Time-window pill always rendered with the active label.
//   - Empty state when no scope params are set.
//   - Window picker callback fires with the chosen key.

import { render, screen, fireEvent } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { ScopeChips } from "~/components/timeline/ScopeChips";
import type { ActiveScope } from "~/lib/timeline";

function mkScope(overrides: Partial<ActiveScope> = {}): ActiveScope {
  return {
    principal: null,
    session_id: null,
    correlation_id: null,
    run_id: null,
    since: null,
    until: null,
    time_window_label: "Last 24h",
    ...overrides,
  };
}

describe("ScopeChips", () => {
  it("renders empty marker when no scope params set", () => {
    render(
      <ScopeChips
        scope={mkScope()}
        windowKey="24h"
        onDismissPrincipal={() => undefined}
        onDismissSession={() => undefined}
        onDismissCorrelation={() => undefined}
        onDismissRunId={() => undefined}
        onWindowChange={() => undefined}
      />,
    );
    expect(screen.getByTestId("scope-empty")).toBeInTheDocument();
  });

  it("renders a principal chip with dismiss button", () => {
    const onDismiss = vi.fn();
    render(
      <ScopeChips
        scope={mkScope({ principal: "alice@example.com" })}
        windowKey="24h"
        onDismissPrincipal={onDismiss}
        onDismissSession={() => undefined}
        onDismissCorrelation={() => undefined}
        onDismissRunId={() => undefined}
        onWindowChange={() => undefined}
      />,
    );
    const chip = screen.getByTestId("scope-chip-principal");
    expect(chip).toHaveTextContent("alice@example.com");
    fireEvent.click(chip.querySelector("button")!);
    expect(onDismiss).toHaveBeenCalled();
  });

  it("renders all three scope chips when all set", () => {
    render(
      <ScopeChips
        scope={mkScope({
          principal: "alice",
          session_id: "s-aaa-bbb",
          correlation_id: "c-xyz",
        })}
        windowKey="24h"
        onDismissPrincipal={() => undefined}
        onDismissSession={() => undefined}
        onDismissCorrelation={() => undefined}
        onDismissRunId={() => undefined}
        onWindowChange={() => undefined}
      />,
    );
    expect(screen.getByTestId("scope-chip-principal")).toBeInTheDocument();
    expect(screen.getByTestId("scope-chip-session")).toBeInTheDocument();
    expect(screen.getByTestId("scope-chip-correlation")).toBeInTheDocument();
  });

  it("renders the time-window pill with the active label", () => {
    render(
      <ScopeChips
        scope={mkScope({ time_window_label: "Last 1h" })}
        windowKey="1h"
        onDismissPrincipal={() => undefined}
        onDismissSession={() => undefined}
        onDismissCorrelation={() => undefined}
        onDismissRunId={() => undefined}
        onWindowChange={() => undefined}
      />,
    );
    expect(screen.getByTestId("scope-chip-time")).toHaveTextContent(/last 1h/i);
  });

  it("fires onWindowChange when a picker button is clicked", () => {
    const onChange = vi.fn();
    render(
      <ScopeChips
        scope={mkScope()}
        windowKey="24h"
        onDismissPrincipal={() => undefined}
        onDismissSession={() => undefined}
        onDismissCorrelation={() => undefined}
        onDismissRunId={() => undefined}
        onWindowChange={onChange}
      />,
    );
    fireEvent.click(screen.getByTestId("time-window-1h"));
    expect(onChange).toHaveBeenCalledWith("1h");
  });

  it("marks the active window as data-active='true'", () => {
    render(
      <ScopeChips
        scope={mkScope()}
        windowKey="6h"
        onDismissPrincipal={() => undefined}
        onDismissSession={() => undefined}
        onDismissCorrelation={() => undefined}
        onDismissRunId={() => undefined}
        onWindowChange={() => undefined}
      />,
    );
    expect(screen.getByTestId("time-window-6h").dataset.active).toBe("true");
    expect(screen.getByTestId("time-window-24h").dataset.active).toBe("false");
  });
});
