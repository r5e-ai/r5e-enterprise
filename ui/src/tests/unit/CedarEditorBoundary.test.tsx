// CedarEditorBoundary.test.tsx — defense-in-depth regression for issue
// #61. The boundary surfaces a textarea fallback when Monaco fails to
// initialize, replacing the prior "infinite Loading..." failure mode.
//
// We assert two failure paths and one happy path:
//
//   1. **Throw path.** A child component that throws synchronously
//      during render is caught by the class-component boundary; the
//      fallback `<textarea>` renders with the same `value`/`onChange`
//      contract; the user can keep editing.
//   2. **Timeout path.** When Monaco's loader hangs forever (no error
//      thrown, no `cedar-editor-mounted` event dispatched), the
//      timeout flips into the same fallback. We exercise this via the
//      `forceTimeout` test seam to avoid wall-clock waits.
//   3. **Happy path.** When the child dispatches the
//      `cedar-editor-mounted` event, the timeout cancels and the
//      child renders normally — the boundary is invisible.

import { describe, expect, it, vi } from "vitest";
import { render, screen, fireEvent, act } from "@testing-library/react";

import CedarEditorBoundary from "~/components/policy/CedarEditorBoundary";

// ---------------------------------------------------------------------------
// Test child #1 — throws synchronously to exercise the error boundary.
// ---------------------------------------------------------------------------

function ThrowingChild(): JSX.Element {
  throw new Error("Monaco initialization: simulated failure");
}

// ---------------------------------------------------------------------------
// Test child #2 — dispatches the cedar-editor-mounted event so the
// timeout cancels and the child renders.
// ---------------------------------------------------------------------------

function MountedChild(): JSX.Element {
  // Fire on first render — mirrors what real CedarEditor does in onMount.
  if (typeof window !== "undefined") {
    queueMicrotask(() => {
      window.dispatchEvent(new Event("cedar-editor-mounted"));
    });
  }
  return <div data-testid="real-editor">real Monaco editor</div>;
}

describe("<CedarEditorBoundary /> (issue #61 defense-in-depth)", () => {
  it("renders the child when no error or timeout fires", () => {
    let captured = "initial";

    render(
      <CedarEditorBoundary
        value={captured}
        onChange={(v) => (captured = v)}
        disableTimeout
      >
        <MountedChild />
      </CedarEditorBoundary>,
    );

    expect(screen.getByTestId("real-editor")).toBeInTheDocument();
    expect(screen.queryByTestId("cedar-editor-fallback")).not.toBeInTheDocument();
  });

  it("surfaces the textarea fallback when the child throws during render", () => {
    let captured = "policy permit (...) when { true };";

    // React 18 logs to console.error when an error boundary catches —
    // silence it so the test output stays clean. We're explicitly
    // testing the boundary's catch path.
    const consoleErrorSpy = vi
      .spyOn(console, "error")
      .mockImplementation(() => {});

    render(
      <CedarEditorBoundary
        value={captured}
        onChange={(v) => {
          captured = v;
        }}
        disableTimeout
      >
        <ThrowingChild />
      </CedarEditorBoundary>,
    );

    const fallback = screen.getByTestId("cedar-editor-fallback");
    expect(fallback).toBeInTheDocument();

    const textarea = screen.getByTestId(
      "cedar-editor-fallback-textarea",
    ) as HTMLTextAreaElement;
    expect(textarea).toBeInTheDocument();
    expect(textarea.value).toBe("policy permit (...) when { true };");

    // The fallback `onChange` flow must keep working — the user has to
    // be able to edit the policy even without Monaco.
    fireEvent.change(textarea, {
      target: { value: "policy forbid (...) when { false };" },
    });
    expect(captured).toBe("policy forbid (...) when { false };");

    // The error message must mention initialization so the user has a
    // chance of understanding what went wrong, and a retry escape hatch
    // must be present.
    expect(
      screen.getByTestId("cedar-editor-fallback-message"),
    ).toHaveTextContent(/Monaco initialization|initialize/i);
    expect(
      screen.getByTestId("cedar-editor-fallback-retry"),
    ).toBeInTheDocument();

    consoleErrorSpy.mockRestore();
  });

  it("surfaces the textarea fallback when Monaco fails to dispatch the mounted event (timeout path)", () => {
    let captured = "policy permit (...);";

    render(
      <CedarEditorBoundary
        value={captured}
        onChange={(v) => {
          captured = v;
        }}
        forceTimeout
      >
        {/* No event dispatch — simulates Monaco's loader hanging. */}
        <div data-testid="loading-spinner">Loading...</div>
      </CedarEditorBoundary>,
    );

    expect(screen.getByTestId("cedar-editor-fallback")).toBeInTheDocument();
    // The timeout path must call out the underlying cause so a developer
    // grepping the user's screenshot can find the static-asset bug.
    expect(
      screen.getByTestId("cedar-editor-fallback-message"),
    ).toHaveTextContent(/loader\.js/);
  });

  it("retry button restores the wrapped editor after a throw", () => {
    let captured = "x";
    let shouldThrow = true;

    function ConditionalChild(): JSX.Element {
      if (shouldThrow) {
        throw new Error("Monaco initialization failed");
      }
      return <div data-testid="recovered-editor">recovered</div>;
    }

    const consoleErrorSpy = vi
      .spyOn(console, "error")
      .mockImplementation(() => {});

    const { rerender } = render(
      <CedarEditorBoundary
        value={captured}
        onChange={(v) => (captured = v)}
        disableTimeout
      >
        <ConditionalChild />
      </CedarEditorBoundary>,
    );

    expect(screen.getByTestId("cedar-editor-fallback")).toBeInTheDocument();

    // Fix the underlying problem and click retry.
    shouldThrow = false;
    act(() => {
      fireEvent.click(screen.getByTestId("cedar-editor-fallback-retry"));
    });
    rerender(
      <CedarEditorBoundary
        value={captured}
        onChange={(v) => (captured = v)}
        disableTimeout
      >
        <ConditionalChild />
      </CedarEditorBoundary>,
    );

    expect(screen.getByTestId("recovered-editor")).toBeInTheDocument();
    expect(
      screen.queryByTestId("cedar-editor-fallback"),
    ).not.toBeInTheDocument();

    consoleErrorSpy.mockRestore();
  });
});
