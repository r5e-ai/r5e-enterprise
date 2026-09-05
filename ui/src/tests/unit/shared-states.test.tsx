// Tests for the shared state primitives: EmptyState, ErrorState,
// Skeleton, and Pill. R5 frame guidance + Constitution Principle VII
// extraction.

import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";

import { EmptyState } from "~/components/shared/states/EmptyState";
import { ErrorState } from "~/components/shared/states/ErrorState";
import { Skeleton } from "~/components/shared/states/Skeleton";
import { Pill } from "~/components/shared/Pill";

describe("EmptyState", () => {
  it("renders title + optional body", () => {
    render(<EmptyState title="No data" body="Nothing to see." />);
    expect(screen.getByText("No data")).toBeInTheDocument();
    expect(screen.getByText("Nothing to see.")).toBeInTheDocument();
  });

  it("invokes the action callback when the CTA is clicked", () => {
    const onClick = vi.fn();
    render(
      <EmptyState
        title="No matches"
        action={{ label: "Clear filters", onClick }}
      />,
    );
    fireEvent.click(screen.getByText("Clear filters"));
    expect(onClick).toHaveBeenCalledTimes(1);
  });

  it("supports custom test id", () => {
    render(<EmptyState testId="custom-empty" title="Empty" />);
    expect(screen.getByTestId("custom-empty")).toBeInTheDocument();
  });
});

describe("ErrorState", () => {
  it("renders title + body + detail", () => {
    render(
      <ErrorState
        title="Pipeline failure"
        body="Connection lost"
        detail="ECONNREFUSED at 10.0.0.1:5432"
      />,
    );
    expect(screen.getByText("Pipeline failure")).toBeInTheDocument();
    expect(screen.getByText("Connection lost")).toBeInTheDocument();
    expect(screen.getByText(/ECONNREFUSED/)).toBeInTheDocument();
  });

  it("renders retry + secondary actions", () => {
    const retry = vi.fn();
    const secondary = vi.fn();
    render(
      <ErrorState
        title="Boom"
        retry={{ onClick: retry }}
        secondary={{ label: "View pipeline", onClick: secondary }}
      />,
    );
    fireEvent.click(screen.getByText("Retry now"));
    fireEvent.click(screen.getByText("View pipeline"));
    expect(retry).toHaveBeenCalledTimes(1);
    expect(secondary).toHaveBeenCalledTimes(1);
  });

  it("uses role=alert", () => {
    render(<ErrorState title="x" />);
    expect(screen.getByRole("alert")).toBeInTheDocument();
  });
});

describe("Skeleton", () => {
  it("Skeleton.Block renders with the supplied className", () => {
    const { container } = render(<Skeleton.Block className="h-8 w-32" />);
    const el = container.querySelector("[data-testid='skeleton-block']");
    expect(el?.className).toContain("h-8");
    expect(el?.className).toContain("w-32");
    expect(el?.className).toContain("animate-pulse");
  });

  it("Skeleton.Histogram renders the requested number of bars", () => {
    const { container } = render(<Skeleton.Histogram bars={5} />);
    const root = container.querySelector("[data-testid='skeleton-histogram']");
    expect(root?.children.length).toBe(5);
  });

  it("Skeleton.Rows renders the requested number of rows", () => {
    const { container } = render(<Skeleton.Rows rows={3} />);
    const root = container.querySelector("[data-testid='skeleton-rows']");
    expect(root?.children.length).toBe(3);
  });
});

describe("Pill", () => {
  it("renders with the requested tone class", () => {
    render(<Pill tone="success">PROVEN-SAFE</Pill>);
    const pill = screen.getByText("PROVEN-SAFE");
    expect(pill.className).toContain("border-r5e-success");
    expect(pill.getAttribute("data-tone")).toBe("success");
  });

  it("renders outline variant without the bg fill", () => {
    render(
      <Pill tone="danger" outline>
        DENIED
      </Pill>,
    );
    const pill = screen.getByText("DENIED");
    // Outline variant: text-r5e-danger but no bg-r5e-danger/15
    expect(pill.className).toContain("text-r5e-danger");
    expect(pill.className).not.toContain("bg-r5e-danger/15");
  });

  it("respects size prop", () => {
    render(<Pill size="md">BIG</Pill>);
    const pill = screen.getByText("BIG");
    expect(pill.className).toContain("text-[11px]");
  });
});
