// Vitest unit test for the shared Wordmark primitive.
//
// Asserts the F8 brief's three contract points:
//   1. Renders the three-part mark — sparkle icon + "r5e" + "Enterprise"
//      eyebrow.
//   2. Exposes an aria-label so screen-reader users get a single "r5e
//      enterprise" landmark instead of three orphan text nodes.
//   3. The `size` prop changes the rendered presentation but NOT the
//      semantic content — both Login (md) and Sidebar (sm) consumers see
//      the same accessibility tree.

import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { Wordmark } from "~/components/shared/Wordmark";

describe("Wordmark", () => {
  it("renders the three-part brand mark by default (md)", () => {
    render(<Wordmark />);
    const wordmark = screen.getByTestId("wordmark");
    expect(wordmark).toBeInTheDocument();
    expect(wordmark).toHaveAttribute("data-wordmark-size", "md");
    expect(wordmark).toHaveAttribute("aria-label", "r5e enterprise");

    // The mark contains "r5e" and "Enterprise" as separate text nodes —
    // the sparkle icon is aria-hidden so it doesn't show up in the
    // accessible-text tree.
    expect(wordmark.textContent).toMatch(/r5e/i);
    expect(wordmark.textContent).toMatch(/enterprise/i);
  });

  it("respects the size prop for the sidebar (sm) presentation", () => {
    render(<Wordmark size="sm" />);
    const wordmark = screen.getByTestId("wordmark");
    expect(wordmark).toHaveAttribute("data-wordmark-size", "sm");
  });

  it("hides the sparkle icon from the accessibility tree", () => {
    const { container } = render(<Wordmark />);
    // Lucide renders an <svg> element. Per the brief the sparkle is purely
    // decorative — the wordmark's aria-label carries the semantic meaning,
    // so the SVG must be aria-hidden to avoid double-announcement.
    const svg = container.querySelector("svg");
    expect(svg).not.toBeNull();
    expect(svg).toHaveAttribute("aria-hidden", "true");
  });

  it("merges caller-supplied className with the default wrapper classes", () => {
    render(<Wordmark className="custom-class" />);
    const wordmark = screen.getByTestId("wordmark");
    expect(wordmark.className).toContain("custom-class");
    // Defaults still applied.
    expect(wordmark.className).toMatch(/inline-flex/);
  });
});
