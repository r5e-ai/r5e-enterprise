// Vitest unit tests for SuggestionCard — covers the brief-05 redesign
// (source/confidence pill variants, Cedar preview expand, triggered-by
// popover, dismiss dropdown reasons, simulate-first CTA) plus the
// pre-existing `Explain →` basename-collision regression.

import { fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter } from "react-router-dom";

import { SuggestionCard } from "~/components/policy/SuggestionCard";
import type { PolicySuggestion } from "~/hooks/usePolicySuggestions";

function makeSuggestion(
  overrides: Partial<PolicySuggestion> = {},
): PolicySuggestion {
  return {
    id: "sug-001",
    source: "heuristic",
    confidence: 92,
    title: "Forbid bash subprocess writes outside working directory",
    body: "Auditor pattern: 17 denied bash commands writing to /etc/* or /tmp/* in the last 24h.",
    pattern_summary: "tighten scope on bash writes",
    proposed_cedar:
      "forbid (\n  principal,\n  action == Recurse::Action::\"BashExec\",\n  resource\n) when {\n  resource.tags.tool_kind == \"bash\" &&\n  resource.tags.verb in [\"rm\", \"sudo\"]\n};",
    blast_radius_snapshot: null,
    triggered_by_receipt_ids: [
      "11111111-1111-1111-1111-111111111111",
      "22222222-2222-2222-2222-222222222222",
      "33333333-3333-3333-3333-333333333333",
    ],
    triggered_by_count: 17,
    status: "active",
    generated_at: "2026-04-30T10:00:00Z",
    ...overrides,
  };
}

function renderCard(props: {
  suggestion?: PolicySuggestion;
  onAdopt?: () => void;
  onSimulate?: () => void;
  onDismiss?: (reason?: string) => void;
  isPending?: boolean;
} = {}) {
  const onAdopt = props.onAdopt ?? vi.fn();
  const onSimulate = props.onSimulate ?? vi.fn();
  const onDismiss = props.onDismiss ?? vi.fn();
  const view = render(
    <MemoryRouter
      basename="/admin"
      initialEntries={["/admin/policy-simulator/suggestions"]}
    >
      <SuggestionCard
        suggestion={props.suggestion ?? makeSuggestion()}
        onAdopt={onAdopt}
        onSimulate={onSimulate}
        onDismiss={onDismiss}
        isPending={props.isPending ?? false}
      />
    </MemoryRouter>,
  );
  return { ...view, onAdopt, onSimulate, onDismiss };
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("SuggestionCard 'Explain' link", () => {
  it("renders with a single /admin prefix (no double-prefix)", () => {
    renderCard();
    const link = screen.getByTestId("suggestion-explain");
    const href = link.getAttribute("href") ?? "";
    expect(href.startsWith("/admin/chat")).toBe(true);
    expect(href.startsWith("/admin/admin")).toBe(false);
    expect(href).toMatch(/[?&]chat=open\b/);
    expect(href).toMatch(/[?&]seed=/);
  });
});

describe("SuggestionCard pills (brief 05)", () => {
  it("HEURISTIC source uses outline accent; HIGH confidence uses solid success", () => {
    renderCard({ suggestion: makeSuggestion({ source: "heuristic", confidence: 95 }) });
    const sourcePill = screen.getByTestId("suggestion-source-pill");
    const confPill = screen.getByTestId("suggestion-confidence-pill");
    expect(sourcePill).toHaveAttribute("data-tone", "accent");
    expect(sourcePill.textContent?.toLowerCase()).toContain("heuristic");
    expect(confPill).toHaveAttribute("data-tone", "success");
    expect(confPill.textContent?.toLowerCase()).toContain("high");
  });

  it("LLM source uses solid accent; MEDIUM confidence uses warning tone", () => {
    renderCard({ suggestion: makeSuggestion({ source: "llm", confidence: 80 }) });
    const sourcePill = screen.getByTestId("suggestion-source-pill");
    const confPill = screen.getByTestId("suggestion-confidence-pill");
    expect(sourcePill).toHaveAttribute("data-tone", "accent");
    expect(sourcePill.textContent?.toLowerCase()).toContain("llm");
    expect(confPill).toHaveAttribute("data-tone", "warning");
  });

  it("LOW confidence (<70) uses outline neutral and de-emphasises the card", () => {
    const { container } = renderCard({
      suggestion: makeSuggestion({ confidence: 55 }),
    });
    const confPill = screen.getByTestId("suggestion-confidence-pill");
    expect(confPill).toHaveAttribute("data-tone", "neutral");
    const card = container.querySelector("[data-testid^='suggestion-card-']");
    expect(card?.getAttribute("data-low-confidence")).toBe("true");
  });
});

describe("SuggestionCard Cedar preview", () => {
  it("collapses Cedar source by default and expands on click", () => {
    const longCedar = Array.from({ length: 12 }, (_, i) => `line ${i + 1};`).join(
      "\n",
    );
    renderCard({ suggestion: makeSuggestion({ proposed_cedar: longCedar }) });
    const pre = screen.getByTestId("suggestion-proposed-rule");
    expect(pre.getAttribute("data-expanded")).toBe("false");
    expect(pre.textContent ?? "").toContain("line 1;");
    expect(pre.textContent ?? "").not.toContain("line 12;");

    fireEvent.click(screen.getByTestId("suggestion-toggle-rule"));
    expect(pre.getAttribute("data-expanded")).toBe("true");
    expect(pre.textContent ?? "").toContain("line 12;");
  });

  it("does NOT show the toggle when source has fewer than the preview-line cap", () => {
    renderCard({
      suggestion: makeSuggestion({ proposed_cedar: "permit(...);" }),
    });
    expect(screen.queryByTestId("suggestion-toggle-rule")).toBeNull();
  });
});

describe("SuggestionCard triggered-by", () => {
  it("renders count + opens a popover with example receipt links", () => {
    renderCard();
    expect(screen.getByTestId("suggestion-triggered-by")).toBeInTheDocument();
    const toggle = screen.getByTestId("suggestion-triggered-by-toggle");
    expect(toggle.textContent ?? "").toMatch(/example/i);

    fireEvent.click(toggle);
    const popover = screen.getByTestId("suggestion-triggered-by-popover");
    const links = within(popover).getAllByRole("link");
    expect(links.length).toBe(3);
    expect(links[0]?.getAttribute("href")).toContain(
      "/admin/dashboard/receipts/11111111-1111-1111-1111-111111111111",
    );
  });

  it("popover overlays the rest of the card (absolute positioning, F004)", () => {
    // Pre-fix the popover was rendered as a sibling inside a flex
    // column without absolute positioning, so opening it pushed the
    // blast-radius preview + footer downward instead of floating over
    // them. Pin the absolute + top-full + z-index classes so a
    // regression on the wrapper className shows up here.
    renderCard();
    fireEvent.click(screen.getByTestId("suggestion-triggered-by-toggle"));
    const popover = screen.getByTestId("suggestion-triggered-by-popover");
    expect(popover.className).toMatch(/\babsolute\b/);
    expect(popover.className).toMatch(/\btop-full\b/);
    expect(popover.className).toMatch(/\bz-30\b/);
  });

  it("popover closes when Escape is pressed (F004 + F007 keyboard a11y)", () => {
    renderCard();
    fireEvent.click(screen.getByTestId("suggestion-triggered-by-toggle"));
    expect(screen.getByTestId("suggestion-triggered-by-popover")).toBeInTheDocument();
    fireEvent.keyDown(document, { key: "Escape" });
    expect(screen.queryByTestId("suggestion-triggered-by-popover")).toBeNull();
  });

  it("hides the line entirely when no trigger metadata is on the wire", () => {
    renderCard({
      suggestion: makeSuggestion({
        triggered_by_receipt_ids: null,
        triggered_by_count: null,
      }),
    });
    expect(screen.queryByTestId("suggestion-triggered-by")).toBeNull();
  });
});

describe("SuggestionCard dismiss dropdown", () => {
  it("opens a menu with 4 reason options on Dismiss click", () => {
    const onDismiss = vi.fn();
    renderCard({ onDismiss });
    fireEvent.click(screen.getByTestId("suggestion-dismiss"));
    expect(screen.getByTestId("suggestion-dismiss-menu")).toBeInTheDocument();
    expect(
      screen.getByTestId("suggestion-dismiss-reason-not_relevant"),
    ).toBeInTheDocument();
    expect(
      screen.getByTestId("suggestion-dismiss-reason-wrong_policy_shape"),
    ).toBeInTheDocument();
    expect(
      screen.getByTestId("suggestion-dismiss-reason-already_covered"),
    ).toBeInTheDocument();
    expect(
      screen.getByTestId("suggestion-dismiss-reason-other"),
    ).toBeInTheDocument();
  });

  it("invokes onDismiss with the canonical reason label on a non-Other pick", () => {
    const onDismiss = vi.fn();
    renderCard({ onDismiss });
    fireEvent.click(screen.getByTestId("suggestion-dismiss"));
    fireEvent.click(
      screen.getByTestId("suggestion-dismiss-reason-not_relevant"),
    );
    expect(onDismiss).toHaveBeenCalledWith("Not relevant");
  });

  it("Other route requires a free-form note before submitting", () => {
    const onDismiss = vi.fn();
    renderCard({ onDismiss });
    fireEvent.click(screen.getByTestId("suggestion-dismiss"));
    fireEvent.click(screen.getByTestId("suggestion-dismiss-reason-other"));
    // Input now visible; submit button disabled until note typed.
    const submit = screen.getByTestId("suggestion-dismiss-other-submit");
    expect(submit).toBeDisabled();
    fireEvent.change(screen.getByTestId("suggestion-dismiss-other-note"), {
      target: { value: "engine guessed wrong" },
    });
    expect(submit).not.toBeDisabled();
    fireEvent.click(submit);
    expect(onDismiss).toHaveBeenCalledTimes(1);
    expect(onDismiss).toHaveBeenCalledWith("Other: engine guessed wrong");
  });

  it("Escape closes the dismiss menu (F007 — keyboard a11y)", () => {
    renderCard();
    fireEvent.click(screen.getByTestId("suggestion-dismiss"));
    expect(screen.getByTestId("suggestion-dismiss-menu")).toBeInTheDocument();
    fireEvent.keyDown(document, { key: "Escape" });
    expect(screen.queryByTestId("suggestion-dismiss-menu")).toBeNull();
  });

  it("Enter on the Other note submits the dismissal (F007 — keyboard a11y)", () => {
    const onDismiss = vi.fn();
    renderCard({ onDismiss });
    fireEvent.click(screen.getByTestId("suggestion-dismiss"));
    fireEvent.click(screen.getByTestId("suggestion-dismiss-reason-other"));
    const note = screen.getByTestId("suggestion-dismiss-other-note");
    fireEvent.change(note, { target: { value: "stale signal" } });
    fireEvent.keyDown(note, { key: "Enter" });
    expect(onDismiss).toHaveBeenCalledTimes(1);
    expect(onDismiss).toHaveBeenCalledWith("Other: stale signal");
  });

  it("Enter on an empty Other note does NOT submit (F007 — guard)", () => {
    const onDismiss = vi.fn();
    renderCard({ onDismiss });
    fireEvent.click(screen.getByTestId("suggestion-dismiss"));
    fireEvent.click(screen.getByTestId("suggestion-dismiss-reason-other"));
    const note = screen.getByTestId("suggestion-dismiss-other-note");
    fireEvent.keyDown(note, { key: "Enter" });
    expect(onDismiss).not.toHaveBeenCalled();
  });
});

describe("SuggestionCard CTAs", () => {
  it("Adopt + Simulate-first invoke their respective handlers", () => {
    const onAdopt = vi.fn();
    const onSimulate = vi.fn();
    renderCard({ onAdopt, onSimulate });
    fireEvent.click(screen.getByTestId("suggestion-adopt"));
    fireEvent.click(screen.getByTestId("suggestion-simulate"));
    expect(onAdopt).toHaveBeenCalledTimes(1);
    expect(onSimulate).toHaveBeenCalledTimes(1);
  });

  it("isPending disables both buttons", () => {
    renderCard({ isPending: true });
    expect(screen.getByTestId("suggestion-adopt")).toBeDisabled();
    expect(screen.getByTestId("suggestion-simulate")).toBeDisabled();
    expect(screen.getByTestId("suggestion-dismiss")).toBeDisabled();
  });
});

describe("SuggestionCard adopted/dismissed states", () => {
  it("renders an Adopted pill and hides the action footer for adopted cards", () => {
    renderCard({
      suggestion: makeSuggestion({ status: "adopted_as_draft" }),
    });
    expect(screen.getByTestId("suggestion-status-adopted")).toBeInTheDocument();
    expect(screen.queryByTestId("suggestion-adopt")).toBeNull();
    expect(screen.queryByTestId("suggestion-dismiss")).toBeNull();
  });

  it("renders the dismiss reason on dismissed cards", () => {
    renderCard({
      suggestion: makeSuggestion({
        status: "dismissed",
        dismiss_reason: "Already covered",
      }),
    });
    expect(screen.getByTestId("suggestion-status-dismissed")).toBeInTheDocument();
    const reason = screen.getByTestId("suggestion-dismiss-reason");
    expect(reason.textContent ?? "").toContain("Already covered");
  });
});

describe("SuggestionCard blast-radius preview", () => {
  it("renders 'X unintended · Y matches intent' when snapshot has counts", () => {
    renderCard({
      suggestion: makeSuggestion({
        blast_radius_snapshot: {
          matches_intent: 5,
          unintended: 12,
          would_have_allowed: 0,
          no_change: 1572,
        },
      }),
    });
    const summary = screen.getByTestId("suggestion-blast-radius");
    expect(summary.textContent ?? "").toContain("12 unintended");
    expect(summary.textContent ?? "").toContain("5 matches intent");
  });

  it("omits the line entirely when snapshot is null", () => {
    renderCard({ suggestion: makeSuggestion({ blast_radius_snapshot: null }) });
    expect(screen.queryByTestId("suggestion-blast-radius")).toBeNull();
  });

  it("renders 'Engine ran, no policy delta' when snapshot exists with all-zero counts (F004 fix-pass-2)", () => {
    // Pre-fix-pass-2 BlastRadiusInlineSummary returned null both when the
    // engine had not run AND when it ran and confirmed zero impact —
    // hiding the high-confidence-no-impact signal that's actually useful
    // for triage. The snapshot's existence (engines don't emit empty
    // snapshots) is now the "engine ran" signal; an explicit success
    // line surfaces it.
    renderCard({
      suggestion: makeSuggestion({
        blast_radius_snapshot: {
          matches_intent: 0,
          unintended: 0,
          would_have_allowed: 0,
          no_change: 1572,
          total_affected: 0,
          computed_at: "2026-04-30T10:00:00Z",
        },
      }),
    });
    const summary = screen.getByTestId("suggestion-blast-radius");
    expect(summary.getAttribute("data-engine-ran")).toBe("true");
    expect(summary.getAttribute("data-empty")).toBe("true");
    expect(summary.textContent ?? "").toMatch(/engine ran, no policy delta/i);
    expect(screen.getByTestId("suggestion-blast-no-delta")).toBeInTheDocument();
  });
});

describe("SuggestionCard timestamp format (F006 fix-pass-2)", () => {
  // Pre-fix-pass-2 the page header showed "Last run: 2 min ago" while the
  // card header `<time>` rendered the raw ISO string — two formats for
  // the same kind of value inside one viewport. Both surfaces now read
  // `relativeFromNow(suggestion.generated_at)`.
  it("renders the generated_at as a relative time string (not raw ISO)", () => {
    const fiveMinAgo = new Date(Date.now() - 5 * 60_000).toISOString();
    renderCard({ suggestion: makeSuggestion({ generated_at: fiveMinAgo }) });
    const time = screen.getByTestId("suggestion-generated-at");
    // Visible label is the relative form…
    expect(time.textContent ?? "").toMatch(/(\d+\s*min ago|just now)/i);
    // …but the absolute timestamp is preserved for a11y / tooltips.
    expect(time.getAttribute("dateTime")).toBe(fiveMinAgo);
    expect(time.getAttribute("title")).toBe(fiveMinAgo);
  });
});
