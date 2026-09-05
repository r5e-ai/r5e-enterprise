// Vitest unit test for BlastRadiusPanel — focused on the basename-collision
// regression: the sample-receipts list renders a `<Link to>` that deep-links
// to the Receipt Detail drawer. Before the consolidation in this MR, the
// component built `/admin/dashboard/receipts/<id>` inline; under
// `<BrowserRouter basename="/admin">` (mirrored here by
// `<MemoryRouter basename="/admin">`) react-router auto-prepends the
// basename for outbound URLs, so a non-stripped target rendered as
// `<a href="/admin/admin/dashboard/receipts/<id>">` — no route match,
// blank page on click. The fix routes the link through
// `receiptDetailPath()` which strips the basename first.
//
// This test asserts the rendered href is the SINGLE-prefixed shape. With
// the bug present + the wrapper mounted under `basename="/admin"`, this
// test would have failed at unit-test time. See the matching reflect note
// for the adversarial-check (revert the fix, see this fail, re-apply).

import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { MemoryRouter, Route, Routes } from "react-router-dom";

import { BlastRadiusPanel } from "~/components/policy/BlastRadiusPanel";
import type { BlastRadiusResult } from "~/hooks/useBlastRadius";

function makeResult(
  sample: { run_id: string; classification?: "unintended" | "matches_intent" },
): BlastRadiusResult {
  return {
    draft_id: "draft-xyz",
    window_days: 30,
    total_receipts_in_window: 100,
    total_affected: 1,
    matches_intent: sample.classification === "matches_intent" ? 1 : 0,
    unintended: sample.classification === "unintended" ? 1 : 0,
    would_have_allowed: 0,
    no_change: 0,
    sample_receipts: [
      {
        run_id: sample.run_id,
        classification: sample.classification ?? "unintended",
        summary: "an audited call",
      },
    ],
    computed_at: "2026-04-30T12:00:00Z",
  };
}

// Mount under a real `policy-simulator` route so relative
// `<Link to="receipts/...">` paths resolve against the simulator parent —
// matches how App.tsx wires the page in production.
function renderPanel(result: BlastRadiusResult) {
  return render(
    <MemoryRouter basename="/admin" initialEntries={["/admin/policy-simulator"]}>
      <Routes>
        <Route
          path="/policy-simulator"
          element={
            <BlastRadiusPanel
              result={result}
              isPending={false}
              error={null}
              onRun={() => {}}
            />
          }
        />
      </Routes>
    </MemoryRouter>,
  );
}

describe("BlastRadiusPanel sample-receipts list", () => {
  it("renders a sample-receipt 'view full receipt' link as a child of the current parent route", () => {
    renderPanel(makeResult({ run_id: "abc-123" }));
    const link = screen.getByRole("link", { name: /view full receipt/i });
    // Per F4 brief + GAN F005 — the link is RELATIVE so the drawer
    // overlays whichever parent route the auditor is on (the test mounts
    // under `/admin/policy-simulator`, so the drawer is at
    // `/admin/policy-simulator/receipts/<id>`).
    expect(link).toHaveAttribute(
      "href",
      "/admin/policy-simulator/receipts/abc-123",
    );
    expect(link.getAttribute("href")).not.toMatch(/^\/admin\/admin/);
  });

  it("percent-encodes the run_id in the rendered href", () => {
    renderPanel(makeResult({ run_id: "weird id/with chars" }));
    const link = screen.getByRole("link", { name: /view full receipt/i });
    // encodeURIComponent yields "weird%20id%2Fwith%20chars".
    expect(link).toHaveAttribute(
      "href",
      "/admin/policy-simulator/receipts/weird%20id%2Fwith%20chars",
    );
    expect(link.getAttribute("href")).not.toMatch(/^\/admin\/admin/);
  });
});

describe("BlastRadiusPanel — F4 Wiz 4-cell matrix", () => {
  // Per backend `blast_radius_algorithm.md` §"Outputs":
  //   total_affected = matches_intent + unintended
  // (would_have_allowed is a SUBSET of no_change in the algorithm and is
  // NOT included in the denominator.) Test fixtures keep this invariant
  // so the SPA's MatchesIntentTopline computation matches what real
  // backend results will look like.
  function fullResult(overrides: Partial<BlastRadiusResult> = {}): BlastRadiusResult {
    const base = {
      draft_id: "draft-xyz",
      window_days: 30,
      total_receipts_in_window: 1750,
      matches_intent: 0,
      unintended: 127,
      would_have_allowed: 51,
      no_change: 1572,
      sample_receipts: [],
      computed_at: "2026-04-30T12:00:00Z",
      ...overrides,
    };
    return {
      ...base,
      total_affected: overrides.total_affected ?? base.matches_intent + base.unintended,
    };
  }

  it("renders all four cells of the Wiz matrix", () => {
    renderPanel(fullResult({ matches_intent: 100, unintended: 50, would_have_allowed: 28 }));
    expect(screen.getByTestId("cell-no-change")).toBeInTheDocument();
    expect(screen.getByTestId("cell-would-have-allowed")).toBeInTheDocument();
    expect(screen.getByTestId("cell-unintended")).toBeInTheDocument();
    expect(screen.getByTestId("cell-matches-intent")).toBeInTheDocument();
  });

  it("renders MATCHES INTENT as a percentage on the topline (matches / total_affected)", () => {
    // matches=92, unintended=5 → total_affected=97 → 92/97 = 94.84% → 95%
    renderPanel(
      fullResult({ matches_intent: 92, unintended: 5, would_have_allowed: 3 }),
    );
    expect(screen.getByTestId("matches-intent-pct").textContent).toBe("95%");
    // Above the 75% threshold → success-state.
    expect(screen.getByTestId("matches-intent-topline").getAttribute("data-state"))
      .toBe("success");
  });

  it("renders an EMPTY state on the topline when total_affected is 0 (vacuous match)", () => {
    // No receipts affected → topline must NOT render 0% in success-green.
    // Per GAN F003 — the brief's intent is 'safe rule, didn't fire' which
    // is an empty state, not a 0% success metric.
    renderPanel(
      fullResult({ matches_intent: 0, unintended: 0, would_have_allowed: 0, total_affected: 0 }),
    );
    expect(screen.getByTestId("matches-intent-pct").textContent).toBe("—");
    expect(screen.getByTestId("matches-intent-topline").getAttribute("data-state"))
      .toBe("empty");
  });

  it("renders the topline in WARNING tone when match-rate is below the 75% threshold", () => {
    // matches=50, unintended=50 → 50/100 = 50% → below threshold.
    renderPanel(
      fullResult({ matches_intent: 50, unintended: 50, would_have_allowed: 0 }),
    );
    expect(screen.getByTestId("matches-intent-pct").textContent).toBe("50%");
    expect(screen.getByTestId("matches-intent-topline").getAttribute("data-state"))
      .toBe("warning");
  });

  it("emphasizes UNINTENDED when count > 0 (ring highlight)", () => {
    renderPanel(fullResult({ unintended: 127 }));
    const cell = screen.getByTestId("cell-unintended");
    expect(cell.className).toContain("ring-2");
  });

  it("sorts UNINTENDED sample rows to the top of the sample-receipts list", () => {
    const result = fullResult({
      unintended: 1,
      matches_intent: 1,
      would_have_allowed: 1,
      total_affected: 3,
      sample_receipts: [
        { run_id: "r-matches", classification: "matches_intent", summary: "matches" },
        { run_id: "r-noop", classification: "no_change", summary: "noop" },
        { run_id: "r-would", classification: "would_have_allowed", summary: "would" },
        { run_id: "r-unintended", classification: "unintended", summary: "unintended" },
      ],
    });
    renderPanel(result);
    const list = screen.getByTestId("sample-receipts");
    const items = list.querySelectorAll("li");
    // First row must be UNINTENDED — that's the regression-surfacing intent.
    expect(items[0]?.textContent).toContain("unintended");
  });

  it("does not render sample-receipts list when result has no samples", () => {
    renderPanel(fullResult({ sample_receipts: [] }));
    expect(screen.queryByTestId("sample-receipts")).toBeNull();
  });

  it("renders the idle CTA when result is null and not pending", () => {
    render(
      <MemoryRouter basename="/admin" initialEntries={["/admin/policy-simulator"]}>
        <Routes>
          <Route
            path="/policy-simulator"
            element={
              <BlastRadiusPanel
                result={null}
                isPending={false}
                error={null}
                onRun={() => {}}
              />
            }
          />
        </Routes>
      </MemoryRouter>,
    );
    expect(screen.getByTestId("blast-radius-idle")).toBeInTheDocument();
  });
});

// FR-027 + FR-026 (c) advisories + FR-026 (d) show-all toggle — restored in
// !89 fix-pass-2.
describe("BlastRadiusPanel — FR-026 + FR-027 advisories", () => {
  function fullResult(overrides: Partial<BlastRadiusResult> = {}): BlastRadiusResult {
    const base = {
      draft_id: "draft-xyz",
      window_days: 30,
      total_receipts_in_window: 1750,
      matches_intent: 0,
      unintended: 0,
      would_have_allowed: 0,
      no_change: 0,
      sample_receipts: [],
      computed_at: "2026-04-30T12:00:00Z",
      ...overrides,
    };
    return {
      ...base,
      total_affected: overrides.total_affected ?? base.matches_intent + base.unintended,
    };
  }

  it("renders the FR-027 unintended-block advisory when unintended > 0", () => {
    renderPanel(fullResult({ matches_intent: 50, unintended: 5 }));
    const advisory = screen.getByTestId("unintended-block-advisory");
    expect(advisory).toBeInTheDocument();
    expect(advisory.textContent).toMatch(/incorrectly blocked/i);
    expect(advisory.textContent).toMatch(/narrow/i);
    // FR-027 deep-link to the suggestions queue.
    const link = screen.getByTestId("unintended-block-advisory-suggestions-link");
    expect(link).toHaveAttribute("href", "/admin/policy-simulator/suggestions");
  });

  it("does NOT render the FR-027 advisory when unintended == 0", () => {
    renderPanel(fullResult({ matches_intent: 50, unintended: 0 }));
    expect(screen.queryByTestId("unintended-block-advisory")).toBeNull();
  });

  it("renders the FR-026 (c) would-have-allowed advisory when would_have_allowed > 0", () => {
    renderPanel(fullResult({ matches_intent: 50, unintended: 0, would_have_allowed: 7 }));
    const advisory = screen.getByTestId("would-have-allowed-advisory");
    expect(advisory).toBeInTheDocument();
    expect(advisory.textContent).toMatch(/previously-denied/i);
    expect(advisory.textContent).toMatch(/loosening/i);
  });

  it("does NOT render the FR-026 (c) advisory when would_have_allowed == 0", () => {
    renderPanel(fullResult({ matches_intent: 50 }));
    expect(screen.queryByTestId("would-have-allowed-advisory")).toBeNull();
  });

  it("FR-026 (d) — show-all toggle hides no_change rows from sample list by default", () => {
    const result = fullResult({
      unintended: 1,
      no_change: 3,
      total_affected: 1,
      sample_receipts: [
        { run_id: "r-noop-1", classification: "no_change", summary: "noop1" },
        { run_id: "r-unintended", classification: "unintended", summary: "unintended" },
        { run_id: "r-noop-2", classification: "no_change", summary: "noop2" },
      ],
    });
    renderPanel(result);
    // Default — toggle off, no_change rows hidden.
    const list = screen.getByTestId("sample-receipts");
    expect(list.querySelectorAll('[data-testid="sample-receipt-no_change"]').length).toBe(0);
    expect(list.querySelectorAll('[data-testid="sample-receipt-unintended"]').length).toBe(1);

    // Flip the toggle — no_change rows revealed.
    const toggle = screen.getByTestId("blast-radius-show-all");
    fireEvent.click(toggle);
    const listAfter = screen.getByTestId("sample-receipts");
    expect(listAfter.querySelectorAll('[data-testid="sample-receipt-no_change"]').length).toBe(2);
    expect(listAfter.querySelectorAll('[data-testid="sample-receipt-unintended"]').length).toBe(1);
  });
});
