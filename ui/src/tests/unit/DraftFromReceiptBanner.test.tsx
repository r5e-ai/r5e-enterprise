// DraftFromReceiptBanner — F4 redesign per `design/briefs/04-policy-simulator.md`.
//
// The banner is rendered above column 01 of the Policy Simulator when the
// auditor arrived from the dashboard's "Draft policy from receipt" CTA.
// We assert:
//   1. Renders the run_id verbatim and the optional event_kind summary
//      with a `· ` separator.
//   2. The "view full receipt" link is single-prefixed (`/admin/...`,
//      not `/admin/admin/...`) — matches the basename-stripping
//      contract enforced by `receiptDetailPath()`.
//   3. Loading + error sub-lines render the right testid affordances.

import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { MemoryRouter, Route, Routes } from "react-router-dom";

import { DraftFromReceiptBanner } from "~/components/policy/DraftFromReceiptBanner";

// Mount the banner under a real `policy-simulator` route so relative
// `<Link to="receipts/...">` paths resolve against the matched parent
// route — same shape as how App.tsx mounts it. Without a matched route,
// react-router resolves relative paths against the bare basename, which
// would yield `/admin/receipts/<id>` instead of
// `/admin/policy-simulator/receipts/<id>`.
function renderBanner(props: Parameters<typeof DraftFromReceiptBanner>[0]) {
  return render(
    <MemoryRouter basename="/admin" initialEntries={["/admin/policy-simulator"]}>
      <Routes>
        <Route
          path="/policy-simulator"
          element={<DraftFromReceiptBanner {...props} />}
        />
      </Routes>
    </MemoryRouter>,
  );
}

describe("DraftFromReceiptBanner", () => {
  it("renders the run_id and event_kind summary", () => {
    renderBanner({
      runId: "a621cbb7-01b7-5781-a06a-f258560402e2",
      summary: "tool_call",
    });
    const banner = screen.getByTestId("draft-from-receipt-banner");
    expect(banner.textContent).toContain("a621cbb7-01b7-5781-a06a-f258560402e2");
    expect(banner.textContent).toContain("tool_call");
  });

  it("'view full receipt' link nests under the current parent route (overlay, not navigation away)", () => {
    renderBanner({ runId: "run-42" });
    const banner = screen.getByTestId("draft-from-receipt-banner");
    const link = within(banner).getByRole("link", { name: /view full receipt/i });
    // Per GAN F005 — relative `receipts/<id>` so the drawer overlays
    // whichever parent route the auditor is on. The MemoryRouter mounts
    // at `/admin/policy-simulator`, so the link href resolves to
    // `/admin/policy-simulator/receipts/run-42`.
    expect(link).toHaveAttribute(
      "href",
      "/admin/policy-simulator/receipts/run-42",
    );
    expect(link.getAttribute("href")).not.toMatch(/^\/admin\/admin/);
  });

  it("surfaces a loading affordance when loading=true", () => {
    renderBanner({ runId: "run-1", loading: true });
    const banner = screen.getByTestId("draft-from-receipt-banner");
    expect(banner.textContent).toContain("Loading skeleton");
  });

  it("renders the error message when error is present", () => {
    renderBanner({
      runId: "run-1",
      error: new Error("network blip"),
    });
    const banner = screen.getByTestId("draft-from-receipt-banner");
    expect(banner.textContent).toContain("network blip");
  });
});
