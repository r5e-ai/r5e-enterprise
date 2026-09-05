// Vitest unit test for ReceiptDetail's drawer-close navigation —
// basename-collision regression coverage (site #1 in the 7-site sweep)
// + GAN F005 parent-aware close.
//
// Symptom before the basename fix: clicking the drawer's Close button (or
// pressing Esc, or clicking the backdrop) called
// `navigate("/admin/dashboard")`. Under `<BrowserRouter basename="/admin">`,
// react-router auto-prepended the basename to navigate() targets — so the
// resulting URL was `/admin/admin/dashboard`, no route match, blank page.
//
// Under GAN F005's parent-aware overlay shape, we ALSO need close() to
// work when the drawer is mounted under the Policy Simulator parent route
// (not Dashboard). The fix is to navigate to `..` instead of a hard-coded
// `/dashboard` — relative navigation walks up to whichever parent mounted
// the drawer.
//
// We test the Close button's onClick. The Esc handler + backdrop call the
// same `close()` function, so they're covered by transitivity.
//
// We mock `useNavigate` to capture the path argument, and mock
// `useReceiptDetail` so the drawer renders without a fetch.

import { fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter, Route, Routes } from "react-router-dom";

const navigateSpy = vi.fn();

// Mock react-router-dom — keep MemoryRouter/Route/Routes/useParams/etc.
// real (so the route params resolve) but stub `useNavigate` with our spy.
vi.mock("react-router-dom", async () => {
  const actual =
    await vi.importActual<typeof import("react-router-dom")>(
      "react-router-dom",
    );
  return {
    ...actual,
    useNavigate: () => navigateSpy,
  };
});

// Mock the data hook — the drawer should render even without data; the
// header has a Close button regardless of the loading state.
vi.mock("~/hooks/useReceiptDetail", () => ({
  useReceiptDetail: () => ({
    data: null,
    isLoading: true,
    isError: false,
    error: null,
  }),
}));

// PayloadTab/VerifyTab/ExportEvidenceButton are children of the drawer
// body; we don't render them in the loading state, but stub them anyway
// so the import graph doesn't drag in a fetch on mount.
vi.mock("~/components/audit/PayloadTab", () => ({
  PayloadTab: () => null,
  isPredicateOnlyUri: () => false,
}));
vi.mock("~/components/audit/VerifyTab", () => ({ VerifyTab: () => null }));
vi.mock("~/components/audit/ExportEvidenceButton", () => ({
  ExportEvidenceButton: () => null,
}));
vi.mock("~/components/audit/ProofTab", () => ({ ProofTab: () => null }));

import ReceiptDetail from "~/pages/ReceiptDetail";

afterEach(() => {
  navigateSpy.mockReset();
});

describe("ReceiptDetail close()", () => {
  it("navigates to the parent route via `..` (parent-aware, no /admin prefix)", () => {
    render(
      <MemoryRouter
        basename="/admin"
        initialEntries={["/admin/dashboard/receipts/abc-123"]}
      >
        <Routes>
          <Route
            path="/dashboard/receipts/:run_id"
            element={<ReceiptDetail />}
          />
        </Routes>
      </MemoryRouter>,
    );

    const close = screen.getByRole("button", { name: /close drawer/i });
    fireEvent.click(close);

    expect(navigateSpy).toHaveBeenCalledTimes(1);
    const arg = navigateSpy.mock.calls[0]?.[0];
    expect(typeof arg).toBe("string");
    // `..` works regardless of which parent mounts the drawer (Dashboard
    // OR Policy Simulator). Per GAN F005 — a hard-coded `/dashboard`
    // would jump the auditor away from the simulator on close, contrary
    // to the brief's overlay mandate.
    expect(arg as string).toBe("..");
    // The basename-collision bug: navigate("/admin/dashboard") would have
    // round-tripped to /admin/admin/dashboard via the router.
    expect(arg as string).not.toMatch(/^\/admin\b/);
  });
});

describe("ReceiptDetail tab order (R2 redesign)", () => {
  it("renders the brief's tab order: IDENTITY · PREDICATE · PROOF · POLICY · PAYLOAD · VERIFY", () => {
    render(
      <MemoryRouter
        basename="/admin"
        initialEntries={["/admin/dashboard/receipts/abc-123"]}
      >
        <Routes>
          <Route
            path="/dashboard/receipts/:run_id"
            element={<ReceiptDetail />}
          />
        </Routes>
      </MemoryRouter>,
    );

    const tabs = screen.getAllByRole("tab");
    expect(tabs).toHaveLength(6);
    expect(tabs[0]).toHaveAttribute("data-testid", "tab-identity");
    expect(tabs[1]).toHaveAttribute("data-testid", "tab-predicate");
    expect(tabs[2]).toHaveAttribute("data-testid", "tab-proof");
    expect(tabs[3]).toHaveAttribute("data-testid", "tab-policy");
    expect(tabs[4]).toHaveAttribute("data-testid", "tab-payload");
    expect(tabs[5]).toHaveAttribute("data-testid", "tab-verify");
  });
});
