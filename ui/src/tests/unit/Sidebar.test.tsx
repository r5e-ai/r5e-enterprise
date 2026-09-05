// Vitest unit test for the global Sidebar.
//
// Asserts the brief's two contract points:
//   1. Renders three nav links — Receipts, Policy Simulator, Chat.
//   2. The link whose `to` matches the current location pathname is marked
//      active (highlighted via `aria-current="page"` from react-router's
//      NavLink).
//
// Sidebar has no external data dependencies — no useAuth, no fetch — so the
// test only needs a MemoryRouter wrapper.
//
// IMPORTANT: the production SPA mounts <BrowserRouter basename="/admin">
// (see App.tsx). The test wrapper MUST mirror that with `basename="/admin"`
// so basename-collision bugs (passing absolute `/admin/...` paths to NavLink
// `to`, which auto-prefixes the basename a second time → `/admin/admin/...`,
// no route match, blank page) are caught at unit-test time. The original
// !52 ship of this test omitted `basename` and that's why the Sidebar
// basename collision shipped to demo verification.

import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { MemoryRouter } from "react-router-dom";

import { Sidebar } from "~/components/shared/Sidebar";

function renderAt(initialPath: string) {
  // The MemoryRouter is configured with basename="/admin" to match the
  // production BrowserRouter. `initialEntries` are the FULL paths the
  // browser would see (including the `/admin` prefix); react-router strips
  // the basename internally before route matching.
  return render(
    <MemoryRouter basename="/admin" initialEntries={[initialPath]}>
      <Sidebar />
    </MemoryRouter>,
  );
}

describe("Sidebar", () => {
  it("renders the four top-level nav links (Receipts, Policy Simulator, MCP Registry, Chat)", () => {
    renderAt("/admin/dashboard");
    const nav = screen.getByTestId("sidebar-nav");
    // Use getByRole within the nav so we don't pick up unrelated <a> tags.
    expect(within(nav).getByRole("link", { name: /receipts/i })).toBeInTheDocument();
    expect(
      within(nav).getByRole("link", { name: /policy simulator/i }),
    ).toBeInTheDocument();
    expect(
      within(nav).getByRole("link", { name: /mcp registry/i }),
    ).toBeInTheDocument();
    expect(within(nav).getByRole("link", { name: /chat/i })).toBeInTheDocument();
  });

  it("highlights the MCP Registry link on /admin/mcp-registry", () => {
    renderAt("/admin/mcp-registry");
    const link = screen.getByTestId("sidebar-link-mcp-registry");
    expect(link).toHaveAttribute("aria-current", "page");
  });

  it("renders the workspace label", () => {
    renderAt("/admin/dashboard");
    const ws = screen.getByTestId("sidebar-workspace");
    // Post-F8 the inline "r5e enterprise" string is rendered through the
    // shared <Wordmark /> primitive (sparkle + r5e + ENTERPRISE eyebrow);
    // assert via the wordmark testid + its aria-label so the contract is
    // "Sidebar shows the brand wordmark", not "Sidebar contains the exact
    // literal text node".
    const wordmark = within(ws).getByTestId("wordmark");
    expect(wordmark).toBeInTheDocument();
    expect(wordmark).toHaveAttribute("aria-label", "r5e enterprise");
    expect(within(ws).getByText(/\/ audit/i)).toBeInTheDocument();
  });

  it("highlights the Receipts link on /admin/dashboard", () => {
    renderAt("/admin/dashboard");
    const link = screen.getByTestId("sidebar-link-receipts");
    expect(link).toHaveAttribute("aria-current", "page");
  });

  it("highlights the Receipts link when a receipt drawer is open (/admin/dashboard/receipts/<id>)", () => {
    renderAt("/admin/dashboard/receipts/abc-123");
    const link = screen.getByTestId("sidebar-link-receipts");
    expect(link).toHaveAttribute("aria-current", "page");
  });

  it("highlights the Policy Simulator link on /admin/policy-simulator", () => {
    renderAt("/admin/policy-simulator");
    const link = screen.getByTestId("sidebar-link-policy-simulator");
    expect(link).toHaveAttribute("aria-current", "page");
  });

  it("highlights the Policy Simulator link on /admin/policy-simulator/suggestions", () => {
    renderAt("/admin/policy-simulator/suggestions");
    const link = screen.getByTestId("sidebar-link-policy-simulator");
    expect(link).toHaveAttribute("aria-current", "page");
  });

  it("highlights the Chat link on /admin/chat", () => {
    renderAt("/admin/chat");
    const link = screen.getByTestId("sidebar-link-chat");
    expect(link).toHaveAttribute("aria-current", "page");
  });

  it("does NOT mark Policy Simulator as active when on Dashboard", () => {
    renderAt("/admin/dashboard");
    const link = screen.getByTestId("sidebar-link-policy-simulator");
    expect(link).not.toHaveAttribute("aria-current", "page");
  });

  // Regression test for the basename-collision bug shipped in MR !52
  // (Batch B). Sidebar passed `routes.dashboard` (absolute `/admin/dashboard`)
  // straight to NavLink's `to` prop. Under `<BrowserRouter basename="/admin">`,
  // NavLink auto-prepends the basename for outbound URLs, so the rendered
  // <a> href becomes `/admin/admin/dashboard` — no route match, blank page.
  // This test asserts the rendered href is the SINGLE-prefixed form. With
  // the bug present + the test wrapper now mounted under `basename="/admin"`,
  // this would have failed at unit-test time.
  it("renders nav link hrefs with a single /admin prefix (no double-prefix)", () => {
    renderAt("/admin/dashboard");
    expect(screen.getByTestId("sidebar-link-receipts")).toHaveAttribute(
      "href",
      "/admin/dashboard",
    );
    expect(screen.getByTestId("sidebar-link-policy-simulator")).toHaveAttribute(
      "href",
      "/admin/policy-simulator",
    );
    expect(screen.getByTestId("sidebar-link-chat")).toHaveAttribute(
      "href",
      "/admin/chat",
    );
  });
});
