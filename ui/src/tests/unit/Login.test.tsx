// Vitest unit test for the F8 Login redesign.
//
// Covers the brief's contract points (`design/briefs/08-login.md`):
//   1. Renders the centered card with Wordmark + "Audit Console" title +
//      "for AI agents" subtitle.
//   2. The Sign-in CTA is an <a href> pointing at the Gateway's
//      /admin/login/start endpoint with a `return_to` query param —
//      defaults to /admin/dashboard, but respects an inbound `?return_to=`
//      when present.
//   3. Clicking the CTA flips the button into a "Redirecting…" loading
//      state. Modifier-clicks (cmd/ctrl) DO NOT flip the loading state
//      so users can open the SSO link in a new tab.
//   4. When the URL carries `?error=...`, an error banner renders above
//      the CTA and the CTA label switches from "Sign in" to "Try again".
//   5. The footer renders the version + workspace + privacy links.
//
// Login uses `useLocation()` to read the search string (so it re-renders
// when the IdP redirects back with `?error=...` even within the same SPA
// session). The test wrapper therefore mounts a `MemoryRouter` configured
// with the production basename so basename-collision bugs (passing
// absolute `/admin/...` paths to NavLink/anchor `to` props) would surface
// here too, mirroring the Sidebar test.

import { fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter } from "react-router-dom";

import Login from "~/pages/Login";

function renderWithSearch(search: string): ReturnType<typeof render> {
  // MemoryRouter takes the FULL initial path (including the basename
  // prefix); react-router strips the basename internally before route
  // matching. A plain `/admin/login?...` mirrors what the Gateway redirects
  // the browser to after a failed IdP round-trip.
  return render(
    <MemoryRouter
      basename="/admin"
      initialEntries={[`/admin/login${search}`]}
    >
      <Login />
    </MemoryRouter>,
  );
}

describe("Login (F8)", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("renders the wordmark, title, subtitle, and SSO button", () => {
    renderWithSearch("");

    expect(screen.getByTestId("wordmark")).toBeInTheDocument();
    expect(
      screen.getByRole("heading", { level: 1, name: /audit console/i }),
    ).toBeInTheDocument();
    expect(screen.getByText(/for ai agents/i)).toBeInTheDocument();
    const cta = screen.getByTestId("login-sso-button");
    expect(cta).toHaveTextContent(/sign in/i);
    expect(cta.getAttribute("href")).toContain("/admin/login/start?return_to=");
  });

  it("encodes the dashboard path as the default return_to", () => {
    renderWithSearch("");
    const cta = screen.getByTestId("login-sso-button");
    expect(cta.getAttribute("href")).toBe(
      `/admin/login/start?return_to=${encodeURIComponent("/admin/dashboard")}`,
    );
  });

  it("respects an inbound ?return_to= query param", () => {
    renderWithSearch("?return_to=%2Fadmin%2Fpolicy-simulator%2Fsuggestions");
    const cta = screen.getByTestId("login-sso-button");
    expect(cta.getAttribute("href")).toBe(
      `/admin/login/start?return_to=${encodeURIComponent("/admin/policy-simulator/suggestions")}`,
    );
  });

  it("flips into the redirecting state on left-click", () => {
    renderWithSearch("");
    const cta = screen.getByTestId("login-sso-button");
    fireEvent.click(cta, { button: 0 });
    expect(cta).toHaveTextContent(/redirecting/i);
    expect(cta).toHaveAttribute("aria-disabled", "true");
  });

  it("does NOT flip loading on a cmd/ctrl click (allow open-in-new-tab)", () => {
    renderWithSearch("");
    const cta = screen.getByTestId("login-sso-button");
    fireEvent.click(cta, { button: 0, metaKey: true });
    expect(cta).toHaveTextContent(/sign in/i);
    expect(cta).not.toHaveAttribute("aria-disabled", "true");
  });

  it("renders the error banner when ?error= is present", () => {
    renderWithSearch(
      "?error=oauth_invalid_grant&error_description=The+code+expired",
    );

    const banner = screen.getByTestId("login-error");
    expect(banner).toBeInTheDocument();
    expect(banner).toHaveTextContent(/sign-in failed/i);
    expect(banner).toHaveTextContent(/the code expired/i);

    // The CTA label switches from "Sign in" to "Try again" when the error
    // banner is showing.
    expect(screen.getByTestId("login-sso-button")).toHaveTextContent(
      /try again/i,
    );
  });

  it("renders only the error code when no description is supplied", () => {
    renderWithSearch("?error=server_error");
    const banner = screen.getByTestId("login-error");
    expect(banner).toHaveTextContent(/server_error/i);
  });

  it("renders the footer with version + workspace breadcrumbs", () => {
    renderWithSearch("");
    const footer = screen.getByTestId("login-footer");
    expect(footer).toHaveTextContent(/r5e-enterprise/i);
    expect(footer).toHaveTextContent(/audit-dev/i);
    expect(footer).toHaveTextContent(/privacy/i);
    // Version is rendered in its own pill so we can assert on the v-prefix.
    expect(screen.getByTestId("login-version").textContent).toMatch(/^v/);
  });
});
