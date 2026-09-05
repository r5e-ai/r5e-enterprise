// Vitest unit test for the global TopBar.
//
// Asserts the brief's two contract points:
//   1. Renders user info from useAuth — role pill + principal subject.
//   2. Sign-out button hits the logout endpoint (POST) and then redirects
//      the browser to /admin/login (NOT /admin/login/start, which would
//      re-trigger SSO immediately — see issue #20).
//
// useAuth is mocked so the test doesn't need a QueryClientProvider or a
// running Gateway. window.location.assign is stubbed so we can assert the
// redirect target without actually navigating.

import { fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { TopBar } from "~/components/shared/TopBar";

// Mock useAuth to return a fixed authenticated state.
vi.mock("~/hooks/useAuth", () => ({
  useAuth: () => ({
    status: "authenticated",
    principal: "alice@corp",
    role: "platform_operator",
    tenantId: "tenant-1",
  }),
}));

describe("TopBar", () => {
  let assignSpy: ReturnType<typeof vi.fn>;
  const originalLocation = window.location;

  beforeEach(() => {
    assignSpy = vi.fn();
    // jsdom's `window.location.assign` property is non-configurable, so the
    // canonical workaround is to replace `window.location` wholesale with a
    // plain object that exposes only the surface our code touches.
    // (See https://github.com/jsdom/jsdom/issues/3492 for the long story.)
    delete (window as { location?: Location }).location;
    (window as { location: Pick<Location, "assign" | "pathname" | "search"> }).location = {
      assign: assignSpy,
      pathname: "/admin/dashboard",
      search: "",
    };
    // Mock fetch to record the logout POST.
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(new Response(null, { status: 200 })),
    );
  });

  afterEach(() => {
    (window as { location: Location }).location = originalLocation;
    vi.unstubAllGlobals();
    vi.clearAllMocks();
  });

  it("renders the role pill from useAuth (uppercase, snake replaced)", () => {
    render(<TopBar />);
    const pill = screen.getByTestId("topbar-role-pill");
    // Role `platform_operator` → "platform operator" (underscore replaced),
    // rendered uppercase via the `uppercase` Tailwind class.
    expect(pill).toHaveTextContent(/platform operator/i);
  });

  it("renders the principal subject from useAuth", () => {
    render(<TopBar />);
    expect(screen.getByTestId("topbar-principal")).toHaveTextContent(
      "alice@corp",
    );
  });

  it("renders the sign-out button", () => {
    render(<TopBar />);
    expect(screen.getByTestId("topbar-signout")).toBeInTheDocument();
  });

  it("renders pageContent and actions slots when provided", () => {
    render(
      <TopBar
        pageContent={<span data-testid="page-content">My page</span>}
        actions={<button data-testid="page-action">act</button>}
      />,
    );
    expect(screen.getByTestId("page-content")).toHaveTextContent("My page");
    expect(screen.getByTestId("page-action")).toBeInTheDocument();
  });

  it("clicking sign-out POSTs to the logout endpoint and redirects to /admin/login", async () => {
    render(<TopBar />);
    fireEvent.click(screen.getByTestId("topbar-signout"));
    // Wait for the async chain in handleSignOut to flush.
    await vi.waitFor(() => {
      expect(assignSpy).toHaveBeenCalledWith("/admin/login");
    });
    // Confirm the POST went through too.
    expect(globalThis.fetch).toHaveBeenCalledWith(
      "/admin/logout",
      expect.objectContaining({ method: "POST", credentials: "include" }),
    );
  });
});
