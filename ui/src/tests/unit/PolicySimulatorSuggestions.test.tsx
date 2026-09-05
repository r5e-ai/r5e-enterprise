// Vitest unit test for PolicySimulatorSuggestions' outbound nav targets —
// basename-collision regression coverage (sites #4 + #5 in the 7-site sweep).
//
// Three navigation surfaces in this page were previously at risk of
// double-prefixing under `<BrowserRouter basename="/admin">`:
//
//   1. The auditor-fallback "← Back to dashboard" Link (when an auditor
//      hits this operator-only page).
//   2. The TopBar "← Simulator" Link (always rendered for operators).
//   3. `navigate(...)` after a successful adopt-suggestion mutation,
//      pointing the operator at /admin/policy-simulator?mode=draft&draft_id=...
//
// `<MemoryRouter basename="/admin">` mirrors production. With the bug
// present, react-router would render `href="/admin/admin/..."` for the
// Links and `navigate("/admin/policy-simulator?...")` would round-trip to
// `/admin/admin/policy-simulator?...`. These tests assert single-prefix.

import { fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter } from "react-router-dom";

// Mock useNavigate so we can capture the post-adopt redirect target.
const navigateSpy = vi.fn();
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

// Default: pretend an operator is signed in. Per-test we'll override to
// auditor for the auth-gated branch. The role is widened to the union
// of valid roles so per-test overrides don't fight TS narrowing.
type AuthResult = {
  status: "authenticated";
  role: "platform_operator" | "tenant_auditor";
  principal: string;
  tenantId: string;
};
const authMock: { current: () => AuthResult } = {
  current: () => ({
    status: "authenticated",
    role: "platform_operator",
    principal: "operator-1",
    tenantId: "tenant-a",
  }),
};
vi.mock("~/hooks/useAuth", () => ({
  useAuth: () => authMock.current(),
}));

// Suggestion-list hook returns an empty queue so the page renders the
// EmptyState; refresh + adopt + dismiss are stubs we reach into per test.
const adoptMock = vi.fn();
vi.mock("~/hooks/usePolicySuggestions", async () => {
  const actual = await vi.importActual<
    typeof import("~/hooks/usePolicySuggestions")
  >("~/hooks/usePolicySuggestions");
  return {
    ...actual,
    usePolicySuggestionsList: () => ({
      data: { suggestions: [], next_cursor: null },
      isLoading: false,
      isError: false,
      error: null,
    }),
    useAdoptPolicySuggestion: () => ({
      isPending: false,
      error: null,
      variables: undefined,
      mutate: adoptMock,
    }),
    useDismissPolicySuggestion: () => ({
      isPending: false,
      error: null,
      variables: undefined,
      mutate: () => {},
    }),
    useRefreshPolicySuggestions: () => ({
      isPending: false,
      error: null,
      mutate: () => {},
    }),
  };
});

import PolicySimulatorSuggestions from "~/pages/PolicySimulatorSuggestions";

function renderPage() {
  return render(
    <MemoryRouter
      basename="/admin"
      initialEntries={["/admin/policy-simulator/suggestions"]}
    >
      <PolicySimulatorSuggestions />
    </MemoryRouter>,
  );
}

afterEach(() => {
  navigateSpy.mockReset();
  adoptMock.mockReset();
  authMock.current = () => ({
    status: "authenticated",
    role: "platform_operator",
    principal: "operator-1",
    tenantId: "tenant-a",
  });
});

// --- latestGeneratedAt -----------------------------------------------------

import { latestGeneratedAt } from "~/lib/policy_suggestions";
import type { PolicySuggestion } from "~/hooks/usePolicySuggestions";

function mkRow(
  overrides: Partial<PolicySuggestion> & { confidence: number; generated_at: string },
): PolicySuggestion {
  return {
    id: "x",
    source: "heuristic",
    pattern_summary: "p",
    proposed_cedar: "permit(...);",
    blast_radius_snapshot: null,
    status: "active",
    ...overrides,
  } as PolicySuggestion;
}

describe("latestGeneratedAt", () => {
  it("picks the most-recent timestamp regardless of confidence ordering", () => {
    // Pre-fix the page read sorted[0].generated_at, where the sort order
    // is confidence DESC then time DESC. So a stale high-confidence row
    // would hide a fresh low-confidence one. The helper must NOT defer
    // to confidence.
    const rows = [
      mkRow({
        id: "a",
        confidence: 95,
        generated_at: "2026-04-01T00:00:00Z",
      }),
      mkRow({
        id: "b",
        confidence: 60,
        generated_at: "2026-04-30T12:00:00Z",
      }),
    ];
    expect(latestGeneratedAt(rows)).toBe("2026-04-30T12:00:00Z");
  });

  it("returns null on empty input", () => {
    expect(latestGeneratedAt([])).toBeNull();
  });

  it("ignores rows with un-parseable timestamps", () => {
    const rows = [
      mkRow({ id: "a", confidence: 95, generated_at: "not-a-date" }),
      mkRow({ id: "b", confidence: 70, generated_at: "2026-04-30T00:00:00Z" }),
    ];
    expect(latestGeneratedAt(rows)).toBe("2026-04-30T00:00:00Z");
  });
});

describe("PolicySimulatorSuggestions outbound nav targets", () => {
  it("auditor's '← Back to dashboard' Link has a single /admin prefix", () => {
    authMock.current = () => ({
      status: "authenticated",
      role: "tenant_auditor",
      principal: "auditor-1",
      tenantId: "tenant-a",
    });
    renderPage();
    const card = screen.getByTestId("suggestions-forbidden");
    const link = within(card).getByRole("link", {
      name: /back to dashboard/i,
    });
    expect(link).toHaveAttribute("href", "/admin/dashboard");
    expect(link.getAttribute("href")).not.toMatch(/^\/admin\/admin/);
  });

  it("operator's TopBar '← Simulator' Link has a single /admin prefix", () => {
    renderPage();
    const link = screen.getByRole("link", { name: /simulator/i });
    expect(link).toHaveAttribute("href", "/admin/policy-simulator");
    expect(link.getAttribute("href")).not.toMatch(/^\/admin\/admin/);
  });

  it("post-adopt navigate() target is basename-stripped (no /admin prefix)", async () => {
    // Wire the adopt mock to invoke its onSuccess handler synchronously
    // so we can observe the navigate call without spinning up TanStack.
    adoptMock.mockImplementation(
      (
        _vars: { id: string },
        opts?: { onSuccess?: (resp: { draft_id: string }) => void },
      ) => {
        opts?.onSuccess?.({ draft_id: "draft-42" });
      },
    );

    // Render with a single suggestion so the Adopt button exists. We
    // override the mock for this specific test by re-mocking via the
    // same module reference.
    const mod = await import("~/hooks/usePolicySuggestions");
    vi.spyOn(mod, "usePolicySuggestionsList").mockReturnValue({
      data: {
        suggestions: [
          {
            id: "sug-001",
            source: "heuristic",
            confidence: 95,
            pattern_summary: "narrow scope",
            proposed_cedar: "permit(...);",
            blast_radius_snapshot: null,
            status: "active",
            generated_at: "2026-04-30T10:00:00Z",
          },
        ],
        next_cursor: null,
      },
      isLoading: false,
      isError: false,
      error: null,
      // The hook return type is wide; cast through unknown to satisfy TS
      // without depending on the full UseQueryResult shape in tests.
    } as unknown as ReturnType<typeof mod.usePolicySuggestionsList>);

    renderPage();
    const adoptBtn = await screen.findByTestId("suggestion-adopt");
    fireEvent.click(adoptBtn);

    expect(adoptMock).toHaveBeenCalledTimes(1);
    expect(navigateSpy).toHaveBeenCalledTimes(1);
    const arg = navigateSpy.mock.calls[0]?.[0] as string;
    expect(typeof arg).toBe("string");
    // Brief 05: navigate to `?mode=draft&suggestion=<id>&draft_id=<id>`
    // — the `&suggestion=` param is the new contract so the simulator
    // can render a "drafting from suggestion" banner; the `&draft_id=`
    // param is the existing path that picks up the saved draft.
    expect(arg).toBe(
      "/policy-simulator?mode=draft&suggestion=sug-001&draft_id=draft-42",
    );
    // The basename-collision bug: navigate("/admin/policy-simulator?...")
    // would round-trip through basename to /admin/admin/policy-simulator?... .
    expect(arg).not.toMatch(/^\/admin\b/);
  });
});
