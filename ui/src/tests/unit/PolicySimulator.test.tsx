// Vitest unit test for PolicySimulator's outbound `<Link>` targets —
// basename-collision regression coverage (sites #2, #3 in the 7-site sweep).
//
// Three render-time targets in the page that previously embedded absolute
// `/admin/...` paths and were therefore at risk of double-prefixing under
// `<BrowserRouter basename="/admin">`:
//
//   1. TopBar "Suggestions →" link (always rendered).
//   2. SuggestionsRedirect footer "Open suggestions" Link (rendered when
//      ?mode=suggestions).
//   3. SourceReceiptBanner "view full receipt →" Link (rendered when
//      ?mode=draft&run_id=xxx is in the URL).
//
// We mock every hook that touches the network so the component renders
// against an empty/idle state. `<MemoryRouter basename="/admin">` mirrors
// production; if any `<Link>` were still passing an absolute `/admin/...`
// path, react-router would render `href="/admin/admin/..."` and these
// tests would fail.

import { render, screen, within, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter, Route, Routes } from "react-router-dom";

// ----- Mocks ---------------------------------------------------------------

vi.mock("~/hooks/useAuth", () => ({
  useAuth: () => ({
    status: "authenticated",
    role: "platform_operator",
    principal: "operator-1",
    tenantId: "tenant-a",
  }),
}));

vi.mock("~/hooks/useBlastRadius", () => ({
  useBlastRadius: () => ({
    result: null,
    isPending: false,
    error: null,
    run: () => {},
  }),
}));

// Module-level mutable references so each `it` block can dial in what the
// mocked hooks should return. Vitest module mocks are per-file singletons,
// so we reach into these closures from within the factory below.
//
// Default state: nothing seeded (matches the prior behaviour). Individual
// tests call `setNextDraft` / `setNextSuggestion` to feed values into the
// page's prefill effects (F003 — fix-pass-2).
type Draft = {
  id: string;
  cedar_source?: string | null;
  scope_metadata?: unknown;
  condition_metadata?: unknown;
};
type Suggestion = {
  id: string;
  proposed_cedar: string;
  source: "heuristic" | "llm";
  confidence: number;
  pattern_summary: string;
  status: "active";
  generated_at: string;
};

let nextDraft: Draft | undefined = undefined;
let nextSuggestion: Suggestion | undefined = undefined;
const createDraftSpy = vi.fn();

function setNextDraft(d: Draft | undefined): void {
  nextDraft = d;
}
function setNextSuggestion(s: Suggestion | undefined): void {
  nextSuggestion = s;
}
function resetSeedingState(): void {
  nextDraft = undefined;
  nextSuggestion = undefined;
  createDraftSpy.mockReset();
}

vi.mock("~/hooks/usePolicyDrafts", () => ({
  useCreatePolicyDraft: () => ({
    isPending: false,
    error: null,
    mutate: createDraftSpy,
  }),
  useDraftFromReceipt: () => ({
    isPending: false,
    isError: false,
    error: null,
    mutate: () => {},
  }),
  usePolicyDraft: (id?: string) => ({
    data: id && nextDraft && nextDraft.id === id ? nextDraft : undefined,
    isLoading: false,
    isError: false,
    error: null,
  }),
  useUpdatePolicyDraft: () => ({
    isPending: false,
    error: null,
    mutate: () => {},
  }),
}));

// usePolicySuggestion (singular) feeds the SIMULATE FIRST sandbox path
// (F001 fix in fix-pass-2): the simulator fetches the suggestion when
// `?suggestion=&sandbox=1` is on the URL and seeds the editor from
// `suggestion.proposed_cedar` without creating a saved draft.
vi.mock("~/hooks/usePolicySuggestions", () => ({
  usePolicySuggestion: (id?: string) => ({
    data:
      id && nextSuggestion && nextSuggestion.id === id ? nextSuggestion : undefined,
    isLoading: false,
    isError: false,
    error: null,
  }),
}));

vi.mock("~/hooks/useReceiptDetail", () => ({
  useReceiptDetail: () => ({
    data: null,
    isLoading: false,
    isError: false,
    error: null,
  }),
}));

// Heavy children that aren't part of the link surface — stub them out.
// CedarEditor mock surfaces the `value` prop via a data-attribute so the
// suggestions-handoff tests below can assert what got seeded into the
// editor without dragging Monaco into the test harness (F003 fix-pass-2).
vi.mock("~/components/policy/CedarEditor", () => ({
  default: ({ value }: { value: string }) => (
    <div data-testid="cedar-editor-stub" data-cedar-value={value} />
  ),
}));
vi.mock("~/components/policy/CedarDiffEditor", () => ({
  default: () => null,
}));
vi.mock("~/components/policy/BlastRadiusPanel", () => ({
  BlastRadiusPanel: () => null,
}));
vi.mock("~/components/policy/ScopePicker", () => ({
  ScopePicker: () => null,
}));
vi.mock("~/components/policy/ConditionBuilder", () => ({
  ConditionBuilder: () => null,
}));

import PolicySimulator from "~/pages/PolicySimulator";

// Mount under a real `policy-simulator` route so:
//   1. Relative `<Link to="receipts/...">` paths resolve against the
//      simulator parent (per GAN F005 receipt-drawer overlay).
//   2. The `<Outlet />` slot mounts a child route in production. We wire a
//      no-op child here so `useOutlet()` reflects the matching state when
//      the test path includes `/receipts/...`.
function renderAt(initialPath: string) {
  return render(
    <MemoryRouter basename="/admin" initialEntries={[initialPath]}>
      <Routes>
        <Route path="/policy-simulator" element={<PolicySimulator />}>
          <Route path="receipts/:run_id" element={<div data-testid="receipt-drawer-child" />} />
        </Route>
      </Routes>
    </MemoryRouter>,
  );
}

describe("PolicySimulator outbound Link targets", () => {
  it("TopBar 'Suggestions →' link has a single /admin prefix", () => {
    renderAt("/admin/policy-simulator");
    const actions = screen.getByTestId("topbar-actions");
    const link = within(actions).getByRole("link", {
      name: /suggestions/i,
    });
    expect(link).toHaveAttribute(
      "href",
      "/admin/policy-simulator/suggestions",
    );
    expect(link.getAttribute("href")).not.toMatch(/^\/admin\/admin/);
  });

  it("'Open suggestions' footer link has a single /admin prefix when ?mode=suggestions", () => {
    renderAt("/admin/policy-simulator?mode=suggestions");
    const link = screen.getByRole("link", { name: /open suggestions/i });
    expect(link).toHaveAttribute(
      "href",
      "/admin/policy-simulator/suggestions",
    );
    expect(link.getAttribute("href")).not.toMatch(/^\/admin\/admin/);
  });

  it("DraftFromReceiptBanner 'view full receipt' link nests under the simulator route when ?mode=draft&run_id=xxx", () => {
    // F4 redesign — the source-receipt banner was extracted into the
    // standalone <DraftFromReceiptBanner /> component (testid:
    // `draft-from-receipt-banner`).
    //
    // Per GAN F005 — the link is RELATIVE so the receipt drawer overlays
    // the simulator (`/admin/policy-simulator/receipts/<id>`) instead
    // of swapping to Dashboard. The previous absolute
    // `/admin/dashboard/receipts/<id>` would navigate away from the
    // simulator, contrary to the brief's "doesn't navigate away" mandate.
    renderAt("/admin/policy-simulator?mode=draft&run_id=run-007");
    const banner = screen.getByTestId("draft-from-receipt-banner");
    const link = within(banner).getByRole("link", {
      name: /view full receipt/i,
    });
    expect(link).toHaveAttribute(
      "href",
      "/admin/policy-simulator/receipts/run-007",
    );
    expect(link.getAttribute("href")).not.toMatch(/^\/admin\/admin/);
  });
});

// Brief 05 cross-MR contract — when the suggestions page navigates here
// with `?mode=draft&suggestion=<id>&draft_id=<id>` (ADOPT) or
// `?mode=draft&suggestion=<id>&sandbox=1` (SIMULATE FIRST), the simulator
// must read the params and render an attribution banner. Pre-fix the
// suggestions page emitted these params and the simulator silently
// dropped them, leaving the operator on the default Cedar template.
describe("PolicySimulator suggestions handoff (brief 05)", () => {
  beforeEach(() => {
    resetSeedingState();
  });

  it("renders the attribution banner with the suggestion id when ?mode=draft&suggestion=<id>&draft_id=<id>", () => {
    renderAt(
      "/admin/policy-simulator?mode=draft&suggestion=sug-007&draft_id=draft-42",
    );
    const banner = screen.getByTestId("suggestion-attribution-banner");
    expect(banner.textContent ?? "").toContain("sug-007");
    expect(banner.textContent ?? "").toMatch(/drafting from suggestion/i);
    // back-to-suggestions link is single-prefixed.
    const back = within(banner).getByRole("link", {
      name: /back to suggestions/i,
    });
    expect(back).toHaveAttribute(
      "href",
      "/admin/policy-simulator/suggestions",
    );
    expect(back.getAttribute("href")).not.toMatch(/^\/admin\/admin/);
  });

  it("uses 'Sandbox simulate' label when ?sandbox=1", () => {
    renderAt(
      "/admin/policy-simulator?mode=draft&suggestion=sug-009&sandbox=1",
    );
    const banner = screen.getByTestId("suggestion-attribution-banner");
    expect(banner.textContent ?? "").toMatch(/sandbox simulate from suggestion/i);
    expect(banner.textContent ?? "").toContain("sug-009");
  });

  it("does not render the attribution banner when ?suggestion is absent", () => {
    renderAt("/admin/policy-simulator?mode=draft&run_id=run-007");
    expect(screen.queryByTestId("suggestion-attribution-banner")).toBeNull();
  });

  // F003 (fix-pass-2) — pin the actual seeding behaviour.
  //
  // Pre-fix-pass-2 the only assertions in this describe block were on the
  // attribution banner text; the `usePolicyDraft` mock returned
  // `{ data: undefined }` for every test, so the `useEffect` that seeds
  // `cedarSource` from the saved draft never ran. F001 (sandbox path
  // doesn't seed) and the analogous ADOPT path were CI-invisible. These
  // two tests close the gap by feeding values through the mocks and
  // asserting the seeded `cedarSource` reaches the editor stub via its
  // `value` prop (see the `~/components/policy/CedarEditor` mock above).

  it("ADOPT path: seeds the Cedar editor from the saved draft when ?suggestion=&draft_id= is set", async () => {
    setNextDraft({
      id: "draft-42",
      cedar_source: "// adopt path seeded\nforbid(principal, action, resource);",
    });
    renderAt(
      "/admin/policy-simulator?mode=draft&suggestion=sug-007&draft_id=draft-42",
    );
    const editor = await screen.findByTestId("cedar-editor-stub");
    await waitFor(() => {
      expect(editor.getAttribute("data-cedar-value") ?? "").toContain(
        "// adopt path seeded",
      );
    });
  });

  it("SANDBOX path: seeds the Cedar editor from the suggestion when ?suggestion=&sandbox=1 is set, without creating a saved draft", async () => {
    setNextSuggestion({
      id: "sug-009",
      proposed_cedar:
        "// sandbox path seeded\nforbid(principal, action == Recurse::Action::\"BashExec\", resource);",
      source: "heuristic",
      confidence: 88,
      pattern_summary: "sandbox seed",
      status: "active",
      generated_at: "2026-04-30T10:00:00Z",
    });
    renderAt(
      "/admin/policy-simulator?mode=draft&suggestion=sug-009&sandbox=1",
    );
    const editor = await screen.findByTestId("cedar-editor-stub");
    await waitFor(() => {
      expect(editor.getAttribute("data-cedar-value") ?? "").toContain(
        "// sandbox path seeded",
      );
    });
    // Sandbox is the no-saved-draft path. The page must not call
    // `useCreatePolicyDraft().mutate(...)` just to render. (A dry-run
    // would mint a transient draft via `ensureDraftThen`, but the
    // operator hasn't run one in this test.)
    expect(createDraftSpy).not.toHaveBeenCalled();
    // And the attribution banner advertises the sandbox copy.
    const banner = screen.getByTestId("suggestion-attribution-banner");
    expect(banner.textContent ?? "").toMatch(/sandbox simulate from suggestion/i);
    expect(banner.textContent ?? "").toContain("sug-009");
  });
});

// B6 regression — the Cedar editor must reach interactive state, not
// linger forever in the Suspense / @monaco-editor/react "Loading..."
// fallback. The bug was at the loader-config layer (jsDelivr CDN blocked
// by CSP), but the symptom was a frozen editor pane on
// /admin/policy-simulator. This test pins the Suspense-resolution
// contract: once the lazy CedarEditor module is available, the editor
// container renders and the skeleton is gone.
//
// Mocking strategy: the top-of-file mock for ~/components/policy/CedarEditor
// returns `() => null`, which behaves as a same-tick-resolved lazy import.
// We assert the page does NOT contain a stuck "Loading..." node and DOES
// expose its interactive surface (the SIMULATE tab + the SAVE-status
// indicator that lives in the editor's section header).
describe("PolicySimulator B6 regression — editor reaches interactive state", () => {
  it("does not show a stuck 'Loading...' fallback on the simulate tab", async () => {
    renderAt("/admin/policy-simulator");

    // Wait for the Suspense boundary to resolve (microtask + first paint).
    // findByTestId polls for the element so the Suspense fallback has time
    // to swap out before we assert.
    await screen.findByTestId("policy-simulator");
    await screen.findByTestId("save-status-unsaved");

    // The default @monaco-editor/react fallback string was the user-visible
    // symptom of B6. Stamping a regression test here so reverting the
    // loader-config wiring (or accidentally re-introducing a CDN-only
    // loader path) shows up as a unit-test failure rather than a manual
    // browser-smoke regression.
    const stuck = screen.queryByText(/^Loading\.\.\.$/);
    expect(stuck).toBeNull();

    // The custom EditorSkeleton (which IS valid during the brief Suspense
    // window before the lazy chunk arrives) must also be gone after
    // resolution.
    expect(screen.queryByTestId("editor-skeleton")).toBeNull();

    // The ModeTabs surface must be present — confirms we reached the
    // interactive shell, not a permanent fallback.
    expect(screen.getByTestId("mode-tab-simulate")).toBeInTheDocument();
  });
});
