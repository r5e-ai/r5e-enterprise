// Vitest unit test for PayloadTab — issue #60 (predicate-only UX).
//
// Two paths under test:
//   1. Pre-fetch: when `payloadUri` starts with a predicate-only scheme
//      (`recurse://import/` or `recurse://system/predicate-only/`), the
//      Fetch button MUST NOT render and the friendly explanation banner
//      MUST appear instead. This is the demo-blocking case (auditor opens
//      an imported tool_call receipt → Payload tab → no broken-looking
//      "Internal error" banner).
//   2. Real-payload: when `payloadUri` is `s3://...` or null, the Fetch
//      button + attested-access advisory render unchanged.

import type { ReactNode } from "react";
import { fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

// Stub useAuth — PayloadTab uses it for the `Fetching as <principal>`
// label; for the predicate-only path the advisory is suppressed entirely
// so this is mostly relevant to the s3:// path.
vi.mock("~/hooks/useAuth", () => ({
  useAuth: () => ({ status: "authenticated", principal: "alice@corp" }),
}));

import { PayloadTab, isPredicateOnlyUri } from "~/components/audit/PayloadTab";

function withClient(node: ReactNode): JSX.Element {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return <QueryClientProvider client={client}>{node}</QueryClientProvider>;
}

describe("isPredicateOnlyUri", () => {
  it("recognizes the imported scheme", () => {
    expect(
      isPredicateOnlyUri("recurse://import/claude_code/sess/abc-123"),
    ).toBe(true);
  });

  it("recognizes the system-event scheme", () => {
    expect(
      isPredicateOnlyUri("recurse://system/predicate-only/run-456"),
    ).toBe(true);
  });

  it("rejects s3:// payload URIs", () => {
    expect(isPredicateOnlyUri("s3://bucket/path/run.json")).toBe(false);
  });

  it("rejects null / undefined / empty", () => {
    expect(isPredicateOnlyUri(null)).toBe(false);
    expect(isPredicateOnlyUri(undefined)).toBe(false);
    expect(isPredicateOnlyUri("")).toBe(false);
  });

  it("rejects unrelated recurse:// schemes", () => {
    expect(isPredicateOnlyUri("recurse://system/metrics/abc")).toBe(false);
  });
});

describe("PayloadTab predicate-only rendering (issue #60)", () => {
  beforeEach(() => {
    // Spy on fetch so we can confirm NO request goes out for the
    // predicate-only path (the button should never appear, so the user
    // can never trigger one).
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response("{}", { status: 200 }),
    );
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("imported receipts: hides Fetch button, renders friendly explanation, echoes URI", () => {
    render(
      withClient(
        <PayloadTab
          runId="run-imported-1"
          payloadUri="recurse://import/claude_code/sess/run-imported-1"
        />,
      ),
    );

    // Friendly explanation banner present.
    const banner = screen.getByTestId("payload-predicate-only");
    expect(banner).toBeTruthy();
    expect(banner.textContent).toContain("Predicate-only receipt");
    expect(banner.textContent).toContain(
      "signed_predicate IS the full audit content",
    );

    // payload_uri echoed for auditor traceability.
    const uriEl = screen.getByTestId("payload-predicate-only-uri");
    expect(uriEl.textContent).toContain(
      "recurse://import/claude_code/sess/run-imported-1",
    );

    // Fetch button NOT in the DOM.
    expect(screen.queryByTestId("payload-fetch-button")).toBeNull();
    // The "this access is itself attested" advisory should also be absent
    // for predicate-only — no access is occurring (nothing to attest).
    expect(
      screen.queryByTestId("payload-attested-access-notice"),
    ).toBeNull();

    // Confirm no network request was made on render.
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  it("system-event receipts: also hides Fetch button (existing 200 path still works pre-fetch)", () => {
    render(
      withClient(
        <PayloadTab
          runId="run-sys-1"
          payloadUri="recurse://system/predicate-only/run-sys-1"
        />,
      ),
    );

    expect(screen.getByTestId("payload-predicate-only")).toBeTruthy();
    expect(screen.queryByTestId("payload-fetch-button")).toBeNull();
  });

  it("real-payload receipts (s3://): renders Fetch button + attested-access advisory", () => {
    render(
      withClient(
        <PayloadTab
          runId="run-real-1"
          payloadUri="s3://bucket/tenants/foo/runs/run-real-1.json"
        />,
      ),
    );

    expect(screen.getByTestId("payload-fetch-button")).toBeTruthy();
    expect(screen.getByTestId("payload-attested-access-notice")).toBeTruthy();
    expect(screen.queryByTestId("payload-predicate-only")).toBeNull();
  });

  it("missing payloadUri prop: defaults to fetch UI (pre-issue-#60 behavior preserved)", () => {
    render(withClient(<PayloadTab runId="run-unknown" />));

    expect(screen.getByTestId("payload-fetch-button")).toBeTruthy();
    expect(screen.queryByTestId("payload-predicate-only")).toBeNull();
  });

  it("manual fetch returning 422 ERR_PREDICATE_ONLY: renders friendly banner, not red error", async () => {
    // Simulate a user-triggered fetch (no `payloadUri` was passed, so the
    // pre-fetch conditional did not catch it) where the backend returns
    // 422 ERR_PREDICATE_ONLY. The fetch error path must render the same
    // friendly explanation banner the pre-fetch conditional would have.
    vi.mocked(globalThis.fetch).mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          error: "ERR_PREDICATE_ONLY",
          error_description:
            "Receipt is predicate-only (imported source artifact). The signed_predicate IS the full audit content; no separate payload bytes were stored. payload_uri=recurse://import/claude_code/sess/x",
          correlation_id: "01TEST",
          attested_run_id: null,
        }),
        { status: 422, headers: { "Content-Type": "application/json" } },
      ),
    );

    render(withClient(<PayloadTab runId="run-422" />));

    // Click Fetch.
    fireEvent.click(screen.getByTestId("payload-fetch-button"));

    // Wait for the mutation to settle by polling for the friendly banner.
    await screen.findByTestId("payload-predicate-only");

    // Generic red error banner must NOT appear (the friendly path took
    // precedence).
    expect(screen.queryByRole("alert")).toBeNull();
  });
});
