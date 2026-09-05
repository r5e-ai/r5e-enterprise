// EventInspector — F10 right-side panel.
//
// Asserts:
//   - Empty state when no event is selected.
//   - Selected event renders RECEIPT DATA + SEMANTIC ARGUMENTS sections.
//   - Related events list each fire onSelectRelated when clicked.
//   - Bottom CTAs render (Draft Policy Rule + Export Receipt).

import { render, screen, fireEvent } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { describe, expect, it, vi } from "vitest";
import { MemoryRouter } from "react-router-dom";

import { EventInspector } from "~/components/timeline/EventInspector";
import type { TimelineEvent, RelatedEvent } from "~/lib/timeline";

function ev(overrides: Partial<TimelineEvent> = {}): TimelineEvent {
  return {
    run_id: "r-1",
    timestamp: "2026-05-01T03:00:00Z",
    ts_ms: Date.parse("2026-05-01T03:00:00Z"),
    category: "subprocess_exec",
    display_summary: "Bash: ls",
    policy_decision: "allow",
    verification_level: "global_inclusion_verified",
    session_id: "s1",
    correlation_id: null,
    event_kind: "tool_call",
    tags: { semantic_args: { verb: "ls", writes: false } },
    principal_subject: "alice",
    principal_kind: "obo_human",
    ...overrides,
  };
}

function rel(overrides: Partial<RelatedEvent> = {}): RelatedEvent {
  return {
    ...ev(),
    relation: "same_correlation",
    ...overrides,
  };
}

function withProviders(ui: JSX.Element): JSX.Element {
  // ExportEvidenceButton uses TanStack Query; the inspector is mounted
  // under MemoryRouter for navigate() drills. `initialEntries` must start
  // with the basename — same wrapping convention as the production
  // BrowserRouter mount in App.tsx.
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return (
    <QueryClientProvider client={qc}>
      <MemoryRouter basename="/admin" initialEntries={["/admin/timeline"]}>
        {ui}
      </MemoryRouter>
    </QueryClientProvider>
  );
}

describe("EventInspector", () => {
  it("renders empty state when no event selected", () => {
    render(
      withProviders(
        <EventInspector
          selected={null}
          related={[]}
          onSelectRelated={() => undefined}
        />,
      ),
    );
    expect(screen.getByTestId("event-inspector-empty")).toBeInTheDocument();
  });

  it("renders RECEIPT DATA + SEMANTIC ARGUMENTS for a selected event", () => {
    render(
      withProviders(
        <EventInspector
          selected={ev({
            run_id: "selected-run",
            principal_subject: "alice",
          })}
          related={[]}
          onSelectRelated={() => undefined}
        />,
      ),
    );
    const inspector = screen.getByTestId("event-inspector");
    expect(inspector.dataset.runId).toBe("selected-run");
    expect(screen.getByTestId("receipt-data-section")).toHaveTextContent("alice");
    expect(screen.getByTestId("semantic-arguments-section")).toHaveTextContent(/verb/);
  });

  it("renders the related events list and triggers onSelectRelated when clicked", () => {
    const onSelect = vi.fn();
    const related = [
      rel({ run_id: "rel-a", display_summary: "Bash: git status" }),
      rel({ run_id: "rel-b", display_summary: "Bash: ls /etc" }),
    ];
    render(
      withProviders(
        <EventInspector
          selected={ev({ run_id: "main" })}
          related={related}
          onSelectRelated={onSelect}
        />,
      ),
    );
    const rows = screen.getAllByTestId("related-event-row");
    expect(rows).toHaveLength(2);
    fireEvent.click(rows[0]!);
    expect(onSelect).toHaveBeenCalledWith("rel-a");
  });

  it("F007: related-event row renders event_kind (not category) for non-deny events", () => {
    // Brief 10-session-trace.md:140 — "Each entry: timestamp +
    // event_kind chip + truncated display_summary + decision indicator."
    // Pre-fix, the row used CategoryPill which renders the category.
    render(
      withProviders(
        <EventInspector
          selected={ev({ run_id: "main" })}
          related={[
            rel({
              run_id: "rel-a",
              event_kind: "mcp_tool_call",
              category: "subprocess_exec",
              policy_decision: "allow",
            }),
          ]}
          onSelectRelated={() => undefined}
        />,
      ),
    );
    const row = screen.getByTestId("related-event-row");
    expect(row).toHaveTextContent("mcp_tool_call");
    // The category should NOT be in the chip text — pre-fix it was
    // rendered via CategoryPill.
    expect(row).not.toHaveTextContent("subprocess_exec");
  });

  it("F007: deny rows still show the deny pill (not the event_kind chip)", () => {
    render(
      withProviders(
        <EventInspector
          selected={ev({ run_id: "main" })}
          related={[
            rel({
              run_id: "rel-deny",
              event_kind: "tool_call",
              policy_decision: "deny",
            }),
          ]}
          onSelectRelated={() => undefined}
        />,
      ),
    );
    const row = screen.getByTestId("related-event-row");
    expect(row).toHaveTextContent("deny");
  });

  it("renders the bottom CTAs (Draft Policy Rule + Export Receipt)", () => {
    render(
      withProviders(
        <EventInspector
          selected={ev()}
          related={[]}
          onSelectRelated={() => undefined}
        />,
      ),
    );
    expect(screen.getByTestId("event-inspector-ctas")).toBeInTheDocument();
    expect(screen.getByTestId("cta-draft-policy")).toBeInTheDocument();
  });
});
