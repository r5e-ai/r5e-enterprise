// R2 redesign — DrawerHeader unit tests.
//
// Asserts the brief's contract:
//   - "RECEIPT" mono-caps eyebrow + run_id (truncated to 36 chars)
//   - Tier completeness pill rendered when advisory is present
//     (warning tone for partial, success for full)
//   - "Draft policy from receipt" + "Export Evidence (.zip)" actions
//   - Close button (X) wired to onClose

import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { DrawerHeader } from "~/components/audit/DrawerHeader";

// Stub ExportEvidenceButton — it owns its own QueryClient + fetch path; we
// don't need to mount that here. Just confirm DrawerHeader renders it.
vi.mock("~/components/audit/ExportEvidenceButton", () => ({
  ExportEvidenceButton: ({ runId }: { runId: string }) => (
    <button data-testid="export-evidence-button">export {runId}</button>
  ),
}));

describe("DrawerHeader", () => {
  it("renders RECEIPT eyebrow + the run_id", () => {
    render(
      <DrawerHeader
        runId="abc-123"
        tierAdvisory={null}
        onClose={() => {}}
        onDraftPolicy={() => {}}
      />,
    );
    expect(screen.getByTestId("drawer-eyebrow")).toHaveTextContent(/receipt/i);
    expect(screen.getByTestId("drawer-run-id")).toHaveTextContent("abc-123");
  });

  it("truncates a long run_id to 36 chars with an ellipsis", () => {
    const long = "a".repeat(64);
    render(
      <DrawerHeader
        runId={long}
        tierAdvisory={null}
        onClose={() => {}}
        onDraftPolicy={() => {}}
      />,
    );
    const code = screen.getByTestId("drawer-run-id");
    expect(code.textContent?.length).toBeLessThanOrEqual(36);
    expect(code.textContent).toMatch(/…$/);
    // Title attribute carries the full run_id for hover tooltip.
    expect(code).toHaveAttribute("title", long);
  });

  it("renders a warning-tone tier completeness pill for advisory=partial", () => {
    render(
      <DrawerHeader
        runId="abc-123"
        tierAdvisory="partial"
        onClose={() => {}}
        onDraftPolicy={() => {}}
      />,
    );
    const pill = screen.getByTestId("tier-completeness-advisory");
    expect(pill).toHaveTextContent(/tier completeness: partial/i);
    expect(pill).toHaveAttribute("data-tone", "warning");
  });

  it("renders a success-tone pill for advisory=full", () => {
    render(
      <DrawerHeader
        runId="abc-123"
        tierAdvisory="full"
        onClose={() => {}}
        onDraftPolicy={() => {}}
      />,
    );
    const pill = screen.getByTestId("tier-completeness-advisory");
    expect(pill).toHaveAttribute("data-tone", "success");
  });

  it("hides the tier pill when advisory is null", () => {
    render(
      <DrawerHeader
        runId="abc-123"
        tierAdvisory={null}
        onClose={() => {}}
        onDraftPolicy={() => {}}
      />,
    );
    expect(
      screen.queryByTestId("tier-completeness-advisory"),
    ).not.toBeInTheDocument();
  });

  it("renders Draft policy + Export Evidence + Close actions", () => {
    render(
      <DrawerHeader
        runId="abc-123"
        tierAdvisory={null}
        onClose={() => {}}
        onDraftPolicy={() => {}}
      />,
    );
    expect(
      screen.getByTestId("draft-policy-from-receipt"),
    ).toHaveTextContent(/draft policy from receipt/i);
    expect(screen.getByTestId("export-evidence-button")).toBeInTheDocument();
    expect(screen.getByTestId("drawer-close")).toBeInTheDocument();
  });

  it("invokes onClose when Close is clicked", () => {
    const onClose = vi.fn();
    render(
      <DrawerHeader
        runId="abc-123"
        tierAdvisory={null}
        onClose={onClose}
        onDraftPolicy={() => {}}
      />,
    );
    fireEvent.click(screen.getByTestId("drawer-close"));
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("invokes onDraftPolicy when Draft is clicked", () => {
    const onDraft = vi.fn();
    render(
      <DrawerHeader
        runId="abc-123"
        tierAdvisory={null}
        onClose={() => {}}
        onDraftPolicy={onDraft}
      />,
    );
    fireEvent.click(screen.getByTestId("draft-policy-from-receipt"));
    expect(onDraft).toHaveBeenCalledTimes(1);
  });

  it("hides Draft + Export when runId is absent", () => {
    render(
      <DrawerHeader
        runId={null}
        tierAdvisory={null}
        onClose={() => {}}
        onDraftPolicy={() => {}}
      />,
    );
    expect(
      screen.queryByTestId("draft-policy-from-receipt"),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByTestId("export-evidence-button"),
    ).not.toBeInTheDocument();
    // Close still renders.
    expect(screen.getByTestId("drawer-close")).toBeInTheDocument();
  });
});
