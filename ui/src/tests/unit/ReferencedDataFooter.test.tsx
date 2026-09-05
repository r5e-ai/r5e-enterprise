// Vitest unit tests for the F5 <ReferencedDataFooter /> overlay-aware
// receipt links (F003 from MR !93 fix-pass-2 GAN).
//
// Per design/briefs/06-chat-drawer.md + FR-038: clicking either the
// per-tool-call receipt link OR the message-attestation receipt link
// from the chat surface MUST open the receipt detail OVER the chat
// (background-location modal pattern). The footer renders Links with
// `state={{ backgroundLocation: location }}` and uses `receiptDetailPath()`
// (basename-stripped) so the App's <Routes location={backgroundLocation}>
// switch keeps the chat surface mounted underneath.

import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";

import { ReferencedDataFooter } from "~/components/chat/ReferencedDataFooter";
import type { ChatMessage } from "~/hooks/useChatConversation";

function ProbeLocation(): null {
  // Render-side helper to expose the active location to assertions —
  // the Link's state is checked by inspecting the rendered href + then
  // simulating a click via location-hooks proxy. We don't actually need
  // it; React Router serializes the state into the underlying history
  // entry and we assert `to` shape via the rendered href.
  useLocation();
  return null;
}

const baseMessage: ChatMessage = {
  localId: "msg-asst-1",
  role: "assistant",
  content: "Done.",
  toolCalls: [
    {
      id: "tc-1",
      tool: "verify_receipt",
      args: { run_id: "abc" },
      status: "success",
      result: { valid: true },
      attestationRunId: "11111111-2222-3333-4444-555555555555",
    },
  ],
  attestationRunId: "99999999-8888-7777-6666-555555555555",
  status: "completed",
  errors: [],
  createdAt: "2026-04-30T12:00:00Z",
};

function renderFooter(message: ChatMessage = baseMessage) {
  return render(
    <MemoryRouter basename="/admin" initialEntries={["/admin/chat"]}>
      <Routes>
        <Route
          path="/chat"
          element={
            <>
              <ReferencedDataFooter
                message={message}
                principalSubject="alice@corp"
                principalRole="tenant_auditor"
              />
              <ProbeLocation />
            </>
          }
        />
      </Routes>
    </MemoryRouter>,
  );
}

describe("ReferencedDataFooter — F003 overlay-aware receipt links", () => {
  it("renders the per-tool-call receipt link via receiptDetailPath() (basename-safe)", () => {
    renderFooter();
    const link = screen.getByTestId("referenced-data-tool-receipt-tc-1");
    // basename "/admin" is auto-prepended by react-router; receiptDetailPath()
    // strips the basename, so the rendered href ends up as the full
    // `/admin/dashboard/...` path exactly once.
    expect(link.getAttribute("href")).toBe(
      "/admin/dashboard/receipts/11111111-2222-3333-4444-555555555555",
    );
  });

  it("renders the message-attestation receipt link via receiptDetailPath()", () => {
    renderFooter();
    const link = screen.getByTestId("referenced-data-message-receipt-link");
    expect(link.getAttribute("href")).toBe(
      "/admin/dashboard/receipts/99999999-8888-7777-6666-555555555555",
    );
  });

  it("hides the footer when there are no tool calls and no attestation run id", () => {
    const empty: ChatMessage = {
      ...baseMessage,
      toolCalls: [],
      attestationRunId: null,
    };
    const { container } = renderFooter(empty);
    expect(container.querySelector('[data-testid="referenced-data-footer"]')).toBeNull();
  });
});
