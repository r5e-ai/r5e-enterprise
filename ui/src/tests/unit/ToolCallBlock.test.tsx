// Vitest unit tests for the F5 <ToolCallBlock /> compact preview + expand.
//
// Per design/briefs/06-chat-drawer.md:
//   - Default state: `[Tool: name]` + truncated preview line + status badge.
//   - Click chevron → expand, showing request + response JSON inline.
//   - `attested_run_id` link points to the receipt detail route.
//   - Status icon: spinner / check / cross.

import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { MemoryRouter } from "react-router-dom";

import { ToolCallBlock } from "~/components/chat/ToolCallBlock";
import type { ToolCall } from "~/hooks/useChatConversation";

function renderToolCall(call: ToolCall) {
  return render(
    <MemoryRouter basename="/admin" initialEntries={["/admin/dashboard"]}>
      <ToolCallBlock call={call} />
    </MemoryRouter>,
  );
}

describe("ToolCallBlock — F5 compact preview + expand", () => {
  it("renders [Tool: name] header + status badge by default (collapsed)", () => {
    renderToolCall({
      id: "tc-1",
      tool: "verify_receipt",
      args: { run_id: "abc" },
      status: "success",
      result: { valid: true, checks_passed: 5 },
      attestationRunId: "11111111-2222-3333-4444-555555555555",
    });
    expect(screen.getByTestId("tool-call-name-verify_receipt")).toHaveTextContent(
      "[Tool: verify_receipt]",
    );
    // Body is hidden when collapsed.
    expect(screen.queryByTestId("tool-call-body-verify_receipt")).toBeNull();
    // Preview line is rendered.
    expect(
      screen.getByTestId("tool-call-preview-verify_receipt"),
    ).toBeInTheDocument();
  });

  it("expands the body on toggle click revealing request + response", () => {
    renderToolCall({
      id: "tc-2",
      tool: "query_receipts",
      args: { decision: "deny", limit: 5 },
      status: "success",
      result: { count: 5 },
      attestationRunId: "abc-def",
    });
    fireEvent.click(screen.getByTestId("tool-call-toggle-query_receipts"));
    expect(
      screen.getByTestId("tool-call-body-query_receipts"),
    ).toBeInTheDocument();
    expect(screen.getByTestId("tool-call-args-query_receipts")).toHaveTextContent(
      /decision/,
    );
    expect(
      screen.getByTestId("tool-call-result-query_receipts"),
    ).toHaveTextContent(/count/);
  });

  it("renders the attested_run_id link to the receipt detail route when expanded", () => {
    const runId = "11111111-2222-3333-4444-555555555555";
    renderToolCall({
      id: "tc-3",
      tool: "verify_receipt",
      args: {},
      status: "success",
      attestationRunId: runId,
    });
    fireEvent.click(screen.getByTestId("tool-call-toggle-verify_receipt"));
    const link = screen.getByTestId("tool-call-receipt-verify_receipt");
    // BrowserRouter basename `/admin` re-prepends; we used receiptDetailPath
    // which strips the basename to avoid double-prefixing.
    expect(link.getAttribute("href")).toBe(
      `/admin/dashboard/receipts/${encodeURIComponent(runId)}`,
    );
  });

  it("renders the running spinner for in-flight tool calls", () => {
    renderToolCall({
      id: "tc-4",
      tool: "find_similar",
      args: { run_id: "x" },
      status: "running",
    });
    expect(
      screen.getByTestId("tool-call-status-running"),
    ).toBeInTheDocument();
  });

  it("renders an error detail line when status is error and a message is present", () => {
    renderToolCall({
      id: "tc-5",
      tool: "fetch_payload",
      args: { run_id: "x" },
      status: "error",
      errorMessage: "upstream 503 — retry later",
    });
    fireEvent.click(screen.getByTestId("tool-call-toggle-fetch_payload"));
    expect(screen.getByRole("alert")).toHaveTextContent(/upstream 503/);
  });
});
