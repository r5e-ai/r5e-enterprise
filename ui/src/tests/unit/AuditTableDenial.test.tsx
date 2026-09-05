// Spec 012 S6c — a `tool_use_denied` row reads as a denial in the table:
// DENY pill, red tool pill named after the tool, rule in COMMAND, and a
// session chip on every row that carries `client_session_id`.

import { render, screen, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { MemoryRouter } from "react-router-dom";

import { AuditTable } from "~/components/audit/AuditTable";
import type { ReceiptRow } from "~/hooks/useReceipts";
import { defaultColumnVisibility } from "~/lib/auditLogColumns";

function row(runId: string, eventKind: string, tags: Record<string, unknown> | null): ReceiptRow {
  return {
    run_id: runId,
    signed_predicate: {
      run_id: runId,
      session_id: runId,
      turn_id: null,
      event_kind: eventKind,
      machine_identity: null,
      principal: { kind: "obo_human", subject: "claude-code:abc" },
      tenant_id: "01TEN_LOCAL",
      policy_canonical_hash: null,
      payload_hash: null,
      payload_uri: null,
      correlation_id: null,
      signer_kms_key_id: null,
      signer_key_version: null,
      timestamp: "2026-09-02T21:15:50.000000Z",
      tool_name: null,
      tool_summary: null,
    },
    outer_container: {
      verification_level: "global_inclusion_verified",
      tier_completeness_advisory: "partial",
      session_chain_epoch: 0,
      session_chain_root: null,
      // The ledger default: the PARENT call's decision, even on a denial.
      policy_decision: "allow",
      outcome: "success",
      upstream_status_code: null,
      commit_retry_exhausted: false,
      tags,
    },
  };
}

const denied = row("denied", "tool_use_denied", {
  kind: "agent_turn",
  tool_name: "Bash",
  call_id: "toolu_01",
  cedar_rule_id: "policy6",
  deny_reason: "denied_by_cedar_policy",
  client_session_id: "3f8fc437-ccc5-4ce9-8b07-436226bd7ca4",
});
const parent = row("parent", "llm_call_attested", {
  kind: "agent_turn",
  decision_summary: "all deny",
  tool_use_intent_count: 1,
  client_session_id: "3f8fc437-ccc5-4ce9-8b07-436226bd7ca4",
});

function renderTable(rows: ReceiptRow[]) {
  return render(
    <MemoryRouter>
      <AuditTable
        rows={rows}
        visibility={defaultColumnVisibility()}
        sort={null}
        onSortClick={vi.fn()}
        selectedIds={new Set()}
        onToggleRow={vi.fn()}
        onToggleAll={vi.fn()}
        onOpen={vi.fn()}
      />
    </MemoryRouter>,
  );
}

describe("AuditTable — tool_use_denied rows", () => {
  it("renders the denial as DENY with the tool named and the rule that fired", () => {
    renderTable([denied]);
    const tr = screen.getByTestId("receipt-row");
    expect(within(tr).getByTestId("decision-pill-deny")).toBeInTheDocument();
    expect(within(tr).queryByTestId("decision-pill-allow")).toBeNull();
    const pill = within(tr).getByTestId("tool-pill");
    expect(pill).toHaveAttribute("data-tool-kind", "bash");
    expect(pill).toHaveAttribute("data-denial", "true");
    expect(pill).toHaveTextContent("Bash");
    expect(within(tr).getByTestId("command-text")).toHaveTextContent("policy6");
    expect(within(tr).getByTestId("row-chip-session")).toHaveTextContent("3f8fc437");
  });

  it("keeps the parent call with an all-deny summary as an allow row", () => {
    renderTable([parent]);
    const tr = screen.getByTestId("receipt-row");
    expect(within(tr).getByTestId("decision-pill-allow")).toBeInTheDocument();
    expect(within(tr).getByTestId("row-chip-session")).toHaveTextContent("3f8fc437");
  });

  it("leaves the cells empty for a denial written without tags", () => {
    renderTable([row("old", "tool_use_denied", null)]);
    const tr = screen.getByTestId("receipt-row");
    expect(within(tr).getByTestId("decision-pill-deny")).toBeInTheDocument();
    expect(within(tr).queryByTestId("tool-pill")).toBeNull();
    expect(within(tr).queryByTestId("command-text")).toBeNull();
  });
});
