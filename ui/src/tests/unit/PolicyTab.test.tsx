// PolicyTab unit tests (MR !90 fix-pass — F004 GAN test-gap).
//
// Asserts:
//   - Cedar source viewer renders the source_excerpt with line numbers.
//   - The matched-line range gets the highlighted-bg class.
//   - Decision rationale callout shows allow/deny pill + matched-policy
//     file:line line.
//   - Free-form decision_rationale (when present on outer_container)
//     surfaces under the source viewer.
//   - Fallback panel renders when no source_excerpt is present.

import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { PolicyTab } from "~/components/audit/PolicyTab";
import type { ReceiptDetail } from "~/hooks/useReceiptDetail";

function makeData(opts: {
  matched?: ReceiptDetail["matched_policy"];
  decision?: "allow" | "deny" | null;
  policyHash?: string | null;
  rationale?: string | null;
} = {}): ReceiptDetail {
  const oc: ReceiptDetail["outer_container"] = {
    verification_level: null,
    tier_completeness_advisory: null,
    session_chain_epoch: null,
    session_chain_root: null,
    policy_decision: opts.decision === undefined ? "allow" : opts.decision,
    outcome: null,
    upstream_status_code: null,
    commit_retry_exhausted: null,
    tags: null,
  };
  if (opts.rationale != null) {
    (oc as unknown as { decision_rationale: string }).decision_rationale =
      opts.rationale;
  }
  return {
    run_id: "run_01HZQ",
    signed_predicate: {
      run_id: "run_01HZQ",
      session_id: null,
      turn_id: null,
      event_kind: "tool_call",
      machine_identity: null,
      principal: null,
      tenant_id: null,
      policy_canonical_hash:
        opts.policyHash === undefined
          ? "abc123".repeat(8)
          : opts.policyHash,
      payload_hash: null,
      payload_uri: null,
      correlation_id: null,
      signer_kms_key_id: null,
      signer_key_version: null,
      timestamp: "2026-04-29T12:00:00.000Z",
    },
    outer_container: oc,
    matched_policy:
      opts.matched === undefined
        ? {
            bundle_id: "bundle-01",
            file: "policies/network.cedar",
            line_start: 12,
            line_end: 14,
            source_excerpt: [
              "permit (",
              "  principal,",
              '  action == Action::"NetworkEgress",',
              "  resource",
              ");",
            ].join("\n"),
          }
        : opts.matched,
  };
}

describe("PolicyTab", () => {
  it("renders the policy_canonical_hash chip when present", () => {
    render(<PolicyTab data={makeData()} />);
    const tab = screen.getByTestId("policy-tab");
    expect(tab).toHaveTextContent(/policy_canonical_hash/i);
    // Truncated short form (first 16 + ... + last 12).
    expect(tab.textContent).toMatch(/abc123/);
  });

  it("renders the Cedar source viewer with line numbers + matched-line highlight", () => {
    render(<PolicyTab data={makeData()} />);
    // Five lines starting from line_start=12, so 12..16 line numbers.
    for (const lineNo of [12, 13, 14, 15, 16]) {
      expect(
        document.querySelector(`[data-line="${lineNo}"]`),
      ).not.toBeNull();
    }
    // Matched range 12..14 should have highlighted bg.
    const matched = document.querySelector('[data-line="12"]');
    expect(matched?.className).toMatch(/bg-r5e-accent\/15/);
    const unmatched = document.querySelector('[data-line="15"]');
    expect(unmatched?.className ?? "").not.toMatch(/bg-r5e-accent\/15/);
  });

  it("renders the decision rationale callout with allow pill", () => {
    render(<PolicyTab data={makeData({ decision: "allow" })} />);
    const cal = screen.getByTestId("policy-decision-rationale");
    expect(cal).toHaveTextContent(/decision/i);
    expect(cal).toHaveTextContent("allow");
    expect(cal).toHaveTextContent("policies/network.cedar");
    expect(cal).toHaveTextContent("12");
  });

  it("uses the danger tone for deny decisions", () => {
    render(<PolicyTab data={makeData({ decision: "deny" })} />);
    const cal = screen.getByTestId("policy-decision-rationale");
    expect(cal).toHaveTextContent("deny");
    // The decision pill in the rationale has data-tone=danger.
    const pill = cal.querySelector('[data-tone="danger"]');
    expect(pill).not.toBeNull();
  });

  it("surfaces a free-form decision_rationale when backend ships it", () => {
    render(
      <PolicyTab
        data={makeData({
          decision: "deny",
          rationale: "Egress to ext.api/exfil blocked by network.cedar",
        })}
      />,
    );
    expect(
      screen.getByText(
        /egress to ext\.api\/exfil blocked by network\.cedar/i,
      ),
    ).toBeInTheDocument();
  });

  it("renders the fallback panel when no source excerpt is present", () => {
    render(<PolicyTab data={makeData({ matched: null })} />);
    expect(
      screen.getByText(/no matched policy excerpt available/i),
    ).toBeInTheDocument();
  });
});
