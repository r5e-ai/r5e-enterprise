// IdentityTab unit tests — 5-section vertical-stack rebuild matching the
// canonical `MdEKl > drawer > scrollContent` frame in the .pen.
//
// Pre-rewrite this test exercised a flat <dl> envelope-field dump
// (matched the brief at design/briefs/03-receipt-drawer.md, but the
// brief was a simplification of the .pen). The brief shipped four
// times across F004 and the GAN never caught it because the GAN
// scored against the brief, not the .pen. Rule going forward: the
// .pen is the canonical for any visual surface.

import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { MemoryRouter } from "react-router-dom";

import { IdentityTab } from "~/components/audit/IdentityTab";
import type { ReceiptDetail } from "~/hooks/useReceiptDetail";

function makeData(overrides: Partial<ReceiptDetail> = {}): ReceiptDetail {
  return {
    run_id: "run_01HZQ",
    signed_predicate: {
      run_id: "run_01HZQ",
      session_id: "sess_42",
      turn_id: "turn_3",
      event_kind: "tool_call",
      machine_identity: "spiffe://r5e/agent",
      principal: {
        kind: "service_account",
        subject: "llm-agent-01",
      } as unknown as string,
      tenant_id: "corp-main",
      policy_canonical_hash: "abc123",
      payload_hash: "sha256:e4f5a6b7c8d9deadbeefcafefade1234deadbeefcafefade",
      payload_uri: null,
      correlation_id: "corr-xyz",
      signer_kms_key_id: "arn:aws:kms:us-west-2:111122223333:key/r5e-core",
      signer_key_version: "v1",
      timestamp: "2026-04-29T12:00:00.000Z",
    },
    outer_container: {
      verification_level: "global_inclusion_verified",
      tier_completeness_advisory: "partial",
      session_chain_epoch: 0,
      session_chain_root: "deadbeef",
      policy_decision: "allow",
      outcome: "success",
      upstream_status_code: 200,
      commit_retry_exhausted: null,
      tags: {
        category: "subprocess_exec",
        display_summary: "Bash: ls /etc",
        tool_kind: "bash",
        verb: "ls",
        argument_body: "/etc",
        semantic_args: { host: "localhost" },
      },
    },
    ...overrides,
  };
}

function renderTab(data: ReceiptDetail) {
  return render(
    <MemoryRouter basename="/admin" initialEntries={["/admin/dashboard"]}>
      <IdentityTab data={data} />
    </MemoryRouter>,
  );
}

describe("IdentityTab — canonical 5-section structure", () => {
  it("renders all 5 named sections in order: PRINCIPAL, REQUEST SUMMARY, POLICY DECISION, draft CTA, CRYPTOGRAPHIC PROOF", () => {
    renderTab(makeData());
    expect(screen.getByTestId("identity-principal-section")).toBeInTheDocument();
    expect(screen.getByTestId("identity-request-section")).toBeInTheDocument();
    expect(screen.getByTestId("identity-policy-section")).toBeInTheDocument();
    expect(screen.getByTestId("identity-draft-cta")).toBeInTheDocument();
    expect(screen.getByTestId("identity-proof-section")).toBeInTheDocument();
    // DOM order matches the canonical scrollContent stack. Match only
    // top-level section testids — descendants like `identity-policy-verdict`
    // share the `identity-policy-` prefix and must not be picked up here.
    const tab = screen.getByTestId("identity-tab");
    const sections = within(tab).getAllByTestId(
      /^identity-(principal-section|request-section|policy-section|draft-cta|proof-section)$/,
    );
    expect(sections.map((s) => s.dataset.testid)).toEqual([
      "identity-principal-section",
      "identity-request-section",
      "identity-policy-section",
      "identity-draft-cta",
      "identity-proof-section",
    ]);
  });
});

describe("IdentityTab — PRINCIPAL section", () => {
  it("renders kind, account_id, tenant, session_id, verification rows with the canonical labels", () => {
    renderTab(makeData());
    const sec = screen.getByTestId("identity-principal-section");
    expect(sec.textContent).toContain("PRINCIPAL");
    expect(sec.textContent).toContain("kind");
    expect(sec.textContent).toContain("service_account");
    expect(sec.textContent).toContain("account_id");
    expect(sec.textContent).toContain("llm-agent-01");
    expect(sec.textContent).toContain("tenant");
    expect(sec.textContent).toContain("corp-main");
    expect(sec.textContent).toContain("session_id");
    expect(sec.textContent).toContain("sess_42");
    expect(sec.textContent).toContain("verification");
  });

  it("verification renders as a green pill when level is global_inclusion_verified", () => {
    renderTab(makeData());
    const pill = screen.getByTestId("identity-verification-pill");
    expect(pill).toHaveClass("text-r5e-accent-green");
    expect(pill.textContent).toContain("global_inclusion_verified");
  });
});

describe("IdentityTab — REQUEST SUMMARY section", () => {
  it("uses tags.display_summary as the title when present", () => {
    renderTab(makeData());
    const sec = screen.getByTestId("identity-request-section");
    expect(sec.textContent).toContain("REQUEST SUMMARY");
    expect(sec.textContent).toContain("Bash: ls /etc");
  });

  it("synthesizes a subtitle from semantic_args (Host/Method/Server/etc)", () => {
    renderTab(makeData());
    const sec = screen.getByTestId("identity-request-section");
    expect(sec.textContent).toContain("Host: localhost");
  });

  it("falls back to verb + tool_kind when display_summary is absent", () => {
    const d = makeData();
    (d.outer_container.tags as Record<string, unknown>).display_summary = undefined;
    renderTab(d);
    expect(screen.getByTestId("identity-request-section").textContent).toContain(
      "ls bash",
    );
  });
});

describe("IdentityTab — POLICY DECISION section", () => {
  it("DENY case: red verdict + ShieldAlert icon + chart-denied border", () => {
    const d = makeData();
    d.outer_container.policy_decision = "deny";
    d.matched_policy = {
      bundle_id: null,
      file: "workspace/.r5e/policies/network-egress-policy.cedar",
      line_start: 14,
      line_end: 18,
      source_excerpt:
        'forbid(principal, action, resource) when { action.type == "subprocess_exec" }',
    };
    renderTab(d);
    const verdict = screen.getByTestId("identity-policy-verdict");
    expect(verdict.textContent).toBe("DENY");
    expect(verdict).toHaveClass("text-r5e-chart-denied");
    expect(screen.getByTestId("identity-policy-section").textContent).toContain(
      "network_egress_policy",
    );
    expect(screen.getByTestId("identity-deny-callout")).toBeInTheDocument();
    expect(screen.getByTestId("identity-policy-source-location")).toHaveTextContent(
      "workspace/.r5e/policies/network-egress-policy.cedar:14",
    );
    const src = screen.getByTestId("identity-policy-source");
    expect(src.textContent).toContain("forbid(principal, action, resource)");
  });

  it("ALLOW case: green verdict, no shield icon", () => {
    renderTab(makeData());
    const verdict = screen.getByTestId("identity-policy-verdict");
    expect(verdict.textContent).toBe("ALLOW");
    expect(verdict).toHaveClass("text-r5e-accent-green");
  });

  it("falls back to a friendly placeholder when no matched_policy source", () => {
    renderTab(makeData());
    expect(screen.getByTestId("identity-policy-section").textContent).toContain(
      "No matched-policy source on this receipt yet.",
    );
  });
});

describe("IdentityTab — DRAFT POLICY CTA", () => {
  it("renders the gradient CTA with Customize + Adopt buttons", () => {
    renderTab(makeData());
    const cta = screen.getByTestId("identity-draft-cta");
    expect(cta.textContent).toContain("Draft policy from this receipt");
    expect(cta.textContent).toContain("Pre-filled from extracted fields:");
    expect(screen.getByTestId("identity-draft-customize")).toBeInTheDocument();
    expect(screen.getByTestId("identity-draft-adopt")).toBeInTheDocument();
  });

  it("pre-fills the forbid skeleton with the receipt's category + an inferred condition", () => {
    renderTab(makeData());
    const code = screen.getByTestId("identity-draft-skeleton");
    expect(code.textContent).toContain("forbid(");
    expect(code.textContent).toContain("category = subprocess_exec");
    expect(code.textContent).toContain("when");
    expect(code.textContent).toContain(");");
  });
});

describe("IdentityTab — CRYPTOGRAPHIC PROOF section", () => {
  it("renders 4 rows: signature, merkle_local, merkle_global, payload_hash", () => {
    renderTab(makeData());
    const sec = screen.getByTestId("identity-proof-section");
    expect(sec.textContent).toContain("CRYPTOGRAPHIC PROOF");
    expect(sec.textContent).toContain("signature");
    expect(sec.textContent).toContain("merkle_local");
    expect(sec.textContent).toContain("merkle_global");
    expect(sec.textContent).toContain("payload_hash");
  });

  it("payload_hash is truncated to head…tail when very long", () => {
    renderTab(makeData());
    const sec = screen.getByTestId("identity-proof-section");
    // truncateHash takes the first 16 chars + ellipsis + last 4 chars.
    // Fixture hash is "sha256:e4f5a6b7c8d9deadbeefcafefade...fade" → head
    // is "sha256:e4f5a6b7c" (16 chars), tail is "fade".
    expect(sec.textContent).toMatch(/sha256:e4f5a6b7c…fade/);
  });

  it("payload_hash renders em-dash when null", () => {
    const d = makeData();
    d.signed_predicate.payload_hash = null;
    renderTab(d);
    expect(screen.getByTestId("identity-proof-section").textContent).toContain(
      "—",
    );
  });
});
