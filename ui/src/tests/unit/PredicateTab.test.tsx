// PredicateTab unit tests (MR !90 fix-pass — F004 GAN test-gap).
//
// Asserts:
//   - The signed_predicate JSON renders inside `predicate-json` <pre>.
//   - The predicate-only callout fires for `recurse://import/...` and
//     `recurse://system/predicate-only/...` URIs (issue #60 / FR-019).
//   - The callout is suppressed for normal external-payload URIs.
//   - When `signed_predicate.predicate` is present it's preferred over
//     the envelope itself for the JSON body.

import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { PredicateTab } from "~/components/audit/PredicateTab";
import type { ReceiptDetail } from "~/hooks/useReceiptDetail";

function makeData(opts: {
  payloadUri?: string | null;
  predicate?: Record<string, unknown> | null;
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
      payload_uri: opts.payloadUri ?? null,
      correlation_id: null,
      signer_kms_key_id: null,
      signer_key_version: null,
      timestamp: "2026-04-29T12:00:00.000Z",
      predicate: opts.predicate,
    },
    outer_container: {
      verification_level: null,
      tier_completeness_advisory: null,
      session_chain_epoch: null,
      session_chain_root: null,
      policy_decision: "allow",
      outcome: null,
      upstream_status_code: null,
      commit_retry_exhausted: null,
      tags: null,
    },
  };
}

describe("PredicateTab", () => {
  it("renders the signed_predicate envelope JSON when no inner predicate", () => {
    render(<PredicateTab data={makeData({})} />);
    const json = screen.getByTestId("predicate-json");
    expect(json.textContent).toMatch(/run_id/);
    expect(json.textContent).toMatch(/run_01HZQ/);
  });

  it("prefers the inner `predicate` object when present", () => {
    render(
      <PredicateTab
        data={makeData({
          predicate: { inner_field: "inner_value", count: 7 },
        })}
      />,
    );
    const json = screen.getByTestId("predicate-json");
    expect(json.textContent).toMatch(/inner_field/);
    expect(json.textContent).toMatch(/inner_value/);
    // The envelope's run_id should NOT appear when we render the inner only.
    expect(json.textContent).not.toMatch(/signer_kms_key_id/);
  });

  it("shows the predicate-only callout for `recurse://import/` URIs", () => {
    render(
      <PredicateTab
        data={makeData({
          payloadUri: "recurse://import/claude-code/session-abc",
        })}
      />,
    );
    expect(
      screen.getByTestId("predicate-only-callout"),
    ).toBeInTheDocument();
    expect(
      screen.getByTestId("predicate-only-callout"),
    ).toHaveTextContent(/complete signed payload/i);
  });

  it("shows the predicate-only callout for `recurse://system/predicate-only/` URIs", () => {
    render(
      <PredicateTab
        data={makeData({
          payloadUri: "recurse://system/predicate-only/ui_login",
        })}
      />,
    );
    expect(
      screen.getByTestId("predicate-only-callout"),
    ).toBeInTheDocument();
  });

  it("suppresses the callout for normal s3:// URIs", () => {
    render(
      <PredicateTab
        data={makeData({
          payloadUri: "s3://payloads/run_01HZQ.json",
        })}
      />,
    );
    expect(
      screen.queryByTestId("predicate-only-callout"),
    ).not.toBeInTheDocument();
  });

  it("suppresses the callout when payload_uri is null", () => {
    render(<PredicateTab data={makeData({ payloadUri: null })} />);
    expect(
      screen.queryByTestId("predicate-only-callout"),
    ).not.toBeInTheDocument();
  });
});
