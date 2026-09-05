// ProofTab unit tests (MR !90 fix-pass — F004 GAN test-gap, with the
// F001 'Signature row showed leaf_hash' regression locked in via the
// "Signature row absent" assertion).
//
// Asserts:
//   - DSSE column renders the wire-exposed fields (algorithm + KMS key
//     + key version + payload hash) but NOT a 'Signature' row (F001:
//     the wire shape doesn't yet expose `dsse_signature_b64`; until #50
//     ships the Verify Locally button is the auditor's signature
//     surface).
//   - The leaf_hash now lives inside MerkleColumn (the leaf IS the
//     bottom of the Merkle tree, not a DSSE artifact).
//   - Local + global proof step counts surface; tier completeness row
//     present.
//   - When proof is null the proof-path SVG is replaced by a fallback
//     banner.
//   - ExpandableHashRow toggles between truncated and full value on
//     click.

import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { ProofTab } from "~/components/audit/ProofTab";
import type { ReceiptDetail } from "~/hooks/useReceiptDetail";

function makeData(opts: {
  proof?: ReceiptDetail["proof"];
  payloadHash?: string | null;
  signerKey?: string | null;
  keyVersion?: string | null;
} = {}): ReceiptDetail {
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
      payload_hash:
        opts.payloadHash === undefined
          ? "deadbeef".repeat(8)
          : opts.payloadHash,
      payload_uri: null,
      correlation_id: null,
      signer_kms_key_id:
        opts.signerKey === undefined
          ? "arn:aws:kms:us-west-2:111122223333:key/r5e-core-beam-signing"
          : opts.signerKey,
      signer_key_version: opts.keyVersion === undefined ? "v1" : opts.keyVersion,
      timestamp: "2026-04-29T12:00:00.000Z",
    },
    outer_container: {
      verification_level: "global_inclusion_verified",
      tier_completeness_advisory: "partial",
      session_chain_epoch: 0,
      session_chain_root: "1234567890abcdef".repeat(4),
      policy_decision: "allow",
      outcome: null,
      upstream_status_code: null,
      commit_retry_exhausted: null,
      tags: null,
    },
    proof:
      opts.proof === undefined
        ? {
            leaf_hash: "abcdef0123456789".repeat(4),
            local_path: [
              { sibling: "11".repeat(32), direction: "left" },
              { sibling: "22".repeat(32), direction: "right" },
            ],
            epoch_root: "ee".repeat(32),
            global_path: [{ sibling: "33".repeat(32), direction: "left" }],
            global_root: "ff".repeat(32),
            sth: null,
          }
        : opts.proof,
  };
}

describe("ProofTab", () => {
  it("renders the DSSE column with algorithm + signer KMS key + key version + payload hash, but NOT a Signature row (F001 regression)", () => {
    render(<ProofTab data={makeData()} />);
    const dsse = screen.getByTestId("proof-dsse-column");
    expect(dsse).toHaveTextContent(/DSSE signature/i);
    expect(dsse).toHaveTextContent("ES256");
    expect(dsse).toHaveTextContent(/signer kms key/i);
    expect(dsse).toHaveTextContent(/r5e-core-beam-signing/);
    expect(dsse).toHaveTextContent(/key version/i);
    expect(dsse).toHaveTextContent("v1");
    expect(dsse).toHaveTextContent(/payload hash/i);
    // F001 regression: a row labelled 'Signature' must NOT exist
    // (the wire doesn't expose dsse_signature_b64 yet — see #50).
    expect(dsse.textContent).not.toMatch(/^Signature$/m);
    // ...and the leaf_hash must NOT be inside the DSSE column.
    expect(dsse.textContent).not.toMatch(/abcdef01234/);
  });

  it("renders the Merkle column with leaf hash + session root + step counts + tier", () => {
    render(<ProofTab data={makeData()} />);
    const merkle = screen.getByTestId("proof-merkle-column");
    expect(merkle).toHaveTextContent(/Merkle inclusion/i);
    expect(merkle).toHaveTextContent(/session chain epoch/i);
    expect(merkle).toHaveTextContent("0");
    expect(merkle).toHaveTextContent(/leaf hash/i);
    expect(merkle).toHaveTextContent(/session chain root/i);
    expect(merkle).toHaveTextContent(/local inclusion proof/i);
    expect(merkle).toHaveTextContent(/2 steps/);
    expect(merkle).toHaveTextContent(/global inclusion proof/i);
    expect(merkle).toHaveTextContent(/present/);
    expect(merkle).toHaveTextContent(/tier completeness/i);
    expect(merkle).toHaveTextContent("partial");
  });

  it("singularises the inclusion-step label when there is exactly one step", () => {
    const data = makeData();
    if (data.proof) {
      data.proof.local_path = [{ sibling: "aa".repeat(32), direction: "left" }];
    }
    render(<ProofTab data={data} />);
    const merkle = screen.getByTestId("proof-merkle-column");
    expect(merkle.textContent).toMatch(/1 step(?!s)/);
    expect(merkle.textContent).not.toMatch(/1 steps/);
  });

  it("shows 'pending' when global_root is absent", () => {
    const data = makeData();
    if (data.proof) {
      data.proof.global_root = null;
    }
    render(<ProofTab data={data} />);
    const merkle = screen.getByTestId("proof-merkle-column");
    expect(merkle).toHaveTextContent(/global inclusion proof/i);
    expect(merkle).toHaveTextContent(/pending/);
  });

  it("renders a fallback banner when proof is null", () => {
    render(<ProofTab data={makeData({ proof: null })} />);
    expect(
      screen.getByText(/no proof envelope available/i),
    ).toBeInTheDocument();
  });

  it("ExpandableHashRow toggles between truncated and full hash on click", () => {
    const fullHash = "z".repeat(80);
    const data = makeData();
    if (data.proof) {
      data.proof.leaf_hash = fullHash;
    }
    render(<ProofTab data={data} />);
    const merkle = screen.getByTestId("proof-merkle-column");
    // The leaf-hash row renders a button (the row toggle). Find the
    // collapsed form first — full string should not be present yet.
    expect(merkle.textContent).not.toMatch(new RegExp(fullHash));
    // Click any expandable hash button inside the merkle column. The
    // first one is leaf hash.
    const buttons = merkle.querySelectorAll("button[aria-expanded]");
    expect(buttons.length).toBeGreaterThan(0);
    const leafButton = buttons[0] as HTMLElement;
    expect(leafButton).toHaveAttribute("aria-expanded", "false");
    fireEvent.click(leafButton);
    expect(leafButton).toHaveAttribute("aria-expanded", "true");
    expect(merkle.textContent).toMatch(new RegExp(fullHash));
  });

  it("renders the RFC 9162 STH block when proof.sth is set", () => {
    const data = makeData();
    if (data.proof) {
      data.proof.sth = "BASE64-STH-PAYLOAD";
    }
    render(<ProofTab data={data} />);
    expect(screen.getByText(/rfc 9162 sth/i)).toBeInTheDocument();
    expect(screen.getByText("BASE64-STH-PAYLOAD")).toBeInTheDocument();
  });
});
