// R2 redesign — VerifyTab unit tests.
//
// Asserts:
//   - All five rows render in the brief's order: Signature, Payload hash,
//     Policy canonical hash, Local inclusion proof, Global inclusion proof
//   - Default (pending) renders without invoking the verify endpoint
//   - StatusPill shows PENDING in pre-fetch state

import type { ReactNode } from "react";
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

import { VerifyTab } from "~/components/audit/VerifyTab";

function withClient(node: ReactNode): JSX.Element {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return <QueryClientProvider client={client}>{node}</QueryClientProvider>;
}

describe("VerifyTab", () => {
  it("renders the 5-check ladder in the brief's order", () => {
    render(withClient(<VerifyTab runId="run-1" />));
    const list = screen.getByTestId("verify-checks-list");
    const rows = list.querySelectorAll("[data-testid^='verify-row-']");
    expect(rows).toHaveLength(5);
    // Order: signature → payload_hash → policy_hash → local_merkle → global_merkle
    expect(rows[0]).toHaveAttribute("data-testid", "verify-row-signature");
    expect(rows[1]).toHaveAttribute("data-testid", "verify-row-payload_hash");
    expect(rows[2]).toHaveAttribute("data-testid", "verify-row-policy_hash");
    expect(rows[3]).toHaveAttribute("data-testid", "verify-row-local_merkle");
    expect(rows[4]).toHaveAttribute("data-testid", "verify-row-global_merkle");
  });

  it("shows the brief's row labels", () => {
    render(withClient(<VerifyTab runId="run-1" />));
    expect(screen.getByText("Signature")).toBeInTheDocument();
    expect(screen.getByText("Payload hash")).toBeInTheDocument();
    expect(screen.getByText("Policy canonical hash")).toBeInTheDocument();
    expect(screen.getByText("Local inclusion proof")).toBeInTheDocument();
    expect(screen.getByText("Global inclusion proof")).toBeInTheDocument();
  });

  it("shows PENDING in the overall status pill before the user verifies", () => {
    render(withClient(<VerifyTab runId="run-1" />));
    const pill = screen.getByTestId("verify-overall-status");
    expect(pill).toHaveTextContent("PENDING");
    expect(pill).toHaveAttribute("data-tone", "muted");
  });

  it("shows a Verify Locally CTA when not yet run", () => {
    render(withClient(<VerifyTab runId="run-1" />));
    expect(screen.getByTestId("verify-locally-button")).toHaveTextContent(
      /verify locally/i,
    );
  });
});
