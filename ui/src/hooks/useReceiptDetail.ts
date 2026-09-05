// useReceiptDetail — TanStack-Query hook backing the Receipt Detail drawer
// (T079, Phase 4 US2).
//
// Per `contracts/audit_api_extensions.md` GET /v1/audit/receipts/:run_id
// (the Receipt Detail extension) and the F004 plan:
//   - The detail endpoint widens the F002 `signed_predicate + outer_container`
//     shape with `tier_completeness_advisory`, the full Merkle proof envelope,
//     and the matched-policy line range (per FR-017 + FR-018).
//   - The query is cookie-authed (same path as `useReceipts`); error normalization
//     happens inside `api.get` via the F001 envelope → ApiError.
//   - We cache aggressively (`staleTime: 30s`) because the detail surface is
//     immutable post-commit; refetching only buys us a redundant fetch.
//
// This hook is intentionally a *single* GET; the verify / payload / export
// flows are mutations owned by their respective components (VerifyLocallyButton,
// PayloadTab, ExportEvidenceButton) so each one can carry its own loading +
// error state without coupling.

import { useQuery } from "@tanstack/react-query";

import { api } from "~/lib/api";
import { apiPaths } from "~/lib/apiPaths";
import type { VerifyResponse } from "~/lib/types";

/**
 * Five-step verify-result shape from POST /v1/audit/receipts/:run_id/verify.
 * Each row is one cryptographic check; the SPA renders these as five rows
 * with status icons (green/red) per FR-018.
 *
 * ## Wire types are codegen'd (issue #48 retire-F2)
 *
 * `VerifyResponse`, `VerifyCheck`, and `VerifyCheckName` were hand-maintained
 * here pre-#48. Now derived from `~/lib/types` via the JSON Schema codegen
 * pipeline (`apps/recurse_gateway/priv/schemas/verify_response.json`); the
 * SPA cannot drift again without a schema bump + `pnpm gen:types`. CI gate
 * enforces.
 *
 * `VerifyCheck` and `VerifyCheckName` are derived from the codegen'd
 * `VerifyResponse` via TypeScript indexed-access types so a future schema
 * change to `checks[].name` (e.g., adding a sixth check kind) propagates
 * automatically; no hand-edit required.
 */
export type { VerifyResponse } from "~/lib/types";
export type VerifyCheck = VerifyResponse["checks"][number];
export type VerifyCheckName = VerifyCheck["name"];

/**
 * Receipt Detail wire shape. Mirrors the F002 split-envelope (signed_predicate +
 * outer_container) with the F004 detail extension fields appended. We keep
 * everything optional / nullable to match the flexible JSON Schemas in
 * `apps/recurse_gateway/priv/schemas/attestation.json` (the placeholder
 * `Attestation` interface in `lib/types.ts` is `[k: string]: unknown` today).
 */
export interface ReceiptDetail {
  run_id: string;
  signed_predicate: {
    run_id: string;
    session_id: string | null;
    turn_id: string | null;
    event_kind: string | null;
    machine_identity: string | null;
    principal: string | null;
    /** Structured principal — F004 detail extension. */
    principal_detail?: {
      kind: string;
      subject: string;
      display_name?: string | null;
      groups?: string[] | null;
    } | null;
    tenant_id: string | null;
    policy_canonical_hash: string | null;
    payload_hash: string | null;
    payload_uri: string | null;
    correlation_id: string | null;
    signer_kms_key_id: string | null;
    signer_key_version: string | null;
    timestamp: string | null;
    /** Free-form predicate detail — rendered as JSON in the Predicate tab. */
    predicate?: Record<string, unknown> | null;
  };
  outer_container: {
    verification_level: string | null;
    tier_completeness_advisory: string | null;
    session_chain_epoch: number | null;
    session_chain_root: string | null;
    policy_decision: "allow" | "deny" | null;
    outcome: string | null;
    upstream_status_code: number | null;
    commit_retry_exhausted: boolean | null;
    /**
     * Tool-call extractor enriched tags (Wave C). Mirrors the receipts
     * list shape — schema-on-read; stable top-level keys (`category`,
     * `display_summary`, `scope_kind`, `scope_value`,
     * `target_resources`, `semantic_args`). Null for non-tool_call
     * rows AND for tool_call rows imported before the extractor
     * pipeline existed.
     *
     * Hand-maintained TS type (the receipt detail endpoint has no JSON
     * Schema yet — F2 closed the receipts LIST schema but the DETAIL
     * surface is in the 27-other-hand-maintained sweep filed as #50).
     * When that sweep lands, this field becomes codegen'd from the new
     * `audit_receipts_detail_response.json`.
     */
    tags?: { [k: string]: unknown } | null;
  };
  /** Full Merkle inclusion proof envelope (F004 detail extension). */
  proof?: {
    leaf_hash: string;
    /** Sibling hashes for the local (epoch) Merkle path, leaf → epoch root. */
    local_path?: Array<{ sibling: string; direction: "left" | "right" }>;
    epoch_root?: string | null;
    /** Sibling hashes for the global Merkle path, epoch root → global root. */
    global_path?: Array<{ sibling: string; direction: "left" | "right" }>;
    global_root?: string | null;
    /** RFC 9162 STH (signed tree head) — opaque base64 for now. */
    sth?: string | null;
  } | null;
  /** Matched policy line range (FR-018 — Cedar source highlighting). */
  matched_policy?: {
    bundle_id: string | null;
    file: string | null;
    line_start: number | null;
    line_end: number | null;
    /** Cedar source excerpt; the full bundle isn't shipped per response. */
    source_excerpt: string | null;
  } | null;
}

const DETAIL_PATH = (runId: string) => apiPaths.audit.receiptDetail(runId);
const VERIFY_PATH = (runId: string) => apiPaths.audit.verify(runId);
const PAYLOAD_PATH = (runId: string) => apiPaths.audit.payload(runId);

/**
 * Receipt-detail query key. Pinned to `['receipt', runId]` so a `setQueryData`
 * write from a Live-tail update can't accidentally invalidate a per-row cache.
 */
export function receiptDetailQueryKey(runId: string): readonly unknown[] {
  return ["receipt", runId] as const;
}

/**
 * Single-receipt fetch. Disabled when `runId` is absent so callers can mount
 * the hook before the URL params resolve (e.g. inside a route component).
 */
export function useReceiptDetail(runId: string | undefined) {
  return useQuery<ReceiptDetail, Error>({
    queryKey: receiptDetailQueryKey(runId ?? ""),
    queryFn: () => api.get<ReceiptDetail>(DETAIL_PATH(runId ?? "")),
    enabled: !!runId,
    staleTime: 30_000,
  });
}

/** Public path helpers for the verify/payload mutations. Re-exported so the
 *  component-level `useMutation` callers don't have to repeat the URL shape. */
export const receiptDetailPaths = {
  verify: VERIFY_PATH,
  payload: PAYLOAD_PATH,
} as const;
