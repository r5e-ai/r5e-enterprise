// VerifyTab — 5-check verification ladder for the Receipt Drawer's
// VERIFY tab (R2 redesign).
//
// Per `design/briefs/03-receipt-drawer.md`:
//   - StatusPill at top: VALID (green) / INVALID (red) / PENDING
//   - 5 check rows:
//       1. Signature                — DSSE ES256 verified vs archived KMS pubkey
//       2. Payload hash             — SHA-256 over canonical predicate bytes
//       3. Policy canonical hash    — Cedar bundle hash matches archived
//       4. Local inclusion proof    — RFC 9162 path verifies against session root
//       5. Global inclusion proof   — Session root included in global ledger
//   - Each row: ✓ green or ✗ red icon, label, detail (mono where it's an ID).
//
// Wraps the existing 5-check verify mutation but in the brief's ladder layout
// with a top-level StatusPill (rather than `overall <status>` muted text).

import { useMutation } from "@tanstack/react-query";
import { useState } from "react";

import { CheckRow } from "~/components/audit/CheckRow";
import { Pill } from "~/components/shared/Pill";
import { ErrorState } from "~/components/shared/states";
import {
  receiptDetailPaths,
  type VerifyCheckName,
  type VerifyResponse,
} from "~/hooks/useReceiptDetail";
import { ApiError, api, useApiErrorHandler } from "~/lib/api";

interface Props {
  runId: string;
}

// Brief's 5-check order — matches the ladder in `03-receipt-drawer.md`.
// The backend names are stable; the labels + details come from the brief.
const CHECK_ORDER: ReadonlyArray<{
  name: VerifyCheckName;
  testId: string;
  label: string;
  defaultDetail: string;
}> = [
  {
    name: "signature",
    testId: "signature",
    label: "Signature",
    defaultDetail: "DSSE ES256 verified against archived KMS pubkey",
  },
  {
    name: "payload_hash_match",
    testId: "payload_hash",
    label: "Payload hash",
    defaultDetail: "SHA-256 over canonical predicate bytes matches",
  },
  {
    name: "policy_hash_match",
    testId: "policy_hash",
    label: "Policy canonical hash",
    defaultDetail: "Committed policy bundle hash matches archived",
  },
  {
    name: "local_merkle_inclusion",
    testId: "local_merkle",
    label: "Local inclusion proof",
    defaultDetail: "RFC 9162 path verifies against session Merkle root",
  },
  {
    name: "global_merkle_inclusion",
    testId: "global_merkle",
    label: "Global inclusion proof",
    defaultDetail: "Session root included in global ledger at epoch N",
  },
] as const;

type RowState = "pending" | "running" | "pass" | "fail";

const PENDING_STATES: Record<VerifyCheckName, RowState> = {
  signature: "pending",
  local_merkle_inclusion: "pending",
  global_merkle_inclusion: "pending",
  policy_hash_match: "pending",
  payload_hash_match: "pending",
};

const RUNNING_STATES: Record<VerifyCheckName, RowState> = {
  signature: "running",
  local_merkle_inclusion: "running",
  global_merkle_inclusion: "running",
  policy_hash_match: "running",
  payload_hash_match: "running",
};

const FAIL_STATES: Record<VerifyCheckName, RowState> = {
  signature: "fail",
  local_merkle_inclusion: "fail",
  global_merkle_inclusion: "fail",
  policy_hash_match: "fail",
  payload_hash_match: "fail",
};

export function VerifyTab({ runId }: Props): JSX.Element {
  const [rowStates, setRowStates] =
    useState<Record<VerifyCheckName, RowState>>(PENDING_STATES);
  const [details, setDetails] =
    useState<Partial<Record<VerifyCheckName, string>>>({});
  const handleApiError = useApiErrorHandler();

  const mutation = useMutation<VerifyResponse, Error, void>({
    mutationFn: () => api.post<VerifyResponse>(receiptDetailPaths.verify(runId)),
    onMutate: () => {
      setRowStates(RUNNING_STATES);
      setDetails({});
    },
    onSuccess: (data) => {
      const next: Record<VerifyCheckName, RowState> = { ...PENDING_STATES };
      const det: Partial<Record<VerifyCheckName, string>> = {};
      for (const c of data.checks) {
        next[c.name] = c.status === "pass" ? "pass" : "fail";
        det[c.name] = c.explanation;
      }
      setRowStates(next);
      setDetails(det);
    },
    onError: (error) => {
      setRowStates(FAIL_STATES);
      handleApiError(error);
    },
  });

  // Backend ships `overall_status` as `"pass"` / `"fail"`; the brief calls
  // for the user-facing pill to read VALID / INVALID. Map at render time.
  const overallStatus = mutation.data?.overall_status ?? null;
  const hasRun = !!mutation.data;
  const overallTone =
    overallStatus === "pass"
      ? "success"
      : overallStatus === "fail"
        ? "danger"
        : "muted";
  const overallLabel =
    overallStatus === "pass"
      ? "VALID"
      : overallStatus === "fail"
        ? "INVALID"
        : mutation.isPending
          ? "VERIFYING…"
          : "PENDING";

  return (
    <div className="flex flex-col gap-3" data-testid="verify-tab">
      <div className="flex items-center justify-between">
        <Pill
          tone={overallTone}
          size="md"
          testId="verify-overall-status"
        >
          {overallLabel}
        </Pill>
        <button
          type="button"
          onClick={() => mutation.mutate()}
          disabled={mutation.isPending}
          className="rounded bg-r5e-accent px-3 py-1.5 text-xs font-semibold uppercase tracking-[0.1em] text-white hover:bg-r5e-accent/90 disabled:cursor-not-allowed disabled:opacity-50"
          data-testid="verify-locally-button"
        >
          {mutation.isPending
            ? "Verifying…"
            : hasRun
              ? "Re-verify"
              : "Verify Locally"}
        </button>
      </div>

      {mutation.isError && mutation.error instanceof ApiError && (
        <ErrorState
          compact
          title="Verification failed"
          detail={mutation.error.error_description}
          retry={{ onClick: () => mutation.mutate() }}
          testId="verify-error"
        />
      )}

      <ul
        className="flex flex-col divide-y divide-r5e-border/40 rounded border border-r5e-border bg-r5e-surface"
        data-testid="verify-checks-list"
      >
        {CHECK_ORDER.map((c) => {
          const state = rowStates[c.name];
          const detail = details[c.name] ?? c.defaultDetail;
          return (
            <CheckRow
              key={c.name}
              testId={`verify-row-${c.testId}`}
              label={c.label}
              detail={detail}
              state={state}
            />
          );
        })}
      </ul>
    </div>
  );
}
