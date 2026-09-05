// useBlastRadius — TanStack Query hook for the F004 Blast Radius dry-run
// surface (T095 — Phase 5 US3).
//
// Per `contracts/audit_api_extensions.md` §"Policy drafts" + `contracts/blast_radius_algorithm.md`:
//   - POST /v1/policy/drafts/{id}/dry-run kicks off the computation.
//     ≤10K-receipt windows return 200 with the full summary; larger windows
//     return 202 with `{job_id, poll_url}`.
//   - On 202, the SPA polls `GET <poll_url>` (typically
//     `/v1/policy/drafts/{id}/dry-run/{job_id}`) at 1 Hz until the job
//     finishes. Phoenix.PubSub via the live-tail WebSocket bridge is reserved
//     as a polish-time optimization — Phase-5 ships polling for simplicity.
//   - The four-cell classification (`matches_intent`, `unintended`,
//     `would_have_allowed`, `no_change`) lives at the response top-level so
//     the UI's `<BlastRadiusPanel />` can render the FR-026 + FR-027 surface.
//
// Cache key shape: keyed on `(draft_id, window_days)` so re-running with a
// different window doesn't shadow the previous result.

import {
  useMutation,
  useQuery,
  useQueryClient,
  type UseMutationResult,
  type UseQueryResult,
} from "@tanstack/react-query";
import { useCallback, useState } from "react";

import { api, useApiErrorHandler } from "~/lib/api";
import { apiPaths } from "~/lib/apiPaths";

// ---------------------------------------------------------------------------
// Wire shape
// ---------------------------------------------------------------------------

export type BlastRadiusClassification =
  | "matches_intent"
  | "unintended"
  | "would_have_allowed"
  | "no_change";

/** A single sample receipt entry returned alongside the counts. */
export interface BlastRadiusSampleReceipt {
  run_id: string;
  classification: BlastRadiusClassification;
  /** Optional one-line summary; falls back to run_id when absent. */
  summary?: string;
  committed_at?: string;
}

/** Synchronous (or completed-async) Blast Radius result. */
export interface BlastRadiusResult {
  draft_id: string;
  window_days: number;
  total_receipts_in_window: number;
  total_affected: number;
  matches_intent: number;
  unintended: number;
  would_have_allowed: number;
  no_change: number;
  sample_receipts: BlastRadiusSampleReceipt[];
  computed_at: string;
  attested_run_id?: string | null;
}

/** 202-Accepted async-job envelope. */
export interface BlastRadiusJobAccepted {
  draft_id: string;
  job_id: string;
  poll_url: string;
}

/** Discriminated union of dry-run responses. */
export type DryRunInitialResponse =
  | { kind: "sync"; result: BlastRadiusResult }
  | { kind: "async"; job: BlastRadiusJobAccepted };

/** Polled job status. `state: "complete"` carries the full result. */
export type BlastRadiusJobStatus =
  | { state: "pending" | "running" }
  | {
      state: "complete";
      result: BlastRadiusResult;
    }
  | {
      state: "failed";
      error: string;
    };

export interface DryRunRequest {
  /** Default = backend default (30 days). */
  window_days?: number;
  /** Force async even for small windows. */
  async?: boolean;
}

const DRY_RUN_PATH = (id: string) => apiPaths.policy.dryRun(id);

const DRY_RUN_POLL_PATH = (id: string, jobId: string) =>
  `${apiPaths.policy.dryRun(id)}/${encodeURIComponent(jobId)}`;

const POLL_INTERVAL_MS = 1_000;

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

/**
 * Heuristic — the API returns a flat shape for sync, `{job_id, poll_url}` for
 * async. We branch on the presence of `job_id` since the SPA can't easily
 * read the HTTP status code through the shared `api` wrapper.
 */
function isAsyncResponse(
  body: BlastRadiusResult | BlastRadiusJobAccepted,
): body is BlastRadiusJobAccepted {
  return (
    typeof (body as BlastRadiusJobAccepted).job_id === "string" &&
    typeof (body as BlastRadiusJobAccepted).poll_url === "string"
  );
}

// ---------------------------------------------------------------------------
// Mutation — kicks off the dry-run
// ---------------------------------------------------------------------------

interface KickoffArgs {
  draftId: string;
  request?: DryRunRequest;
}

export function useBlastRadiusKickoff(): UseMutationResult<
  DryRunInitialResponse,
  Error,
  KickoffArgs
> {
  const handleApiError = useApiErrorHandler();
  return useMutation<DryRunInitialResponse, Error, KickoffArgs>({
    mutationFn: async ({ draftId, request }) => {
      const body = await api.post<BlastRadiusResult | BlastRadiusJobAccepted>(
        DRY_RUN_PATH(draftId),
        request ?? {},
      );
      if (isAsyncResponse(body)) {
        return { kind: "async", job: body };
      }
      return { kind: "sync", result: body };
    },
    onError: handleApiError,
  });
}

// ---------------------------------------------------------------------------
// Query — polls a long-running job until completion
// ---------------------------------------------------------------------------

interface PollOptions {
  enabled?: boolean;
  /** Override the default 1Hz polling cadence (e.g. backoff after errors). */
  intervalMs?: number;
}

export function useBlastRadiusPoll(
  draftId: string | undefined,
  jobId: string | undefined,
  options: PollOptions = {},
): UseQueryResult<BlastRadiusJobStatus, Error> {
  const enabled = (options.enabled ?? true) && !!draftId && !!jobId;
  return useQuery<BlastRadiusJobStatus, Error>({
    queryKey: ["blast_radius_job", draftId ?? "", jobId ?? ""] as const,
    queryFn: () =>
      api.get<BlastRadiusJobStatus>(DRY_RUN_POLL_PATH(draftId ?? "", jobId ?? "")),
    enabled,
    refetchInterval: (query) => {
      const data = query.state.data;
      if (!data) return options.intervalMs ?? POLL_INTERVAL_MS;
      if (data.state === "complete" || data.state === "failed") return false;
      return options.intervalMs ?? POLL_INTERVAL_MS;
    },
  });
}

// ---------------------------------------------------------------------------
// Combined hook — ergonomic single entry point used by the BlastRadiusPanel.
// ---------------------------------------------------------------------------

export interface UseBlastRadiusReturn {
  /** Final result (sync OR completed-async). `null` until ready. */
  result: BlastRadiusResult | null;
  /** Job state when running async. `null` for sync runs. */
  jobStatus: BlastRadiusJobStatus | null;
  /** True while waiting for either the kickoff or the polling job. */
  isPending: boolean;
  /** Kickoff error OR poll error. */
  error: Error | null;
  /**
   * Trigger a dry-run. Resets prior state on each call. Per F002 fix-pass-2,
   * the call accepts an explicit `draftId` override so the parent can pass
   * the freshly-created draft id directly from `createDraft.onSuccess`
   * without waiting for the closure'd `useBlastRadius(draftId)` to
   * re-render. Defaults to the hook's bound `draftId` when omitted.
   */
  run: (overrides?: { draftId?: string; request?: DryRunRequest }) => void;
  /** Reset back to idle (e.g. after the user edits the draft). */
  reset: () => void;
}

/**
 * High-level wrapper combining kickoff + poll. The component just calls
 * `run()` and reads `{result, isPending, error}` — the async/sync seam is
 * opaque.
 *
 * Per F002 — `run` accepts an optional `{draftId}` override so callers
 * coordinating with a `createDraft.onSuccess` flow can hand the freshly
 * created id straight through instead of relying on the next render to
 * re-bind the closure. Without the override, the FIRST dry-run after a
 * brand-new draft no-ops because `useBlastRadius(undefined).run()`
 * early-returns on the stale `!draftId` guard.
 */
export function useBlastRadius(
  draftId: string | undefined,
): UseBlastRadiusReturn {
  const qc = useQueryClient();
  const kickoff = useBlastRadiusKickoff();

  // We hold the in-flight job_id in component state so the polling query key
  // is stable across re-renders. `null` means we're either idle or in a
  // sync-completed state.
  const [jobId, setJobId] = useState<string | null>(null);
  const [pollDraftId, setPollDraftId] = useState<string | null>(null);
  const [syncResult, setSyncResult] = useState<BlastRadiusResult | null>(null);

  // Polling uses whichever draftId the kickoff was fired against (override
  // OR hook-bound). Falls back to the hook-bound `draftId` so the polling
  // key is stable when no override is in flight.
  const poll = useBlastRadiusPoll(pollDraftId ?? draftId, jobId ?? undefined, {
    enabled: !!jobId,
  });

  const run = useCallback(
    (overrides?: { draftId?: string; request?: DryRunRequest }) => {
      const targetDraftId = overrides?.draftId ?? draftId;
      if (!targetDraftId) return;
      // Clear prior state so the panel renders the in-flight UI immediately.
      setJobId(null);
      setSyncResult(null);
      setPollDraftId(targetDraftId);
      kickoff.mutate(
        { draftId: targetDraftId, request: overrides?.request },
        {
          onSuccess: (resp) => {
            if (resp.kind === "sync") {
              setSyncResult(resp.result);
            } else {
              setJobId(resp.job.job_id);
            }
          },
        },
      );
    },
    [draftId, kickoff],
  );

  const reset = useCallback(() => {
    setJobId(null);
    setPollDraftId(null);
    setSyncResult(null);
    kickoff.reset();
    if (draftId) {
      qc.removeQueries({ queryKey: ["blast_radius_job", draftId] });
    }
  }, [draftId, kickoff, qc]);

  // Resolve the final result from whichever path completed.
  let result: BlastRadiusResult | null = syncResult;
  let jobStatus: BlastRadiusJobStatus | null = poll.data ?? null;
  if (jobStatus && jobStatus.state === "complete") {
    result = jobStatus.result;
  }

  const isPending =
    kickoff.isPending ||
    (jobId !== null &&
      jobStatus !== null &&
      (jobStatus.state === "pending" || jobStatus.state === "running"));

  const error: Error | null =
    kickoff.error ??
    poll.error ??
    (jobStatus && jobStatus.state === "failed"
      ? new Error(jobStatus.error)
      : null);

  return { result, jobStatus, isPending, error, run, reset };
}
