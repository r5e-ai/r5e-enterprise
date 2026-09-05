// useLiveTail — bridges the LiveTailClient to TanStack Query's cache for
// the Dashboard's audit-log table (T067, Phase 3 US1).
//
// Per `contracts/frontend_architecture.md` §"Live-tail integration" +
// `contracts/live_tail_transport.md` §"SPA row cap and eviction":
//   - Connects when `enabled === true`; closes on unmount or toggle-off.
//   - Prepends incoming `attestation` frames into the first page of the
//     receipts infinite-query cache via `setQueryData`.
//   - Enforces the 5,000-row default cap; evicts oldest non-pinned rows
//     FIFO when the cap is exceeded.
//   - Pinned rows survive eviction. Three pin sources are passed in by the
//     caller (`pinned` Set<string>): user-selected (bulk action), favorited,
//     in-scroll-viewport.
//   - Fires a one-time toast on first eviction in the session and a
//     `Live-tail paused` toast when all rows are pinned (incoming frames are
//     dropped — there is nothing to evict).
//   - Surfaces backfill truncation via toast.
//
// The toast surface is intentionally minimal — we publish toasts via a tiny
// in-module event bus so the Dashboard (or any component) can render them
// without coupling this hook to a specific toast library.

import { useEffect, useRef } from "react";
import { useQueryClient, type InfiniteData } from "@tanstack/react-query";

import { apiPaths } from "~/lib/apiPaths";
import {
  LiveTailClient,
  type AttestationFrame,
  type ReceiptFilter,
} from "~/lib/live_tail";
import {
  receiptsQueryKey,
  type ReceiptsFilter,
  type ReceiptRow,
  type ReceiptsPage,
} from "~/hooks/useReceipts";

const DEFAULT_MAX_ROWS = 5_000;
const LIVE_TAIL_PATH = apiPaths.liveTail;

// ---------------------------------------------------------------------------
// Lightweight toast event bus
// ---------------------------------------------------------------------------

export type LiveTailToast = {
  id: string;
  /** Stable key — identical IDs are de-duplicated within a session. */
  kind: "trim" | "paused" | "backfill_truncated" | "fatal";
  message: string;
};

type ToastListener = (toast: LiveTailToast) => void;

const toastListeners = new Set<ToastListener>();
const oneTimeFired = new Set<string>();

/** Subscribe to live-tail toasts. Returns an unsubscribe function. */
export function subscribeLiveTailToasts(listener: ToastListener): () => void {
  toastListeners.add(listener);
  return () => toastListeners.delete(listener);
}

function emitToast(toast: LiveTailToast, options: { once?: boolean } = {}): void {
  if (options.once) {
    if (oneTimeFired.has(toast.id)) return;
    oneTimeFired.add(toast.id);
  }
  toastListeners.forEach((cb) => cb(toast));
}

// ---------------------------------------------------------------------------
// Filter conversion: SPA filter shape → wire filter shape
// ---------------------------------------------------------------------------

function toWireFilter(filter: ReceiptsFilter): ReceiptFilter {
  const wire: ReceiptFilter = {};
  if (filter.event_kind) wire.event_kind = [filter.event_kind];
  if (filter.policy_decision) wire.policy_decision = filter.policy_decision;
  if (filter.principal_subject)
    wire.principal_subject = filter.principal_subject;
  if (filter.since) wire.since = filter.since;
  return wire;
}

// ---------------------------------------------------------------------------
// Convert an attestation frame to a row shape consumed by the table
// ---------------------------------------------------------------------------

// Live-tail frames carry a thinner shape than the paginated GET; the
// SPA materializes a `ReceiptRow` from the SSE frame so the table can
// render newly-arrived attestations without waiting for a refetch.
// The cast at the verification_level edge is the SSE frame → schema
// adaptation: the wire frame ships `verification_level` as `string` for
// SSE-stream looseness; the receipts list schema (post-#48) pins it to
// the canonical 3-atom enum. Live-tail frames in practice carry the
// same atoms, so the cast is shape-stable; if a future frame leaks an
// unknown verification_level the row's pill renderer renders a neutral
// fallback.
const KNOWN_VERIFICATION_LEVELS = new Set([
  "signed",
  "local_inclusion_verified",
  "global_inclusion_verified",
]);

type RowVerificationLevel = ReceiptRow["outer_container"]["verification_level"];

function narrowVerificationLevel(value: string): RowVerificationLevel {
  return KNOWN_VERIFICATION_LEVELS.has(value)
    ? (value as RowVerificationLevel)
    : null;
}

function frameToRow(frame: AttestationFrame): ReceiptRow {
  return {
    run_id: frame.run_id,
    signed_predicate: {
      run_id: frame.run_id,
      session_id: frame.session_id,
      turn_id: null,
      event_kind: frame.event_kind,
      machine_identity: null,
      // Wire schema (post-#48): principal is a JSON object, not a flat
      // string — fixed across `useReceipts.ReceiptRow`. Live-tail frames
      // carry only the subject string; wrap it in the object shape so
      // the row materialized here is the same shape as a row arriving
      // via the paginated GET. Downstream renderers read
      // `principal.subject` (or fall back to `account_id`).
      principal: { subject: frame.principal_subject },
      tenant_id: frame.tenant_id,
      policy_canonical_hash: null,
      payload_hash: null,
      payload_uri: null,
      correlation_id: null,
      signer_kms_key_id: null,
      signer_key_version: null,
      timestamp: frame.committed_at,
      // B7 — live-tail frames don't carry tool detail; a row arriving
      // via SSE will read tool_name/tool_summary as null (the row will
      // re-render with full detail once it lands in the paginated
      // listing on the next refetch).
      tool_name: null,
      tool_summary: null,
    },
    outer_container: {
      verification_level: narrowVerificationLevel(frame.verification_level),
      tier_completeness_advisory: null,
      session_chain_epoch: null,
      session_chain_root: null,
      policy_decision: frame.policy_decision,
      outcome: null,
      upstream_status_code: null,
      commit_retry_exhausted: null,
      // tags arrives on the row's first paginated refetch; live-tail SSE
      // frames don't carry the extracted enrichment.
      tags: null,
    },
  };
}

// ---------------------------------------------------------------------------
// Eviction
// ---------------------------------------------------------------------------

interface EvictionResult {
  rows: ReceiptRow[];
  evictionCount: number;
  /** True when no eviction was possible (every row is pinned). */
  stalled: boolean;
}

/**
 * Drop the oldest non-pinned rows until `rows.length <= maxRows`. Returns the
 * surviving rows, the number evicted, and a `stalled` flag (true when the
 * cap is exceeded but nothing can be evicted because every row is pinned).
 *
 * The implementation walks the tail (oldest end) backwards looking for
 * non-pinned rows to drop. With at most a handful of pins relative to the
 * cap (5,000), the inner loop is O(maxRows) worst-case but typically O(k)
 * where k is the small overflow.
 */
function evictOldestNonPinned(
  rows: ReceiptRow[],
  maxRows: number,
  pinned: Set<string>,
): EvictionResult {
  if (rows.length <= maxRows) {
    return { rows, evictionCount: 0, stalled: false };
  }

  const toEvict = rows.length - maxRows;
  const survived: ReceiptRow[] = [];
  let evicted = 0;

  // Walk from oldest (end of array — newest is index 0) backwards.
  // Reverse iteration so we pick the oldest non-pinned first.
  const reversed = rows.slice().reverse();
  const keptReversed: ReceiptRow[] = [];
  for (const row of reversed) {
    if (evicted < toEvict && !pinned.has(row.run_id)) {
      evicted += 1;
      continue;
    }
    keptReversed.push(row);
  }
  survived.push(...keptReversed.reverse());

  const stalled = evicted < toEvict;
  return { rows: survived, evictionCount: evicted, stalled };
}

/**
 * Re-paginate a flat row list back into TanStack Query's infinite-query
 * page shape. We stuff every row into the first page so cursor pagination
 * for "load older" still resolves against the original `next_cursor`
 * tokens stored on subsequent pages.
 */
function repaginate(
  rows: ReceiptRow[],
  prior: InfiniteData<ReceiptsPage, string | undefined>,
): InfiniteData<ReceiptsPage, string | undefined> {
  const firstPage: ReceiptsPage = {
    receipts: rows,
    cursor: prior.pages[0]?.cursor ?? null,
  };
  return {
    ...prior,
    pages: [firstPage, ...prior.pages.slice(1)],
  };
}

// ---------------------------------------------------------------------------
// The hook
// ---------------------------------------------------------------------------

export interface UseLiveTailOptions {
  filter: ReceiptsFilter;
  enabled: boolean;
  /** run_ids the SPA wants to keep regardless of overflow. */
  pinned: Set<string>;
  /** Override the 5,000 default cap (e.g., for tests or tier-config). */
  maxRows?: number;
}

export function useLiveTail({
  filter,
  enabled,
  pinned,
  maxRows = DEFAULT_MAX_ROWS,
}: UseLiveTailOptions): void {
  const queryClient = useQueryClient();
  const clientRef = useRef<LiveTailClient | null>(null);
  // Pinned set + filter must be readable inside the WebSocket callback
  // without re-subscribing on every render.
  const pinnedRef = useRef(pinned);
  pinnedRef.current = pinned;
  const filterRef = useRef(filter);
  filterRef.current = filter;

  // Re-key for hook re-run when the filter or enabled state changes.
  const filterKey = JSON.stringify(filter);

  useEffect(() => {
    if (!enabled) return;

    const client = new LiveTailClient(LIVE_TAIL_PATH, toWireFilter(filter));
    clientRef.current = client;

    client.on("attestation", (frame: AttestationFrame) => {
      const key = receiptsQueryKey(filterRef.current);
      queryClient.setQueryData<InfiniteData<ReceiptsPage, string | undefined>>(
        key,
        (old) => {
          const newRow = frameToRow(frame);
          if (!old || old.pages.length === 0) {
            // No prior page set — seed a single-page snapshot so the
            // table shows the new row immediately. Cursor stays null
            // because the user hasn't loaded any older pages yet.
            return {
              pages: [{ receipts: [newRow], cursor: null }],
              pageParams: [undefined],
            };
          }
          const allRows = [
            newRow,
            ...old.pages.flatMap((page) => page.receipts),
          ];
          const result = evictOldestNonPinned(
            allRows,
            maxRows,
            pinnedRef.current,
          );
          if (result.stalled) {
            // Every row is pinned — drop the new row, surface the paused
            // toast, leave the cache untouched.
            emitToast({
              id: "live-tail-paused",
              kind: "paused",
              message:
                "Live-tail paused — clear selection or scroll to resume.",
            });
            return old;
          }
          if (result.evictionCount > 0) {
            emitToast(
              {
                id: "live-tail-trimmed",
                kind: "trim",
                message: `Live-tail trimmed older rows (showing latest ${maxRows}); use the time-range filter to view earlier receipts.`,
              },
              { once: true },
            );
          }
          return repaginate(result.rows, old);
        },
      );
    });

    client.on("backfill_summary", (summary) => {
      if (summary.truncated) {
        emitToast({
          id: "live-tail-backfill-truncated",
          kind: "backfill_truncated",
          message:
            "Some receipts may be missing — refresh to see the full window.",
        });
      }
    });

    client.on("error", (err) => {
      // Recoverable errors (e.g., invalid filter); surface but keep the
      // connection open per the wire contract.
      emitToast({
        id: `live-tail-error-${err.code}`,
        kind: "fatal",
        message: `Live-tail error: ${err.message}`,
      });
    });

    client.on("close", (ev) => {
      if (ev.code === 4001 || ev.code === 4002 || ev.code === 4003) {
        emitToast({
          id: `live-tail-fatal-${ev.code}`,
          kind: "fatal",
          message: `Live-tail closed (code ${ev.code}); please refresh.`,
        });
      }
    });

    client.open();

    return () => {
      client.close();
      clientRef.current = null;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [enabled, filterKey, maxRows, queryClient]);

  // Push filter changes to an open socket (handled inside the client when
  // the underlying ref-tracked filter changes are sent via setFilter).
  useEffect(() => {
    if (clientRef.current) {
      clientRef.current.setFilter(toWireFilter(filter));
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filterKey]);
}

// Exported for unit tests.
export const __test = { evictOldestNonPinned, frameToRow, repaginate };
