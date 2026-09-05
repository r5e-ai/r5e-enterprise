// useReceipts — TanStack-Query infinite hook backing the Dashboard table
// (T066, Phase 3 US1).
//
// Per `contracts/frontend_architecture.md` §"State management" + audit_api_extensions.md
// `GET /v1/audit/receipts` shape:
//   - Cursor pagination via opaque server-signed `cursor` token (D8).
//   - Filter state lives in URL search params (`useSearchParams`); the hook
//     accepts a typed filter object so callers can compose URL → filter
//     translation in one place (see `Dashboard.tsx`).
//   - Filter changes invalidate the prior page set automatically because the
//     `queryKey` includes the serialized filter shape — TanStack Query
//     fetches a fresh first page when the key changes.
//   - The hook returns the standard infinite-query surface; the Dashboard
//     flattens `data.pages` into a single virtualized list.
//
// ## Wire types are codegen'd (issue #48 retire-F2)
//
// `ReceiptsPage`, `ReceiptRow`, `ReceiptsFacets` were hand-maintained TS
// interfaces in this file pre-issue-#48. They drifted from the backend
// (most notably: `signed_predicate.machine_identity` and `signed_predicate.principal`
// were typed as `string | null` here when the handler emits JSONB maps).
// Now derived from `~/lib/types` via the JSON Schema codegen pipeline
// (`apps/recurse_gateway/priv/schemas/audit_receipts_list_response.json`),
// so the SPA cannot drift again without a schema bump + `pnpm gen:types`
// regeneration. CI gate: `pnpm gen:types && git diff --exit-code src/lib/types.ts`.
//
// `ReceiptsFilter` stays hand-maintained — it's an SPA-internal URL-param
// shape (composed by `Dashboard.tsx` from `useSearchParams`), NOT a wire
// shape the backend emits. Codegen-from-JSON-Schema doesn't apply here
// because the filter goes OUT as query params, not as a JSON body.

import { useInfiniteQuery, type InfiniteData } from "@tanstack/react-query";

import { api } from "~/lib/api";
import { apiPaths } from "~/lib/apiPaths";
import type { AuditReceiptsListResponse } from "~/lib/types";

/** Public filter shape consumed by `Dashboard.tsx`. */
export interface ReceiptsFilter {
  event_kind?: string;
  policy_decision?: "allow" | "deny";
  principal_subject?: string;
  session_id?: string;
  turn_id?: string;
  verification_level?:
    | "signed"
    | "local_inclusion_verified"
    | "global_inclusion_verified";
  tier_completeness_advisory?: "partial" | "full";
  /** ISO 8601 timestamp; rendered into `since=` on the wire (server reads as filter). */
  since?: string;
  /**
   * ISO 8601 timestamp; closes the time window above the receipts list.
   * Wired through to the URL + page request, but as of the F004 ship the
   * receipts handler does NOT push `until` to SQL (see #45). The Histogram
   * component clamps its render to `[since, until]` client-side regardless,
   * so the visible chart matches the URL state. Backend pushdown is filed
   * as a follow-up.
   */
  until?: string;
  /** Free-text search (server-side fuzzy match). Optional — wire shape only when set. */
  q?: string;
}

/**
 * Page envelope returned by `GET /v1/audit/receipts`. Codegen'd from
 * `apps/recurse_gateway/priv/schemas/audit_receipts_list_response.json`.
 */
export type ReceiptsPage = AuditReceiptsListResponse;

/**
 * A single row from the receipts page (F001 split-envelope shape per
 * `ReceiptSerializers.signed_predicate/2` + `outer_container/2` default opts).
 * Indexed-access type from the codegen'd `AuditReceiptsListResponse` so a
 * future schema bump propagates here automatically.
 */
export type ReceiptRow = AuditReceiptsListResponse["receipts"][number];

/**
 * Facet aggregations returned when the request sets `?facets=true`.
 * Counts are computed by the backend over the FULL filtered universe via
 * SQL `GROUP BY` (NOT the paginated page), so the dashboard's left-rail
 * picker can render correct totals regardless of LIMIT/cursor — see
 * `Recurse.Gateway.AuditPlane.ReceiptsHandler.compute_facets/1` and the
 * backing `PostgresMerkleLedger.query_facets/1`. Issue #44 (2026-04-30).
 *
 * Each axis is a string→count map. Kinds with zero rows in the filtered
 * set are ABSENT from the map (the SPA fills them in at count 0 from the
 * canonical enum at `~/lib/event_kinds.ts`).
 */
export type ReceiptsFacets = NonNullable<AuditReceiptsListResponse["facets"]>;

const DEFAULT_PAGE_SIZE = 100;
const RECEIPTS_PATH = apiPaths.audit.receipts;

/**
 * Build the deterministic query key. Two filters with the same fields in
 * different declaration order MUST produce the same cache entry, so we sort
 * keys before stringification.
 */
export function receiptsQueryKey(filter: ReceiptsFilter): readonly unknown[] {
  const sorted: Record<string, string> = {};
  for (const key of Object.keys(filter).sort()) {
    const value = filter[key as keyof ReceiptsFilter];
    if (value !== undefined && value !== "") sorted[key] = String(value);
  }
  return ["receipts", sorted] as const;
}

function buildPath(
  filter: ReceiptsFilter,
  cursor: string | undefined,
  facets: boolean,
): string {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(filter)) {
    if (value !== undefined && value !== "") params.set(key, String(value));
  }
  if (cursor !== undefined) params.set("cursor", cursor);
  if (!params.has("limit")) params.set("limit", String(DEFAULT_PAGE_SIZE));
  if (facets) params.set("facets", "true");
  const qs = params.toString();
  return qs ? `${RECEIPTS_PATH}?${qs}` : RECEIPTS_PATH;
}

export interface UseReceiptsOptions {
  /**
   * If true, requests `?facets=true` so each page envelope includes
   * per-axis counts over the FULL filtered universe (NOT just this
   * page). The Dashboard left-rail picker uses this for correct
   * counts; consumers that only show the table (e.g. a session
   * timeline) can leave it false and skip the extra GROUP BY round
   * trip. Defaults to false for back-compat with existing callers.
   */
  facets?: boolean;
}

export function useReceipts(filter: ReceiptsFilter, options: UseReceiptsOptions = {}) {
  const facets = options.facets === true;
  return useInfiniteQuery<
    ReceiptsPage,
    Error,
    InfiniteData<ReceiptsPage, string | undefined>,
    readonly unknown[],
    string | undefined
  >({
    queryKey: [...receiptsQueryKey(filter), { facets }] as const,
    queryFn: ({ pageParam }) =>
      api.get<ReceiptsPage>(buildPath(filter, pageParam, facets)),
    initialPageParam: undefined,
    getNextPageParam: (lastPage) => lastPage.cursor ?? undefined,
    staleTime: 5_000,
  });
}
