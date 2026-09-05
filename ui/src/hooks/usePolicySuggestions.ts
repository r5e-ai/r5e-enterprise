// usePolicySuggestions — TanStack Query hooks for the F004 policy-suggestions
// surface (T136 — Phase 7 US5).
//
// Per `contracts/audit_api_extensions.md` §"Policy suggestions":
//   - GET    /v1/policy/suggestions               — list (cursor-paginated)
//   - GET    /v1/policy/suggestions/{id}          — fetch single (open-in-UI;
//                                                   distinct from list because
//                                                   the open emits an attested
//                                                   PolicySuggestionView)
//   - POST   /v1/policy/suggestions/{id}/adopt    — adopt as draft
//   - POST   /v1/policy/suggestions/{id}/dismiss  — dismiss with optional reason
//   - POST   /v1/policy/suggestions/refresh       — manual rerun (rate-limited
//                                                   per FR-030a; 429 ⇒ retry-after)
//
// Sources, confidence shape, and blast-radius snapshot all match the API
// contract; the UI groups by source when the list grows long and color-grades
// the confidence pill at 90/70 thresholds (per the prompt brief).
//
// All endpoints are cookie-authenticated and the F001 error envelope is
// normalized into `ApiError` by the shared `api` client. Each mutation
// invalidates the suggestions list cache so the surface re-renders without
// explicit refetch wiring.

import {
  useMutation,
  useQuery,
  useQueryClient,
  type UseMutationResult,
  type UseQueryResult,
} from "@tanstack/react-query";

import { api, ApiError, useApiErrorHandler } from "~/lib/api";
import { apiPaths } from "~/lib/apiPaths";

// ---------------------------------------------------------------------------
// Wire shape
// ---------------------------------------------------------------------------

export type PolicySuggestionSource = "heuristic" | "llm";

export type PolicySuggestionStatus =
  | "active"
  | "adopted_as_draft"
  | "dismissed";

/** Inline blast-radius snapshot stored on each suggestion (engine-computed). */
export interface PolicySuggestionBlastRadiusSnapshot {
  total_scanned?: number;
  total_affected?: number;
  matches_intent?: number;
  unintended?: number;
  would_have_allowed?: number;
  no_change?: number;
  computed_at?: string;
}

/** Single suggestion envelope returned by the suggestions endpoints. */
export interface PolicySuggestion {
  id: string;
  source: PolicySuggestionSource;
  /** 0-100 integer per data-model. */
  confidence: number;
  /** Optional human-friendly title (brief 05). Falls back to a derived
   *  one-liner when absent on the wire. */
  title?: string | null;
  /** Optional explanatory body (brief 05). Renders below `title`. */
  body?: string | null;
  /**
   * Legacy single-line summary. Engines emit this today; the brief 05
   * redesign splits it into title+body but we keep this on the type so
   * callers can degrade gracefully when the new fields aren't on the wire.
   */
  pattern_summary: string;
  proposed_cedar: string;
  blast_radius_snapshot?: PolicySuggestionBlastRadiusSnapshot | null;
  /**
   * Up to 5 receipt run_ids that triggered this suggestion. The
   * SuggestionCard's "Triggered by" link opens a popover with these IDs.
   * Optional — falls back to a count-only label when absent.
   */
  triggered_by_receipt_ids?: string[] | null;
  /** When the engine has more matches than the 5 it returns, this carries
   *  the full count for the "17 receipts → view 5 examples" muted line. */
  triggered_by_count?: number | null;
  /** Reason supplied at dismiss-time (when status === "dismissed"). */
  dismiss_reason?: string | null;
  status: PolicySuggestionStatus;
  generated_at: string;
  /** Set when the suggestion has been adopted; back-reference to the draft. */
  adopted_as_draft_id?: string | null;
  inserted_at?: string;
}

export interface PolicySuggestionsListPage {
  suggestions: PolicySuggestion[];
  next_cursor: string | null;
}

export interface PolicySuggestionsListFilter {
  /** Defaults to `active` server-side. */
  status?: PolicySuggestionStatus;
  /** `any` = no source filter (server-side default). */
  source?: PolicySuggestionSource | "any";
  cursor?: string;
  limit?: number;
}

export interface AdoptSuggestionResponse {
  draft_id: string;
  suggestion_id: string;
}

export interface DismissSuggestionPayload {
  /** Legacy camel-shape kept for backwards compat with mock + transitional
   *  backends. The canonical schema-side field name is `dismiss_reason` —
   *  see `apps/recurse_gateway/.../policy_suggestion.ex`. */
  reason?: string;
  /** Canonical wire field — once the backend MR lands plumbing
   *  `dismiss_reason` through `do_dismiss/3` + the schema, the UI will
   *  drop the legacy `reason` alias. */
  dismiss_reason?: string;
}

export interface RefreshSuggestionsPayload {
  /** Defaults to both sources server-side. */
  sources?: PolicySuggestionSource[];
}

export interface RefreshSuggestionsResponse {
  run_id: string;
  sources_triggered: PolicySuggestionSource[];
}

/**
 * Shape returned in the F001-error body when the refresh endpoint is
 * rate-limited (FR-030a). The wire `Retry-After` header value is mirrored
 * here as `retry_after_seconds` so the SPA can render a human-readable toast.
 */
export interface RefreshRateLimitedDetail {
  retry_after_seconds: number;
}

// ---------------------------------------------------------------------------
// Path helpers
// ---------------------------------------------------------------------------

const SUGGESTIONS_PATH = apiPaths.suggestions.list;
const SUGGESTION_PATH = (id: string) => apiPaths.suggestions.detail(id);
const ADOPT_PATH = (id: string) => apiPaths.suggestions.adopt(id);
const DISMISS_PATH = (id: string) => apiPaths.suggestions.dismiss(id);
const REFRESH_PATH = apiPaths.suggestions.refresh;

function buildListPath(filter: PolicySuggestionsListFilter): string {
  const params = new URLSearchParams();
  if (filter.status) params.set("status", filter.status);
  if (filter.source && filter.source !== "any") {
    params.set("source", filter.source);
  }
  if (filter.cursor) params.set("cursor", filter.cursor);
  if (filter.limit !== undefined) params.set("limit", String(filter.limit));
  const qs = params.toString();
  return qs ? `${SUGGESTIONS_PATH}?${qs}` : SUGGESTIONS_PATH;
}

// ---------------------------------------------------------------------------
// Query keys
// ---------------------------------------------------------------------------

export function policySuggestionsListKey(
  filter: PolicySuggestionsListFilter,
): readonly unknown[] {
  const sorted: Record<string, string> = {};
  for (const key of Object.keys(filter).sort()) {
    const value = filter[key as keyof PolicySuggestionsListFilter];
    if (value !== undefined && value !== "") sorted[key] = String(value);
  }
  return ["policy_suggestions", "list", sorted] as const;
}

export function policySuggestionKey(id: string | undefined): readonly unknown[] {
  return ["policy_suggestions", "one", id ?? ""] as const;
}

// ---------------------------------------------------------------------------
// Read hooks
// ---------------------------------------------------------------------------

/** List suggestions. Defaults to `status=active`. */
export function usePolicySuggestionsList(
  filter: PolicySuggestionsListFilter = {},
): UseQueryResult<PolicySuggestionsListPage, Error> {
  return useQuery<PolicySuggestionsListPage, Error>({
    queryKey: policySuggestionsListKey(filter),
    queryFn: () =>
      api.get<PolicySuggestionsListPage>(buildListPath(filter)),
    staleTime: 10_000,
  });
}

/** Fetch a single suggestion (this *opens* it in the UI per the contract). */
export function usePolicySuggestion(
  id: string | undefined,
): UseQueryResult<PolicySuggestion, Error> {
  return useQuery<PolicySuggestion, Error>({
    queryKey: policySuggestionKey(id),
    queryFn: () => api.get<PolicySuggestion>(SUGGESTION_PATH(id ?? "")),
    enabled: !!id,
    staleTime: 5_000,
  });
}

// ---------------------------------------------------------------------------
// Mutations
// ---------------------------------------------------------------------------

function invalidateSuggestionLists(qc: ReturnType<typeof useQueryClient>): void {
  qc.invalidateQueries({ queryKey: ["policy_suggestions", "list"] });
}

/** Adopt a suggestion as a new policy draft. */
export function useAdoptPolicySuggestion(): UseMutationResult<
  AdoptSuggestionResponse,
  Error,
  { id: string }
> {
  const qc = useQueryClient();
  const handleApiError = useApiErrorHandler();
  return useMutation<AdoptSuggestionResponse, Error, { id: string }>({
    mutationFn: ({ id }) => api.post<AdoptSuggestionResponse>(ADOPT_PATH(id)),
    onSuccess: (_resp, { id }) => {
      qc.invalidateQueries({ queryKey: policySuggestionKey(id) });
      invalidateSuggestionLists(qc);
      // The adopt flow creates a new draft on the backend; bust draft caches
      // so the simulator surface picks it up the next time it lists drafts.
      qc.invalidateQueries({ queryKey: ["policy_drafts", "list"] });
    },
    onError: handleApiError,
  });
}

/** Dismiss a suggestion (optionally with a free-form reason). */
export function useDismissPolicySuggestion(): UseMutationResult<
  void,
  Error,
  { id: string; reason?: string }
> {
  const qc = useQueryClient();
  const handleApiError = useApiErrorHandler();
  return useMutation<void, Error, { id: string; reason?: string }>({
    mutationFn: async ({ id, reason }) => {
      const payload: DismissSuggestionPayload = {};
      if (reason) {
        // Send both wire shapes during the transitional window. The backend
        // dismiss handler currently ignores the body entirely
        // (`do_dismiss/3` doesn't read `conn.body_params`); when the
        // follow-up MR lands the schema + handler change, it can pluck off
        // either field while we phase the legacy `reason` out. Mocks +
        // existing fixtures continue to read `reason` so the dismissed-tab
        // card display keeps working in dev.
        //
        // Tracked: backend MR for `dismiss_reason` schema field (see
        // GAN F002 on MR !92, fix-pass-2).
        payload.reason = reason;
        payload.dismiss_reason = reason;
      }
      await api.post<void>(DISMISS_PATH(id), payload);
    },
    onSuccess: (_resp, { id }) => {
      qc.invalidateQueries({ queryKey: policySuggestionKey(id) });
      invalidateSuggestionLists(qc);
    },
    onError: handleApiError,
  });
}

/**
 * Manual refresh — kicks the heuristic + LLM engines outside their regular
 * cadence. Surfaces 429 rate-limit responses (FR-030a) as `RefreshRateLimited`
 * errors carrying the `retry_after_seconds` from the F001 envelope so the
 * caller can render a toast like "Rate limited. Try again in N minutes."
 */
export class RefreshRateLimited extends Error {
  readonly retry_after_seconds: number;
  constructor(retryAfter: number) {
    super(
      `Suggestion refresh is rate-limited; retry in ${retryAfter} second${
        retryAfter === 1 ? "" : "s"
      }.`,
    );
    this.name = "RefreshRateLimited";
    this.retry_after_seconds = retryAfter;
  }
}

/**
 * Heuristic to lift `retry_after_seconds` off whichever shape the gateway
 * surfaces. The contract guarantees the wire `Retry-After` header but we
 * can't read response headers through `apiFetch`; the broker mirrors the
 * value into the F001-envelope body so we can pluck it off the ApiError.
 */
function liftRetryAfter(error: ApiError): number {
  // The error body might either include a `retry_after_seconds` field at the
  // envelope root or nest it under a `details` bag. Prefer the explicit field
  // when it's there; fall back to a conservative 60s otherwise.
  const detail = (error as unknown as { retry_after_seconds?: number })
    .retry_after_seconds;
  if (typeof detail === "number" && detail > 0) return detail;
  return 60;
}

export function useRefreshPolicySuggestions(): UseMutationResult<
  RefreshSuggestionsResponse,
  Error,
  RefreshSuggestionsPayload | void
> {
  const qc = useQueryClient();
  const handleApiError = useApiErrorHandler();
  return useMutation<
    RefreshSuggestionsResponse,
    Error,
    RefreshSuggestionsPayload | void
  >({
    mutationFn: async (payload) => {
      try {
        return await api.post<RefreshSuggestionsResponse>(
          REFRESH_PATH,
          payload ?? {},
        );
      } catch (err) {
        if (err instanceof ApiError && err.status === 429) {
          throw new RefreshRateLimited(liftRetryAfter(err));
        }
        throw err;
      }
    },
    onSuccess: () => {
      // The engine writes new suggestions asynchronously, but invalidating
      // immediately gives a snappier "we tried" UX; the next refetch picks
      // up rows as the engine commits them.
      invalidateSuggestionLists(qc);
    },
    onError: handleApiError,
  });
}
