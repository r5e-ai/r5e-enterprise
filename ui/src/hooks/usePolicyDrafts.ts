// usePolicyDrafts — TanStack Query hooks for the F004 policy-drafts CRUD
// surface (T095 — Phase 5 US3).
//
// Per `contracts/audit_api_extensions.md` §"Policy drafts":
//   - GET    /v1/policy/drafts                  — list (cursor-paginated)
//   - POST   /v1/policy/drafts                  — create
//   - GET    /v1/policy/drafts/{id}             — fetch one
//   - PATCH  /v1/policy/drafts/{id}             — edit
//   - DELETE /v1/policy/drafts/{id}             — soft-archive
//   - POST   /v1/policy/drafts/from-receipt     — skeleton from receipt
//
// All endpoints are cookie-authenticated and the F001 error envelope is
// normalized into `ApiError` by the shared `api` client. Each mutation
// invalidates the relevant list-key on success so the UI stays consistent
// without explicit refetch wiring.
//
// We model drafts loosely (`Record<string, unknown>` for the metadata bags)
// because the typed schema lives at `apps/recurse_gateway/priv/schemas/`
// and the codegen-emitted `PolicyDraft` interface is currently a placeholder.
// The narrow fields we DO depend on are typed explicitly.

import {
  useMutation,
  useQuery,
  useQueryClient,
  type UseMutationResult,
  type UseQueryResult,
} from "@tanstack/react-query";

import { api, useApiErrorHandler } from "~/lib/api";
import { apiPaths } from "~/lib/apiPaths";

// ---------------------------------------------------------------------------
// Wire-shape types
// ---------------------------------------------------------------------------

export type PolicyDraftStatus = "draft" | "adopted_as_draft" | "archived";

export type PolicyDraftScopeKind = "principal" | "role" | "group" | "tenant";

/**
 * Wire shape for `scope_metadata` per the backend changeset validator at
 * `apps/recurse_gateway/lib/recurse_gateway/admin/policy_drafts/policy_draft.ex`
 * (`validate_scope_metadata_shape/1`): the row requires `scope_kind` +
 * `scope_value` keys; anything else 400s with
 * "must include :scope_kind and :scope_value keys".
 *
 * The backend tolerates either atom- or string-keyed JSONB on round-trip
 * (Ecto stores atoms as strings), but we always emit string keys from the
 * SPA so the wire bytes are stable.
 */
export interface PolicyDraftScopeMetadata {
  scope_kind: PolicyDraftScopeKind;
  scope_value: string;
}

/**
 * Wire shape for a single `condition_metadata` entry per the backend
 * `validate_condition_metadata_shape/1`: every entry must be a map with a
 * `kind` key (atom or string). Per-kind shape validation is the
 * suggestion-engine's responsibility downstream — we only enforce the
 * outer envelope here.
 *
 * UI surfaces these as friendlier labels but the wire bytes track the
 * canonical strings exactly: `"eq" | "neq" | "in" | "time_window" |
 * "group_member"`.
 */
export type PolicyDraftConditionKind =
  | "eq"
  | "neq"
  | "in"
  | "time_window"
  | "group_member";

export interface PolicyDraftConditionMetadata {
  /** Backend-required discriminator. */
  kind: PolicyDraftConditionKind;
  /** Cedar axis key (e.g., `resource.tags.tool_kind`). */
  attr: string;
  /**
   * Per-kind value shape:
   *   - eq / neq / group_member → string
   *   - in                       → string[]  (chip list)
   *   - time_window              → [string, string] (ISO range)
   * Backend stores opaquely as JSONB; the SPA + suggestion-engine agree on
   * shape per `kind`.
   */
  value: unknown;
}

/** Inline summary surfaced on draft list rows (`last_blast_radius_summary`). */
export interface BlastRadiusSummary {
  total_scanned?: number;
  total_affected?: number;
  matches_intent?: number;
  unintended?: number;
  would_have_allowed?: number;
  no_change?: number;
  computed_at?: string;
}

/** Single draft envelope returned by the drafts endpoints. */
export interface PolicyDraft {
  id: string;
  tenant_id: string;
  author_principal_subject: string;
  source_receipt_run_id: string | null;
  /** Excerpt on list responses; full source on GET-one. */
  cedar_source_excerpt?: string | null;
  cedar_source?: string | null;
  scope_metadata?: PolicyDraftScopeMetadata | null;
  condition_metadata?: PolicyDraftConditionMetadata[] | null;
  status: PolicyDraftStatus;
  created_at: string;
  updated_at: string;
  last_blast_radius_summary?: BlastRadiusSummary | null;
}

export interface PolicyDraftsListPage {
  drafts: PolicyDraft[];
  next_cursor: string | null;
}

export interface PolicyDraftsListFilter {
  status?: PolicyDraftStatus;
  author_principal_subject?: string;
  cursor?: string;
  limit?: number;
}

export interface CreatePolicyDraftPayload {
  cedar_source: string;
  scope_metadata?: PolicyDraftScopeMetadata;
  condition_metadata?: PolicyDraftConditionMetadata[];
  source_receipt_run_id?: string | null;
}

export interface UpdatePolicyDraftPayload {
  cedar_source?: string;
  scope_metadata?: PolicyDraftScopeMetadata;
  condition_metadata?: PolicyDraftConditionMetadata[];
}

export interface FromReceiptPayload {
  source_receipt_run_id: string;
}

// ---------------------------------------------------------------------------
// Path helpers
// ---------------------------------------------------------------------------

const DRAFTS_PATH = apiPaths.policy.drafts;
const DRAFT_PATH = (id: string) => apiPaths.policy.draftDetail(id);
const FROM_RECEIPT_PATH = apiPaths.policy.fromReceipt;

function buildListPath(filter: PolicyDraftsListFilter): string {
  const params = new URLSearchParams();
  if (filter.status) params.set("status", filter.status);
  if (filter.author_principal_subject) {
    params.set("author_principal_subject", filter.author_principal_subject);
  }
  if (filter.cursor) params.set("cursor", filter.cursor);
  if (filter.limit !== undefined) params.set("limit", String(filter.limit));
  const qs = params.toString();
  return qs ? `${DRAFTS_PATH}?${qs}` : DRAFTS_PATH;
}

// ---------------------------------------------------------------------------
// Query keys
// ---------------------------------------------------------------------------

export function policyDraftsListKey(
  filter: PolicyDraftsListFilter,
): readonly unknown[] {
  const sorted: Record<string, string> = {};
  for (const key of Object.keys(filter).sort()) {
    const value = filter[key as keyof PolicyDraftsListFilter];
    if (value !== undefined && value !== "") sorted[key] = String(value);
  }
  return ["policy_drafts", "list", sorted] as const;
}

export function policyDraftKey(id: string | undefined): readonly unknown[] {
  return ["policy_drafts", "one", id ?? ""] as const;
}

// ---------------------------------------------------------------------------
// Read hooks
// ---------------------------------------------------------------------------

/** List drafts. Defaults to `status=draft` (matches API default). */
export function usePolicyDraftsList(
  filter: PolicyDraftsListFilter = {},
): UseQueryResult<PolicyDraftsListPage, Error> {
  return useQuery<PolicyDraftsListPage, Error>({
    queryKey: policyDraftsListKey(filter),
    queryFn: () => api.get<PolicyDraftsListPage>(buildListPath(filter)),
    staleTime: 10_000,
  });
}

/** Fetch a single draft by id. Disabled when id is absent. */
export function usePolicyDraft(
  id: string | undefined,
): UseQueryResult<PolicyDraft, Error> {
  return useQuery<PolicyDraft, Error>({
    queryKey: policyDraftKey(id),
    queryFn: () => api.get<PolicyDraft>(DRAFT_PATH(id ?? "")),
    enabled: !!id,
    staleTime: 5_000,
  });
}

// ---------------------------------------------------------------------------
// Mutations
// ---------------------------------------------------------------------------

/** Helper — invalidate every drafts-list cache regardless of filter. */
function invalidateDraftLists(qc: ReturnType<typeof useQueryClient>): void {
  qc.invalidateQueries({ queryKey: ["policy_drafts", "list"] });
}

/** Create a new draft. */
export function useCreatePolicyDraft(): UseMutationResult<
  PolicyDraft,
  Error,
  CreatePolicyDraftPayload
> {
  const qc = useQueryClient();
  const handleApiError = useApiErrorHandler();
  return useMutation<PolicyDraft, Error, CreatePolicyDraftPayload>({
    mutationFn: (payload) => api.post<PolicyDraft>(DRAFTS_PATH, payload),
    onSuccess: (draft) => {
      qc.setQueryData(policyDraftKey(draft.id), draft);
      invalidateDraftLists(qc);
    },
    onError: handleApiError,
  });
}

/** Generate a draft skeleton from a source receipt. */
export function useDraftFromReceipt(): UseMutationResult<
  PolicyDraft,
  Error,
  FromReceiptPayload
> {
  const qc = useQueryClient();
  const handleApiError = useApiErrorHandler();
  return useMutation<PolicyDraft, Error, FromReceiptPayload>({
    mutationFn: (payload) => api.post<PolicyDraft>(FROM_RECEIPT_PATH, payload),
    onSuccess: (draft) => {
      qc.setQueryData(policyDraftKey(draft.id), draft);
      invalidateDraftLists(qc);
    },
    onError: handleApiError,
  });
}

/** Edit (PATCH) an existing draft. */
export function useUpdatePolicyDraft(
  id: string | undefined,
): UseMutationResult<PolicyDraft, Error, UpdatePolicyDraftPayload> {
  const qc = useQueryClient();
  const handleApiError = useApiErrorHandler();
  return useMutation<PolicyDraft, Error, UpdatePolicyDraftPayload>({
    mutationFn: (payload) => {
      if (!id) throw new Error("usePatchPolicyDraft: id is required");
      return api.patch<PolicyDraft>(DRAFT_PATH(id), payload);
    },
    onSuccess: (draft) => {
      qc.setQueryData(policyDraftKey(draft.id), draft);
      invalidateDraftLists(qc);
    },
    onError: handleApiError,
  });
}

/** Soft-archive (DELETE) a draft. Returns 204 → undefined. */
export function useArchivePolicyDraft(
  id: string | undefined,
): UseMutationResult<void, Error, void> {
  const qc = useQueryClient();
  const handleApiError = useApiErrorHandler();
  return useMutation<void, Error, void>({
    mutationFn: async () => {
      if (!id) throw new Error("useArchivePolicyDraft: id is required");
      await api.delete<void>(DRAFT_PATH(id));
    },
    onSuccess: () => {
      if (id) qc.invalidateQueries({ queryKey: policyDraftKey(id) });
      invalidateDraftLists(qc);
    },
    onError: handleApiError,
  });
}
