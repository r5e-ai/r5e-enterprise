// HTTP client for the F004 Audit Console SPA.
//
// Per contracts/frontend_architecture.md §"Error handling":
//   - Cookie-aware (credentials: 'include') — never reads/sends JWTs directly.
//   - Normalizes non-2xx responses to the F001 error envelope shape and throws
//     `ApiError` with `attested_run_id` so the error UX can deep-link to the
//     denial receipt.
//   - Skeletal runtime schema validation hook (`validateAgainstSchema`) — full
//     zod schemas land in T043 alongside generated types.
//
// Global 401 handling (S-3 in the audit-pass-resolver-consolidation plan):
//   - `useApiErrorHandler` returns a memoized `onError` callback that
//     invalidates the `["auth", "me"]` query whenever an `ApiError` with
//     `status: 401` flows through. This re-runs `useAuth`, which transitions
//     to `unauthenticated`, which fires `RequireAuth`'s redirect-to-login.
//   - Components retain whatever inline error rendering they already do —
//     the global handler is additive: it ensures session expiry mid-page
//     redirects to login through the same path as page-load auth checks.

import { useCallback } from "react";
import {
  MutationCache,
  QueryCache,
  QueryClient,
  useQueryClient,
} from "@tanstack/react-query";

/**
 * F001 error-envelope shape (mirrored from
 * apps/recurse_gateway/priv/schemas/error_envelope.schema.json).
 *
 * `attested_run_id` is present for forbidden errors that produced a denial
 * receipt; the SPA uses it to render a "View attested receipt" link in error
 * toasts.
 */
export type ApiErrorEnvelope = {
  error: string;
  error_description: string;
  correlation_id: string;
  attested_run_id?: string | null;
  status: number;
};

export class ApiError extends Error {
  readonly error: string;
  readonly error_description: string;
  readonly correlation_id: string;
  readonly attested_run_id: string | null;
  readonly status: number;

  constructor(envelope: ApiErrorEnvelope) {
    super(envelope.error_description);
    this.name = "ApiError";
    this.error = envelope.error;
    this.error_description = envelope.error_description;
    this.correlation_id = envelope.correlation_id;
    this.attested_run_id = envelope.attested_run_id ?? null;
    this.status = envelope.status;
  }
}

type Method = "GET" | "POST" | "PUT" | "PATCH" | "DELETE";

/**
 * Skeletal runtime schema validator. Returns the input unmodified for now;
 * T043 wires real zod schemas generated from
 * `apps/recurse_gateway/priv/schemas/*.json`. Per the contract, validation
 * mismatches will eventually log a warning and fall through to the response
 * (defensive — drift between SPA and API mid-deploy must not break the UI).
 */
export function validateAgainstSchema<T>(_path: string, json: unknown): T {
  return json as T;
}

async function apiFetch<T>(
  method: Method,
  path: string,
  body?: unknown,
): Promise<T> {
  const response = await fetch(path, {
    method,
    credentials: "include",
    headers: body !== undefined
      ? { "Content-Type": "application/json", Accept: "application/json" }
      : { Accept: "application/json" },
    body: body !== undefined ? JSON.stringify(body) : null,
  });

  if (!response.ok) {
    let envelope: Partial<ApiErrorEnvelope> = {};
    try {
      envelope = await response.json();
    } catch {
      // Non-JSON error body (e.g., gateway 502 HTML) — synthesize an envelope
      // so the SPA's error UX still renders a usable message.
    }
    throw new ApiError({
      error: envelope.error ?? "unknown_error",
      error_description:
        envelope.error_description ?? `HTTP ${response.status}`,
      correlation_id: envelope.correlation_id ?? "unknown",
      attested_run_id: envelope.attested_run_id ?? null,
      status: response.status,
    });
  }

  // 204 No Content — return undefined cast to T (caller knows the contract).
  if (response.status === 204) {
    return undefined as T;
  }

  const json: unknown = await response.json();
  return validateAgainstSchema<T>(path, json);
}

export const api = {
  get: <T>(path: string) => apiFetch<T>("GET", path),
  post: <T>(path: string, body?: unknown) => apiFetch<T>("POST", path, body),
  put: <T>(path: string, body?: unknown) => apiFetch<T>("PUT", path, body),
  patch: <T>(path: string, body?: unknown) => apiFetch<T>("PATCH", path, body),
  delete: <T>(path: string) => apiFetch<T>("DELETE", path),
};

/**
 * Global 401-on-error handler — wires every TanStack Query `onError` into the
 * single auth-redirect path. When an `ApiError` with `status: 401` is caught,
 * we invalidate the `["auth", "me"]` cache so `useAuth` re-runs, which flips
 * its state to `unauthenticated`, which triggers `RequireAuth`'s full-page
 * redirect to `/admin/login/start`. Non-401 errors fall through unchanged so
 * components can render their own inline messages.
 *
 * Compose with a mutation's existing `onError` rather than overwriting it —
 * this handler does not consume the error.
 *
 * v5 note: `useQuery` no longer accepts an `onError` option (the option moved
 * off the per-hook surface in TanStack Query v5). Per-query 401 handling is
 * therefore wired globally via `createAuditConsoleQueryClient()` below; this
 * hook is for `useMutation` callers which retain `onError`.
 */
export function useApiErrorHandler(): (error: unknown) => void {
  const queryClient = useQueryClient();
  return useCallback(
    (error: unknown) => {
      if (error instanceof ApiError && error.status === 401) {
        queryClient.invalidateQueries({ queryKey: ["auth", "me"] });
      }
    },
    [queryClient],
  );
}

/**
 * Construct the SPA's `QueryClient` with a global 401 handler attached to
 * BOTH the `QueryCache` and `MutationCache`. Queries don't expose `onError`
 * in v5, but the cache-level callbacks fire for every query/mutation error
 * — exactly the cross-cutting hook S-3 calls for. The auth-me query itself
 * is excluded so a 401 from `/v1/auth/me` doesn't recursively invalidate
 * its own cache.
 */
export function createAuditConsoleQueryClient(): QueryClient {
  const handleError = (error: unknown, queryKey?: readonly unknown[]) => {
    if (!(error instanceof ApiError) || error.status !== 401) return;
    // Don't invalidate the auth-me query in response to its own 401 — that
    // would loop. `useAuth` already transitions to `unauthenticated` from
    // its own error state.
    if (
      queryKey &&
      queryKey.length >= 2 &&
      queryKey[0] === "auth" &&
      queryKey[1] === "me"
    ) {
      return;
    }
    client.invalidateQueries({ queryKey: ["auth", "me"] });
  };

  const client: QueryClient = new QueryClient({
    defaultOptions: {
      queries: {
        // Conservative defaults; per-query options override per
        // contracts/frontend_architecture.md (e.g., useAuth uses staleTime 60s,
        // retry false).
        refetchOnWindowFocus: false,
      },
    },
    queryCache: new QueryCache({
      onError: (error, query) => handleError(error, query.queryKey),
    }),
    mutationCache: new MutationCache({
      onError: (error) => handleError(error),
    }),
  });

  return client;
}
