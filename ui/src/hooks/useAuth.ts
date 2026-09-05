// useAuth — TanStack-Query-backed hook that derives the SPA's auth state
// from the Gateway's lightweight `/v1/auth/me` endpoint.
//
// Per contracts/frontend_architecture.md §"Auth state model":
//   - staleTime: 60_000 — refresh roughly every minute.
//   - retry: false — a 401 fails fast and the wrapper triggers a redirect.
//   - The SPA never reads, stores, or transmits the JWT directly.
//
// Response shape: per the codegen-emitted `AuthMe` type (sourced from
// `apps/recurse_gateway/priv/schemas/auth_me.json` via `pnpm gen:types`),
// the API returns flat snake_case fields (`principal_subject`,
// `recurse_role`, `tenant_id`, plus session-envelope timestamps). There
// is no `authenticated` discriminator — the API returns 200 with the
// principal envelope when authenticated, or 401 (which manifests as
// `isError === true` here) when not.

import { useQuery } from "@tanstack/react-query";

import { api } from "~/lib/api";
import { authMePath, type AuthState } from "~/lib/auth";
import type { AuthMe } from "~/lib/types";

export function useAuth(): AuthState {
  const { data, isLoading, isError } = useQuery<AuthMe>({
    queryKey: ["auth", "me"],
    queryFn: () => api.get<AuthMe>(authMePath),
    staleTime: 60_000,
    retry: false,
  });

  if (isLoading) return { status: "loading" };
  if (isError || !data) {
    return { status: "unauthenticated" };
  }

  return {
    status: "authenticated",
    principal: data.principal_subject,
    role: data.recurse_role,
    tenantId: data.tenant_id,
  };
}
