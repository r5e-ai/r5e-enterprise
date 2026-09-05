// Cookie-aware auth helpers for the F004 SPA.
//
// Per contracts/frontend_architecture.md §"Auth state model":
//   - The SPA never reads, stores, or transmits the JWT directly.
//   - Authentication is implicit from the HttpOnly Session Cookie.
//   - Login uses a full-page redirect to `/admin/login/start?return_to=...`
//     because the OAuth flow ends in a 302 from an external IdP and the SPA
//     must re-bootstrap after the cookie is set (see browser_oidc_flow.md).

import { apiPaths } from "~/lib/apiPaths";
import { routes } from "~/lib/routes";

/**
 * Trigger the SSO login flow. Issues a full-page navigation (NOT
 * client-side router navigation) to the Gateway's `/admin/login/start`
 * endpoint with the current location preserved as `return_to` so the user
 * lands back where they were after the IdP round-trip.
 */
export function redirectToLogin(returnTo?: string): void {
  const target = returnTo ?? window.location.pathname + window.location.search;
  const url = `${apiPaths.auth.loginStart}?return_to=${encodeURIComponent(target)}`;
  window.location.assign(url);
}

/**
 * Sign out via `POST /admin/logout`. The Gateway returns 200 with
 * `{redirect_to}`; the SPA navigates the browser there and TanStack Query's
 * cache should be invalidated by the caller. Implementation lands in a
 * subsequent phase — this helper exists so consumers don't hand-roll the
 * redirect URL.
 */
export const logoutEndpoint = apiPaths.auth.logout;

/**
 * Auth state shape returned by `useAuth()`. `loading` covers the initial
 * `/v1/auth/me` round-trip; `unauthenticated` is the terminal state on any
 * error (including 401 — the SPA does not retry on auth failure).
 */
export type AuthState =
  | { status: "loading" }
  | { status: "unauthenticated" }
  | {
      status: "authenticated";
      principal: string;
      role: "tenant_auditor" | "platform_operator";
      tenantId: string;
    };

/**
 * Path to the lightweight identity endpoint. Returns
 * `{principal_subject, recurse_role, tenant_id, browser_session_id}` derived
 * from the current authenticated request — never the JWT or cookie content.
 */
export const authMePath = apiPaths.auth.me;

// Re-export so consumers can import auth + routes from one place.
export { routes };
