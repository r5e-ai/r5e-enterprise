// RequireAuth — route guard wrapper.
//
// Per contracts/frontend_architecture.md §"Routing":
//   - Renders children only when `useAuth()` reports `authenticated`.
//   - On `unauthenticated`, issues a *full-page* navigation to
//     `/admin/login/start?return_to=<current path>`. NOT client-side router
//     navigation — the OAuth flow ends in a 302 from an external IdP, and the
//     SPA must re-bootstrap after the cookie is set.
//   - Renders a minimal "Loading…" placeholder while the initial
//     `/v1/auth/me` request is in flight.

import { useEffect, type ReactNode } from "react";

import { useAuth } from "~/hooks/useAuth";
import { apiPaths } from "~/lib/apiPaths";

type Props = {
  children: ReactNode;
};

export function RequireAuth({ children }: Props): ReactNode {
  const auth = useAuth();

  // Trigger the redirect from an effect so React doesn't warn about
  // navigating during render. The component renders nothing in this state —
  // the browser is about to leave the page anyway.
  useEffect(() => {
    if (auth.status === "unauthenticated") {
      const returnTo = window.location.pathname + window.location.search;
      window.location.assign(
        `${apiPaths.auth.loginStart}?return_to=${encodeURIComponent(returnTo)}`,
      );
    }
  }, [auth.status]);

  if (auth.status === "loading") {
    return (
      <div
        role="status"
        aria-live="polite"
        className="flex h-screen items-center justify-center"
      >
        Loading…
      </div>
    );
  }

  if (auth.status === "unauthenticated") {
    // Redirect is in flight (see effect above); render nothing.
    return null;
  }

  return children;
}
