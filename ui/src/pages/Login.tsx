// Login page — F8 redesign per `design/briefs/08-login.md`.
//
// `/admin/login` is the SPA's only unauthenticated route. We must NOT call
// `useAuth` here — the route exists precisely for callers who have no valid
// session cookie. The auth flow is fully delegated to the Gateway's
// `/admin/login/start?return_to=<path>` endpoint, which proxies to WorkOS;
// after the IdP round-trip the Gateway sets the session cookie and redirects
// the browser back into the SPA. Implementation contract:
// `contracts/browser_oidc_flow.md` + `lib/auth.ts:redirectToLogin/1`.
//
// Visual contract (per F8 brief + `01-shared-systems.md`):
//   - Centered card on `bg-r5e-bg`, max-width 380px, `rounded-r5e-lg`,
//     subtle `border-r5e-border`, padded 48px desktop / 32px mobile.
//   - Behind the card: a soft radial-gradient halo in the `r5e-accent`
//     token at 18% alpha, blurred 40px. The halo is composed via
//     Tailwind's `theme()` function inside an arbitrary `bg-[...]`
//     class, which resolves directly from the codegen'd Tailwind
//     config (single source of truth: `ui/design-tokens.json`).
//     No hand-written CSS variables, no third-source-of-truth drift.
//   - `<Wordmark />` (sparkle + "r5e" + "ENTERPRISE" eyebrow), centered.
//   - H1 "Audit Console" + muted subtitle "for AI agents".
//   - Sign-in `<a>` styled as accent button → full-page navigation to
//     `/admin/login/start?return_to=<encoded current path>`. Loading state
//     swaps the label to a spinner + "Redirecting…" between click and the
//     browser actually leaving the page (the redirect is instant in the
//     happy path, but on slow links the spinner reassures the user).
//   - Below-button hint, then footer at viewport bottom (version pulled
//     from `__APP_VERSION__` Vite define when present, else falls back to
//     "v0.1.0" from package.json — the build pipeline can wire this up
//     without code changes here).
//   - Error state: when the URL carries `?error=...` (and optionally
//     `?error_description=...`), an inline `ErrorState` banner renders
//     above the Sign in button with a "Try again" affordance that
//     re-issues the SSO redirect. This handles the IdP-error-redirect-
//     back path in `browser_oidc_flow.md`.
//
// IMPORTANT: The button is an `<a href>`, not a JS-driven `<button onClick>`.
// The brief explicitly calls for a full-page redirect (NOT an SPA route)
// because the OAuth flow ends with a 302 from an external IdP and the SPA
// must re-bootstrap after the cookie is set. Keeping it as an anchor means
// users can right-click → "Open in new tab", and the link is crawlable by
// keyboard / screen readers without depending on a click handler.

import { Loader2 } from "lucide-react";
import { useEffect, useMemo, useState, type MouseEvent } from "react";
import { useLocation } from "react-router-dom";

import { ErrorState } from "~/components/shared/states/ErrorState";
import { Wordmark } from "~/components/shared/Wordmark";
import { apiPaths } from "~/lib/apiPaths";
import { routes } from "~/lib/routes";

// Build-time injected version (see vite.config.ts `define`). Falls back to
// the package.json default when the define isn't wired (e.g. unit tests).
declare const __APP_VERSION__: string | undefined;

const FALLBACK_VERSION = "0.1.0";

function getAppVersion(): string {
  // Vite's `define` replaces `__APP_VERSION__` at build time. The `typeof`
  // operator on an undeclared identifier is the one form that does NOT
  // throw a ReferenceError — it returns the string `"undefined"` — so a
  // single typeof guard cleanly covers both the wired-up build (returns
  // the injected version) and the jsdom/unwired build (returns the
  // fallback) without a try/catch.
  if (typeof __APP_VERSION__ === "string" && __APP_VERSION__.length > 0) {
    return __APP_VERSION__;
  }
  return FALLBACK_VERSION;
}

/**
 * Build the full SSO start URL with the current pathname encoded as the
 * return_to. Defaults to the dashboard when the user lands on /admin/login
 * directly (i.e. no pre-redirect path to remember).
 */
function buildSsoUrl(returnTo: string): string {
  return `${apiPaths.auth.loginStart}?return_to=${encodeURIComponent(returnTo)}`;
}

/**
 * Parse query-string params from a `?...` search string. Pulled into a
 * helper so the test seam (jsdom's URL parser) is consistent across the
 * error and return-to paths, and so it stays a pure function of the
 * search string the component already gets from `useLocation()`.
 */
function readQueryParam(search: string, name: string): string | null {
  if (!search) return null;
  const params = new URLSearchParams(search);
  return params.get(name);
}

export default function Login(): JSX.Element {
  const [isRedirecting, setIsRedirecting] = useState(false);

  // We're rendered inside <BrowserRouter> (App.tsx) but Login itself does no
  // routing — it only needs to OBSERVE the current location's search string
  // so the error banner state stays in sync when the IdP redirects the user
  // back here with `?error=...` after a failed round-trip. Using
  // `useLocation()` (instead of reading `window.location.search` directly)
  // is also what makes the component re-render on URL-only changes (same
  // pathname, different search) — useful for the synthetic test environment
  // and resilient to back/forward navigation.
  const location = useLocation();
  const search = location.search;

  // The return_to defaults to the dashboard, but if the user reached
  // /admin/login via a Gateway redirect that attached `?return_to=<path>`,
  // respect that param. Open-redirect protection lives on the Gateway
  // side: `validate_return_to/1` in
  // `apps/recurse_gateway/lib/recurse_gateway/admin/browser_auth/login_handler.ex:160-168`
  // rejects absolute URLs / cross-origin paths with `400 invalid_return_to`.
  // The SPA forwards the param verbatim — no client-side validation needed.
  const returnTo = useMemo<string>(() => {
    const fromQuery = readQueryParam(search, "return_to");
    if (fromQuery && fromQuery.length > 0) return fromQuery;
    return routes.dashboard;
  }, [search]);

  const ssoUrl = useMemo(() => buildSsoUrl(returnTo), [returnTo]);

  // Error banner state. Mirrors the IdP-error redirect-back contract from
  // browser_oidc_flow.md: a failed auth round-trip lands back at
  // /admin/login?error=<code>&error_description=<human readable>.
  const errorCode = readQueryParam(search, "error");
  const errorDescription = readQueryParam(search, "error_description");

  // Reset the loading state if the page becomes visible again (browser
  // back/forward) — without this, hitting Back after a failed redirect
  // would leave the button stuck in the redirecting state.
  useEffect(() => {
    function onPageShow(): void {
      setIsRedirecting(false);
    }
    window.addEventListener("pageshow", onPageShow);
    return () => window.removeEventListener("pageshow", onPageShow);
  }, []);

  function handleSignInClick(event: MouseEvent<HTMLAnchorElement>): void {
    // Loading-state contract for keyboard users: while a previous click
    // is mid-redirect, swallow further activations (Enter on the focused
    // anchor, repeat clicks). pointer-events-none would have caught a
    // mouse re-click but not a keyboard activation.
    if (isRedirecting) {
      event.preventDefault();
      return;
    }
    // Allow modifier-clicks to open in a new tab unmodified — only flip
    // the loading state for the in-page navigation case.
    if (
      event.metaKey ||
      event.ctrlKey ||
      event.shiftKey ||
      event.altKey ||
      event.button !== 0
    ) {
      return;
    }
    setIsRedirecting(true);
    // Don't preventDefault — we WANT the anchor's full-page navigation to
    // happen so the OIDC round-trip starts immediately.
  }

  return (
    <div
      data-testid="login-page"
      className="relative flex min-h-screen flex-col items-center justify-center overflow-hidden bg-r5e-bg px-4 py-12 font-sans text-r5e-text"
    >
      <main className="relative flex w-full flex-1 items-center justify-center">
        {/*
         * Halo backdrop — soft radial gradient in the accent color, blurred.
         * Sized to roughly the card footprint so the glow stays centered
         * on the card and doesn't bleed across the viewport. The gradient
         * resolves the `r5e-accent` token via Tailwind's `theme()` function
         * at build time, so the only source of truth is the codegen'd
         * Tailwind config (which itself derives from
         * `ui/design-tokens.json`).
         */}
        <div
          aria-hidden="true"
          data-testid="login-halo"
          className="pointer-events-none absolute left-1/2 top-1/2 h-[520px] w-[520px] -translate-x-1/2 -translate-y-1/2 bg-[radial-gradient(circle_at_center,theme(colors.r5e-accent/18%)_0%,transparent_60%)] blur-[40px]"
        />

        <section
          data-testid="login-card"
          className="relative z-10 w-full max-w-[380px] rounded-r5e-lg border border-r5e-border bg-r5e-surface px-8 py-8 shadow-[0_30px_80px_-30px_rgba(0,0,0,0.7)] sm:px-12 sm:py-12"
          aria-labelledby="login-title"
        >
          <header className="mb-8 flex flex-col items-center text-center">
            <Wordmark size="md" />
            <h1
              id="login-title"
              className="mt-6 text-2xl font-semibold tracking-tight text-r5e-text"
            >
              Audit Console
            </h1>
            <p className="mt-1 text-sm text-r5e-muted">for AI agents</p>
          </header>

          {errorCode ? (
            <div className="mb-6 text-left">
              <ErrorState
                compact
                testId="login-error"
                title="Sign-in failed"
                body={
                  <>
                    The identity provider returned an error
                    {errorDescription
                      ? `: ${errorDescription}.`
                      : ` (${errorCode}).`}{" "}
                    Try again, or contact your admin if the problem persists.
                  </>
                }
              />
            </div>
          ) : null}

          <a
            href={ssoUrl}
            onClick={handleSignInClick}
            data-testid="login-sso-button"
            aria-disabled={isRedirecting}
            tabIndex={isRedirecting ? -1 : undefined}
            className={[
              "flex w-full items-center justify-center gap-2 rounded-r5e-md bg-r5e-accent px-4 py-3 text-sm font-semibold text-r5e-text transition-colors",
              "hover:bg-r5e-accent-glow",
              "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-r5e-accent-glow focus-visible:ring-offset-2 focus-visible:ring-offset-r5e-surface",
              isRedirecting ? "pointer-events-none opacity-80" : "",
            ]
              .filter(Boolean)
              .join(" ")}
          >
            {isRedirecting ? (
              <>
                <Loader2
                  className="h-4 w-4 animate-spin"
                  aria-hidden="true"
                />
                <span>Redirecting…</span>
              </>
            ) : (
              <span>{errorCode ? "Try again" : "Sign in"}</span>
            )}
          </a>

          <p className="mt-4 text-center text-xs text-r5e-muted">
            You will be redirected to your identity provider.
          </p>
        </section>
      </main>

      <footer
        data-testid="login-footer"
        className="relative z-10 mt-12 flex flex-wrap items-center justify-center gap-x-2 gap-y-1 text-[11px] text-r5e-muted"
      >
        <span>r5e-enterprise</span>
        <span aria-hidden="true">·</span>
        <span data-testid="login-version">v{getAppVersion()}</span>
        <span aria-hidden="true">·</span>
        <span>audit-dev</span>
        <span aria-hidden="true">·</span>
        <span>platform</span>
        <span aria-hidden="true">·</span>
        <span>privacy</span>
      </footer>
    </div>
  );
}
