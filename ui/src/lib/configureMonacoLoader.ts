// configureMonacoLoader — point @monaco-editor/loader at a same-origin path
// (B6 — Policy Simulator stuck-on-Loading fix).
//
// `@monaco-editor/loader` (used internally by @monaco-editor/react) defaults
// to fetching Monaco's AMD bootstrap from
// `https://cdn.jsdelivr.net/npm/monaco-editor@<version>/min/vs/loader.js`.
// Our admin SPA runs under a strict CSP set by
// `Recurse.Gateway.Plug.SecurityHeaders`:
//
//     script-src 'self' 'wasm-unsafe-eval'
//
// The cross-origin script-tag injection from jsDelivr is blocked, so
// `loader.init()` never resolves, and `@monaco-editor/react` hangs on its
// default `loading="Loading..."` placeholder forever.
//
// The fix: ship monaco's `min/vs/` directory as a static asset at
// `/admin/vs/*` (synced from `node_modules/monaco-editor/min/vs/` at
// dev/build time via the `copy:monaco` script in `ui/package.json`) and
// configure the loader to fetch from that same-origin path. Monaco's AMD
// loader uses `<script>`-tag injection (not eval) in browser environments,
// so same-origin scripts satisfy `script-src 'self'` cleanly.
//
// This module's side effect runs ONCE at app boot (imported from main.tsx
// before <App /> mounts). It is idempotent: `loader.config` merges into
// existing state, so a second call is a no-op for the path already set.
//
// Tests verify the configured `paths.vs` value via the regression spec at
// `tests/unit/MonacoLoaderConfig.test.ts`.

import loader from "@monaco-editor/loader";

/**
 * Same-origin path under which Monaco's `min/vs/` directory is served.
 *
 * The leading `/admin/` matches the SPA's BrowserRouter basename and the
 * Plug.Static prefix on the Gateway side: requests to `/admin/vs/loader.js`
 * resolve to `apps/recurse_gateway/priv/static/admin/vs/loader.js`, which
 * the build pipeline (`pnpm sync-to-priv`) populates from `ui/public/vs/`.
 *
 * Exported for the regression test.
 */
export const MONACO_LOCAL_VS_PATH = "/admin/vs";

/**
 * Configure `@monaco-editor/loader` to load Monaco from the same-origin
 * `/admin/vs` path instead of the default jsDelivr CDN.
 *
 * Call once at app boot, before any `@monaco-editor/react` editor mounts.
 */
export function configureMonacoLoader(): void {
  loader.config({
    paths: {
      vs: MONACO_LOCAL_VS_PATH,
    },
  });
}
