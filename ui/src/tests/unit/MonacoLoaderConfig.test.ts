// MonacoLoaderConfig.test.ts — regression for B6 (Policy Simulator
// stuck-on-Loading).
//
// The bug: `@monaco-editor/loader`'s default vs path is the jsDelivr CDN
// (`https://cdn.jsdelivr.net/npm/monaco-editor@<v>/min/vs`). The admin
// SPA's strict CSP (`script-src 'self' 'wasm-unsafe-eval'`, set by
// `Recurse.Gateway.Plug.SecurityHeaders`) blocks that cross-origin
// script. The result: `loader.init()` never resolves, and Monaco-React
// stays on its default `loading="Loading..."` placeholder forever — what
// the user sees on `/admin/policy-simulator`.
//
// The fix: `lib/configureMonacoLoader.ts` calls
// `loader.config({ paths: { vs: "/admin/vs" } })` at boot from main.tsx,
// pointing at a same-origin static path served out of
// `apps/recurse_gateway/priv/static/admin/vs/` (synced from
// `node_modules/monaco-editor/min/vs/` by `pnpm copy:monaco`).
//
// This test asserts:
//   1. `MONACO_LOCAL_VS_PATH` is a same-origin path (no scheme; starts
//      with `/`); it is not a third-party URL.
//   2. After `configureMonacoLoader()` runs, the loader's effective
//      vs-path is the same-origin one (proxied via a `loader.config`
//      spy because the loader's internal state is private).
//
// Future regressions (someone reverting the loader.config call, or a
// dependency-bump pulling a new default CDN URL into the loader)
// re-trip this test.

import { describe, expect, it, vi } from "vitest";

// Hoisted mock — vitest's `vi.mock` is hoisted above all imports, so the
// loader stub is in place by the time configureMonacoLoader.ts evaluates.
// `vi.hoisted` is the canonical way to expose the spy back to the test
// body without tripping the no-reference-before-init rule.
const { configSpy } = vi.hoisted(() => ({ configSpy: vi.fn() }));

vi.mock("@monaco-editor/loader", () => ({
  default: { config: configSpy, init: vi.fn(), __getMonacoInstance: vi.fn() },
}));

describe("Monaco loader configuration (B6)", () => {
  it("MONACO_LOCAL_VS_PATH is a same-origin path under /admin/", async () => {
    const { MONACO_LOCAL_VS_PATH } = await import(
      "~/lib/configureMonacoLoader"
    );
    // Must NOT be a CDN URL (the original B6 bug).
    expect(MONACO_LOCAL_VS_PATH).not.toMatch(/^https?:\/\//);
    expect(MONACO_LOCAL_VS_PATH).not.toContain("cdn.jsdelivr.net");
    expect(MONACO_LOCAL_VS_PATH).not.toContain("unpkg.com");
    // Must be an absolute same-origin path under the SPA basename so that
    // requests like `/admin/vs/loader.js` resolve to the static asset
    // shipped by the Gateway.
    expect(MONACO_LOCAL_VS_PATH).toMatch(/^\/admin\//);
  });

  it("configureMonacoLoader() points the loader at the local /admin/vs path", async () => {
    configSpy.mockClear();
    const { configureMonacoLoader, MONACO_LOCAL_VS_PATH } = await import(
      "~/lib/configureMonacoLoader"
    );
    configureMonacoLoader();

    expect(configSpy).toHaveBeenCalledTimes(1);
    expect(configSpy).toHaveBeenCalledWith({
      paths: { vs: MONACO_LOCAL_VS_PATH },
    });
  });
});
