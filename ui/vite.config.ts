// F004 T004 — Vite dev/build config per contracts/frontend_architecture.md.
//
// Dev server proxies to localhost:4000 (Gateway). Production build emits to
// ui/dist/, then `pnpm run sync-to-priv` copies it to
// apps/recurse_gateway/priv/static/admin/ which Plug.Static serves at runtime
// (and which `mix release` includes in the deployment artifact).
//
// The synced directory is gitignored at the repo root (.gitignore F004 block).

import { defineConfig } from "vite";
import type { Plugin } from "vite";
import react from "@vitejs/plugin-react";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const devMocksEnabled = process.env.VITE_DEV_MOCKS === "1";

// GAN MR !96 finding (codex_cli): a static `import` of `./vite-plugins/dev-mocks`
// caused production builds to parse the mock module + its `src/lib/*` deps
// (timeline-constants, displayField) even when VITE_DEV_MOCKS is unset,
// weakening the "never loads in prod" claim. Use a dynamic import gated on
// the env var so the module is only evaluated when actually needed.
async function loadDevMocksPlugin(): Promise<Plugin | null> {
  if (!devMocksEnabled) return null;
  const mod = await import("./vite-plugins/dev-mocks");
  return mod.devMocksPlugin();
}

export default defineConfig(async () => {
  const devMocksPlugin = await loadDevMocksPlugin();
  return {
  // The SPA loads at /admin/, served by Plug.Static under priv/static/admin/.
  // Asset URLs must therefore be relative-to-/admin/ at runtime so that the
  // browser fetches /admin/assets/* (which the router maps to priv/static/admin/assets/*)
  // rather than /assets/* (which 404s through the catch-all). This MUST live
  // at the top level — Vite ignores `build.base`.
  base: "/admin/",
  plugins: [
    ...(devMocksPlugin ? [devMocksPlugin] : []),
    react(),
  ],
  resolve: {
    alias: {
      "~": path.resolve(__dirname, "src"),
    },
  },
  server: {
    port: 5173,
    strictPort: true,
    proxy: {
      "/v1": {
        target: "http://localhost:4000",
        changeOrigin: false,
      },
      "/.well-known": {
        target: "http://localhost:4000",
        changeOrigin: false,
      },
      "/admin/live-tail": {
        target: "ws://localhost:4000",
        ws: true,
        changeOrigin: false,
      },
      "/admin/login": {
        target: "http://localhost:4000",
        changeOrigin: false,
      },
      "/admin/logout": {
        target: "http://localhost:4000",
        changeOrigin: false,
      },
      // Dev-only server-side cookie mint (DevLoginHandler). The Gateway
      // 404s this path unless :dev_login_enabled? is set in config/dev.exs,
      // so proxying it unconditionally is safe.
      "/admin/test/login": {
        target: "http://localhost:4000",
        changeOrigin: false,
      },
    },
  },
  build: {
    outDir: "dist",
    emptyOutDir: true,
    sourcemap: true,
    target: "es2022",
  },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/tests/setup.ts"],
    include: ["src/tests/unit/**/*.{test,spec}.{ts,tsx}"],
  },
  };
});
