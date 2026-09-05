// SPA entrypoint — mounts <App /> into #root and pulls in the Tailwind CSS
// bundle once. Per contracts/frontend_architecture.md §"Folder layout".
//
// Boot-time third-party SDK config is colocated here:
//   - `createAuditConsoleQueryClient()` (called inside App.tsx) — TanStack
//     Query.
//   - `configureMonacoLoader()` — points @monaco-editor/loader at the
//     same-origin `/admin/vs` path so it loads under our strict CSP
//     (B6 fix; see lib/configureMonacoLoader.ts for the why).
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import App from "~/App";
import { configureMonacoLoader } from "~/lib/configureMonacoLoader";
import "~/index.css";

// Run boot-time config before any component mounts. Monaco lazy-loads on
// the PolicySimulator route, but the loader's `init()` resolves against
// whatever paths it has at the moment it's called — so we set them up here
// while the editor chunk is still un-fetched.
configureMonacoLoader();

const rootEl = document.getElementById("root");
if (!rootEl) {
  throw new Error("Root element #root not found in index.html");
}

createRoot(rootEl).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
