// App.tsx — SPA root. Wraps the router in a TanStack Query provider and wires
// the route table from contracts/frontend_architecture.md §"Routing".
//
// Route guards: every authenticated route is wrapped in <RequireAuth>, which
// triggers a full-page redirect to /admin/login/start if the session cookie
// is missing or expired (see browser_oidc_flow.md). Login is the only public
// route.
//
// Nested route shape: ReceiptDetail is a child of Dashboard so the audit-log
// view stays mounted underneath the drawer overlay (preserves filter state,
// scroll position, live-tail subscription).
//
// Chat drawer (F004 Phase 6 US4): the Audit Agent chat surface mounts as a
// persistent right-side overlay on EVERY authenticated route (FR-036). The
// `routes.chat` direct-link path simply opens the drawer with no host page
// behind it. Drawer visibility is URL-driven via `?chat=open`; toggling is
// up to the per-page top-bar (or the suggestion chip surface).
//
// Modal routes (F5): the chat surface's tool-call `attested_run_id` link
// opens a receipt-detail drawer OVER the chat without unmounting it. We
// implement this via React Router's canonical "background location"
// pattern — see <AppRoutes /> below.

import type { Location } from "react-router-dom";
import type { ReactNode } from "react";
import { QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Navigate, Route, Routes, useLocation } from "react-router-dom";

import { RequireAuth } from "~/components/shared/RequireAuth";
import { Sidebar } from "~/components/shared/Sidebar";
import { createAuditConsoleQueryClient } from "~/lib/api";
import { ADMIN_BASE, routes, stripBasename } from "~/lib/routes";
import ChatDrawer from "~/pages/ChatDrawer";
import ChatPage from "~/pages/ChatPage";
import Dashboard from "~/pages/Dashboard";
import Login from "~/pages/Login";
import McpRegistry from "~/pages/McpRegistry";
import McpRegistryDetail from "~/pages/McpRegistryDetail";
import PolicySimulator from "~/pages/PolicySimulator";
import PolicySimulatorSuggestions from "~/pages/PolicySimulatorSuggestions";
import ReceiptDetail from "~/pages/ReceiptDetail";
import ReceiptDetailModal from "~/pages/ReceiptDetailModal";
import TimelinePage from "~/pages/TimelinePage";

// Route definitions in `lib/routes.ts` are absolute (`/admin/...`). Strip the
// `/admin` prefix here so the values plug straight into <Route path>; we mount
// react-router under `/admin` via BrowserRouter's `basename`.

// Singleton — avoid re-creating the cache on every render. The factory wires
// a global 401 handler via QueryCache + MutationCache so session-expired
// errors trigger the same redirect path as page-load auth checks (S-3 in the
// audit-pass-resolver-consolidation plan).
const queryClient = createAuditConsoleQueryClient();

/**
 * AuthenticatedShell — wraps a protected page so the Audit Agent chat
 * drawer (FR-036) mounts on every authenticated surface in addition to
 * the page-specific UI, and so the global Sidebar nav frames every
 * authenticated route.
 *
 * Layout: a horizontal flex with the Sidebar (220px, fixed) on the left
 * and a flex-1 column holding the page content. The TopBar is rendered
 * BY EACH PAGE (not here) so pages can inject their own page-context
 * slot content via `<TopBar pageContent={...} actions={...} />`.
 *
 * ChatDrawer is conditionally visible based on the `?chat=open` URL search
 * param it owns.
 */
function AuthenticatedShell({
  children,
}: {
  children: ReactNode;
}): JSX.Element {
  return (
    <RequireAuth>
      <div
        data-testid="authenticated-shell"
        className="flex h-screen w-screen overflow-hidden bg-r5e-bg font-sans text-r5e-text"
      >
        <Sidebar />
        <div className="flex min-w-0 flex-1 flex-col overflow-hidden">
          {children}
        </div>
        <ChatDrawer />
      </div>
    </RequireAuth>
  );
}

/**
 * AppRoutes — the actual <Routes /> tree, separated from <App /> so we can
 * call React Router hooks (`useLocation`) inside the BrowserRouter provider.
 *
 * Background-location overlay pattern:
 *   When a `<Link>` is clicked with `state.backgroundLocation` set, the
 *   primary <Routes /> matches against THAT location (so the underlying
 *   surface stays mounted), and a parallel <Routes /> renders the modal
 *   target against the ACTUAL location. This is the canonical React Router
 *   pattern (see https://reactrouter.com/v6/start/concepts#modal-routes)
 *   and is what powers the F5 brief's "click attested_run_id → opens that
 *   receipt's drawer over the chat" flow without unmounting <ChatPage />.
 *
 *   Today only the receipt-detail surface uses this. If more modal targets
 *   are added later, register them inside the second <Routes /> block.
 */
function AppRoutes(): JSX.Element {
  const location = useLocation();
  const backgroundLocation = (
    location.state as { backgroundLocation?: Location } | null
  )?.backgroundLocation;

  return (
    <>
      <Routes location={backgroundLocation ?? location}>
        {/* Public route */}
        <Route path={stripBasename(routes.login)} element={<Login />} />

        {/* Spec 012 S6c — the SPA root (`/admin`, `/admin/`) has no page of
            its own; land on the dashboard. The gateway router redirects the
            same paths before the SPA loads; this covers the Vite dev server
            and any direct client-side navigation to the root. */}
        <Route
          path="/"
          element={<Navigate to={stripBasename(routes.dashboard)} replace />}
        />

        {/* Protected routes — wrap each element in AuthenticatedShell so
            the persistent Audit Agent chat drawer mounts everywhere. */}
        <Route
          path={stripBasename(routes.dashboard)}
          element={
            <AuthenticatedShell>
              <Dashboard />
            </AuthenticatedShell>
          }
        >
          {/* Nested drawer route — relative path against the Dashboard parent. */}
          <Route path="receipts/:run_id" element={<ReceiptDetail />} />
        </Route>

        {/* F10 — Investigation Timeline. Sessions / agents grouped, with
            event-inspector showing tags + jump-to-receipt. The drawer is
            nested so it overlays the timeline (preserving investigation
            context); ReceiptDetail's close behavior routes back to the
            timeline when location.state.returnTo is set. */}
        <Route
          path={stripBasename(routes.timeline)}
          element={
            <AuthenticatedShell>
              <TimelinePage />
            </AuthenticatedShell>
          }
        >
          <Route path="receipts/:run_id" element={<ReceiptDetail />} />
        </Route>

        <Route
          path={stripBasename(routes.policySimulator)}
          element={
            <AuthenticatedShell>
              <PolicySimulator />
            </AuthenticatedShell>
          }
        >
          {/* Nested drawer route — mirrors the Dashboard nested
              receipts/:run_id shape so the receipt drawer overlays the
              simulator without navigating away. Per F4 brief + GAN F005.
              The same `<ReceiptDetail />` element is mounted; its close
              button uses `..` so it returns to whichever parent mounted
              it. (The modal-overlay route below — !93's background-
              location pattern — is the alternate path used from the chat
              surface; both can coexist.) */}
          <Route path="receipts/:run_id" element={<ReceiptDetail />} />
        </Route>
        <Route
          path={stripBasename(routes.policySimulatorSuggestions)}
          element={
            <AuthenticatedShell>
              <PolicySimulatorSuggestions />
            </AuthenticatedShell>
          }
        />
        {/* Standalone full-page chat surface (F5 redesign). The slide-in
            <ChatDrawer /> overlay is still mounted on every other route via
            <AuthenticatedShell />, but `/admin/chat` is its own dedicated
            page with TopBar + history dropdown + "New chat". Both surfaces
            wrap the shared <ChatThread /> component. */}
        <Route
          path={stripBasename(routes.chat)}
          element={
            <AuthenticatedShell>
              <ChatPage />
            </AuthenticatedShell>
          }
        />
        {/* MCP Trusted Registry — Path B vertical slice. */}
        <Route
          path={stripBasename(routes.mcpRegistry)}
          element={
            <AuthenticatedShell>
              <McpRegistry />
            </AuthenticatedShell>
          }
        />
        <Route
          path={stripBasename(routes.mcpRegistryDetail)}
          element={
            <AuthenticatedShell>
              <McpRegistryDetail />
            </AuthenticatedShell>
          }
        />
      </Routes>

      {/* Modal-overlay routes — render IN ADDITION to the underlying
          <Routes /> when a backgroundLocation is set in history state.
          The receipt-detail modal is its own self-contained 720px right
          drawer (no Dashboard <aside> parent), so it can layer over any
          authenticated surface (chat, policy simulator, etc.). Closing
          the modal pops the history entry — the underlying surface
          remains mounted with all its state intact. */}
      {backgroundLocation && (
        <Routes>
          <Route
            path={stripBasename(routes.receiptDetail)}
            element={<ReceiptDetailModal />}
          />
        </Routes>
      )}
    </>
  );
}

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter basename={ADMIN_BASE}>
        <AppRoutes />
      </BrowserRouter>
    </QueryClientProvider>
  );
}
