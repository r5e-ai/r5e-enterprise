// Single source-of-truth for SPA route paths.
// Per contracts/frontend_architecture.md §"Routing".
//
// All paths are absolute (mounted under the Gateway's `/admin/*` prefix in
// production via Vite's `base` config). The SPA itself reasons in absolute
// paths so deep-links from receipts, error toasts, and external links resolve
// the same way regardless of which route is currently active.
//
// `receiptDetail` is a sub-route of `dashboard` so the audit-log page can
// remain mounted underneath the drawer overlay (preserves filter state,
// scroll position, live-tail subscription) when a receipt URL is opened
// directly.
export const ADMIN_BASE = "/admin";

export const routes = {
  login: "/admin/login",
  dashboard: "/admin/dashboard",
  receiptDetail: "/admin/dashboard/receipts/:run_id",
  policySimulator: "/admin/policy-simulator",
  policySimulatorSuggestions: "/admin/policy-simulator/suggestions",
  chat: "/admin/chat",
  mcpRegistry: "/admin/mcp-registry",
  mcpRegistryDetail: "/admin/mcp-registry/:id",
  timeline: "/admin/timeline",
  // F10/F008: timeline-scoped drawer route — opening the full R2 receipt
  // detail drawer FROM the Investigation Timeline mounts the same
  // ReceiptDetail component but keeps the timeline (and its URL chips)
  // mounted underneath, so close() returns to the investigation surface
  // rather than the dashboard. The sister path under /dashboard remains
  // for table-row clicks.
  timelineReceiptDetail: "/admin/timeline/receipts/:run_id",
} as const;

export type RouteKey = keyof typeof routes;

// Strip the `/admin` basename prefix from an absolute route path so the
// result is safe to pass to react-router primitives that auto-prefix the
// basename (`<Route path>`, `<Link to>`, `<NavLink to>`, `navigate()`).
//
// Why this exists: `routes.*` are absolute (`/admin/...`) by design — pages
// reason in absolute paths for cross-page deep-links, error breadcrumbs,
// and external return-to URLs. But `<BrowserRouter basename="/admin">`
// means router-internal navigation must be RELATIVE to the basename; if
// you pass `/admin/dashboard` to `<Link to>`, the basename gets prepended
// again and you land on `/admin/admin/dashboard` (no route matches → blank
// page). This helper is the canonical bridge.
//
// Pattern is shared by App.tsx (`<Route path>`), Sidebar (`<NavLink to>`),
// page-level navigate() calls, and BulkActionBar's draft-from-selection
// link. Keep all consumers using this helper — Constitution Principle VII
// (Interface-First on Second Consumer).
export function stripBasename(path: string): string {
  if (path.startsWith(ADMIN_BASE)) {
    const rest = path.slice(ADMIN_BASE.length);
    return rest.length === 0 ? "/" : rest;
  }
  return path;
}

// Router-safe path to the MCP Registry detail page for a given entry id.
//
// `routes.mcpRegistryDetail` is a *pattern* (`/admin/mcp-registry/:id`) used
// as a `<Route path>`, so it cannot be passed to `<Link to>` directly.
// Same shape as `receiptDetailPath` below.
export function mcpRegistryDetailPath(id: string): string {
  return stripBasename(`/admin/mcp-registry/${encodeURIComponent(id)}`);
}

// Router-safe path to the Investigation Timeline scoped to a single principal.
//
// The Timeline (F10) reads scope params (`principal`, `session_id`,
// `correlation_id`, `run_id`) from `useSearchParams`. R1 row drill-paths
// (principal cell click, session_id chip, correlation_id chip) and R2
// drawer's "View in timeline" CTA all funnel through this helper so the
// URL shape stays canonical. New consumers SHOULD call this rather than
// rebuilding the template (Constitution Principle VII — Interface-First on
// Second Consumer).
export interface TimelineScope {
  principal?: string;
  session_id?: string;
  correlation_id?: string;
  run_id?: string;
  /** ISO 8601 since-timestamp; takes precedence over the time-window key. */
  since?: string;
  until?: string;
}

export function timelinePath(scope: TimelineScope = {}): string {
  const params = new URLSearchParams();
  if (scope.principal) params.set("principal", scope.principal);
  if (scope.session_id) params.set("session_id", scope.session_id);
  if (scope.correlation_id) params.set("correlation_id", scope.correlation_id);
  if (scope.run_id) params.set("run_id", scope.run_id);
  if (scope.since) params.set("since", scope.since);
  if (scope.until) params.set("until", scope.until);
  const qs = params.toString();
  const base = stripBasename(routes.timeline);
  return qs ? `${base}?${qs}` : base;
}

// Router-safe path to the Receipt Detail drawer for a given run_id.
//
// `routes.receiptDetail` is a *pattern* (`/admin/dashboard/receipts/:run_id`)
// used as a `<Route path>`, so it cannot be passed to `<Link to>` directly
// — consumers have to interpolate the run_id and (per the basename note
// above) strip the basename. Two consumers had grown the same template
// literal inline (BlastRadiusPanel's sample-receipt list, PolicySimulator's
// source-receipt banner); per Constitution Principle VII the second
// consumer extracts the helper. New router consumers should call this
// rather than rebuilding the template.
export function receiptDetailPath(runId: string): string {
  return stripBasename(`/admin/dashboard/receipts/${encodeURIComponent(runId)}`);
}

// Router-safe path to the timeline-scoped Receipt Detail drawer (F10/F008).
// Mirrors `receiptDetailPath` but resolves under `/admin/timeline/...` so
// the drawer overlays the Investigation Timeline rather than the
// Dashboard. Used by EventInspector's "View full Tags" link.
export function timelineReceiptDetailPath(runId: string): string {
  return stripBasename(`/admin/timeline/receipts/${encodeURIComponent(runId)}`);
}
