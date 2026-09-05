// Sidebar — global left-rail navigation for the Audit Console SPA.
//
// Per `design/r5e-enterprise-audit-ui.pen` Dashboard screen (sidebar `5lsTD`)
// and the surface-gap brief: the Console's top-level surfaces (Receipts,
// Policy Simulator, Chat) were unreachable from the UI before this MR — only
// the Dashboard rendered and there was no way to navigate to PolicySimulator
// or Chat without hand-typing the URL.
//
// This component renders inside `AuthenticatedShell` so it appears on every
// authenticated route. It is intentionally NOT mounted on `/admin/login` (the
// public Login page does not use the shell).
//
// The sidebar exposes ONLY top-level surfaces — PolicySimulatorSuggestions
// (`/admin/policy-simulator/suggestions`) is reached from inside the
// PolicySimulator page (a tab + the "Suggestions →" link in its TopBar
// content), not from here. Keeping the global nav small mirrors the design's
// 3-item layout in `5lsTD` and avoids navigation noise.
//
// Active-state matching uses react-router's NavLink with `end={false}`, which
// matches the exact path AND any descendant path. That keeps "Receipts"
// highlighted when the receipt drawer (`/admin/dashboard/receipts/<id>`) is
// open, and keeps "Policy Simulator" highlighted on
// `/admin/policy-simulator/suggestions`.
//
// Basename note: `routes.*` are absolute `/admin/...` paths but the SPA's
// BrowserRouter is mounted with `basename="/admin"`. NavLink auto-prefixes
// the basename for outbound URLs, so we MUST strip `/admin` from the `to`
// prop or we'd land on `/admin/admin/...`. `stripBasename` is the canonical
// helper (defined in `lib/routes.ts`); see also App.tsx and BulkActionBar.

import { Activity, Inbox, MessageCircle, Package, Shield } from "lucide-react";
import type { ComponentType, SVGProps } from "react";
import { NavLink } from "react-router-dom";

import { Wordmark } from "~/components/shared/Wordmark";
import { routes, stripBasename } from "~/lib/routes";
import { slug } from "~/lib/strings";

type IconProps = SVGProps<SVGSVGElement>;

interface NavItem {
  label: string;
  to: string;
  icon: ComponentType<IconProps>;
}

const NAV_ITEMS: ReadonlyArray<NavItem> = [
  { label: "Receipts", to: routes.dashboard, icon: Inbox },
  // F10 Investigation Timeline — sits between Receipts and Policy Simulator
  // per `design/briefs/10-session-trace.md` ("Drill paths into the Timeline
  // — From sidebar nav → 'Investigation'"). Lucide `Activity` icon mirrors
  // the brief's recommendation.
  { label: "Investigation", to: routes.timeline, icon: Activity },
  { label: "Policy Simulator", to: routes.policySimulator, icon: Shield },
  { label: "MCP Registry", to: routes.mcpRegistry, icon: Package },
  { label: "Chat", to: routes.chat, icon: MessageCircle },
];

export function Sidebar(): JSX.Element {
  return (
    <aside
      data-testid="global-sidebar"
      aria-label="Primary navigation"
      className="flex h-screen w-[220px] shrink-0 flex-col border-r border-r5e-border bg-r5e-surface px-4 py-4 font-sans"
    >
      {/* Workspace label — F8 brief refactors the inline "r5e enterprise"
          string into the shared `<Wordmark />` so the sidebar chrome and
          the unauthenticated Login card render the same brand mark.
          The "/ audit" workspace tag stays here (sidebar-only chrome). */}
      <div className="flex flex-col gap-1 pb-4" data-testid="sidebar-workspace">
        <Wordmark size="sm" />
        <span className="text-[12px] text-r5e-muted">/ audit</span>
      </div>

      <div className="h-px w-full bg-r5e-border" aria-hidden="true" />

      {/* Nav section */}
      <nav className="flex flex-col gap-0.5 pt-4" data-testid="sidebar-nav">
        {NAV_ITEMS.map((item) => (
          <SidebarLink key={item.to} item={item} />
        ))}
      </nav>
    </aside>
  );
}

function SidebarLink({ item }: { item: NavItem }): JSX.Element {
  const Icon = item.icon;
  return (
    <NavLink
      to={stripBasename(item.to)}
      data-testid={`sidebar-link-${slug(item.label)}`}
      end={false}
      className={({ isActive }) =>
        [
          "flex h-9 items-center gap-2 rounded-md px-3 text-[13px] transition-colors",
          isActive
            ? "bg-r5e-accent/15 text-r5e-text"
            : "text-r5e-muted hover:bg-r5e-bg hover:text-r5e-text",
        ].join(" ")
      }
    >
      <Icon className="h-4 w-4 shrink-0" aria-hidden="true" />
      <span>{item.label}</span>
    </NavLink>
  );
}

