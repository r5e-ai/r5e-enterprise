// Dashboard — F004 audit-log surface (T065, Phase 3 US1).
//
// Per `design/r5e-enterprise-audit-ui.pen` Dashboard screen +
// `contracts/frontend_architecture.md`:
//   - Top bar: app brand + role pill + sign-out affordance.
//   - Left sidebar: faceted filters (`event_kind`, `policy_decision`,
//     `verification_level`) with live counts (FR-012). Counts come from
//     the page envelope when the backend ships them; for now an empty
//     `null` count renders as a dash and the UI degrades gracefully.
//   - Main pane: structured query bar (free-text search → `?q=`),
//     histogram (FR-011) above the table, sortable column headers
//     (#31), paged-pagination footer with explicit page numbers (#32),
//     column-picker dropdown in the table topbar (#33).
//   - Table: TanStack Virtual (50 visible + 25 above + 25 below per D8).
//   - Bulk-action bar: appears when ≥1 row is selected (FR-015 affordances).
//   - Drawer: nested route `<Outlet />` renders `ReceiptDetail` overlay.
//
// State management:
//   - URL search params own filter state (deep-linkable).
//   - Component-local `useState` owns selection + live-tail toggle +
//     sort axis + page index (UI ephemera).
//   - localStorage (via `auditLogStorage`) owns column visibility so
//     reloads preserve the operator's picker selection.
//   - TanStack Query owns receipts data (via `useReceipts` infinite hook).
//   - `useLiveTail` bridges the live WebSocket into the same TanStack cache.
//
// This page MUST be wrapped in `<RequireAuth>` (the App router does that).

import { useCallback, useEffect, useMemo, useState } from "react";
import { Outlet, useNavigate, useOutlet, useSearchParams } from "react-router-dom";
import { Download, X } from "lucide-react";

import { AuditTable } from "~/components/audit/AuditTable";
import { BulkActionBar } from "~/components/audit/BulkActionBar";
import { ColumnPicker } from "~/components/audit/ColumnPicker";
import { downloadEvidence } from "~/components/audit/ExportEvidenceButton";
import { FilterFacet } from "~/components/audit/FilterFacet";
import { Histogram, type HistogramWindow } from "~/components/audit/Histogram";
import { LiveTailToggle } from "~/components/audit/LiveTailToggle";
import { PageNavigator } from "~/components/audit/PageNavigator";
import { ParserDriftPanel } from "~/components/audit/ParserDriftPanel";
import { TopBar } from "~/components/shared/TopBar";
import {
  AUDIT_LOG_PAGE_SIZE,
  nextSortState,
  pageSlice,
  sortRows,
  type AuditLogColumnId,
  type AuditLogColumnVisibility,
  type AuditLogSortState,
} from "~/lib/auditLogColumns";
import {
  loadColumnVisibility,
  saveColumnVisibility,
} from "~/lib/auditLogStorage";
import {
  buildFacetRows,
  CANONICAL_EVENT_KINDS,
  CANONICAL_POLICY_DECISIONS,
  CANONICAL_VERIFICATION_LEVELS,
} from "~/lib/event_kinds";
import { toolKindToChartToken } from "~/lib/chartTokens";
import {
  ALL_CALL_KINDS,
  CALL_KINDS,
  CALL_KIND_PARAM,
  callKindFromParam,
  callKindOf,
  groupRowsBySession,
  type CallKind,
} from "~/lib/receiptView";
import {
  KNOWN_CATEGORIES,
  categoryColorToken,
  categoryFromRow,
  effectiveDecision,
  tagsOf,
} from "~/lib/tags";
import { useAuth } from "~/hooks/useAuth";
import { useLiveTail, subscribeLiveTailToasts, type LiveTailToast } from "~/hooks/useLiveTail";
import { ToastStack, type ToastItem, type ToastTone } from "~/components/shared/ToastStack";
import { ApiError } from "~/lib/api";
import {
  useReceipts,
  type ReceiptsFacets,
  type ReceiptsFilter,
} from "~/hooks/useReceipts";

// Tool FilterFacet chip-color resolver. Delegates to the shared
// `toolKindToChartToken` in `~/lib/chartTokens` (extracted in MR !86
// fix-pass-3 per Constitution Principle VII — Dashboard's
// `toolKindToColorToken`, ToolCell's `toolKindToken`, and the third
// inline call site triggered the extraction). Returns null for unknown
// tools so FilterFacet falls back to neutral chip chrome — distinct
// from ToolCell's pill behavior, which defaults to `chart-ui` (slate)
// because a tool-cell pill always has to render some color.

// (#58) Header + body cell widths come from the AUDIT_LOG_COLUMNS
// registry. Pre-#58 widths were duplicated in two separate maps —
// HEADER_WIDTHS in Dashboard.tsx + per-cell `w-N` literals in
// ReceiptRow.tsx — and desynced on horizontal scroll.

export default function Dashboard(): JSX.Element {
  const auth = useAuth();
  const navigate = useNavigate();
  const outlet = useOutlet();
  const [searchParams, setSearchParams] = useSearchParams();

  // Filter state derived from URL (deep-linkable).
  const filter: ReceiptsFilter = useMemo(() => {
    const f: ReceiptsFilter = {};
    const ek = searchParams.get("event_kind");
    if (ek) f.event_kind = ek;
    // `policy_decision` is NOT sent to the server: the SQL column holds
    // the parent call's "allow" for a `tool_use_denied` row (spec 012 S6
    // finding), so the axis is applied client-side via
    // `effectiveDecision` — see `decisionFilter` below.
    const vl = searchParams.get("verification_level");
    if (
      vl === "signed" ||
      vl === "local_inclusion_verified" ||
      vl === "global_inclusion_verified"
    ) {
      f.verification_level = vl;
    }
    const q = searchParams.get("q");
    if (q) f.q = q;
    const ps = searchParams.get("principal_subject");
    if (ps) f.principal_subject = ps;
    const since = searchParams.get("since");
    if (since) f.since = since;
    const until = searchParams.get("until");
    if (until) f.until = until;
    return f;
  }, [searchParams]);

  // Wave C — `category` is a Tags-derived axis filter applied client-side
  // because the backend's `apply_filter/3` does not yet push the
  // `outer_container.tags->>'category'` predicate to SQL. Filed as a
  // /reflect follow-up; see also the in-memory-post-filter recency
  // trap pattern (the recency trap WILL bite once the universe grows
  // past the loaded LIMIT — but for the demo with ≤2k receipts this
  // surfaces the right rows and the auditor can read what they came
  // for). The separate state shape (not on `ReceiptsFilter`) keeps
  // the wire-shape contract honest — what the SPA sends to the
  // backend matches what the backend accepts, no silently-dropped
  // params.
  const categoryFilter = searchParams.get("category");
  // Tool axis filter (FR-009 — "auditor MUST be able to filter by tool
  // name"). Same client-side pattern as category: backend
  // apply_filter/3 doesn't push the `tags->>'tool_kind'` predicate yet,
  // so this narrows the loaded set in-memory. Same recency-trap caveat:
  // for the demo's data volume this is honest; once the universe grows
  // the backend will need to push tool_kind down to SQL. Filed as a
  // /reflect follow-up.
  const toolFilter = searchParams.get("tool_kind");
  // Decision axis (spec 012 S6c). Client-side because the server counts
  // and filters on `outer_container.policy_decision`, which is "allow"
  // for a `tool_use_denied` row; `effectiveDecision` reads the denial.
  const decisionParam = searchParams.get("policy_decision");
  const decisionFilter: "allow" | "deny" | null =
    decisionParam === "allow" || decisionParam === "deny" ? decisionParam : null;
  // Call-kind axis (spec 012 plan §10): `agent_turn` unless the URL says
  // otherwise; `?kind=all` shows every kind. Session-title calls, side
  // queries and the console's own `ui_*` reads are behind the toggle.
  const kindFilter: CallKind | null = callKindFromParam(searchParams.get(CALL_KIND_PARAM));

  const {
    data,
    isLoading,
    isError,
    fetchNextPage,
    hasNextPage,
    isFetchingNextPage,
  } = useReceipts(filter, { facets: true });

  // ---------------------------------------------------------------------
  // Selection (bulk actions)
  // ---------------------------------------------------------------------
  const [selection, setSelection] = useState<Set<string>>(new Set());
  const selectedRunIds = useMemo(() => Array.from(selection), [selection]);

  function toggleRow(runId: string, next: boolean): void {
    setSelection((prev) => {
      const copy = new Set(prev);
      if (next) copy.add(runId);
      else copy.delete(runId);
      return copy;
    });
  }

  // ---------------------------------------------------------------------
  // Live-tail toggle + toast plumbing
  // ---------------------------------------------------------------------
  const [liveTailEnabled, setLiveTailEnabled] = useState(false);
  const [toasts, setToasts] = useState<LiveTailToast[]>([]);

  useEffect(() => {
    return subscribeLiveTailToasts((t) => {
      setToasts((prev) => {
        // De-dup by id; latest message wins.
        const filtered = prev.filter((p) => p.id !== t.id);
        return [...filtered, t];
      });
    });
  }, []);

  function dismissToast(id: string): void {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }

  // ---------------------------------------------------------------------
  // Pinned set: union of (selected) ∪ (in-viewport).
  // We track viewport via TanStack Virtual's range below.
  // ---------------------------------------------------------------------
  const [viewportPinned, setViewportPinned] = useState<Set<string>>(new Set());
  const pinned = useMemo(() => {
    const s = new Set<string>();
    selection.forEach((id) => s.add(id));
    viewportPinned.forEach((id) => s.add(id));
    return s;
  }, [selection, viewportPinned]);

  useLiveTail({ filter, enabled: liveTailEnabled, pinned });

  // ---------------------------------------------------------------------
  // Sort state (#31). Default `null` = server order = timestamp DESC.
  // Click cycles ASC → DESC → default per `nextSortState`. Sort is
  // applied client-side over loaded rows; backend `sort_by` / `sort_dir`
  // pushdown is filed as a follow-up issue (see MR description).
  // ---------------------------------------------------------------------
  const [sort, setSort] = useState<AuditLogSortState | null>(null);

  function onSortClick(columnId: AuditLogColumnId): void {
    setSort((prev) => nextSortState(prev, columnId));
    // Resetting to page 0 keeps the user's mental model — they
    // expect the new sort to take them to the top of the result set.
    setPageIndex(0);
  }

  // ---------------------------------------------------------------------
  // Column visibility (#33). Seeded from localStorage; writes back on
  // every change. Required columns (timestamp + summary) are enforced
  // by `toggleColumnVisibility` + the picker UI.
  // ---------------------------------------------------------------------
  const [columnVisibility, setColumnVisibility] = useState<AuditLogColumnVisibility>(
    () => loadColumnVisibility(),
  );

  const onColumnVisibilityChange = useCallback(
    (next: AuditLogColumnVisibility) => {
      setColumnVisibility(next);
      saveColumnVisibility(next);
    },
    [],
  );

  // ---------------------------------------------------------------------
  // Page state (#32). Cursor-based backend → page-indexed front. The
  // first page (index 0) is the initial fetch; advancing past the loaded
  // window calls `fetchNextPage`. Filter changes reset to page 0 so the
  // user doesn't get stranded on a stale page after narrowing the
  // result set. `total_count` is not yet a backend field — see brief +
  // follow-up issue; `totalCount` stays `null` until backend support
  // lands, and the navigator shows "Page N — X loaded" instead of
  // "Page N of M — Y total".
  // ---------------------------------------------------------------------
  const [pageIndex, setPageIndex] = useState(0);

  // Reset to page 0 whenever the filter changes (URL search params
  // recompute `filter` → new memo identity). The category axis
  // (Wave C) lives outside `ReceiptsFilter` but the same reset
  // applies: a new category narrows the visible set.
  useEffect(() => {
    setPageIndex(0);
  }, [filter, categoryFilter, toolFilter, decisionFilter, kindFilter]);

  // ---------------------------------------------------------------------
  // Flatten paged rows for the virtualizer (#31 sort applied here over
  // ALL loaded rows; #32 page slice applied AFTER sort so the page
  // window reflects the active sort axis).
  // ---------------------------------------------------------------------
  const allRows = useMemo(
    () => data?.pages.flatMap((p) => p.receipts) ?? [],
    [data],
  );

  // Wave C — client-side category filter (see categoryFilter comment
  // above). Applied AFTER fetch + BEFORE sort so sort axes operate on
  // the filtered set and the row count reflects what the operator can
  // see. Computed via `categoryFromRow` so the denial-supersedes rule
  // and event_kind fallbacks compose correctly with the URL filter.
  const filteredRows = useMemo(() => {
    let rows = allRows;
    if (categoryFilter) {
      rows = rows.filter((row) => categoryFromRow(row) === categoryFilter);
    }
    if (toolFilter) {
      rows = rows.filter((row) => tagsOf(row)?.tool_kind === toolFilter);
    }
    if (decisionFilter) {
      rows = rows.filter((row) => effectiveDecision(row) === decisionFilter);
    }
    if (kindFilter) {
      rows = rows.filter((row) => callKindOf(row) === kindFilter);
    }
    return rows;
  }, [allRows, categoryFilter, toolFilter, decisionFilter, kindFilter]);

  // No explicit sort → server order (timestamp DESC) regrouped so one
  // client session's calls read together (spec 012 plan §10). A column
  // sort replaces the grouping.
  const sortedRows = useMemo(
    () => (sort === null ? groupRowsBySession(filteredRows) : sortRows(filteredRows, sort)),
    [filteredRows, sort],
  );

  const { start: pageStart, end: pageEnd } = pageSlice(
    sortedRows.length,
    pageIndex,
    AUDIT_LOG_PAGE_SIZE,
  );

  const rows = useMemo(
    () => sortedRows.slice(pageStart, pageEnd),
    [sortedRows, pageStart, pageEnd],
  );

  function onPageChange(nextPageIndex: number): void {
    if (nextPageIndex < 0) return;
    const wouldExceedLoaded =
      (nextPageIndex + 1) * AUDIT_LOG_PAGE_SIZE > allRows.length;
    if (wouldExceedLoaded && hasNextPage && !isFetchingNextPage) {
      void fetchNextPage();
    }
    setPageIndex(nextPageIndex);
  }

  // Server-computed facet counts (over the FULL filtered universe via
  // SQL GROUP BY — see receipts_handler.compute_facets/1). Each page
  // carries the SAME facets payload; we read the first page since it's
  // the most-recently-resolved deterministic copy. When the server
  // hasn't responded yet (or the request was made without `facets:
  // true`) we fall back to an empty map and the picker still renders
  // every canonical kind at count 0.
  const serverFacets: ReceiptsFacets | undefined = data?.pages[0]?.facets;

  // Wave C — Category facet counts. Derived client-side from `allRows`
  // (NOT the category-filtered subset; otherwise the picker would
  // collapse to a single chip once the operator picks one). The
  // backend doesn't aggregate `tags.category` server-side yet — filed
  // as a /reflect follow-up; for the demo's data volume the
  // client-side computation is honest. When the universe exceeds the
  // loaded window the picker silently undercounts; the recency trap
  // pattern applies here too.
  const categoryCounts = useMemo(() => {
    const out: Record<string, number> = {};
    for (const r of allRows) {
      const cat = categoryFromRow(r);
      out[cat] = (out[cat] ?? 0) + 1;
    }
    return out;
  }, [allRows]);

  // Tool facet — distinct `tags.tool_kind` values from the loaded set.
  // Computed off `allRows` (NOT the toolFilter-filtered subset; same
  // rationale as `categoryCounts` — otherwise the picker would collapse
  // to a single chip once a tool is selected). Categories drop out for
  // rows without `tool_kind` (system events, ui_*) — those don't surface
  // in this facet by design (they have no tool axis to filter).
  const toolCounts = useMemo(() => {
    const out: Record<string, number> = {};
    for (const r of allRows) {
      const k = tagsOf(r)?.tool_kind;
      if (!k) continue;
      out[k] = (out[k] ?? 0) + 1;
    }
    return out;
  }, [allRows]);

  // Decision facet — client-side over `allRows` via `effectiveDecision`
  // (the server's `policy_decision` GROUP BY counts a `tool_use_denied`
  // row under "allow"). Same loaded-window scope as the category and
  // tool facets.
  const decisionCounts = useMemo(() => {
    const out: Record<string, number> = {};
    for (const r of allRows) {
      const d = effectiveDecision(r);
      if (!d) continue;
      out[d] = (out[d] ?? 0) + 1;
    }
    return out;
  }, [allRows]);

  // Call-kind facet — client-side over `allRows` via `callKindOf`.
  const kindCounts = useMemo(() => {
    const out: Record<string, number> = {};
    for (const r of allRows) {
      const k = callKindOf(r);
      out[k] = (out[k] ?? 0) + 1;
    }
    return out;
  }, [allRows]);

  function setKindParam(value: string): void {
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev);
      next.set(CALL_KIND_PARAM, value);
      return next;
    });
  }

  // Stable canonical order for the Tool facet (matches the auditor's
  // mental model from the table's TOOL column pill labels). New
  // tool_kinds added by the extractor will surface at the bottom under
  // the `+ Show N empty` affordance until added here.
  const TOOL_KINDS = useMemo(
    () => [
      "bash",
      "edit",
      "notebook_edit",
      "read",
      "search",
      "webfetch",
      "mcp",
      "agent",
      "llm",
      "todo",
    ],
    [],
  );

  // ---------------------------------------------------------------------
  // Histogram buckets (placeholder until backend ships aggregations).
  // Computed over ALL loaded rows (NOT the current page slice) so the
  // histogram represents the full filtered universe the operator can
  // page through. Sort axis doesn't affect histogram bucketing.
  // ---------------------------------------------------------------------
  const histogramData = useMemo(() => {
    const buckets = new Map<string, Record<string, number>>();
    const kindsSet = new Set<string>();
    // Bucket key = R4 category (per design briefs/02-dashboard.md and
    // briefs/00-data-model.md: ONE LAYER PER CATEGORY, not per
    // event_kind). Pre-fix this stacked by event_kind, which made the
    // histogram disagree with the table's category-pill palette and the
    // brief's "Color per CATEGORY" rule. Caught by GAN review of MR !86,
    // finding F004. The Histogram resolves chart-* fills off the
    // category key via `colorClassForKind`.
    //
    // Wave C — bucket the FILTERED set so the histogram visually
    // confirms the operator's category pick (e.g. picking
    // `subprocess_exec` collapses the bars to subprocess-only counts).
    for (const r of filteredRows) {
      const ts = r.signed_predicate.timestamp ?? "";
      const bucket = ts.slice(0, 13); // hour-precision bucket
      const category = categoryFromRow(r);
      kindsSet.add(category);
      const counts = buckets.get(bucket) ?? {};
      counts[category] = (counts[category] ?? 0) + 1;
      buckets.set(bucket, counts);
    }
    return {
      buckets: Array.from(buckets.entries())
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([ts, counts]) => ({ ts, counts })),
      kinds: Array.from(kindsSet),
    };
  }, [filteredRows]);

  // ---------------------------------------------------------------------
  // Virtualizer is now owned by <AuditTable />. Live-tail viewport
  // pinning still needs a "which rows are visible" set; the AuditTable
  // renders all currently-loaded rows under a single <tbody> so we can
  // approximate the pinned set as "all loaded rows on this page".
  // (Pre-rewrite this was per-overscan-window; over-pinning is the
  // safer side of that trade-off — live-tail won't evict an in-flight
  // viewport row.)
  // ---------------------------------------------------------------------
  useEffect(() => {
    setViewportPinned(new Set(rows.map((r) => r.run_id)));
  }, [rows]);

  // ---------------------------------------------------------------------
  // Filter mutations (URL writes)
  // ---------------------------------------------------------------------
  function toggleFacet(key: keyof ReceiptsFilter, value: string): void {
    setSearchParams(
      (prev) => {
        const next = new URLSearchParams(prev);
        if (next.get(key) === value) next.delete(key);
        else next.set(key, value);
        return next;
      },
      { replace: false },
    );
  }

  function clearFacet(key: keyof ReceiptsFilter): void {
    setSearchParams(
      (prev) => {
        const next = new URLSearchParams(prev);
        next.delete(key);
        return next;
      },
      { replace: false },
    );
  }

  function onQueryBarSubmit(value: string): void {
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev);
      if (value) next.set("q", value);
      else next.delete("q");
      return next;
    });
  }

  function onHistogramWindowChange(window: HistogramWindow): void {
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev);
      if (window.since) next.set("since", window.since);
      else next.delete("since");
      if (window.until) next.set("until", window.until);
      else next.delete("until");
      return next;
    });
  }

  function openReceiptDrawer(runId: string): void {
    navigate(`receipts/${runId}`);
  }

  function clearSearchParam(key: string): void {
    setSearchParams(
      (prev) => {
        const next = new URLSearchParams(prev);
        // Deleting `kind` would fall back to the default (`agent_turn`);
        // clearing the chip means "every kind".
        if (key === CALL_KIND_PARAM) next.set(CALL_KIND_PARAM, ALL_CALL_KINDS);
        else next.delete(key);
        return next;
      },
      { replace: false },
    );
  }

  const role = auth.status === "authenticated" ? auth.role : null;

  return (
    <div className="flex min-h-0 flex-1 flex-col bg-r5e-bg font-sans text-r5e-text">
      <TopBar
        pageContent={
          <span className="text-sm font-semibold text-r5e-text">
            Audit Log
          </span>
        }
        actions={
          <DashboardExportEvidenceButton selectedRunIds={selectedRunIds} />
        }
      />

      {/* Histogram + search bar live ABOVE the filters/table split so
          the histogram stretches across the full main width (canonical
          R1 in design/r5e-enterprise-audit-ui.pen — the left filter
          pane starts BELOW the histogram, doesn't extend up alongside
          it). Search bar sits BENEATH the histogram per
          design/briefs/02-dashboard.md "below the histogram (Datadog/
          Splunk convention)". Pre-rewrite both lived inside the main
          pane and the filter rail extended the full page height,
          giving the dashboard a 3-column-from-the-top look that
          didn't match the canonical's stacked composition. */}
      <div className="border-b border-r5e-border bg-r5e-surface/60 px-4 py-3">
        <Histogram
          buckets={histogramData.buckets}
          kinds={histogramData.kinds}
          activeWindow={{
            since: filter.since ?? null,
            until: filter.until ?? null,
          }}
          onWindowChange={onHistogramWindowChange}
        />
      </div>
      {/* Spec 012 S4 — parser drift. Renders nothing until the LLM-proxy
          parsers have reported an event type they could not classify;
          then a compact list of the types, counts and keys-only samples
          (the same rows /readyz counts as `parser_drift`). */}
      <ParserDriftPanel />
      <ActiveFilters
        filter={filter}
        categoryFilter={categoryFilter}
        toolFilter={toolFilter}
        decisionFilter={decisionFilter}
        kindFilter={kindFilter}
        onClear={clearSearchParam}
      />
      <div className="border-b border-r5e-border bg-r5e-surface/40 px-4 py-3">
        <QueryBar initialValue={filter.q ?? ""} onSubmit={onQueryBarSubmit} />
      </div>
      <div className="flex min-h-0 flex-1">
        {/* Left filter rail — faceted filters (page-local; the global nav
            sidebar lives in AuthenticatedShell at the outer level).

            Wave C — order matters. `Category` is the auditor's
            primary 1-glance axis (R4 semantic palette anchors all
            UX); leads. `Event kind` is the legacy coarse axis;
            second. Decision + Verification stay below for the
            crypto-chain workflows. */}
        <aside className="w-64 shrink-0 overflow-y-auto border-r border-r5e-border bg-r5e-surface/60">
          <div className="px-4 py-3 text-xs font-semibold uppercase tracking-wider text-r5e-muted">
            Filters
          </div>
          {/* Call kind (spec 012 plan §10). `agent_turn` is selected by
              default so a Claude Code session reads as its turns and
              denials; the title call, side queries and the console's own
              reads show when toggled. Clicking the active kind (or
              Clear) sets `?kind=all`. */}
          <FilterFacet
            title="Call kind"
            values={buildFacetRows(CALL_KINDS, kindCounts)}
            active={kindFilter ? new Set([kindFilter]) : new Set()}
            onToggle={(v) => setKindParam(v === kindFilter ? ALL_CALL_KINDS : v)}
            onClear={() => setKindParam(ALL_CALL_KINDS)}
          />
          <FilterFacet
            title="Category"
            values={buildFacetRows(KNOWN_CATEGORIES, categoryCounts)}
            active={categoryFilter ? new Set([categoryFilter]) : new Set()}
            onToggle={(v) =>
              setSearchParams((prev) => {
                const next = new URLSearchParams(prev);
                if (next.get("category") === v) next.delete("category");
                else next.set("category", v);
                return next;
              })
            }
            onClear={() =>
              setSearchParams((prev) => {
                const next = new URLSearchParams(prev);
                next.delete("category");
                return next;
              })
            }
            getValueColor={(v) => categoryColorToken(v)}
          />
          {/* Tool facet (FR-009 — auditor must filter by tool name).
              Added in MR !86 fix-pass-2 per GAN finding F005. The picker
              tints each tool_kind chip with its R4 chart-token (matching
              the table's TOOL column pill) — auditor reads "MCP =
              cyan" both in the row and in the rail. */}
          <FilterFacet
            title="Tool"
            values={buildFacetRows(TOOL_KINDS, toolCounts)}
            active={toolFilter ? new Set([toolFilter]) : new Set()}
            onToggle={(v) =>
              setSearchParams((prev) => {
                const next = new URLSearchParams(prev);
                if (next.get("tool_kind") === v) next.delete("tool_kind");
                else next.set("tool_kind", v);
                return next;
              })
            }
            onClear={() =>
              setSearchParams((prev) => {
                const next = new URLSearchParams(prev);
                next.delete("tool_kind");
                return next;
              })
            }
            getValueColor={(v) => toolKindToChartToken(v)}
          />
          <FilterFacet
            title="Event kind"
            values={buildFacetRows(CANONICAL_EVENT_KINDS, serverFacets?.event_kind)}
            active={filter.event_kind ? new Set([filter.event_kind]) : new Set()}
            onToggle={(v) => toggleFacet("event_kind", v)}
            onClear={() => clearFacet("event_kind")}
          />
          <FilterFacet
            title="Decision"
            values={buildFacetRows(CANONICAL_POLICY_DECISIONS, decisionCounts)}
            active={decisionFilter ? new Set([decisionFilter]) : new Set()}
            onToggle={(v) =>
              setSearchParams((prev) => {
                const next = new URLSearchParams(prev);
                if (next.get("policy_decision") === v) next.delete("policy_decision");
                else next.set("policy_decision", v);
                return next;
              })
            }
            onClear={() => clearSearchParam("policy_decision")}
          />
          <FilterFacet
            title="Verification"
            values={buildFacetRows(
              CANONICAL_VERIFICATION_LEVELS,
              serverFacets?.verification_level,
            )}
            active={
              filter.verification_level ? new Set([filter.verification_level]) : new Set()
            }
            onToggle={(v) => toggleFacet("verification_level", v)}
            onClear={() => clearFacet("verification_level")}
          />
        </aside>

        {/* Main pane — table only. Histogram + search bar moved up to
            sit ABOVE the filter+table split (see comment near the
            outer flex). */}
        <main className="flex flex-1 flex-col overflow-hidden">
          {/* Table topbar: bulk-select toggle, loaded count, column picker,
              live-tail toggle. */}
          <div className="flex items-center justify-between border-b border-r5e-border px-4 py-2">
            <div className="flex items-center gap-3">
              <input
                type="checkbox"
                aria-label="Select all rows on this page"
                checked={
                  rows.length > 0 && rows.every((r) => selection.has(r.run_id))
                }
                onChange={(e) => {
                  if (e.target.checked) {
                    setSelection(new Set(rows.map((r) => r.run_id)));
                  } else {
                    setSelection(new Set());
                  }
                }}
                className="h-4 w-4 cursor-pointer accent-r5e-accent"
              />
              <span className="text-xs text-r5e-muted" data-testid="dashboard-row-count">
                {filteredRows.length !== allRows.length
                  ? `${filteredRows.length} of ${allRows.length} row${allRows.length === 1 ? "" : "s"} (${[
                      kindFilter ? `kind: ${kindFilter}` : null,
                      categoryFilter ? `category: ${categoryFilter}` : null,
                      toolFilter ? `tool: ${toolFilter}` : null,
                      decisionFilter ? `decision: ${decisionFilter}` : null,
                    ]
                      .filter(Boolean)
                      .join(", ")})`
                  : `${allRows.length} row${allRows.length === 1 ? "" : "s"} loaded`}
              </span>
            </div>
            <div className="flex items-center gap-3">
              <ColumnPicker
                visibility={columnVisibility}
                onChange={onColumnVisibilityChange}
              />
              <LiveTailToggle
                enabled={liveTailEnabled}
                onToggle={setLiveTailEnabled}
              />
            </div>
          </div>

          {/* #65 fix — single horizontal-scroll container wrapping BOTH
              the header AND the virtualized body so they scroll-track
              together. Pre-#65 the header lived in its own <div>
              outside the body's overflow-auto element; on horizontal
              scroll the body shifted but the header stayed pinned to
              the viewport's left edge, breaking column alignment.

              Architecture:
                - OUTER (this <div>): owns BOTH overflow-x AND overflow-y;
                  also the TanStack Virtual scrollParentRef so vertical
                  virtualization tracks scroll here.
                - INNER (`min-w-fit`): grows to the table's intrinsic
                  width (sum of fixed column widths + the floor of any
                  `min-w-[N] flex-1` columns). When inner > outer, the
                  outer's horizontal scrollbar appears; both header and
                  body scroll left together.
                - HEADER: `position: sticky; top: 0` pins vertically while
                  inner scrolls horizontally — header tracks LEFT with
                  the body but stays at the top vertically. The header
                  is rendered UNCONDITIONALLY inside `min-w-fit` so it
                  remains visible in initial-load, error, and empty
                  states (operators reading the table see the column
                  scaffolding even while filters narrow the result set).
                - Loading / error / empty states render BELOW the header
                  but still inside `min-w-fit` so the variable-width
                  status block sits beneath the column scaffold; their
                  inner content uses normal padding so the messages
                  remain centered visually. */}
          {/* AuditTable — REAL <table> with <colgroup>-driven column
              widths + tanstack-table column-resize handles. Replaced
              the prior bespoke flexbox-emulated table that drifted
              cells out of column alignment whenever row content widths
              varied. The "row open" + "principal-drill" affordances
              live inside the table now (row-level onClick + per-cell
              stopPropagation) — no nested-button gymnastics. See
              `~/components/audit/AuditTable.tsx`. */}
          {isError ? (
            <div className="flex-1 p-6 text-sm text-r5e-danger">
              Failed to load receipts.
            </div>
          ) : (
            <AuditTable
              rows={rows}
              visibility={columnVisibility}
              sort={sort}
              onSortClick={onSortClick}
              selectedIds={selection}
              onToggleRow={toggleRow}
              onToggleAll={(next) => {
                if (next) {
                  setSelection(new Set(rows.map((r) => r.run_id)));
                } else {
                  setSelection(new Set());
                }
              }}
              onOpen={openReceiptDrawer}
              loading={isLoading}
            />
          )}

          {/* Pagination footer (#32). Page numbers + Prev/Next + total. */}
          <PageNavigator
            currentPageIndex={pageIndex}
            loadedCount={sortedRows.length}
            totalCount={null /* backend total_count not yet present — see #32 follow-up */}
            hasMore={Boolean(hasNextPage)}
            isFetching={isFetchingNextPage}
            onPageChange={onPageChange}
          />

          {/* Bulk-action bar */}
          {role && (
            <BulkActionBar
              selectedRunIds={selectedRunIds}
              role={role}
              onClearSelection={() => setSelection(new Set())}
              onOpenDetail={openReceiptDrawer}
            />
          )}
        </main>

        {/* Right drawer slot — populated by nested route. Renders nothing
            when no drawer route is active. */}
      </div>

      {/* Drawer route overlay. It is fixed below the global topbar so the
          drawer and its backdrop cover the histogram/search panels too,
          not just the table split underneath them. */}
      {outlet && (
        <aside
          data-testid="dashboard-receipt-drawer-overlay"
          className="fixed bottom-0 right-0 top-14 z-40 w-[720px] border-l border-r5e-border bg-r5e-surface shadow-2xl"
        >
          <Outlet />
        </aside>
      )}

      {/* Toast stack */}
      <ToastStack
        toasts={liveTailToastItems(toasts)}
        onDismiss={dismissToast}
        testId="dashboard-toasts"
        className="w-96"
      />
    </div>
  );
}

function ActiveFilters({
  filter,
  categoryFilter,
  toolFilter,
  decisionFilter,
  kindFilter,
  onClear,
}: {
  filter: ReceiptsFilter;
  categoryFilter: string | null;
  toolFilter: string | null;
  decisionFilter: "allow" | "deny" | null;
  kindFilter: CallKind | null;
  onClear: (key: string) => void;
}): JSX.Element | null {
  const chips: Array<{ key: string; label: string }> = [];
  if (kindFilter) chips.push({ key: CALL_KIND_PARAM, label: `kind:${kindFilter}` });
  if (categoryFilter) chips.push({ key: "category", label: `category:${categoryFilter}` });
  if (toolFilter) chips.push({ key: "tool_kind", label: `tool:${toolFilter}` });
  if (filter.event_kind) chips.push({ key: "event_kind", label: `event:${filter.event_kind}` });
  if (decisionFilter) chips.push({ key: "policy_decision", label: `decision:${decisionFilter}` });
  if (filter.verification_level) chips.push({ key: "verification_level", label: `verification:${filter.verification_level}` });
  if (filter.principal_subject) chips.push({ key: "principal_subject", label: `principal:${filter.principal_subject}` });
  if (filter.q) chips.push({ key: "q", label: `search:${filter.q}` });
  if (filter.since) chips.push({ key: "since", label: "since" });
  if (filter.until) chips.push({ key: "until", label: "until" });

  if (chips.length === 0) return null;

  return (
    <div
      data-testid="active-filters"
      className="flex flex-wrap items-center gap-2 border-b border-r5e-border bg-r5e-surface/50 px-4 py-2"
    >
      <span className="font-mono text-[10px] uppercase tracking-wider text-r5e-muted">
        Active filters
      </span>
      {chips.map((chip) => (
        <button
          key={chip.key}
          type="button"
          data-testid={`active-filter-${chip.key}`}
          onClick={() => onClear(chip.key)}
          className="inline-flex items-center gap-1 rounded border border-r5e-accent/50 bg-r5e-accent/10 px-2 py-1 font-mono text-[10px] text-r5e-accent hover:bg-r5e-accent/15"
          title={`Remove ${chip.label}`}
        >
          <span className="max-w-[18rem] truncate">{chip.label}</span>
          <X className="h-3 w-3" aria-hidden="true" />
        </button>
      ))}
    </div>
  );
}

function DashboardExportEvidenceButton({
  selectedRunIds,
}: {
  selectedRunIds: string[];
}): JSX.Element {
  const [status, setStatus] = useState<"idle" | "pending" | "error">("idle");
  const [error, setError] = useState<string | null>(null);
  const disabled = selectedRunIds.length === 0 || status === "pending";

  async function onClick(): Promise<void> {
    setStatus("pending");
    setError(null);
    try {
      await downloadEvidence(selectedRunIds);
      setStatus("idle");
    } catch (err) {
      setStatus("error");
      setError(
        err instanceof ApiError
          ? err.error_description
          : err instanceof Error
            ? err.message
            : "Export failed",
      );
    }
  }

  return (
    <div className="flex items-center gap-2">
      {error && (
        <span role="alert" className="max-w-[14rem] truncate text-[10px] text-r5e-danger">
          {error}
        </span>
      )}
      <button
        type="button"
        data-testid="dashboard-export-evidence"
        disabled={disabled}
        onClick={() => void onClick()}
        title={
          selectedRunIds.length === 0
            ? "Select rows to export evidence"
            : `Export evidence for ${selectedRunIds.length} selected receipt${selectedRunIds.length === 1 ? "" : "s"}`
        }
        className="inline-flex items-center gap-1.5 rounded border border-r5e-accent px-3 py-1.5 text-xs font-semibold text-r5e-accent hover:bg-r5e-accent/10 disabled:cursor-not-allowed disabled:border-r5e-border disabled:text-r5e-muted disabled:opacity-60"
      >
        <Download className="h-3.5 w-3.5" aria-hidden="true" />
        {status === "pending" ? "Exporting…" : "Export Evidence"}
      </button>
    </div>
  );
}

// Map a live-tail event kind onto the shared ToastTone palette.
function liveTailToneFor(kind: LiveTailToast["kind"]): ToastTone {
  switch (kind) {
    case "fatal":
      return "danger";
    case "paused":
      return "warning";
    case "trim":
    case "backfill_truncated":
      return "neutral";
    default:
      return "neutral";
  }
}

function liveTailToastItems(
  toasts: LiveTailToast[],
): ReadonlyArray<ToastItem<string>> {
  return toasts.map((t) => ({
    id: t.id,
    tone: liveTailToneFor(t.kind),
    message: t.message,
  }));
}

// ---------------------------------------------------------------------------
// QueryBar — controlled input that submits on Enter; deep-links via `?q=`.
// ---------------------------------------------------------------------------

function QueryBar({
  initialValue,
  onSubmit,
}: {
  initialValue: string;
  onSubmit: (value: string) => void;
}): JSX.Element {
  const [value, setValue] = useState(initialValue);
  useEffect(() => {
    setValue(initialValue);
  }, [initialValue]);
  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        onSubmit(value);
      }}
      role="search"
      className="flex gap-2"
    >
      <input
        type="search"
        value={value}
        onChange={(e) => setValue(e.target.value)}
        placeholder="Search receipts (principal, summary, run_id)…"
        className="flex-1 rounded border border-r5e-border bg-r5e-bg px-3 py-2 text-sm text-r5e-text placeholder:text-r5e-muted focus:border-r5e-accent focus:outline-none"
      />
      <button
        type="submit"
        className="rounded bg-r5e-accent px-4 py-2 text-sm font-medium text-r5e-text hover:bg-r5e-accent-glow"
      >
        Search
      </button>
    </form>
  );
}
