// Audit-log column model — pure module backing Dashboard.tsx (#31, #32, #33).
//
// Single source-of-truth for:
//   - canonical column ids + display labels (rendered in the header row +
//     ColumnPicker dropdown)
//   - which columns are sortable (#31), with a per-column comparator over
//     the loaded `ReceiptRow[]` page
//   - which columns are REQUIRED — post-Pencil-V2 (TOOL/COMMAND/SUBJECT
//     triplet split) only `timestamp` is required: it's the row's temporal
//     anchor and the table loses meaning without it. Every other column is
//     toggleable via the picker. (Pre-V2 `summary` was also required; the
//     triplet now carries the action axis structurally so the synthesized
//     summary is optional.)
//   - default visibility — the columns with `defaultVisible: true` are
//     ON when nothing's persisted in localStorage. The triplet pieces
//     (tool, command, subject) plus timestamp/category/principal/decision/
//     verification_level are on by default (8 of 10); event_kind + summary
//     are off by default (toggleable for users who prefer the legacy
//     synthesized view).
//   - sort cycle: default (timestamp DESC) → ASC by clicked column → DESC
//     by clicked column → back to default. The cycle is per-column; clicking
//     a different column starts the cycle on that column at ASC.
//
// Pure / no React. The hook + components consume the helpers below.
//
// ## Why client-side sort (not backend pushdown)
//
// Brief explicitly permits a client-side fallback: "If backend doesn't yet
// support `sort_by` + `sort_dir` query params, file as a follow-up issue
// and ship client-side sort over loaded rows for now (acceptable demo-side
// fallback)." Backend `ReceiptsHandler` does NOT accept sort_by/sort_dir
// today (verified 2026-04-30) — receipts come back in `inserted_at DESC`
// order from `query_paginated/1`. Filed as follow-up issue (see MR
// description). The `sortRows` comparator below operates over loaded rows
// (`data.pages.flatMap`), preserving the default order when the user
// hasn't picked a sort axis.
//
// When backend support lands, `sortRows` becomes a no-op (or a sanity
// check) and the `sort_by`/`sort_dir` keys are added to `useReceipts`
// query-key + URL-param plumbing. Today it stays here; the API surface
// (`AuditLogSortState`) is forward-stable.

import type { ReceiptRow } from "~/hooks/useReceipts";
import { displayPrincipal } from "~/lib/principal";
import { categoryFromRow, effectiveDecision, viewTagsOf } from "~/lib/tags";

// ---------------------------------------------------------------------------
// Column ids
// ---------------------------------------------------------------------------

/**
 * Canonical column id space. Adding a new id here forces the columns
 * registry below + the ColumnPicker UI + Dashboard.tsx header row to
 * pick it up via TypeScript exhaustiveness checks.
 */
export type AuditLogColumnId =
  | "timestamp"
  | "event_kind"
  | "principal"
  | "summary"
  | "category"
  | "tags"
  | "tool"
  | "command"
  | "subject"
  | "decision"
  | "verification_level";

/** Static column metadata. Iteration order = render order. */
export interface AuditLogColumn {
  id: AuditLogColumnId;
  /** Human label shown in header row + picker. */
  label: string;
  /** Whether the user may click the header to sort. (#31) */
  sortable: boolean;
  /**
   * Whether the column may be hidden via the picker. Required = always shown
   * (the timestamp anchors every row temporally and cannot be hidden).
   *
   * Post-brief-update (TOOL/COMMAND/SUBJECT triplet): only `timestamp` is
   * required. The triplet is default-visible but each piece is individually
   * togglable (the column picker UI exposes all three).
   */
  required: boolean;
  /**
   * Whether this column is ON by default. The user's localStorage-persisted
   * picker state can override; `defaultColumnVisibility()` returns the
   * default ON set.
   */
  defaultVisible: boolean;
  /**
   * Legacy: Tailwind width class once used by the bespoke flexbox table.
   * The new `<AuditTable>` (real `<table>` + `<colgroup>` + tanstack-table)
   * uses the numeric `defaultWidthPx` / `minWidthPx` / `maxWidthPx`
   * fields below for column sizing instead — concrete pixel widths so
   * column resize, persistence, and `<colgroup>` alignment all use one
   * source of truth. `widthClass` is kept ONLY because some shared
   * cell components (TimestampCell etc.) and the live-tail tests still
   * read it; new code paths shouldn't depend on it.
   */
  widthClass: string;
  /**
   * Default column width in pixels. Authoritative for the AuditTable
   * `<colgroup>`. Persisted user resizes (`saveColumnWidths`) override
   * this at runtime; reset clears the override and falls back here.
   */
  defaultWidthPx: number;
  /** Resize floor in pixels. Defaults to 60 if omitted. */
  minWidthPx?: number;
  /** Resize ceiling in pixels. Defaults to 1200 if omitted. */
  maxWidthPx?: number;
}

// Render order matches Pencil's `comp/receipts-table-v2` (`kPFqb`):
//   timestamp · category · tags · principal · TOOL · COMMAND · SUBJECT · decision · verification
//
// `event_kind` and `summary` are kept in the registry as togglable columns
// (defaultVisible: false) for users who want the legacy view.
export const AUDIT_LOG_COLUMNS: readonly AuditLogColumn[] = [
  // Anchor: the temporal axis. Always shown; `required: true` is the only
  // structural minimum left after the triplet split.
  { id: "timestamp", label: "Timestamp", sortable: true, required: true, defaultVisible: true, widthClass: "w-44", defaultWidthPx: 176, minWidthPx: 120 },
  // R4-tinted category pill — the at-a-glance "what kind of action" axis.
  { id: "category", label: "Category", sortable: true, required: false, defaultVisible: true, widthClass: "w-36", defaultWidthPx: 144, minWidthPx: 96 },
  // Canonical R1 rows show a multi-pill tag band alongside the category
  // and decision pills. This column keeps the table scannable without
  // reopening the drawer for scope/target context.
  { id: "tags", label: "Tags", sortable: false, required: false, defaultVisible: true, widthClass: "w-60", defaultWidthPx: 240, minWidthPx: 160, maxWidthPx: 520 },
  // Principal cell with colored dot per principal kind.
  { id: "principal", label: "Principal", sortable: true, required: false, defaultVisible: true, widthClass: "w-48", defaultWidthPx: 192, minWidthPx: 120 },
  // TOOL/COMMAND/SUBJECT — the policy-natural triplet. Each axis is
  // independently sortable + filterable + Cedar-addressable. Replaces the
  // pre-Wave-C synthesized `summary` column as the default action surface.
  { id: "tool", label: "Tool", sortable: true, required: false, defaultVisible: true, widthClass: "w-28", defaultWidthPx: 112, minWidthPx: 80 },
  { id: "command", label: "Command", sortable: true, required: false, defaultVisible: true, widthClass: "w-32", defaultWidthPx: 128, minWidthPx: 80 },
  // SUBJECT is the natural-language slot — long URLs, JSON snippets, file
  // paths. Per design/briefs/02-dashboard-table.md "subject = flex (min
  // 280px, grow)": floor at 280px so the total table width is PREDICTABLE
  // (that lets the wrapping single horizontal-scroll container show a
  // scrollbar at narrow viewports per #65) while flex-1 lets the column
  // expand on wide viewports rather than leaving dead horizontal space.
  // Cap at max-w-[640px] + overflow-hidden so live `argument_body` values
  // (which can be entire bash command lines until issue #66 lands the
  // broker-resident migration) don't blow the row out to 18,000px wide
  // and defeat the truncate inside SubjectCell. Without overflow-hidden
  // on this wrapper, the inner `truncate` is a no-op because the parent
  // row's `min-w-fit` (from #65) propagates fit-content up the tree.
  { id: "subject", label: "Subject", sortable: false, required: false, defaultVisible: true, widthClass: "min-w-[280px] max-w-[640px] flex-1 overflow-hidden", defaultWidthPx: 480, minWidthPx: 240, maxWidthPx: 1200 },
  // Decision is a small pill (ALLOW/DENY); content-sized.
  { id: "decision", label: "Decision", sortable: true, required: false, defaultVisible: true, widthClass: "w-20", defaultWidthPx: 88, minWidthPx: 72 },
  { id: "verification_level", label: "Verification", sortable: true, required: false, defaultVisible: true, widthClass: "w-40", defaultWidthPx: 176, minWidthPx: 120 },
  // Togglable / off-by-default. event_kind is the legacy coarse axis;
  // summary is the synthesized one-liner for users who prefer it over the
  // structured triplet. Same containment as subject (long live values).
  { id: "event_kind", label: "Event kind", sortable: true, required: false, defaultVisible: false, widthClass: "w-40", defaultWidthPx: 160, minWidthPx: 96 },
  { id: "summary", label: "Summary", sortable: false, required: false, defaultVisible: false, widthClass: "min-w-[280px] max-w-[640px] flex-1 overflow-hidden", defaultWidthPx: 480, minWidthPx: 240, maxWidthPx: 1200 },
] as const;

export const AUDIT_LOG_COLUMN_IDS: readonly AuditLogColumnId[] =
  AUDIT_LOG_COLUMNS.map((c) => c.id);

const COLUMN_BY_ID: Record<AuditLogColumnId, AuditLogColumn> = AUDIT_LOG_COLUMNS.reduce(
  (acc, c) => {
    acc[c.id] = c;
    return acc;
  },
  {} as Record<AuditLogColumnId, AuditLogColumn>,
);

export function getAuditLogColumn(id: AuditLogColumnId): AuditLogColumn {
  return COLUMN_BY_ID[id];
}

// ---------------------------------------------------------------------------
// Visibility
// ---------------------------------------------------------------------------

/** Set-shaped visibility map. The user toggles entries in/out. */
export type AuditLogColumnVisibility = ReadonlySet<AuditLogColumnId>;

/** Default: only the columns marked `defaultVisible: true`. */
export function defaultColumnVisibility(): AuditLogColumnVisibility {
  return new Set(
    AUDIT_LOG_COLUMNS.filter((c) => c.defaultVisible).map((c) => c.id),
  );
}

/**
 * Toggle a column's visibility. Required columns (post-Pencil-V2: only
 * `timestamp`) cannot be hidden — attempting to hide one is a no-op (the
 * picker UI also disables that checkbox; this helper is the second line
 * of defense).
 */
export function toggleColumnVisibility(
  current: AuditLogColumnVisibility,
  id: AuditLogColumnId,
): AuditLogColumnVisibility {
  const col = COLUMN_BY_ID[id];
  const next = new Set(current);
  if (next.has(id)) {
    if (col.required) return current; // can't hide required columns
    next.delete(id);
  } else {
    next.add(id);
  }
  return next;
}

/**
 * Reconcile a stored visibility set against the current column registry.
 * Drops unknown ids (forward-compat: a stored id that's been removed from
 * the registry simply doesn't render) and force-adds required ids (a stored
 * set that pre-dates a column being marked required must include it).
 */
export function normalizeColumnVisibility(
  raw: Iterable<string>,
): AuditLogColumnVisibility {
  const valid = new Set<AuditLogColumnId>();
  for (const id of raw) {
    if (AUDIT_LOG_COLUMN_IDS.includes(id as AuditLogColumnId)) {
      valid.add(id as AuditLogColumnId);
    }
  }
  for (const c of AUDIT_LOG_COLUMNS) {
    if (c.required) valid.add(c.id);
  }
  return valid;
}

/**
 * "X of Y columns" label for the picker trigger. (#33 brief: "Show selected
 * count: '5 of 6 columns'").
 */
export function columnCountLabel(visibility: AuditLogColumnVisibility): string {
  return `${visibility.size} of ${AUDIT_LOG_COLUMN_IDS.length} columns`;
}

// ---------------------------------------------------------------------------
// Sort
// ---------------------------------------------------------------------------

export type SortDirection = "asc" | "desc";

/**
 * Active sort state. `null` → default (timestamp DESC, server order).
 */
export interface AuditLogSortState {
  column: AuditLogColumnId;
  direction: SortDirection;
}

/**
 * Click-cycle for the active sort axis. Per #31 brief:
 *
 *   - Click a header → sort ASC by that column
 *   - Click again → DESC
 *   - Click a third time → return to default (timestamp DESC, i.e. `null`)
 *   - Click a DIFFERENT column → that column ASC (cycle restarts)
 */
export function nextSortState(
  current: AuditLogSortState | null,
  clicked: AuditLogColumnId,
): AuditLogSortState | null {
  if (current === null || current.column !== clicked) {
    return { column: clicked, direction: "asc" };
  }
  if (current.direction === "asc") {
    return { column: clicked, direction: "desc" };
  }
  // current.direction === "desc" → cycle back to default
  return null;
}

/**
 * Pure comparator that returns a SORTED COPY of the input rows. Default
 * (`sort === null`) returns the rows unchanged — backend already orders
 * by `inserted_at DESC` so the SPA preserves that.
 *
 * Comparators are total + stable on ties (we fall back to `run_id` so
 * the order is deterministic across renders; React keys depend on this).
 */
export function sortRows(
  rows: readonly ReceiptRow[],
  sort: AuditLogSortState | null,
): ReceiptRow[] {
  if (sort === null) return rows.slice();
  const { column, direction } = sort;
  const cmp = comparatorFor(column);
  const sign = direction === "asc" ? 1 : -1;
  return rows
    .slice()
    .sort((a, b) => {
      const v = cmp(a, b);
      if (v !== 0) return sign * v;
      // Stable tiebreaker by run_id so renders are deterministic.
      return a.run_id.localeCompare(b.run_id);
    });
}

type RowComparator = (a: ReceiptRow, b: ReceiptRow) => number;

function comparatorFor(column: AuditLogColumnId): RowComparator {
  switch (column) {
    case "timestamp":
      return (a, b) =>
        cmpNullableString(
          a.signed_predicate.timestamp ?? null,
          b.signed_predicate.timestamp ?? null,
        );
    case "event_kind":
      return (a, b) =>
        cmpNullableString(
          a.signed_predicate.event_kind ?? null,
          b.signed_predicate.event_kind ?? null,
        );
    case "principal":
      return (a, b) =>
        cmpNullableString(
          displayPrincipal(a.signed_predicate.principal),
          displayPrincipal(b.signed_predicate.principal),
        );
    case "category":
      return (a, b) => cmpNullableString(categoryFromRow(a), categoryFromRow(b));
    case "decision":
      return (a, b) =>
        cmpNullableString(effectiveDecision(a), effectiveDecision(b));
    case "verification_level":
      return (a, b) =>
        cmpNullableString(
          a.outer_container.verification_level,
          b.outer_container.verification_level,
        );
    case "tool":
      return (a, b) => {
        const ta = (viewTagsOf(a)?.tool_kind ?? null) as string | null;
        const tb = (viewTagsOf(b)?.tool_kind ?? null) as string | null;
        return cmpNullableString(ta, tb);
      };
    case "command":
      return (a, b) => {
        const va = (viewTagsOf(a)?.verb ?? null) as string | null;
        const vb = (viewTagsOf(b)?.verb ?? null) as string | null;
        return cmpNullableString(va, vb);
      };
    case "summary":
    case "subject":
    case "tags":
      // Per AUDIT_LOG_COLUMNS, `summary` and `subject` are `sortable:
      // false` (free-form action text doesn't sort meaningfully). TS
      // exhaustiveness requires the branch. Stable no-op.
      return () => 0;
  }
}

/**
 * `null < non-null` consistently — null/undefined values sort to the start
 * in ASC, end in DESC. Avoids the `localeCompare` crash on null and gives
 * a deterministic position for rows missing the field.
 */
function cmpNullableString(a: string | null, b: string | null): number {
  if (a === b) return 0;
  if (a === null || a === undefined) return -1;
  if (b === null || b === undefined) return 1;
  return a.localeCompare(b);
}

// ---------------------------------------------------------------------------
// Pagination math (#32)
// ---------------------------------------------------------------------------

/** Page size constant. The picker doesn't change this (#32 brief). */
export const AUDIT_LOG_PAGE_SIZE = 50;

/**
 * Compute the slice [start, end) of rows visible on the given page index
 * (0-based) given the total loaded-row count + page size.
 */
export function pageSlice(
  totalLoaded: number,
  pageIndex: number,
  pageSize: number = AUDIT_LOG_PAGE_SIZE,
): { start: number; end: number } {
  const rawStart = Math.max(0, pageIndex * pageSize);
  // Clamp `start` to `totalLoaded` so a page index past the loaded window
  // produces an empty range `[totalLoaded, totalLoaded)` rather than a
  // negative `end - start` (which crashes Array.prototype.slice with weird
  // semantics: `arr.slice(250, 50)` returns []).
  const start = Math.min(rawStart, totalLoaded);
  const end = Math.min(totalLoaded, start + pageSize);
  return { start, end };
}

/**
 * Pick the page numbers shown in the page navigator. We compress the list
 * around the current page (Datadog/ES-table style):
 *
 *   1 ... 4 5 [6] 7 8 ... 17
 *
 * Returns a list of "page" entries (0-based numeric index) interleaved
 * with "ellipsis" sentinels. Always includes the first and last page so
 * the navigator's edges stay reachable.
 */
export type PageNavEntry =
  | { kind: "page"; index: number }
  | { kind: "ellipsis"; key: string };

export function buildPageNav(
  totalPages: number,
  currentPageIndex: number,
  windowSize: number = 1,
): PageNavEntry[] {
  if (totalPages <= 0) return [];
  if (totalPages === 1) return [{ kind: "page", index: 0 }];

  const last = totalPages - 1;
  const lo = Math.max(1, currentPageIndex - windowSize);
  const hi = Math.min(last - 1, currentPageIndex + windowSize);

  const entries: PageNavEntry[] = [{ kind: "page", index: 0 }];

  if (lo > 1) entries.push({ kind: "ellipsis", key: "lo" });

  for (let i = lo; i <= hi; i++) {
    if (i > 0 && i < last) entries.push({ kind: "page", index: i });
  }

  if (hi < last - 1) entries.push({ kind: "ellipsis", key: "hi" });

  if (last > 0) entries.push({ kind: "page", index: last });

  return entries;
}
