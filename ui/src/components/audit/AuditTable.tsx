// AuditTable — REAL <table> replacement for the prior flexbox-emulated
// audit log row. Owns:
//   - <table> with <colgroup> driven by the AUDIT_LOG_COLUMNS registry
//     (numeric pixel widths via `defaultWidthPx`, overridable per-user
//     via the resize handle + persisted to localStorage)
//   - sticky <thead> with sortable columns (delegates to onSortClick) +
//     drag-to-resize handles between columns
//   - virtualized <tbody> via @tanstack/react-virtual (rows are
//     absolutely positioned inside a spacer <tr> per their canonical
//     pattern — works with table-row layout because we use
//     `display: block` on the tbody/tr to opt out of the strict CSS
//     table model exactly where virtualization needs it)
//   - per-row click → onOpen(run_id) for the receipt drawer; principal
//     <td> stops propagation and routes to the Investigation Timeline
//     (the !94 F10 drill, preserved structurally without the bespoke
//     3-button gymnastics the flexbox version needed to avoid invalid
//     nested <button>s)
//   - bulk-select checkbox in the leading <td>
//
// History (May 2026): the prior implementation rendered each row as a
// `<div role="row">` with sibling `<button>` and `<span>` cell wrappers
// styled with flexbox + per-cell Tailwind width classes. Header was a
// SEPARATE flex container reading the same width classes. On live data
// each row's flex layout was independent of every other row's, so cells
// drifted out of column alignment whenever content widths varied (long
// `argument_body` strings, empty SubjectCell, etc.). User-visible
// failure mode: DECISION + VERIFICATION columns floating in random
// horizontal positions across rows, no way to grab a column edge to
// resize. This module replaces all of that with a real <table>.

import {
  getCoreRowModel,
  useReactTable,
  type ColumnDef,
  type ColumnSizingState,
} from "@tanstack/react-table";
import { useCallback, useEffect, useMemo, useState, type ChangeEvent } from "react";
import { useNavigate } from "react-router-dom";

import { CategoryPill } from "~/components/audit/CategoryPill";
import { CommandCell } from "~/components/audit/CommandCell";
import { SubjectCell } from "~/components/audit/SubjectCell";
import { ToolCell } from "~/components/audit/ToolCell";
import { Pill } from "~/components/shared/Pill";
import type { ReceiptRow as ReceiptRowData } from "~/hooks/useReceipts";
import {
  AUDIT_LOG_COLUMNS,
  type AuditLogColumn,
  type AuditLogColumnId,
  type AuditLogColumnVisibility,
  type AuditLogSortState,
} from "~/lib/auditLogColumns";
import {
  loadColumnOrder,
  loadColumnWidths,
  saveColumnOrder,
  saveColumnWidths,
} from "~/lib/auditLogStorage";
import { displayPrincipal } from "~/lib/principal";
import { chipsForRow, compactTargetResources } from "~/lib/rowChips";
import { timelinePath } from "~/lib/routes";
import {
  categoryFromRow,
  displaySummary,
  effectiveDecision,
  viewTagsOf,
} from "~/lib/tags";

interface Props {
  rows: ReceiptRowData[];
  visibility: AuditLogColumnVisibility;
  sort: AuditLogSortState | null;
  onSortClick: (id: AuditLogColumnId) => void;
  selectedIds: Set<string>;
  onToggleRow: (runId: string, selected: boolean) => void;
  onToggleAll: (selected: boolean) => void;
  onOpen: (runId: string) => void;
  /**
   * Optional total-rows footer surface. Rendered ABOVE the table chrome
   * by Dashboard, NOT inside this component — kept here only as a hook
   * so the caller knows the row count we're about to virtualize.
   */
  loading?: boolean;
}

const SELECT_COLUMN_WIDTH_PX = 36;

export function AuditTable({
  rows,
  visibility,
  sort,
  onSortClick,
  selectedIds,
  onToggleRow,
  onToggleAll,
  onOpen,
  loading,
}: Props): JSX.Element {
  const navigate = useNavigate();

  // Persisted operator-chosen column order. Empty = use registry order.
  // Loaded once at mount; persisted on every reorder via the
  // `setColumnOrder` callback below.
  const [columnOrder, setColumnOrderState] = useState<string[]>(() =>
    loadColumnOrder(),
  );
  const setColumnOrder = useCallback((next: string[]): void => {
    setColumnOrderState(next);
    saveColumnOrder(next);
  }, []);

  // Visible columns, ordered first by the operator's persisted preference
  // (when present) and then by registry order for any columns the operator
  // hasn't explicitly placed. This lets us add new registry columns over
  // time without invalidating saved orderings — they just appear at the
  // end of the visible set until the operator drags them.
  const visibleColumns = useMemo<readonly AuditLogColumn[]>(() => {
    const all = AUDIT_LOG_COLUMNS.filter((c) => visibility.has(c.id));
    if (columnOrder.length === 0) return all;
    const byId = new Map<string, AuditLogColumn>(
      all.map((c) => [c.id as string, c]),
    );
    const ordered: AuditLogColumn[] = [];
    for (const id of columnOrder) {
      const col = byId.get(id);
      if (col) {
        ordered.push(col);
        byId.delete(id);
      }
    }
    // Anything not in the persisted order keeps registry order at the end.
    for (const c of all) if (byId.has(c.id as string)) ordered.push(c);
    return ordered;
  }, [visibility, columnOrder]);

  // Live drag state for the column-header drag-to-reorder UI.
  // `draggingColumnId` is the column the operator picked up; cleared
  // on dragend or drop. `dragOverColumnId` highlights the prospective
  // drop target so the operator gets a visual cue before releasing.
  const [draggingColumnId, setDraggingColumnId] = useState<string | null>(null);
  const [dragOverColumnId, setDragOverColumnId] = useState<string | null>(null);

  /**
   * Reorder helper called by the column-header drag handler. Splices
   * `draggedId` out of its current position and inserts it ahead of
   * `targetId` (or to the end when `targetId` is null). Persists the
   * new order. Operates over the FULL registry id list (not just
   * visible) so a column that's currently hidden retains its place
   * relative to its neighbours.
   */
  const reorderColumn = useCallback(
    (draggedId: string, targetId: string | null): void => {
      const fullOrder =
        columnOrder.length > 0
          ? [...columnOrder, ...AUDIT_LOG_COLUMNS.filter((c) => !columnOrder.includes(c.id)).map((c) => c.id)]
          : AUDIT_LOG_COLUMNS.map((c) => c.id);
      const without = fullOrder.filter((id) => id !== draggedId);
      const targetIdx =
        targetId === null ? without.length : without.indexOf(targetId);
      if (targetIdx < 0) return;
      without.splice(targetIdx, 0, draggedId);
      setColumnOrder(without);
    },
    [columnOrder, setColumnOrder],
  );

  // ---------------------------------------------------------------------
  // Column sizing — load persisted widths, fall back to defaults, push
  // updates back to storage on resize.
  // ---------------------------------------------------------------------
  const [columnSizing, setColumnSizing] = useState<ColumnSizingState>(() => {
    const persisted = loadColumnWidths();
    const initial: ColumnSizingState = {};
    for (const c of AUDIT_LOG_COLUMNS) {
      initial[c.id] = persisted[c.id] ?? c.defaultWidthPx;
    }
    return initial;
  });

  useEffect(() => {
    saveColumnWidths(columnSizing);
  }, [columnSizing]);

  // ---------------------------------------------------------------------
  // Build TanStack column defs from the registry.
  // ---------------------------------------------------------------------
  const columns = useMemo<ColumnDef<ReceiptRowData>[]>(() => {
    return visibleColumns.map((col) => ({
      id: col.id,
      accessorFn: (row) => row,
      header: col.label,
      enableSorting: col.sortable,
      enableResizing: true,
      size: columnSizing[col.id] ?? col.defaultWidthPx,
      minSize: col.minWidthPx ?? 60,
      maxSize: col.maxWidthPx ?? 1200,
      cell: ({ row }) => renderCell(col.id, row.original, navigate, onOpen),
    }));
    // We intentionally DON'T include columnSizing in deps — TanStack
    // owns the live size via state; the initial size is a seed.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [visibleColumns, navigate, onOpen]);

  const table = useReactTable({
    data: rows,
    columns,
    state: { columnSizing },
    onColumnSizingChange: setColumnSizing,
    columnResizeMode: "onChange",
    getCoreRowModel: getCoreRowModel(),
  });

  const totalSelected = useMemo(() => {
    let n = 0;
    for (const r of rows) if (selectedIds.has(r.run_id)) n++;
    return n;
  }, [rows, selectedIds]);
  const allSelected = rows.length > 0 && totalSelected === rows.length;

  const handleToggleAll = useCallback(
    (e: ChangeEvent<HTMLInputElement>) => onToggleAll(e.target.checked),
    [onToggleAll],
  );

  // Computed grand-total table width: select column + every visible
  // column at its current sized width. Locks the table to a single
  // intrinsic width so horizontal scroll behaves predictably (one
  // scroll container under the wrapper, header tracks body).
  const totalTableWidthPx = useMemo(() => {
    let w = SELECT_COLUMN_WIDTH_PX;
    for (const c of visibleColumns) w += columnSizing[c.id] ?? c.defaultWidthPx;
    return w;
  }, [visibleColumns, columnSizing]);

  return (
    <div
      data-testid="audit-table-scroll"
      className="flex-1 overflow-auto"
    >
      <table
        data-testid="audit-table"
        className="border-collapse text-sm font-mono text-r5e-text"
        style={{
          width: totalTableWidthPx,
          tableLayout: "fixed",
        }}
      >
        {/* <colgroup> drives every cell's width. With table-layout: fixed
            the browser DOES NOT auto-grow columns to fit content — the
            <col width> is the law. This is the structural fix for the
            "cells drift between rows" bug. */}
        <colgroup>
          <col style={{ width: SELECT_COLUMN_WIDTH_PX }} />
          {visibleColumns.map((c) => (
            <col
              key={c.id}
              data-col-id={c.id}
              style={{ width: columnSizing[c.id] ?? c.defaultWidthPx }}
            />
          ))}
        </colgroup>

        <thead
          data-testid="audit-table-header"
          className="sticky top-0 z-10 bg-r5e-surface/95 backdrop-blur"
        >
          <tr>
            <th
              scope="col"
              className="border-b border-r5e-border px-2 py-2 text-left"
            >
              <input
                type="checkbox"
                aria-label="Select all rows on this page"
                data-testid="audit-table-select-all"
                checked={allSelected}
                onChange={handleToggleAll}
                className="h-4 w-4 cursor-pointer accent-r5e-accent"
              />
            </th>
            {table.getHeaderGroups()[0]?.headers.map((header) => {
              const colDef = AUDIT_LOG_COLUMNS.find(
                (c) => c.id === header.column.id,
              );
              const sortable = colDef?.sortable ?? false;
              const sortDir =
                sort?.column === header.column.id ? sort.direction : null;
              const colId = header.column.id;
              const isDragOver = dragOverColumnId === colId;
              return (
                <th
                  key={header.id}
                  scope="col"
                  data-testid={`audit-table-header-${colId}`}
                  data-drag-over={isDragOver ? "true" : undefined}
                  className={`relative border-b border-r5e-border px-3 py-2 text-left text-[10px] font-semibold uppercase tracking-wider text-r5e-muted ${
                    isDragOver
                      ? "border-l-2 border-l-r5e-accent-purple bg-r5e-accent-purple/5"
                      : ""
                  }`}
                  style={{ width: header.getSize() }}
                  onDragOver={(e) => {
                    // Mark this column as the drop target. preventDefault
                    // is required for the drop event to fire.
                    if (!draggingColumnId || draggingColumnId === colId)
                      return;
                    e.preventDefault();
                    e.dataTransfer.dropEffect = "move";
                    if (dragOverColumnId !== colId) setDragOverColumnId(colId);
                  }}
                  onDragLeave={(e) => {
                    // Only clear when the pointer actually leaves the th
                    // (not when crossing onto a child element).
                    const related = e.relatedTarget as Node | null;
                    if (related && (e.currentTarget as Node).contains(related)) {
                      return;
                    }
                    if (dragOverColumnId === colId) setDragOverColumnId(null);
                  }}
                  onDrop={(e) => {
                    e.preventDefault();
                    const id =
                      e.dataTransfer.getData("text/x-r5e-column") ||
                      draggingColumnId;
                    if (id && id !== colId) reorderColumn(id, colId);
                    setDraggingColumnId(null);
                    setDragOverColumnId(null);
                  }}
                >
                  {/* Drag handle — small left-edge gripper that sets the
                      column as draggable. We use HTML5 native drag/drop
                      (no library) so we don't add a dep. The whole th is
                      the drop target; the drag SOURCE is just this
                      handle so dragging doesn't fire on stray header
                      whitespace clicks. */}
                  <span
                    role="button"
                    aria-label={`Drag to reorder ${colDef?.label ?? colId} column`}
                    data-testid={`audit-table-reorder-${colId}`}
                    draggable
                    onDragStart={(e) => {
                      e.dataTransfer.effectAllowed = "move";
                      e.dataTransfer.setData("text/x-r5e-column", colId);
                      setDraggingColumnId(colId);
                    }}
                    onDragEnd={() => {
                      setDraggingColumnId(null);
                      setDragOverColumnId(null);
                    }}
                    title="Drag to reorder column"
                    className="absolute top-1/2 left-0.5 -translate-y-1/2 cursor-grab select-none px-1 text-r5e-muted/50 hover:text-r5e-accent-purple active:cursor-grabbing"
                  >
                    ⋮⋮
                  </span>
                  {sortable ? (
                    <button
                      type="button"
                      onClick={() =>
                        onSortClick(colId as AuditLogColumnId)
                      }
                      className="flex items-center gap-1 hover:text-r5e-text focus:outline-none focus:ring-1 focus:ring-r5e-accent-glow"
                    >
                      <span>{colDef?.label ?? colId}</span>
                      <span
                        aria-hidden="true"
                        className={`text-[8px] ${sortDir ? "text-r5e-accent" : "text-r5e-muted/50"}`}
                      >
                        {sortDir === "asc"
                          ? "▲"
                          : sortDir === "desc"
                            ? "▼"
                            : "↕"}
                      </span>
                    </button>
                  ) : (
                    <span>{colDef?.label ?? colId}</span>
                  )}
                  {header.column.getCanResize() && (
                    <button
                      type="button"
                      aria-label={`Resize ${colDef?.label ?? header.column.id} column`}
                      data-testid={`audit-table-resize-${header.column.id}`}
                      onMouseDown={header.getResizeHandler()}
                      onTouchStart={header.getResizeHandler()}
                      className="group absolute top-0 -right-1.5 z-20 flex h-full w-3 cursor-col-resize select-none touch-none items-center justify-center"
                    >
                      <span
                        aria-hidden="true"
                        className={`h-5 w-0.5 rounded-full transition-colors ${
                          header.column.getIsResizing()
                            ? "bg-r5e-accent"
                            : "bg-r5e-border/70 group-hover:bg-r5e-accent"
                        }`}
                      />
                    </button>
                  )}
                </th>
              );
            })}
          </tr>
        </thead>

        {loading ? (
          <tbody>
            <tr>
              <td
                colSpan={visibleColumns.length + 1}
                className="px-6 py-12 text-center text-sm text-r5e-muted"
              >
                Loading receipts…
              </td>
            </tr>
          </tbody>
        ) : rows.length === 0 ? (
          <tbody>
            <tr>
              <td
                colSpan={visibleColumns.length + 1}
                data-testid="receipts-empty"
                className="px-6 py-12 text-center text-sm text-r5e-muted"
              >
                No matching audit events
              </td>
            </tr>
          </tbody>
        ) : (
          // Plain <tbody> — every loaded row is rendered. The page is
          // capped at AUDIT_LOG_PAGE_SIZE (100) so DOM cost is bounded.
          // The prior implementation used react-virtual but that
          // doesn't compose with <table> cleanly (jsdom test env
          // returns 0×0 measurements; rows never mount), and at 100
          // rows the perf benefit is nil. If page size grows past
          // ~500 we can re-introduce virtualization via tanstack
          // virtual's table recipe (separate ticket).
          <tbody data-testid="audit-table-body">
            {rows.map((row) => {
              // Decision via `effectiveDecision`: a `tool_use_denied` row's
              // outer container carries the PARENT call's "allow".
              const isDenial = effectiveDecision(row) === "deny";
              const isSelected = selectedIds.has(row.run_id);
              const baseTone = isSelected
                ? "bg-r5e-accent/15 hover:bg-r5e-accent/20"
                : isDenial
                  ? "bg-r5e-chart-denied/[0.04] hover:bg-r5e-chart-denied/[0.08]"
                  : "bg-r5e-surface hover:bg-r5e-surface/60";
              const denialAccent = isDenial
                ? "border-l-2 border-r5e-chart-denied"
                : "border-l-2 border-transparent";
              return (
                <tr
                  key={row.run_id}
                  data-testid="receipt-row"
                  data-row-id={row.run_id}
                  data-denial={isDenial ? "true" : "false"}
                  aria-selected={isSelected}
                  onClick={(e) => {
                    // Skip when the click landed inside an interactive
                    // descendant (checkbox, principal-drill button,
                    // copy button) — those have their own handlers.
                    const t = e.target as HTMLElement;
                    if (
                      t.closest("[data-row-noopen]") ||
                      t.closest("input") ||
                      t.closest("button") ||
                      t.closest("a")
                    ) {
                      return;
                    }
                    onOpen(row.run_id);
                  }}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") {
                      e.preventDefault();
                      onOpen(row.run_id);
                    }
                  }}
                  tabIndex={0}
                  className={`cursor-pointer transition-colors ${baseTone} ${denialAccent} border-b border-r5e-border/40 focus:outline-none focus:ring-1 focus:ring-inset focus:ring-r5e-accent-glow`}
                >
                  <td data-row-noopen="" className="px-2 py-2 align-middle">
                    <input
                      type="checkbox"
                      aria-label={`Select receipt ${row.run_id}`}
                      checked={isSelected}
                      onChange={(e) =>
                        onToggleRow(row.run_id, e.target.checked)
                      }
                      onClick={(e) => e.stopPropagation()}
                      className="h-4 w-4 cursor-pointer accent-r5e-accent"
                    />
                  </td>
                  {visibleColumns.map((col) => (
                    <td
                      key={col.id}
                      data-testid={`row-cell-${col.id}`}
                      className="overflow-hidden truncate px-3 py-2 align-middle"
                      title={cellTitleFor(col.id, row)}
                    >
                      {renderCell(col.id, row, navigate, onOpen)}
                    </td>
                  ))}
                </tr>
              );
            })}
          </tbody>
        )}
      </table>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Cell rendering — re-uses the existing cell components verbatim. The
// CRITICAL difference from the prior flexbox row is that here each cell
// renders inside a real <td> whose width is fixed by the <colgroup>.
// Long content gets `truncate` from the parent <td>; cells can't push
// each other around because the column geometry is browser-enforced.
// ---------------------------------------------------------------------------
function renderCell(
  columnId: AuditLogColumnId,
  row: ReceiptRowData,
  navigate: ReturnType<typeof useNavigate>,
  _onOpen: (runId: string) => void,
): JSX.Element {
  const decision = effectiveDecision(row);
  const isDenial = decision === "deny";
  // `viewTagsOf` derives TOOL / COMMAND / SUBJECT for proxy denials, which
  // carry a tool name but no extractor fields.
  const tags = viewTagsOf(row);
  const category = categoryFromRow(row);
  const principal = displayPrincipal(row.signed_predicate.principal);
  const eventKind = row.signed_predicate.event_kind ?? "—";
  const timestamp = row.signed_predicate.timestamp ?? "—";
  switch (columnId) {
    case "timestamp":
      return <span className="text-xs text-r5e-muted">{timestamp}</span>;
    case "category":
      return (
        <CategoryPill
          category={category}
          forceDenial={isDenial}
          size="sm"
        />
      );
    case "tags":
      return <TagsCell row={row} />;
    case "principal":
      // Principal-cell drill into the F10 Investigation Timeline. Stops
      // propagation so the surrounding row's onClick (open drawer)
      // doesn't fire — the cell's own affordance wins.
      return (
        <button
          type="button"
          data-testid="row-cell-principal-drill"
          aria-label={`View timeline for ${principal}`}
          onClick={(e) => {
            e.stopPropagation();
            navigate(timelinePath({ principal }));
          }}
          title={`View timeline for ${principal}`}
          className="block w-full truncate text-left text-xs text-r5e-muted hover:text-r5e-accent hover:underline focus:outline-none focus:ring-1 focus:ring-r5e-accent-glow"
        >
          {principal}
        </button>
      );
    case "tool":
      return <ToolCell tags={tags} forceDenial={isDenial} />;
    case "command":
      return <CommandCell tags={tags} forceDenial={isDenial} />;
    case "subject":
      return <SubjectCell tags={tags} forceDenial={isDenial} />;
    case "decision":
      return <DecisionPill decision={decision} />;
    case "verification_level":
      return (
        <span className="text-[10px] uppercase tracking-wider text-r5e-muted">
          {row.outer_container.verification_level ?? "—"}
        </span>
      );
    case "event_kind":
      return <span className="text-xs text-r5e-text">{eventKind}</span>;
    case "summary": {
      const summary = displaySummary({
        tags,
        toolName:
          row.signed_predicate.tool_name ??
          (typeof tags?.tool_name === "string" ? tags.tool_name : null),
        toolSummary: row.signed_predicate.tool_summary,
        eventKind,
        principal,
        decision,
        upstreamStatusCode: row.outer_container.upstream_status_code,
      });
      return (
        <span data-testid="row-summary" className="text-xs text-r5e-text">
          {summary}
        </span>
      );
    }
  }
}

function TagsCell({ row }: { row: ReceiptRowData }): JSX.Element {
  const chips = chipsForRow(row);
  const targets = compactTargetResources(chips, 2);
  const hasAny =
    Boolean(chips.session) ||
    Boolean(chips.scope_kind) ||
    Boolean(chips.scope_value) ||
    targets.visible.length > 0;

  if (!hasAny) {
    return <span className="text-xs text-r5e-muted">—</span>;
  }

  return (
    <span
      data-testid="row-tags"
      className="flex min-w-0 flex-wrap items-center gap-1"
    >
      {/* Spec 012 S6c — the client session the call belongs to (short
          form; full id in the tooltip). Rows are grouped by it when no
          sort is active, so the chip is what makes the grouping legible. */}
      {chips.session && (
        <span title={`session ${chips.session}`} className="inline-flex">
          <Pill
            tone="muted"
            outline
            size="xs"
            uppercase={false}
            testId="row-chip-session"
            className="font-mono"
          >
            {chips.session.slice(0, 8)}
          </Pill>
        </span>
      )}
      {chips.scope_kind && (
        <Pill
          tone="muted"
          outline
          size="xs"
          testId="row-chip-scope-kind"
        >
          {chips.scope_kind}
        </Pill>
      )}
      {chips.scope_value && (
        <Pill
          tone="muted"
          outline
          size="xs"
          uppercase={false}
          testId="row-chip-scope-value"
          className="max-w-[12rem] truncate font-mono"
        >
          {chips.scope_value}
        </Pill>
      )}
      {targets.visible.map((resource) => (
        <Pill
          key={resource}
          tone="accent"
          outline
          size="xs"
          uppercase={false}
          testId="row-chip-target"
          className="max-w-[12rem] truncate font-mono"
        >
          {resource}
        </Pill>
      ))}
      {targets.hiddenCount > 0 && (
        <Pill
          tone="muted"
          outline
          size="xs"
          testId="row-chip-target-more"
        >
          +{targets.hiddenCount}
        </Pill>
      )}
    </span>
  );
}

function cellTitleFor(columnId: AuditLogColumnId, row: ReceiptRowData): string | undefined {
  // Native browser tooltip on truncated content — operators want to see
  // the full string without opening the drawer when the column is
  // narrowed.
  const tags = viewTagsOf(row);
  switch (columnId) {
    case "subject":
    case "summary":
      return tags?.argument_body ?? undefined;
    case "principal":
      return displayPrincipal(row.signed_predicate.principal);
    case "tags": {
      const chips = chipsForRow(row);
      const parts = [
        chips.scope_kind,
        chips.scope_value,
        ...chips.target_resources,
      ].filter(Boolean);
      return parts.length > 0 ? parts.join(" · ") : undefined;
    }
    default:
      return undefined;
  }
}

function DecisionPill({
  decision,
}: {
  decision: "allow" | "deny" | null;
}): JSX.Element {
  if (decision === null) {
    return <span className="text-r5e-muted">—</span>;
  }
  const tone =
    decision === "deny"
      ? "bg-r5e-chart-denied/15 text-r5e-chart-denied border-r5e-chart-denied/40"
      : "bg-r5e-success/10 text-r5e-success border-r5e-success/30";
  return (
    <span
      data-testid={`decision-pill-${decision}`}
      className={`inline-flex items-center rounded-sm border px-2 py-[1px] font-mono text-[10px] uppercase tracking-wider ${tone}`}
    >
      {decision}
    </span>
  );
}
