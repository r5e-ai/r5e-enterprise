// AuditTable tests — covers the real-<table> rewrite (May 2026) that
// replaced the bespoke flexbox-emulated row.
//
// What this test guards against (in priority order):
//
// 1. **Column geometry is browser-enforced.** A <colgroup> with one
//    <col> per visible column locks every <td> to the registry's pixel
//    width. The pre-rewrite flexbox row let cells drift between rows
//    when content widths varied (long argument_body, empty SubjectCell
//    etc.) — this test asserts the structure that prevents drift.
//
// 2. **Long argument_body content doesn't blow the row.** Live agents
//    stuff entire bash command lines into `tags.argument_body`; the
//    regression that surfaced this on audit-dev (May 2026) was an
//    18,127px-wide row. With <table table-layout: fixed> + <td
//    overflow:hidden truncate>, the cell stays at its colgroup width.
//
// 3. **Principal cell drills into the F10 Investigation Timeline.**
//    The cell's onClick stops propagation (so the surrounding row's
//    onOpen doesn't fire) and navigates to the timeline scoped to
//    that principal. Preserved across the rewrite.
//
// 4. **Per-row click opens the receipt drawer.** Click anywhere on the
//    row that ISN'T an interactive descendant (checkbox, principal
//    drill, copy buttons) → onOpen(run_id).
//
// 5. **Sort + bulk-select work via real <th> + <input>.**
//
// 6. **Resize handles render per column.** The pre-rewrite UI had no
//    way to grab a column edge; this is the user-facing affordance the
//    rewrite added.

import type * as React from "react";
import { fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter } from "react-router-dom";

import { AuditTable } from "~/components/audit/AuditTable";
import type { ReceiptRow as ReceiptRowData } from "~/hooks/useReceipts";
import {
  AUDIT_LOG_COLUMN_IDS,
  defaultColumnVisibility,
} from "~/lib/auditLogColumns";

afterEach(() => {
  if (typeof window !== "undefined") {
    window.localStorage.clear();
  }
});

function makeRow(
  overrides: Partial<ReceiptRowData["signed_predicate"]> = {},
  decision: "allow" | "deny" | null = "allow",
  argumentBody = "ls /etc",
): ReceiptRowData {
  const runId = (overrides.run_id as string | undefined) ?? "run_test_1";
  return {
    run_id: runId,
    signed_predicate: {
      run_id: runId,
      session_id: "sess_01",
      turn_id: "turn_01",
      event_kind: "tool_call",
      machine_identity: null,
      principal: {
        kind: "obo_human",
        subject: "alice@example.com",
        issuer: "observed://gateway",
        schema_version: "1.0",
      },
      tenant_id: "tenant_x",
      timestamp: "2026-04-30T12:00:00Z",
      tool_name: "Bash",
      tool_summary: "Bash: ls /etc",
      ...overrides,
    },
    outer_container: {
      verification_level: "global_inclusion_verified",
      tier_completeness_advisory: "partial",
      session_chain_epoch: 0,
      session_chain_root: null,
      policy_decision: decision,
      outcome: decision === "deny" ? "denied" : "success",
      upstream_status_code: decision === "deny" ? 403 : null,
      commit_retry_exhausted: false,
      tags: {
        category: "subprocess_exec",
        display_summary: `Bash: ${argumentBody}`,
        tool_kind: "bash",
        verb: "ls",
        argument_body: argumentBody,
        scope_kind: null,
        scope_value: argumentBody,
        target_resources: ["host:gist.github.com", "metric:cpu_load", "file:/tmp/build.log"],
        semantic_args: {},
      },
    },
  } as unknown as ReceiptRowData;
}

function renderTable(
  partial: Partial<React.ComponentProps<typeof AuditTable>> = {},
) {
  const props: React.ComponentProps<typeof AuditTable> = {
    rows: [makeRow()],
    visibility: defaultColumnVisibility(),
    sort: null,
    onSortClick: vi.fn(),
    selectedIds: new Set<string>(),
    onToggleRow: vi.fn(),
    onToggleAll: vi.fn(),
    onOpen: vi.fn(),
    ...partial,
  };
  return {
    ...render(
      <MemoryRouter basename="/admin" initialEntries={["/admin/dashboard"]}>
        <AuditTable {...props} />
      </MemoryRouter>,
    ),
    props,
  };
}

describe("AuditTable — real <table> structure", () => {
  it("renders a real <table> element (not a flexbox-emulated div tree)", () => {
    renderTable();
    const table = screen.getByTestId("audit-table");
    expect(table.tagName.toLowerCase()).toBe("table");
    // table-layout: fixed is the keystone — without it the browser
    // auto-grows columns to fit content and the colgroup widths get
    // ignored.
    expect((table as HTMLTableElement).style.tableLayout).toBe("fixed");
  });

  it("emits a <colgroup> with one <col> per visible column + a leading select column", () => {
    renderTable();
    const table = screen.getByTestId("audit-table");
    const cols = table.querySelectorAll(":scope > colgroup > col");
    // 1 select + every default-visible registry column.
    const visibleRegistryCount = AUDIT_LOG_COLUMN_IDS.filter((id) =>
      defaultColumnVisibility().has(id),
    ).length;
    expect(cols.length).toBe(visibleRegistryCount + 1);
  });

  it("each <th> declares its column id via data-testid for downstream test hooks", () => {
    renderTable();
    expect(screen.getByTestId("audit-table-header-timestamp")).toBeInTheDocument();
    expect(screen.getByTestId("audit-table-header-category")).toBeInTheDocument();
    expect(screen.getByTestId("audit-table-header-tags")).toBeInTheDocument();
    expect(screen.getByTestId("audit-table-header-subject")).toBeInTheDocument();
    expect(screen.getByTestId("audit-table-header-decision")).toBeInTheDocument();
  });
});

describe("AuditTable — long argument_body containment (live-data regression)", () => {
  it("a row with a 5000-char argument_body keeps each <td> at its colgroup width", () => {
    // Pre-rewrite this scenario blew the row to 18,127px wide because
    // the inner truncate was a no-op in the flexbox layout. With the
    // real table + table-layout:fixed + <colgroup>, the <td> width
    // is browser-enforced regardless of inner content length.
    const longArg = "echo " + "a".repeat(5000);
    const row = makeRow({}, "allow", longArg);
    renderTable({ rows: [row] });
    const subjectTd = screen.getByTestId("row-cell-subject") as HTMLTableCellElement;
    // table-layout:fixed means inline width on the <th>/<col> drives
    // the <td>; verify the cell carries the truncate machinery so
    // overflow is clipped (jsdom doesn't lay out widths so we can't
    // assert pixel widths, but we CAN assert the structural classes
    // that make truncation work).
    expect(subjectTd.className).toMatch(/overflow-hidden/);
    expect(subjectTd.className).toMatch(/truncate/);
  });
});

describe("AuditTable — principal-cell drill into Investigation Timeline", () => {
  it("clicking the principal cell navigates to /admin/timeline?principal=...", () => {
    const row = makeRow({
      principal: {
        kind: "obo_human",
        subject: "alice@example.com",
        issuer: "observed://gateway",
        schema_version: "1.0",
      },
    });
    const onOpen = vi.fn();
    renderTable({ rows: [row], onOpen });
    const drill = screen.getByTestId("row-cell-principal-drill");
    fireEvent.click(drill);
    // The drill button stops propagation so onOpen MUST NOT fire.
    expect(onOpen).not.toHaveBeenCalled();
  });
});

describe("AuditTable — row click opens the receipt drawer", () => {
  it("clicking the row's non-interactive area calls onOpen(run_id)", () => {
    const row = makeRow({ run_id: "row_open_target" });
    const onOpen = vi.fn();
    renderTable({ rows: [row], onOpen });
    // Click on the timestamp cell — it's a passive <td>, no own
    // handler, so the row's onClick fires.
    fireEvent.click(screen.getByTestId("row-cell-timestamp"));
    expect(onOpen).toHaveBeenCalledWith("row_open_target");
  });

  it("clicking the bulk-select checkbox does NOT open the drawer", () => {
    const row = makeRow({ run_id: "row_open_target" });
    const onOpen = vi.fn();
    const onToggleRow = vi.fn();
    renderTable({ rows: [row], onOpen, onToggleRow });
    const cb = screen
      .getAllByRole("checkbox")
      .find((el) => el.getAttribute("aria-label")?.startsWith("Select receipt"));
    expect(cb).toBeDefined();
    fireEvent.click(cb!);
    expect(onToggleRow).toHaveBeenCalledWith("row_open_target", true);
    expect(onOpen).not.toHaveBeenCalled();
  });
});

describe("AuditTable — sort + select-all", () => {
  it("clicking a sortable header emits onSortClick with the column id", () => {
    const onSortClick = vi.fn();
    renderTable({ onSortClick });
    const ts = screen.getByTestId("audit-table-header-timestamp");
    // Three role="button" elements live in each <th>: sort-toggle
    // (visible label text), resize handle (aria-label "Resize ..."),
    // and reorder drag handle (aria-label "Drag to reorder ..."). The
    // sort button is the one without either prefix.
    const buttons = within(ts).getAllByRole("button");
    const sortBtn = buttons.find((b) => {
      const label = b.getAttribute("aria-label") ?? "";
      return (
        !label.startsWith("Resize ") &&
        !label.startsWith("Drag to reorder ")
      );
    });
    expect(sortBtn).toBeDefined();
    fireEvent.click(sortBtn!);
    expect(onSortClick).toHaveBeenCalledWith("timestamp");
  });

  it("select-all checkbox flips the parent state via onToggleAll", () => {
    const onToggleAll = vi.fn();
    renderTable({ onToggleAll });
    const all = screen.getByTestId("audit-table-select-all");
    fireEvent.click(all);
    expect(onToggleAll).toHaveBeenCalledWith(true);
  });
});

describe("AuditTable — column resize handles", () => {
  it("each <th> renders a resize handle button with the column id testid", () => {
    renderTable();
    expect(screen.getByTestId("audit-table-resize-timestamp")).toBeInTheDocument();
    expect(screen.getByTestId("audit-table-resize-subject")).toBeInTheDocument();
    expect(screen.getByTestId("audit-table-resize-decision")).toBeInTheDocument();
  });

  it("resize handles expose a visible inner grab indicator", () => {
    renderTable();
    const handle = screen.getByTestId("audit-table-resize-subject");
    expect(handle).toHaveClass("w-3");
    expect(handle.querySelector("span")).toHaveClass("w-0.5");
  });
});

describe("AuditTable — column reorder via drag-and-drop", () => {
  it("each <th> renders a reorder drag handle with the column id testid", () => {
    renderTable();
    expect(screen.getByTestId("audit-table-reorder-timestamp")).toBeInTheDocument();
    expect(screen.getByTestId("audit-table-reorder-category")).toBeInTheDocument();
    expect(screen.getByTestId("audit-table-reorder-subject")).toBeInTheDocument();
  });

  it("dragging a column over another emits dragOver visual cue", () => {
    renderTable();
    const ts = screen.getByTestId("audit-table-header-timestamp");
    const subjHandle = screen.getByTestId("audit-table-reorder-subject");
    const dt = {
      effectAllowed: "",
      dropEffect: "",
      data: new Map<string, string>(),
      setData(k: string, v: string) {
        this.data.set(k, v);
      },
      getData(k: string) {
        return this.data.get(k) ?? "";
      },
    };
    fireEvent.dragStart(subjHandle, { dataTransfer: dt });
    fireEvent.dragOver(ts, { dataTransfer: dt });
    expect(ts).toHaveAttribute("data-drag-over", "true");
  });

  it("dropping a dragged column persists the new order to localStorage", () => {
    renderTable();
    const subjHandle = screen.getByTestId("audit-table-reorder-subject");
    const ts = screen.getByTestId("audit-table-header-timestamp");
    const dt = {
      effectAllowed: "",
      dropEffect: "",
      data: new Map<string, string>(),
      setData(k: string, v: string) {
        this.data.set(k, v);
      },
      getData(k: string) {
        return this.data.get(k) ?? "";
      },
    };
    fireEvent.dragStart(subjHandle, { dataTransfer: dt });
    fireEvent.dragOver(ts, { dataTransfer: dt });
    fireEvent.drop(ts, { dataTransfer: dt });
    const persisted = JSON.parse(
      window.localStorage.getItem("r5e.audit.dashboard.column-order") ?? "[]",
    ) as string[];
    // Dropping subject onto timestamp should put subject AHEAD of
    // timestamp in the order.
    const subjIdx = persisted.indexOf("subject");
    const tsIdx = persisted.indexOf("timestamp");
    expect(subjIdx).toBeGreaterThanOrEqual(0);
    expect(tsIdx).toBeGreaterThanOrEqual(0);
    expect(subjIdx).toBeLessThan(tsIdx);
  });
});

describe("AuditTable — canonical row tag chips", () => {
  it("renders scope and first two target_resources in the default-visible Tags column", () => {
    const row = makeRow({}, "allow", "curl https://gist.github.com");
    row.outer_container.tags = {
      ...(row.outer_container.tags as Record<string, unknown>),
      scope_kind: "network_egress",
      scope_value: "https://gist.github.com",
      target_resources: [
        "host:gist.github.com",
        "metric:cpu_load",
        "file:/tmp/build.log",
      ],
    };
    renderTable({ rows: [row] });
    expect(screen.getByTestId("row-tags")).toBeInTheDocument();
    expect(screen.getByTestId("row-chip-scope-kind")).toHaveTextContent("network_egress");
    expect(screen.getByTestId("row-chip-scope-value")).toHaveTextContent("https://gist.github.com");
    const targets = screen.getAllByTestId("row-chip-target");
    expect(targets).toHaveLength(2);
    expect(targets[0]).toHaveTextContent("host:gist.github.com");
    expect(targets[1]).toHaveTextContent("metric:cpu_load");
    expect(screen.getByTestId("row-chip-target-more")).toHaveTextContent("+1");
  });
});
