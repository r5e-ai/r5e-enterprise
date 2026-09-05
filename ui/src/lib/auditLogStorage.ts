// Audit-log column-visibility persistence (#33).
//
// The picker writes the selected column ids to localStorage so reloads
// preserve the operator's choice. This module is a thin wrapper around
// `window.localStorage` with two responsibilities:
//
//   1. Tolerate localStorage being absent or quota-full (jsdom test env;
//      Safari private mode). All errors are swallowed — visibility falls
//      back to the in-memory default; persistence is best-effort.
//   2. Reconcile the stored ids against the current column registry
//      via `normalizeColumnVisibility` so a registry change is forward
//      compatible (unknown ids dropped; required columns force-added).
//
// Pure / no React. Imported by `Dashboard.tsx` (initial-state seed +
// onChange persist).

import {
  AUDIT_LOG_COLUMN_IDS,
  defaultColumnVisibility,
  normalizeColumnVisibility,
  type AuditLogColumnVisibility,
} from "~/lib/auditLogColumns";

export const AUDIT_LOG_COLUMNS_STORAGE_KEY = "r5e.audit.dashboard.columns";

/**
 * Read the persisted visibility set. Returns the default (all visible)
 * when nothing's persisted, the stored value is malformed, or the
 * storage backend is unavailable.
 */
export function loadColumnVisibility(): AuditLogColumnVisibility {
  const raw = readRaw(AUDIT_LOG_COLUMNS_STORAGE_KEY);
  if (raw === null) return defaultColumnVisibility();
  try {
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return defaultColumnVisibility();
    return normalizeColumnVisibility(
      parsed.filter((v): v is string => typeof v === "string"),
    );
  } catch {
    return defaultColumnVisibility();
  }
}

/**
 * Write the visibility set to localStorage. Normalizes (dedupes + clamps
 * to the registry's id space) before persisting so the round-trip is
 * idempotent. Best-effort: storage failures are silently swallowed.
 */
export function saveColumnVisibility(visibility: AuditLogColumnVisibility): void {
  const normalized = AUDIT_LOG_COLUMN_IDS.filter((id) => visibility.has(id));
  writeRaw(AUDIT_LOG_COLUMNS_STORAGE_KEY, JSON.stringify(normalized));
}

/**
 * Per-column resize widths (#74 follow-up to the AuditTable rewrite).
 * Stored as a `Record<columnId, pixels>`. Columns absent from the
 * record fall back to the registry's `defaultWidthPx`. Best-effort
 * persistence — same swallow-errors behaviour as visibility.
 */
export const AUDIT_LOG_WIDTHS_STORAGE_KEY = "r5e.audit.dashboard.column-widths";

export type AuditLogColumnWidths = Record<string, number>;

export function loadColumnWidths(): AuditLogColumnWidths {
  const raw = readRaw(AUDIT_LOG_WIDTHS_STORAGE_KEY);
  if (raw === null) return {};
  try {
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object") return {};
    const out: AuditLogColumnWidths = {};
    for (const [k, v] of Object.entries(parsed)) {
      if (typeof k === "string" && typeof v === "number" && Number.isFinite(v) && v > 0) {
        out[k] = Math.round(v);
      }
    }
    return out;
  } catch {
    return {};
  }
}

export function saveColumnWidths(widths: AuditLogColumnWidths): void {
  writeRaw(AUDIT_LOG_WIDTHS_STORAGE_KEY, JSON.stringify(widths));
}

/**
 * Per-operator column ordering (drag-to-reorder in AuditTable header).
 * Stored as an ordered array of column ids. Unknown ids are dropped on
 * load; missing ids fall back to the registry's natural order. Same
 * best-effort persistence pattern as widths/visibility.
 */
export const AUDIT_LOG_ORDER_STORAGE_KEY = "r5e.audit.dashboard.column-order";

export function loadColumnOrder(): string[] {
  const raw = readRaw(AUDIT_LOG_ORDER_STORAGE_KEY);
  if (raw === null) return [];
  try {
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter((v): v is string => typeof v === "string");
  } catch {
    return [];
  }
}

export function saveColumnOrder(order: string[]): void {
  writeRaw(AUDIT_LOG_ORDER_STORAGE_KEY, JSON.stringify(order));
}

function readRaw(key: string): string | null {
  if (typeof window === "undefined") return null;
  try {
    return window.localStorage.getItem(key);
  } catch {
    return null;
  }
}

function writeRaw(key: string, value: string): void {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.setItem(key, value);
  } catch {
    // Quota exceeded or storage disabled — visibility still applies for
    // the current session; we just don't persist it.
  }
}
