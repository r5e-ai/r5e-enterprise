// auditLogStorage — tests for the localStorage round-trip used by the
// column picker (#33).

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  AUDIT_LOG_COLUMNS_STORAGE_KEY,
  loadColumnVisibility,
  saveColumnVisibility,
} from "~/lib/auditLogStorage";
import {
  defaultColumnVisibility,
  toggleColumnVisibility,
  type AuditLogColumnId,
} from "~/lib/auditLogColumns";

describe("auditLogStorage", () => {
  beforeEach(() => {
    window.localStorage.clear();
  });

  afterEach(() => {
    window.localStorage.clear();
  });

  it("returns default visibility when nothing is persisted", () => {
    // Post-triplet: defaults to the `defaultVisible: true` subset (8 of 10),
    // not the full registry. The two togglables (summary, event_kind) are
    // off by default.
    const v = loadColumnVisibility();
    expect(v.size).toBe(defaultColumnVisibility().size);
  });

  it("round-trips a custom visibility set", () => {
    const v = toggleColumnVisibility(defaultColumnVisibility(), "decision");
    saveColumnVisibility(v);
    const loaded = loadColumnVisibility();
    expect(loaded.has("decision")).toBe(false);
    expect(loaded.has("timestamp")).toBe(true);
  });

  it("returns default when persisted value is malformed JSON", () => {
    window.localStorage.setItem(AUDIT_LOG_COLUMNS_STORAGE_KEY, "{not-json");
    const v = loadColumnVisibility();
    expect(v.size).toBe(defaultColumnVisibility().size);
  });

  it("returns default when persisted value is not an array", () => {
    window.localStorage.setItem(
      AUDIT_LOG_COLUMNS_STORAGE_KEY,
      JSON.stringify({ timestamp: true }),
    );
    const v = loadColumnVisibility();
    expect(v.size).toBe(defaultColumnVisibility().size);
  });

  it("force-adds required columns when persisted value omits them (forward-compat)", () => {
    // Pre-existing storage (e.g., before timestamp was marked required)
    // shouldn't lock the user out of seeing the timestamp column. Post-
    // triplet, `timestamp` is the ONLY required column — `summary` is now
    // togglable, so a stored set that omits it should remain off.
    window.localStorage.setItem(
      AUDIT_LOG_COLUMNS_STORAGE_KEY,
      JSON.stringify(["decision"]),
    );
    const v = loadColumnVisibility();
    expect(v.has("timestamp")).toBe(true);
    // Summary is no longer required — it stays off when not in the
    // stored set (operator's preference is preserved).
    expect(v.has("summary")).toBe(false);
  });

  it("drops unknown ids on load (forward-compat)", () => {
    window.localStorage.setItem(
      AUDIT_LOG_COLUMNS_STORAGE_KEY,
      JSON.stringify(["timestamp", "summary", "future_col"]),
    );
    const v = loadColumnVisibility();
    expect(v.has("timestamp")).toBe(true);
    expect(v.has("summary")).toBe(true);
    expect(Array.from(v)).not.toContain("future_col");
  });

  it("normalizes (dedupes + drops unknowns) on save", () => {
    const v = new Set<AuditLogColumnId>(["timestamp", "summary", "decision"]);
    saveColumnVisibility(v);
    const raw = window.localStorage.getItem(AUDIT_LOG_COLUMNS_STORAGE_KEY);
    expect(raw).not.toBeNull();
    const parsed = JSON.parse(raw!);
    expect(parsed).toEqual(expect.arrayContaining(["timestamp", "summary", "decision"]));
  });
});
