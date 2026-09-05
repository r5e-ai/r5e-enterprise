// conditionValues — shared coercion helpers for `condition_metadata` value
// shapes (Constitution Principle VII — Interface-First on Second Consumer).
//
// Both `ConditionBuilder.tsx` (the form) and `cedarSourceSplice.ts` (the
// editor-source rewrite) need to coerce wire-shape values into the
// per-kind canonical form:
//
//   - chip-list  (`in` kind):       string[]  (also tolerates legacy
//                                              comma-blob `"a,b,c"` from
//                                              from-receipt skeletons)
//   - ISO range  (`time_window`):   [start, end]  (also tolerates legacy
//                                                  `"start..end"` string)
//
// Pre-Pass-2 the same `v.split(",")...` parser appeared inline in both
// modules; per Principle VII the second consumer triggers the extraction
// to this shared module. Both call sites import the helpers; the duplicate
// parsers are removed.

/**
 * Coerce an unknown wire value into a canonical string[] chip list.
 *
 * Accepted inputs:
 *   - string[]  → filtered to non-empty entries (after String() coercion)
 *   - string    → split on `,`, trimmed, non-empty entries kept
 *                 (legacy comma-blob shape; from-receipt skeletons may
 *                 emit this on the backend round-trip)
 *   - anything else (number, boolean, null, undefined, object) → []
 *
 * Idempotent under nested calls: `coerceChipList(coerceChipList(x))` ===
 * `coerceChipList(x)`.
 */
export function coerceChipList(v: unknown): string[] {
  if (Array.isArray(v)) {
    return v.map((x) => String(x)).filter((s) => s.length > 0);
  }
  if (typeof v === "string" && v.length > 0) {
    return v
      .split(",")
      .map((s) => s.trim())
      .filter((s) => s.length > 0);
  }
  return [];
}

/**
 * Coerce an unknown wire value into a canonical [start, end] tuple.
 *
 * Accepted inputs:
 *   - [start, end] (length-2 array) → tupled, `String()`-coerced
 *   - string containing `..`        → split, trimmed (legacy `"a..b"`
 *                                     shape)
 *   - anything else                 → ["", ""]
 */
export function coerceRange(v: unknown): [string, string] {
  if (Array.isArray(v) && v.length === 2) {
    return [String(v[0] ?? ""), String(v[1] ?? "")];
  }
  if (typeof v === "string" && v.includes("..")) {
    const [a, b] = v.split("..");
    return [a?.trim() ?? "", b?.trim() ?? ""];
  }
  return ["", ""];
}
