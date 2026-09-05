// cedarSourceSplice — string-level rewrite of a Cedar policy's `when { … }`
// block from a structured `condition_metadata` array (T-PolicySim F002 fix
// + !89 fix-pass-2 hardening).
//
// Per `design/briefs/04-policy-simulator.md` §"Conditions builder":
//   "When a condition is added, the Cedar editor's `when { ... }` block
//    updates accordingly (live two-way binding)."
//
// The brief's load-bearing demo interaction is the CODE↔INTENT↔IMPACT loop:
// the auditor adds a row in the conditions builder; the Cedar editor's
// `when {…}` block reflects it; the dry-run re-evaluates the live source
// and the Blast Radius cells flip in real time. Without this binding the
// row is inert against the Blast Radius algorithm, since the dry-run reads
// `draft.cedar_source` exclusively.
//
// We deliberately use a string-level splice instead of a full AST consumer:
//   1. The vast majority of Cedar sources we author start from the
//      suggestion-engine's skeleton (single rule, single `when {…}` block)
//      so a plain string match is sufficient.
//   2. A real Cedar AST round-trip would require pulling in
//      `@cedar-policy/parser` and a renderer that preserves comments —
//      an explicit non-goal for the May-10 demo per the brief.
//   3. Hand-written Cedar that the operator authors directly is preserved
//      as-is when there are no condition rows (the splice is a no-op).
//
// SENTINEL-SCOPED EDIT REGION (PR !89 fix-pass-2 / F001 BLOCKER fix):
// ----------------------------------------------------------------------
// The splicer used to REPLACE the entire `when {…}` body with the rendered
// rows. That destroys clauses the from-receipt skeleton seeds OUTSIDE the
// row builder — most importantly the `principal.tenant_id == "<tenant>"`
// guard. A non-tenant-scoped policy is a security regression.
//
// Fix: scope the rewrite to a sentinel-bracketed region. We render rows
// inside marker comments that the splicer recognizes:
//
//   when {
//     principal.tenant_id == "tenant-acme"   <- preserved seed clause
//     // [r5e:conditions:start]
//     && resource.tags.tool_kind == "bash"   <- managed by builder
//     // [r5e:conditions:end]
//   }
//
// Splice algorithm:
//   - sentinels present  → replace body BETWEEN sentinels with new rows.
//                          Pre-existing seed clauses outside sentinels are
//                          preserved across edits.
//   - sentinels absent + rows is empty  → leave source untouched (we have
//                          nothing to manage; no need to mark anything).
//   - sentinels absent + rows non-empty → preserve current `when {…}` body
//                          and APPEND a sentinel block joined with `&&`.
//
// Idempotency: the sentinel-aware edits are repeatable; calling
// `splice(splice(src, rows), rows)` returns the same source as the first
// call (modulo whitespace-on-empty-rows where we keep a one-line marker).
//
// COMMENT-AWARE WALKERS (F008): the brace + terminator walkers also skip
// Cedar `//` line comments, so a comment containing `{`, `}`, or `;` is
// no longer mistaken for structural syntax.
//
// Public surface:
//   * `renderConditionClause(c)`  — render ONE condition row to a Cedar
//     when-clause string.
//   * `renderWhenBody(rows)`      — render a full `when {…}` body for the
//     no-existing-block insert path (newline joined, "true" when empty).
//   * `spliceConditionsIntoCedar(source, rows)` — find-or-create the rule's
//     `when {…}` block and rewrite the sentinel-managed body. Idempotent.
//   * `CONDITIONS_SENTINEL_START` / `CONDITIONS_SENTINEL_END` — exported
//     for tests + downstream consumers that need the marker contract.

import type {
  PolicyDraftConditionKind,
  PolicyDraftConditionMetadata,
} from "~/hooks/usePolicyDrafts";
import { coerceChipList, coerceRange } from "~/lib/conditionValues";

// ---------------------------------------------------------------------------
// Sentinel markers — bracket the UI-managed clause region inside `when {…}`
// ---------------------------------------------------------------------------

/** Comment line that opens the UI-managed condition region. */
export const CONDITIONS_SENTINEL_START = "// [r5e:conditions:start]";
/** Comment line that closes the UI-managed condition region. */
export const CONDITIONS_SENTINEL_END = "// [r5e:conditions:end]";

// ---------------------------------------------------------------------------
// Per-row → Cedar clause rendering
// ---------------------------------------------------------------------------

/**
 * Render a single value as a Cedar literal. Strings are double-quoted with
 * embedded `"` and `\` escaped; numbers and booleans pass through as-is.
 */
function renderLiteral(v: unknown): string {
  if (typeof v === "number" || typeof v === "boolean") return String(v);
  if (v === null || v === undefined) return '""';
  const s = String(v);
  return `"${s.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

function renderChips(v: unknown): string {
  // Per F004 — defer to the shared `coerceChipList` helper (also used by
  // ConditionBuilder.valueAsChips). The helper tolerates the legacy
  // comma-blob string shape, so a draft loaded from the backend with
  // `"rm,sudo,chmod"` round-trips to a non-empty chip list rather than
  // being silently dropped (F003 — this used to bail to `[]` here).
  const list = coerceChipList(v);
  return `[${list.map(renderLiteral).join(", ")}]`;
}

function renderRange(v: unknown): [string, string] {
  // Per F004 — shared helper, same as ConditionBuilder.valueAsRange.
  return coerceRange(v);
}

/**
 * Render ONE condition row into a Cedar when-clause expression.
 * Returns `null` for incomplete rows (e.g. empty attr / empty value) so the
 * caller can drop them — partial rows in the builder shouldn't pollute the
 * source until the user finishes typing.
 */
export function renderConditionClause(
  row: PolicyDraftConditionMetadata,
): string | null {
  const attr = (row.attr ?? "").trim();
  if (attr.length === 0) return null;
  const kind: PolicyDraftConditionKind = row.kind;

  switch (kind) {
    case "eq": {
      const v = typeof row.value === "string" ? row.value : "";
      if (v.trim().length === 0) return null;
      return `${attr} == ${renderLiteral(v)}`;
    }
    case "neq": {
      const v = typeof row.value === "string" ? row.value : "";
      if (v.trim().length === 0) return null;
      return `${attr} != ${renderLiteral(v)}`;
    }
    case "in": {
      // Per F003 — coerce through `renderChips` (which routes through the
      // shared `coerceChipList`) instead of guarding on `Array.isArray`
      // here. A draft loaded from the backend may carry the legacy
      // comma-blob shape (e.g. `"rm,sudo"`); the shared helper splits it
      // back into chips so the rendered clause is `attr in ["rm", "sudo"]`,
      // not silently dropped.
      const chips = coerceChipList(row.value);
      if (chips.length === 0) return null;
      return `${attr} in ${renderChips(chips)}`;
    }
    case "time_window": {
      // Per F007 — honor the user-edited `attr` instead of hardcoding
      // `context.timestamp`. The default attr ships as
      // `context.timestamp` (see CONDITION_TEMPLATES.time_window — F009),
      // but the operator MAY override it (e.g. to
      // `context.session_age_seconds`) and the splicer must respect it.
      const [start, end] = renderRange(row.value);
      if (start.length === 0 && end.length === 0) return null;
      const parts: string[] = [];
      if (start.length > 0) parts.push(`${attr} >= ${renderLiteral(start)}`);
      if (end.length > 0) parts.push(`${attr} <= ${renderLiteral(end)}`);
      return parts.join(" && ");
    }
    case "group_member": {
      // Per F007 — `attr` carries the LEFT-HAND side of `<lhs> in
      // Group::"<value>"`. Default is `principal` (matches the Cedar
      // EID convention) but the operator may target `principal.parent`,
      // `resource.owner`, etc. The splicer used to hardcode `principal`.
      const v = typeof row.value === "string" ? row.value : "";
      if (v.trim().length === 0) return null;
      return `${attr} in Group::${renderLiteral(v.trim())}`;
    }
    default: {
      const _exhaustive: never = kind;
      void _exhaustive;
      return null;
    }
  }
}

/**
 * Render the BODY of a `when { … }` block when no existing block is
 * present and we need to materialize one from scratch.
 *
 * Each clause goes on its own line, joined with ` &&` so the block reads
 * top-to-bottom. Empty input → `"  true"` so the resulting block parses as
 * a permissive condition (the `when` block always needs SOMETHING).
 */
export function renderWhenBody(rows: PolicyDraftConditionMetadata[]): string {
  const clauses = rows.map(renderConditionClause).filter((c): c is string => c !== null);
  if (clauses.length === 0) return "  true";
  return clauses.map((c, i) => `  ${c}${i < clauses.length - 1 ? " &&" : ""}`).join("\n");
}

// ---------------------------------------------------------------------------
// Sentinel-managed region rendering
// ---------------------------------------------------------------------------

/**
 * Render the sentinel-bracketed managed region. Always emits the start +
 * end markers so subsequent splices can find the region and replace just
 * the inner content. Empty rows render an empty managed region (no
 * clauses), preserving any seed clauses that live OUTSIDE the sentinels.
 *
 * The first `&&` (joining the managed region to a preserved-seed clause
 * that precedes it) is the caller's responsibility — see the splice
 * algorithm in `spliceConditionsIntoCedar`.
 */
function renderManagedRegion(rows: PolicyDraftConditionMetadata[]): string {
  const clauses = rows
    .map(renderConditionClause)
    .filter((c): c is string => c !== null);
  if (clauses.length === 0) {
    return `  ${CONDITIONS_SENTINEL_START}\n  ${CONDITIONS_SENTINEL_END}`;
  }
  const inner = clauses
    .map((c, i) => `  ${c}${i < clauses.length - 1 ? " &&" : ""}`)
    .join("\n");
  return `  ${CONDITIONS_SENTINEL_START}\n${inner}\n  ${CONDITIONS_SENTINEL_END}`;
}

// ---------------------------------------------------------------------------
// Splice — find-or-create the `when { … }` block in a Cedar source string.
// ---------------------------------------------------------------------------

/**
 * Replace (or create) the UI-managed clause region in a Cedar source so
 * its content matches `rows`. Returns the new source.
 *
 * Algorithm (F001 fix-pass-2):
 *   1. Search for the first `when {` after a top-level `permit(...)` /
 *      `forbid(...)` head. Greedy on whitespace: `when{`, `when {`,
 *      `when    {` all work.
 *   2. Walk braces (comment- and string-aware) until the matching `}`.
 *   3. Look for the sentinel pair INSIDE the body:
 *        a. Both present → replace the slice between them with the
 *           rendered managed region (preserving everything before/after
 *           the sentinels — the seed tenant guard, hand-edited clauses,
 *           etc.).
 *        b. Sentinels absent + rows is empty → leave source untouched.
 *           The seed body (e.g. `principal.tenant_id == "..."`) stays
 *           intact; we don't mark anything yet.
 *        c. Sentinels absent + rows non-empty → keep the existing body,
 *           strip its trailing newline, append ` &&\n<managed region>` so
 *           the merge is well-formed Cedar.
 *   4. If no `when {` found, append `when { <body> };` before the trailing
 *      `;` of the most recent rule. The body uses `renderWhenBody` (no
 *      sentinel) on first creation, then becomes sentinel-scoped on the
 *      next splice.
 *   5. If the source has no rule head at all, leave it alone.
 *
 * Idempotency: calling `splice(splice(src, rows), rows)` returns the same
 * source as the single-call version — the sentinel region anchors the
 * rewrite.
 */
export function spliceConditionsIntoCedar(
  source: string,
  rows: PolicyDraftConditionMetadata[],
): string {
  if (typeof source !== "string" || source.length === 0) return source;

  const whenStart = findWhenBlock(source);

  if (whenStart !== null) {
    const close = findMatchingBrace(source, whenStart.openBraceIndex);
    if (close === null) {
      // Malformed source — bail rather than mangle.
      return source;
    }
    const bodyStart = whenStart.openBraceIndex + 1;
    const body = source.slice(bodyStart, close);

    const sentinelStart = body.indexOf(CONDITIONS_SENTINEL_START);
    const sentinelEnd = body.indexOf(
      CONDITIONS_SENTINEL_END,
      sentinelStart + CONDITIONS_SENTINEL_START.length,
    );

    if (sentinelStart !== -1 && sentinelEnd !== -1) {
      // (3a) Sentinel pair present — replace just the managed region. Keep
      // everything before the start sentinel and after the end sentinel
      // exactly as the operator wrote it.
      const prefix = body.slice(0, sentinelStart);
      const suffix = body.slice(sentinelEnd + CONDITIONS_SENTINEL_END.length);
      const managed = renderManagedRegion(rows);
      // The managed region renders its own `  ` indent on the start
      // sentinel; strip any horizontal whitespace at the very end of
      // `prefix` (NOT line-end via /m, which matches zero-width at the
      // first newline and leaves trailing spaces intact) so indentation
      // doesn't compound across re-splices.
      const trimmedPrefix = prefix.replace(/[ \t]+$/, "");
      const newBody = `${trimmedPrefix}${managed}${suffix}`;
      const before = source.slice(0, bodyStart);
      const after = source.slice(close);
      return `${before}${newBody}${after}`;
    }

    // No sentinel yet.
    const trimmedBody = body.trim();
    if (rows.length === 0) {
      // (3b) Nothing to manage. Preserve the source verbatim — including
      // the from-receipt seed's `principal.tenant_id == "..."` guard.
      // This is the F001 fix: the OLD splicer would render `"true"` here
      // and wipe the tenant guard.
      return source;
    }

    // (3c) Append a sentinel-scoped managed region to the existing body,
    // joined with `&&` so the merge is well-formed Cedar. We always emit
    // the managed region (even when all rows are incomplete) so subsequent
    // splices can find it.
    const managed = renderManagedRegion(rows);
    const seed = trimmedBody.length > 0 ? `  ${trimmedBody} &&\n` : "";
    const newBody = `\n${seed}${managed}\n`;
    const before = source.slice(0, bodyStart);
    const after = source.slice(close);
    return `${before}${newBody}${after}`;
  }

  // No existing `when {…}` — splice one in before the rule's terminating `;`.
  // When rows are empty, emit `when { true }` (a freshly-created vacuous
  // block — there's nothing to manage yet, so no sentinels). When rows are
  // non-empty, emit a sentinel-bracketed managed region so the next splice
  // can find it (idempotency).
  const semi = findRuleTerminator(source);
  if (semi === null) return source;
  const head = source.slice(0, semi);
  const tail = source.slice(semi);
  // Strip a trailing newline from `head` if present so the inserted block
  // doesn't double-space the trailing semicolon.
  const trimmedHead = head.replace(/\s+$/, "");
  const body =
    rows.length === 0 ? renderWhenBody(rows) : renderManagedRegion(rows);
  return `${trimmedHead}\nwhen {\n${body}\n}\n${tail}`;
}

function findWhenBlock(source: string): { openBraceIndex: number } | null {
  // `\bwhen\s*\{` — `\b` keeps us from matching e.g. `whenever`. We don't
  // allow this inside a string; per the brief Cedar sources are simple
  // single-rule policies for the May-10 demo so a basic regex search is
  // adequate. Per F011, drop the `/g` flag — we only call `.exec()` once
  // and never reuse the regex; `/g` signals "iterating matches" to the
  // next reader when it isn't.
  const re = /\bwhen\s*\{/;
  const match = re.exec(source);
  if (!match) return null;
  const open = source.indexOf("{", match.index);
  return open === -1 ? null : { openBraceIndex: open };
}

/**
 * Walk source from `openIndex+1` to find the matching `}`. Skips characters
 * inside double-quoted strings AND inside Cedar `//` line comments
 * (F008 — a comment containing `{`, `}`, or `;` is NOT structural).
 */
function findMatchingBrace(source: string, openIndex: number): number | null {
  if (source[openIndex] !== "{") return null;
  let depth = 1;
  let i = openIndex + 1;
  let inString = false;
  let inLineComment = false;
  let escape = false;
  while (i < source.length) {
    const ch = source[i]!;
    if (inLineComment) {
      // Comment runs until a literal newline.
      if (ch === "\n") inLineComment = false;
    } else if (inString) {
      if (escape) {
        escape = false;
      } else if (ch === "\\") {
        escape = true;
      } else if (ch === '"') {
        inString = false;
      }
    } else {
      // Detect `//` line comment start. We check BEFORE the brace/string
      // tests so a `//` inside neither is correctly skipped.
      if (ch === "/" && source[i + 1] === "/") {
        inLineComment = true;
        i += 2;
        continue;
      }
      if (ch === '"') {
        inString = true;
      } else if (ch === "{") {
        depth += 1;
      } else if (ch === "}") {
        depth -= 1;
        if (depth === 0) return i;
      }
    }
    i += 1;
  }
  return null;
}

/**
 * Find a `;` outside double-quoted strings, outside any `when {…}` /
 * `unless {…}` block, AND outside Cedar `//` line comments (F008).
 */
function findRuleTerminator(source: string): number | null {
  let depth = 0;
  let inString = false;
  let inLineComment = false;
  let escape = false;
  for (let i = 0; i < source.length; i += 1) {
    const ch = source[i]!;
    if (inLineComment) {
      if (ch === "\n") inLineComment = false;
      continue;
    }
    if (inString) {
      if (escape) escape = false;
      else if (ch === "\\") escape = true;
      else if (ch === '"') inString = false;
      continue;
    }
    if (ch === "/" && source[i + 1] === "/") {
      inLineComment = true;
      i += 1;
      continue;
    }
    if (ch === '"') inString = true;
    else if (ch === "{") depth += 1;
    else if (ch === "}") depth = Math.max(0, depth - 1);
    else if (ch === ";" && depth === 0) return i;
  }
  return null;
}
