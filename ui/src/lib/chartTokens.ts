// Chart-token → Tailwind class resolver (Constitution Principle VII —
// Interface-First on Second Consumer; extracted from CategoryPill /
// FilterFacet / ToolCell after the third inline copy was caught by GAN
// review of MR !86, finding F001 BLOCKER).
//
// ## Why this module exists
//
// Three components need to render an R4 chart-color in slightly different
// shapes:
//   - CategoryPill — solid pill: text + bg/15 + border at full strength.
//   - FilterFacet  — chip: text + hover bg/10 (idle) or bg/20 + text (active).
//   - ToolCell     — small pill: same as CategoryPill (the "tool-pill"
//                    variant is identical to "pill"), but kept separate so
//                    the call sites read clearly.
//
// Pre-extraction these three lived as inline switch statements that drifted
// out of sync (ToolCell typo'd `chart-agent-dispatch` etc.; tags.ts mapped
// `file_search → chart-file-read` while the design brief said
// `r5e-chart-search`). Constitution Principle VII (added 2026-04-29 after
// issue #29) says: when a *third* call site needs the same logic, code
// review MUST flag it as blocking and the work item is to extract a
// shared module — not patch the third copy. This module is that
// extraction.
//
// ## Tailwind 3 JIT requirement
//
// The JIT engine only emits CSS for class strings that appear LITERALLY in
// scanned source. Template-string interpolation (e.g. `text-r5e-${token}`)
// is invisible. Every utility this module returns is a literal string
// constant; the call sites compose them but never substitute into them.
//
// `ui/src/tests/unit/tailwindTokens.test.ts` enforces "every literal
// `r5e-*` class string in src/** resolves to a real token in
// `tailwind.config.ts`" — typos break the build before they can ship.

/**
 * Closed set of design tokens this resolver knows about. New chart-* token?
 *
 * 1. Add it to `ui/design-tokens.json`.
 * 2. Run `pnpm gen:tailwind` (regenerates `ui/tailwind.config.ts`).
 * 3. Add it to this union AND to every variant block in
 *    `chartTokenClasses` below — the type system + the
 *    tailwindTokens.test.ts guardrail will scream if you miss either step.
 */
export type ChartToken =
  | "chart-denied"
  | "chart-subprocess"
  | "chart-file-write"
  | "chart-file-read"
  | "chart-search"
  | "chart-mcp-tool"
  | "chart-agent"
  | "chart-network"
  | "chart-llm"
  | "chart-todo"
  | "chart-ui";

/**
 * The five ways the redesign uses a chart token. Each variant returns the
 * matching trio of static Tailwind classes (text / bg / border) so call
 * sites can compose them into the surrounding utility chain.
 *
 *   - `pill`           — solid R4 pill (CategoryPill default).
 *   - `tool-pill`      — same as `pill`; kept distinct for call-site
 *                        readability.
 *   - `chip-active`    — FilterFacet chip when the value is currently
 *                        selected.
 *   - `chip-idle`      — FilterFacet chip when the value is unselected
 *                        (text-only; bg appears on hover).
 *   - `histogram-fill` — SVG `fill-r5e-chart-*` + matching `text-*` pair
 *                        for stacked-area / bar segments. The `bg`/`border`
 *                        slots are empty — the histogram composes the
 *                        `fill` via the `text` slot's sibling utility.
 *                        Added 2026-05-01 (MR !86 fix-pass-3, finding
 *                        F005) so Histogram.categoryColorClass stops
 *                        being a 4th parallel chart-token resolver.
 */
export type ChartVariant =
  | "pill"
  | "tool-pill"
  | "chip-active"
  | "chip-idle"
  | "histogram-fill";

export interface ChartClasses {
  text: string;
  bg: string;
  border: string;
}

const ALL_TOKENS = [
  "chart-denied",
  "chart-subprocess",
  "chart-file-write",
  "chart-file-read",
  "chart-search",
  "chart-mcp-tool",
  "chart-agent",
  "chart-network",
  "chart-llm",
  "chart-todo",
  "chart-ui",
] as const satisfies readonly ChartToken[];

/** Test helper — exhaustive iteration over the closed token set. */
export const CHART_TOKENS: readonly ChartToken[] = ALL_TOKENS;

/**
 * Resolve a chart token + variant to the trio of static Tailwind utility
 * classes. Pure; total over `ChartToken × ChartVariant`. Static literal
 * strings only — no template interpolation, no string concatenation —
 * because Tailwind 3's JIT needs to scan them at build time.
 *
 * Variant semantics:
 *   - `pill` and `tool-pill` are identical (text + bg/15 + border) and
 *     reproduce the pre-extraction CategoryPill / ToolCell behavior.
 *   - `chip-active` mirrors FilterFacet's "this value is selected"
 *     branch (bg/20 + text, no border classes).
 *   - `chip-idle` mirrors FilterFacet's "unselected" branch (text +
 *     hover bg/10, no border classes).
 */
export function chartTokenClasses(
  token: ChartToken,
  variant: ChartVariant,
): ChartClasses {
  switch (variant) {
    case "pill":
    case "tool-pill":
      return pillClasses(token);
    case "chip-active":
      return chipActiveClasses(token);
    case "chip-idle":
      return chipIdleClasses(token);
    case "histogram-fill":
      return histogramFillClasses(token);
  }
}

/**
 * Map a `tool_kind` value (`bash`, `edit`, `mcp`, …) to its R4 chart-token
 * name. Pure; total. Returns `null` for unknown tools so callers can
 * fall through to neutral chrome (FilterFacet chip), or default to
 * `chart-ui` (ToolCell pill behavior — encoded at the call site).
 *
 * Extracted in MR !86 fix-pass-3 (Constitution Principle VII NON-NEGOTIABLE)
 * after fix-pass-2 added `Dashboard.toolKindToColorToken` and triggered
 * the third-call-site rule. Pre-extraction, the same switch lived in:
 *   - `ToolCell.tsx::toolKindToken` (defaulted to `chart-ui`)
 *   - `Dashboard.tsx::toolKindToColorToken` (defaulted to `null` for
 *     FilterFacet's neutral fallback)
 *
 * The closed set of tool_kind values is enumerated in
 * `ui/src/lib/tags.ts::ReceiptTags.tool_kind` and produced by the
 * extractor at
 * `apps/recurse_gateway/lib/recurse_gateway/extractors/claude_code_jsonl.ex`.
 */
export function toolKindToChartToken(
  toolKind: string | null | undefined,
): ChartToken | null {
  switch (toolKind) {
    case "bash":
      return "chart-subprocess";
    case "edit":
    case "notebook_edit":
      return "chart-file-write";
    case "read":
      return "chart-file-read";
    case "search":
      return "chart-search";
    case "mcp":
      return "chart-mcp-tool";
    case "agent":
      return "chart-agent";
    case "webfetch":
      return "chart-network";
    case "llm":
      return "chart-llm";
    case "todo":
      return "chart-todo";
    default:
      return null;
  }
}

function pillClasses(token: ChartToken): ChartClasses {
  switch (token) {
    case "chart-denied":
      return { text: "text-r5e-chart-denied", bg: "bg-r5e-chart-denied/15", border: "border-r5e-chart-denied" };
    case "chart-subprocess":
      return { text: "text-r5e-chart-subprocess", bg: "bg-r5e-chart-subprocess/15", border: "border-r5e-chart-subprocess" };
    case "chart-file-write":
      return { text: "text-r5e-chart-file-write", bg: "bg-r5e-chart-file-write/15", border: "border-r5e-chart-file-write" };
    case "chart-file-read":
      return { text: "text-r5e-chart-file-read", bg: "bg-r5e-chart-file-read/15", border: "border-r5e-chart-file-read" };
    case "chart-search":
      return { text: "text-r5e-chart-search", bg: "bg-r5e-chart-search/15", border: "border-r5e-chart-search" };
    case "chart-mcp-tool":
      return { text: "text-r5e-chart-mcp-tool", bg: "bg-r5e-chart-mcp-tool/15", border: "border-r5e-chart-mcp-tool" };
    case "chart-agent":
      return { text: "text-r5e-chart-agent", bg: "bg-r5e-chart-agent/15", border: "border-r5e-chart-agent" };
    case "chart-network":
      return { text: "text-r5e-chart-network", bg: "bg-r5e-chart-network/15", border: "border-r5e-chart-network" };
    case "chart-llm":
      return { text: "text-r5e-chart-llm", bg: "bg-r5e-chart-llm/15", border: "border-r5e-chart-llm" };
    case "chart-todo":
      return { text: "text-r5e-chart-todo", bg: "bg-r5e-chart-todo/15", border: "border-r5e-chart-todo" };
    case "chart-ui":
      return { text: "text-r5e-chart-ui", bg: "bg-r5e-chart-ui/15", border: "border-r5e-chart-ui" };
  }
}

function chipActiveClasses(token: ChartToken): ChartClasses {
  // Active chips: tinted bg + colored text. No border (FilterFacet didn't
  // use one). Empty string for `border` keeps the return shape uniform so
  // call sites can spread the trio without conditionals.
  switch (token) {
    case "chart-denied":
      return { text: "text-r5e-chart-denied", bg: "bg-r5e-chart-denied/20", border: "" };
    case "chart-subprocess":
      return { text: "text-r5e-chart-subprocess", bg: "bg-r5e-chart-subprocess/20", border: "" };
    case "chart-file-write":
      return { text: "text-r5e-chart-file-write", bg: "bg-r5e-chart-file-write/20", border: "" };
    case "chart-file-read":
      return { text: "text-r5e-chart-file-read", bg: "bg-r5e-chart-file-read/20", border: "" };
    case "chart-search":
      return { text: "text-r5e-chart-search", bg: "bg-r5e-chart-search/20", border: "" };
    case "chart-mcp-tool":
      return { text: "text-r5e-chart-mcp-tool", bg: "bg-r5e-chart-mcp-tool/20", border: "" };
    case "chart-agent":
      return { text: "text-r5e-chart-agent", bg: "bg-r5e-chart-agent/20", border: "" };
    case "chart-network":
      return { text: "text-r5e-chart-network", bg: "bg-r5e-chart-network/20", border: "" };
    case "chart-llm":
      return { text: "text-r5e-chart-llm", bg: "bg-r5e-chart-llm/20", border: "" };
    case "chart-todo":
      return { text: "text-r5e-chart-todo", bg: "bg-r5e-chart-todo/20", border: "" };
    case "chart-ui":
      // Pre-extraction quirk preserved: the `chart-ui` chip-active case used
      // `text-r5e-text` (neutral) rather than `text-r5e-chart-ui` (slate).
      // The existing FilterFacet visual has been verified at this exact
      // shape; changing it would alter the rail's appearance in shipping
      // mocks. Kept as-is.
      return { text: "text-r5e-text", bg: "bg-r5e-chart-ui/20", border: "" };
  }
}

function histogramFillClasses(token: ChartToken): ChartClasses {
  // SVG-variant: histogram segments need a literal `fill-r5e-chart-*`
  // utility (Tailwind 3 JIT requires literal class strings — no template
  // interpolation), and the legend swatch / hover tooltip pair the fill
  // with the matching `text-r5e-chart-*` so `bg-current` resolves to the
  // same hue. `bg`/`border` are empty for this variant — the histogram
  // composes via `fill` (in the `text` slot's sibling utility) only.
  switch (token) {
    case "chart-denied":
      return { text: "fill-r5e-chart-denied text-r5e-chart-denied", bg: "", border: "" };
    case "chart-subprocess":
      return { text: "fill-r5e-chart-subprocess text-r5e-chart-subprocess", bg: "", border: "" };
    case "chart-file-write":
      return { text: "fill-r5e-chart-file-write text-r5e-chart-file-write", bg: "", border: "" };
    case "chart-file-read":
      return { text: "fill-r5e-chart-file-read text-r5e-chart-file-read", bg: "", border: "" };
    case "chart-search":
      return { text: "fill-r5e-chart-search text-r5e-chart-search", bg: "", border: "" };
    case "chart-mcp-tool":
      return { text: "fill-r5e-chart-mcp-tool text-r5e-chart-mcp-tool", bg: "", border: "" };
    case "chart-agent":
      return { text: "fill-r5e-chart-agent text-r5e-chart-agent", bg: "", border: "" };
    case "chart-network":
      return { text: "fill-r5e-chart-network text-r5e-chart-network", bg: "", border: "" };
    case "chart-llm":
      return { text: "fill-r5e-chart-llm text-r5e-chart-llm", bg: "", border: "" };
    case "chart-todo":
      return { text: "fill-r5e-chart-todo text-r5e-chart-todo", bg: "", border: "" };
    case "chart-ui":
      return { text: "fill-r5e-chart-ui text-r5e-chart-ui", bg: "", border: "" };
  }
}

function chipIdleClasses(token: ChartToken): ChartClasses {
  // Idle chips: colored text + hover-only bg. No border.
  switch (token) {
    case "chart-denied":
      return { text: "text-r5e-chart-denied", bg: "hover:bg-r5e-chart-denied/10", border: "" };
    case "chart-subprocess":
      return { text: "text-r5e-chart-subprocess", bg: "hover:bg-r5e-chart-subprocess/10", border: "" };
    case "chart-file-write":
      return { text: "text-r5e-chart-file-write", bg: "hover:bg-r5e-chart-file-write/10", border: "" };
    case "chart-file-read":
      return { text: "text-r5e-chart-file-read", bg: "hover:bg-r5e-chart-file-read/10", border: "" };
    case "chart-search":
      return { text: "text-r5e-chart-search", bg: "hover:bg-r5e-chart-search/10", border: "" };
    case "chart-mcp-tool":
      return { text: "text-r5e-chart-mcp-tool", bg: "hover:bg-r5e-chart-mcp-tool/10", border: "" };
    case "chart-agent":
      return { text: "text-r5e-chart-agent", bg: "hover:bg-r5e-chart-agent/10", border: "" };
    case "chart-network":
      return { text: "text-r5e-chart-network", bg: "hover:bg-r5e-chart-network/10", border: "" };
    case "chart-llm":
      return { text: "text-r5e-chart-llm", bg: "hover:bg-r5e-chart-llm/10", border: "" };
    case "chart-todo":
      return { text: "text-r5e-chart-todo", bg: "hover:bg-r5e-chart-todo/10", border: "" };
    case "chart-ui":
      // Idle `chart-ui` chips were styled `text-r5e-muted hover:bg-r5e-surface`
      // pre-extraction (FilterFacet's neutral fall-through). Preserved.
      return { text: "text-r5e-muted", bg: "hover:bg-r5e-surface", border: "" };
  }
}
