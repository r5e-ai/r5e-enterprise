// chartTokens — unit tests for the shared chart-token → Tailwind-class
// resolver extracted in MR !86 fix-pass-2 (Constitution Principle VII).
//
// Asserts:
//   1. Every (token, variant) pair returns static literal Tailwind class
//      strings (Tailwind 3 JIT requirement).
//   2. The `pill` and `tool-pill` variants are identical (the tool-pill
//      alias is an ergonomic distinction, not a visual one).
//   3. Every brief-mapped category resolves through `categoryColorToken`
//      to the token the brief specifies (lockstep with
//      `design/briefs/01-shared-systems.md`'s R4 palette table).
//
// The tailwindTokens.test.ts guardrail catches typo'd token names at
// build time (every literal `r5e-*` class string in src/** must resolve
// to a real token in tailwind.config.ts). This test catches the layer
// above: every category the brief mentions resolves to the right token,
// AND the resolver is exhaustive over the closed token set.

import { describe, expect, it } from "vitest";

import {
  CHART_TOKENS,
  chartTokenClasses,
  toolKindToChartToken,
  type ChartToken,
  type ChartVariant,
} from "~/lib/chartTokens";
import { categoryColorToken } from "~/lib/tags";

const VARIANTS: readonly ChartVariant[] = [
  "pill",
  "tool-pill",
  "chip-active",
  "chip-idle",
  "histogram-fill",
];

describe("chartTokens#chartTokenClasses", () => {
  it("returns static-literal Tailwind class strings for every token + variant", () => {
    for (const token of CHART_TOKENS) {
      for (const variant of VARIANTS) {
        const cls = chartTokenClasses(token, variant);
        // text always set; bg always set (idle uses hover: prefix); border
        // is set for pill variants and empty for chip variants.
        // `histogram-fill` is the SVG variant — text holds a `fill-* text-*`
        // utility pair; bg + border are empty.
        // Match a Tailwind utility chain: optional `hover:` (or other
        // single state-prefix), required base utility, optional `/NN`
        // opacity suffix (e.g. `bg-r5e-chart-denied/15`).
        const tailwindUtility = /^([a-z][a-z0-9-]*:)?[a-z][a-z0-9-]+(\/[0-9]+)?$/;
        const tailwindPair = /^[a-z][a-z0-9-]+ [a-z][a-z0-9-]+$/;
        if (variant === "histogram-fill") {
          expect(cls.text, `${token}/${variant} text`).toMatch(tailwindPair);
          expect(cls.bg, `${token}/${variant} bg`).toBe("");
          expect(cls.border, `${token}/${variant} border`).toBe("");
        } else {
          expect(cls.text, `${token}/${variant} text`).toMatch(tailwindUtility);
          expect(cls.bg, `${token}/${variant} bg`).toMatch(tailwindUtility);
          if (variant === "pill" || variant === "tool-pill") {
            expect(cls.border, `${token}/${variant} border`).toMatch(/^border-r5e-[a-z0-9-]+$/);
          } else {
            expect(cls.border, `${token}/${variant} border`).toBe("");
          }
        }
      }
    }
  });

  it("treats pill and tool-pill as visual aliases", () => {
    for (const token of CHART_TOKENS) {
      const pill = chartTokenClasses(token, "pill");
      const toolPill = chartTokenClasses(token, "tool-pill");
      expect(toolPill).toEqual(pill);
    }
  });

  it("emits chart-search literals (not chart-file-read) for the search variant", () => {
    // Regression guard — pre-extraction, file_search categories drifted
    // through to chart-file-read (green) instead of chart-search (slate).
    // Caught by GAN review of MR !86, finding F001.
    const cls = chartTokenClasses("chart-search", "pill");
    expect(cls.text).toBe("text-r5e-chart-search");
    expect(cls.bg).toBe("bg-r5e-chart-search/15");
    expect(cls.border).toBe("border-r5e-chart-search");
  });

  it("emits chart-todo literals (not chart-ui) for the todo variant", () => {
    // Regression guard — pre-extraction, todo_management drifted through
    // to chart-ui. Caught by GAN review of MR !86, finding F001.
    const cls = chartTokenClasses("chart-todo", "pill");
    expect(cls.text).toBe("text-r5e-chart-todo");
    expect(cls.bg).toBe("bg-r5e-chart-todo/15");
    expect(cls.border).toBe("border-r5e-chart-todo");
  });
});

// The category → token mapping per `design/briefs/01-shared-systems.md`
// R4 palette table. Lockstep with `categoryColorToken` in `~/lib/tags`.
const BRIEF_CATEGORY_MAP: ReadonlyArray<{ category: string; token: ChartToken }> = [
  { category: "subprocess_exec", token: "chart-subprocess" },
  { category: "file_write", token: "chart-file-write" },
  { category: "file_read", token: "chart-file-read" },
  { category: "file_search", token: "chart-search" },
  { category: "mcp_tool_call", token: "chart-mcp-tool" },
  { category: "agent_dispatch", token: "chart-agent" },
  { category: "network_egress", token: "chart-network" },
  { category: "llm_call", token: "chart-llm" },
  { category: "policy_denied", token: "chart-denied" },
  { category: "todo_management", token: "chart-todo" },
  { category: "ui_event", token: "chart-ui" },
  { category: "unknown", token: "chart-ui" },
];

describe("tags#categoryColorToken — lockstep with R4 palette brief", () => {
  it.each(BRIEF_CATEGORY_MAP)(
    "$category resolves to $token (per design/briefs/01-shared-systems.md)",
    ({ category, token }) => {
      expect(categoryColorToken(category)).toBe(token);
    },
  );

  it("notebook_edit shares chart-file-write band (groups with file_write)", () => {
    expect(categoryColorToken("notebook_edit")).toBe("chart-file-write");
  });
});

// The tool_kind → ChartToken mapping per the extractor's `tool_kind`
// alphabet (apps/recurse_gateway/lib/recurse_gateway/extractors/
// claude_code_jsonl.ex). Lockstep with `toolKindToChartToken` in
// `~/lib/chartTokens` (extracted in MR !86 fix-pass-3 per Constitution
// Principle VII — Dashboard's Tool FilterFacet was the third call site
// of the same switch, after ToolCell.toolKindToken and the legacy
// inline copy in Dashboard).
const TOOL_KIND_MAP: ReadonlyArray<{ toolKind: string; token: ChartToken | null }> = [
  { toolKind: "bash", token: "chart-subprocess" },
  { toolKind: "edit", token: "chart-file-write" },
  { toolKind: "notebook_edit", token: "chart-file-write" },
  { toolKind: "read", token: "chart-file-read" },
  { toolKind: "search", token: "chart-search" },
  { toolKind: "mcp", token: "chart-mcp-tool" },
  { toolKind: "agent", token: "chart-agent" },
  { toolKind: "webfetch", token: "chart-network" },
  { toolKind: "llm", token: "chart-llm" },
  { toolKind: "todo", token: "chart-todo" },
];

describe("chartTokens#toolKindToChartToken", () => {
  it.each(TOOL_KIND_MAP)(
    "$toolKind resolves to $token",
    ({ toolKind, token }) => {
      expect(toolKindToChartToken(toolKind)).toBe(token);
    },
  );

  it("returns null for unknown tool_kind values (FilterFacet neutral fallthrough)", () => {
    expect(toolKindToChartToken("unknown_tool")).toBeNull();
    expect(toolKindToChartToken("")).toBeNull();
    expect(toolKindToChartToken(null)).toBeNull();
    expect(toolKindToChartToken(undefined)).toBeNull();
  });
});
