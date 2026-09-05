// ToolCell — the TOOL column's per-row pill. Renders `tags.tool_kind` as
// a compact R4-tinted pill matching Pencil's `comp/receipts-table-v2`
// design (.pen ID `kPFqb` → row-allow `YHWhh` / row-deny `D5oMo`).
//
// Per design:
//   - Bash, Edit, Read, MCP[server], WebFetch, LLM, Agent, Search, Todo
//   - R4 palette by tool_kind (bash=subprocess orange, edit=file_write
//     yellow, etc.). Denial rows force the chart-denied red pill to draw
//     the eye even when the underlying tool was benign.
//   - For MCP, render `MCP[<server>]` not just `MCP` (server extracted
//     from semantic_args.server).
//
// Class strings come from the shared `~/lib/chartTokens` resolver
// (extracted in MR !86 fix-pass-2 per Constitution Principle VII —
// CategoryPill, FilterFacet, and ToolCell were three inline copies of
// the same chart-token → Tailwind-class lookup; the third copy
// motivated the extraction). All return values are static literal
// strings so Tailwind 3 JIT picks them up at build time; the test at
// `ui/src/tests/unit/tailwindTokens.test.ts` enforces this on every push.

import { Ban } from "lucide-react";

import type { ChartToken } from "~/lib/chartTokens";
import { chartTokenClasses, toolKindToChartToken } from "~/lib/chartTokens";
import type { ReceiptTags } from "~/lib/tags";

interface Props {
  tags: ReceiptTags | null;
  /** True iff `outer_container.policy_decision === "deny"`. Forces red. */
  forceDenial?: boolean;
}

/**
 * Map tool_kind → R4 chart-color token name. Delegates to the shared
 * `toolKindToChartToken` resolver in `~/lib/chartTokens` (extracted in
 * MR !86 fix-pass-3 per Constitution Principle VII — Dashboard's Tool
 * FilterFacet was the third call site of the same switch). Unknown
 * tool_kinds default to `chart-ui` (slate neutral) so the row pill
 * always renders something — distinct from FilterFacet's `null`
 * fallthrough where a missing-token chip wants neutral chip chrome,
 * not a slate pill.
 */
function toolKindToken(toolKind: string | null | undefined): ChartToken {
  return toolKindToChartToken(toolKind) ?? "chart-ui";
}

/** Pretty label for the pill — Pencil convention: capitalized + `MCP[server]`. */
function pillLabel(tags: ReceiptTags | null): string {
  const kind = tags?.tool_kind ?? null;
  switch (kind) {
    case "bash":
      return "Bash";
    case "edit":
      return "Edit";
    case "notebook_edit":
      return "Notebook";
    case "read":
      return "Read";
    case "search":
      return "Search";
    case "agent":
      return "Agent";
    case "webfetch":
      return "WebFetch";
    case "llm":
      return "LLM";
    case "todo":
      return "Todo";
    case "mcp": {
      // Runtime narrow: ReceiptTags.semantic_args is
      // `Record<string, unknown> | null`, so a non-string `server` value
      // (a future extractor producer that emits structured server
      // metadata, etc.) would compile-cast to `string` and render
      // `MCP[[object Object]]`. Cast was caught by GAN review of MR !86,
      // finding F009. Narrow defensively.
      const raw = tags?.semantic_args?.server;
      const server = typeof raw === "string" ? raw : null;
      return server ? `MCP[${server}]` : "MCP";
    }
    default:
      return "—";
  }
}

export function ToolCell({ tags, forceDenial = false }: Props): JSX.Element | null {
  // Empty cells render nothing visible — just a non-breaking space placeholder
  // so the column width holds. Avoids "—" noise on rows that genuinely don't
  // have a tool_kind (system events, etc.).
  if (!tags?.tool_kind) {
    return <span aria-hidden="true">&nbsp;</span>;
  }

  const token: ChartToken = forceDenial ? "chart-denied" : toolKindToken(tags.tool_kind);
  const cls = chartTokenClasses(token, "tool-pill");
  const label = pillLabel(tags);

  return (
    <span
      data-testid="tool-pill"
      data-tool-kind={tags.tool_kind}
      data-denial={forceDenial ? "true" : "false"}
      className={`inline-flex items-center gap-1 rounded border px-2 py-[1px] text-[10px] font-mono font-semibold uppercase tracking-wider ${cls.text} ${cls.bg} ${cls.border}`}
    >
      {/* R4 Rule 01: deny-trumps. Lucide Ban (⊘) prefixes the pill on
          denial rows so the auditor sees `⊘ BASH` not just a red pill. */}
      {forceDenial && <Ban size={10} aria-hidden="true" data-testid="tool-pill-denial-icon" />}
      {label}
    </span>
  );
}
