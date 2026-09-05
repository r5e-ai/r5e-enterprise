// FilterFacet — one faceted filter group in the Dashboard left sidebar
// (T068, FR-012; redesigned in Wave C).
//
// Per R1 ("R1. Dashboard — Audit Log (Redesigned)") in the .pen file:
//   - Each facet is a header (facet name) plus a list of value chips with a
//     live count next to each.
//   - **Wave C — collapsed-empty rule**: facet rows with `count === 0` are
//     HIDDEN by default, behind a "+ Show N empty" affordance. ES/Datadog
//     parity. The pre-Wave-C UI rendered all 30 canonical kinds in the
//     left rail, most at 0 — visual clutter that drowned the action.
//   - The user can re-expand the empties (auditor wants to know "what
//     COULD I filter on?"); pressing again collapses them back.
//   - Active values stay visible regardless of count (so the user can
//     unfilter).
//   - Counts are right-aligned in `r5e-muted`.
//   - "Clear" still appears when the facet has any active values.
//
// The component is presentational — the parent (`Dashboard.tsx`) owns the
// URL-search-params source of truth and wires `value`/`onToggle`. Counts
// come from the backend's `?facets=true` envelope (see
// `~/hooks/useReceipts.ReceiptsFacets`).
//
// Optional `getValueColor` prop lets the parent color a value chip with
// the R4 semantic palette (e.g. `policy_denied → r5e-chart-denied`); the
// Category facet supplies it. When omitted, chips fall back to the
// neutral `r5e-accent` highlight used pre-Wave-C.

import { useState } from "react";

import type { ChartToken } from "~/lib/chartTokens";
import { CHART_TOKENS, chartTokenClasses } from "~/lib/chartTokens";

// Class strings for chip variants come from the shared
// `~/lib/chartTokens` resolver (extracted in MR !86 fix-pass-2 per
// Constitution Principle VII — CategoryPill, FilterFacet, and ToolCell
// were three inline copies of the same chart-token → Tailwind-class
// lookup). The `chip-active` and `chip-idle` variants reproduce the
// pre-extraction FilterFacet visuals exactly.
//
// Defensive-narrow set is sourced from `CHART_TOKENS` (the canonical
// closed set in chartTokens.ts) — fix-pass-3 retired the local
// duplicate. Adding a new chart token in chartTokens.ts auto-extends
// this Set.
const KNOWN_CHART_TOKENS: ReadonlySet<string> = new Set<string>(CHART_TOKENS);

interface FacetValue {
  value: string;
  label: string;
  count: number | null;
}

interface Props {
  title: string;
  values: FacetValue[];
  active: Set<string>;
  onToggle: (value: string) => void;
  onClear: () => void;
  /**
   * Optional R4-palette colorer keyed on the value (typically a
   * category). When supplied AND the value resolves to a chart token,
   * the chip is rendered with that hue's text color and a tinted bg
   * when active. Returns the design-token name without `r5e-` (e.g.
   * `chart-subprocess`) or null to fall back to the default chrome.
   */
  getValueColor?: (value: string) => string | null;
  /** Initial collapsed state for empties; tests pass `false` to assert
   *  the empty rows are NOT in the DOM by default. */
  initialEmptyExpanded?: boolean;
}

export function FilterFacet({
  title,
  values,
  active,
  onToggle,
  onClear,
  getValueColor,
  initialEmptyExpanded = false,
}: Props): JSX.Element {
  const [showEmpty, setShowEmpty] = useState<boolean>(initialEmptyExpanded);

  // Wave C: keep active values visible regardless of count, even when
  // the user has collapsed the empties. (An active value with count=0
  // hidden would let the URL state desync from what the operator can
  // see.)
  const visible = values.filter(
    (v) =>
      showEmpty || (v.count ?? 0) > 0 || active.has(v.value),
  );
  // `hideableCount` is the number of rows that WOULD be hidden if the
  // empties were collapsed — used for the affordance label even after
  // the user expands. Without this the toggle disappears the moment
  // the user clicks it (no way to collapse back).
  const hideableCount = values.filter(
    (v) => (v.count ?? 0) === 0 && !active.has(v.value),
  ).length;
  // Currently-hidden count: 0 when expanded; equals hideableCount when
  // collapsed. Drives the test-stable invariant "if any 0-count rows
  // exist, the affordance is in the DOM".
  const hiddenCount = showEmpty ? 0 : hideableCount;

  return (
    <section className="border-b border-r5e-border/60 px-4 py-3">
      <header className="mb-2 flex items-center justify-between">
        <h3 className="text-xs font-semibold uppercase tracking-wider text-r5e-muted">
          {title}
        </h3>
        {active.size > 0 && (
          <button
            type="button"
            onClick={onClear}
            className="text-[10px] uppercase tracking-wider text-r5e-muted hover:text-r5e-text"
          >
            Clear
          </button>
        )}
      </header>
      <ul className="space-y-1">
        {visible.length === 0 && hiddenCount === 0 ? (
          <li className="text-xs text-r5e-muted">No values yet</li>
        ) : (
          visible.map((v) => {
            const isActive = active.has(v.value);
            const colorToken = getValueColor ? getValueColor(v.value) : null;
            const colorClasses = chipColorClasses(colorToken, isActive);
            return (
              <li key={v.value}>
                <button
                  type="button"
                  onClick={() => onToggle(v.value)}
                  aria-pressed={isActive}
                  data-color-token={colorToken ?? undefined}
                  className={`flex w-full items-center justify-between rounded px-2 py-1 text-left text-xs transition-colors focus:outline-none focus:ring-1 focus:ring-r5e-accent-glow ${colorClasses}`}
                >
                  <span className="truncate">{v.label}</span>
                  <span className="ml-2 shrink-0 font-mono text-[10px] text-r5e-muted">
                    {v.count ?? "—"}
                  </span>
                </button>
              </li>
            );
          })
        )}
      </ul>
      {hideableCount > 0 && (
        <button
          type="button"
          data-testid={`facet-show-empty-${title.toLowerCase().replace(/\s+/g, "-")}`}
          onClick={() => setShowEmpty((v) => !v)}
          className="mt-2 text-[10px] uppercase tracking-wider text-r5e-muted hover:text-r5e-text"
          aria-expanded={showEmpty}
        >
          {showEmpty
            ? `− Hide ${hideableCount} empty`
            : `+ Show ${hideableCount} empty`}
        </button>
      )}
    </section>
  );
}

/**
 * Compose the Tailwind utility chain for a chip given a design-token name
 * (or null for the default `r5e-accent` chrome). Delegates to
 * `chartTokenClasses(token, 'chip-active' | 'chip-idle')` from
 * `~/lib/chartTokens`. The token-null fallback (default chip chrome) stays
 * inline because there is no `chart-*` token to resolve.
 */
function chipColorClasses(token: string | null, isActive: boolean): string {
  if (!token) {
    return isActive
      ? "bg-r5e-accent/20 text-r5e-accent"
      : "text-r5e-text hover:bg-r5e-surface";
  }
  // Defensive narrow: if a caller hands us an unknown token (typo, or a
  // future token that hasn't been added to chartTokens.ts yet), fall
  // through to the `chart-ui` neutral band rather than throwing or
  // emitting a non-existent Tailwind class.
  const safeToken: ChartToken = (KNOWN_CHART_TOKENS.has(token) ? token : "chart-ui") as ChartToken;
  const variant = isActive ? "chip-active" : "chip-idle";
  const cls = chartTokenClasses(safeToken, variant);
  return `${cls.bg} ${cls.text}`.trim();
}

// (Callers import `categoryColorToken` directly from `~/lib/tags` —
// re-exporting here would defeat react-refresh's component-only
// invariant.)
