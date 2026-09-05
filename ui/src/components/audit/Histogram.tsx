// Histogram — time-bucketed receipt-volume histogram above the audit table
// (T068, FR-011).
//
// Per the pen-file Dashboard screen:
//   - Stacked bars per bucket, one segment per `event_kind` in the bucket.
//   - Brushable: click-and-drag a horizontal range over the chart selects a
//     `[since, until]` window; clicking a single bucket sets a 1-bucket
//     window (`since=ts`, `until` = next bucket). Preset window buttons
//     (Last 1h | 6h | 24h | 7d | All) live above the chart for the common
//     auditor cases.
//   - Y axis: 0..max with two reference gridlines (min/max readout in the
//     chart's own type label, not a separate axis component).
//   - X axis: leftmost + rightmost bucket-ts labels, plus a midpoint label,
//     so the time anchor is visible without hovering.
//   - SVG-rendered (no chart library). Total surface is small (~40 buckets,
//     ~6 stacks); CSP `script-src 'self' 'wasm-unsafe-eval'` would silently
//     break a CDN-bootstrapped chart lib (echarts/plotly), so hand-rolled
//     SVG is the established pattern here.
//
// Issue #45 — adversarial UI/UX pass on this surface. Three rolled-up
// changes:
//
//   1. Palette overhaul. Pre-#45 four kinds (`tool_call`, `ui_query`,
//      `ui_evidence_export`, `ui_payload_access`) all collapsed onto
//      `r5e-accent` (purple), and four more (`llm_call`, `ui_chat`,
//      `ui_chat_skill_invoked_*`) collapsed onto `r5e-accent-glow`.
//      Eight semantically-distinct kinds → two visually-near-identical
//      purples. The fix groups kinds by SEMANTIC FAMILY (network call,
//      authoring, denial, lifecycle, agent, system) and assigns each
//      family one design-token shade. Within a family, members share
//      a hue but vary by the optional `text-r5e-*` accent + a
//      `data-family` attribute that downstream callers can use to
//      apply secondary patterns/textures (deferred — see follow-up
//      finding in MR description).
//
//   2. Window controls. Pre-#45, `onBrush(sinceIso)` could only set
//      a `since` watermark; auditor could never bound the end of the
//      window or zoom back out without clearing the URL state. The
//      new `onWindowChange({ since, until })` callback, plus a row of
//      preset window buttons + click-drag brush on the chart, lets
//      the auditor compress to "Last 1h" or zoom into a busy hour
//      directly from the dashboard.
//
//   3. Y/X axis labels. Two reference gridlines ("0" + max), three
//      X-axis ticks (first / mid / last bucket ts), and a denial-tick
//      strip beneath the bars so red denial bars are visible even at
//      single-row counts.
//
// Backwards compatibility: the OLD `onBrush(sinceIso)` API is preserved
// as a deprecated optional prop so callers that have not migrated to
// the windowed callback still work. Dashboard.tsx has been moved to
// `onWindowChange`. When all callers are off `onBrush`, delete it.
//
// Color tokens come from `tailwind.config.ts` (codegen'd from
// `ui/design-tokens.json` via
// `ui/scripts/generate-tailwind-config.ts`). NO HARDCODED HEX. The
// per-family palette anchored to existing tokens is:
//
//   - Network call (tool_call, llm_call) → r5e-accent (brand purple,
//     "demo-money" the CTO sees first).
//   - Denial (policy_denied, session_abort, egress_denied, *_denied)
//     → r5e-danger (brand red).
//   - Authoring (ui_policy_*) → r5e-warning (amber, "humans editing").
//   - Lifecycle (ui_login, ui_session, ui_logout) → r5e-success
//     (green, "things working").
//   - Agent / chat (ui_chat, ui_chat_skill_invoked_*) → r5e-accent-glow
//     (lighter purple — sibling of the demo-money network call).
//   - Read / metadata (ui_query, ui_evidence_export, ui_payload_access)
//     → r5e-text (foreground neutral) — these are passive read-side
//     actions and shouldn't compete with the colored signals.
//   - System / unknown → r5e-muted (grey background).
//
// Colorblindness check: deuteranopia/protanopia (the two most common,
// ~8% of men) collapse green ↔ red, NOT red ↔ purple/yellow. The new
// palette anchors the action-bearing kinds (denial = red, authoring =
// amber, lifecycle = green) on hues distinct under both deficiencies;
// the demo-money network calls live in the brand-purple family, also
// distinct from green and red. The neutral families (read = text,
// system = muted) are intentionally lower-contrast and rely on the
// legend for kind-disambiguation. Tests below also assert no two
// adjacent stacked-segment families share a fill class.

import { useMemo, useRef, useState, type MouseEvent as ReactMouseEvent } from "react";
import { HistogramAreaChart } from "~/components/audit/HistogramAreaChart";
import { chartTokenClasses } from "~/lib/chartTokens";
import { KNOWN_CATEGORIES, categoryColorToken } from "~/lib/tags";

/** True iff `kind` is one of the canonical receipt categories
 *  (i.e. the histogram is in category-stack mode rather than
 *  event_kind-stack mode). */
function isKnownCategory(kind: string): boolean {
  return (KNOWN_CATEGORIES as readonly string[]).includes(kind);
}

export interface HistogramBucket {
  /** ISO 8601 bucket start. */
  ts: string;
  /**
   * Counts keyed by stack key. Per design briefs/02-dashboard.md the
   * canonical stack key is **category** (one layer per R4 category).
   * Pre-Wave-D the keys were `event_kind`s; both shapes are still
   * accepted by the color/family resolvers below for backward
   * compatibility. New callers should bucket by category.
   */
  counts: Record<string, number>;
}

/** Time window shape passed back to the parent. `until` may be `null` to
 * signal "open-ended forward window" (the common case until the auditor
 * picks a closing edge). */
export interface HistogramWindow {
  since: string | null;
  until: string | null;
}

/**
 * Preset window options shown as buttons above the chart. Each entry maps
 * to a relative-to-now `[since, until]`. `"all"` sends `{ since: null,
 * until: null }` — clears any existing window.
 */
export const HISTOGRAM_PRESET_KEYS = ["1h", "6h", "24h", "7d", "all"] as const;
export type HistogramPresetKey = (typeof HISTOGRAM_PRESET_KEYS)[number];

const PRESET_LABELS: Record<HistogramPresetKey, string> = {
  "1h": "Last 1h",
  "6h": "Last 6h",
  "24h": "Last 24h",
  "7d": "Last 7d",
  "all": "All",
};

/**
 * Compute `{ since, until }` for a preset, anchored at `now`. Exported
 * for unit-testability — callers can verify the math without rendering.
 */
export function presetToWindow(
  preset: HistogramPresetKey,
  now: Date = new Date(),
): HistogramWindow {
  if (preset === "all") return { since: null, until: null };
  const ms =
    preset === "1h" ? 60 * 60 * 1000 :
    preset === "6h" ? 6 * 60 * 60 * 1000 :
    preset === "24h" ? 24 * 60 * 60 * 1000 :
    /* 7d */ 7 * 24 * 60 * 60 * 1000;
  const sinceDate = new Date(now.getTime() - ms);
  return {
    since: sinceDate.toISOString(),
    until: now.toISOString(),
  };
}

interface Props {
  buckets: HistogramBucket[];
  /** Distinct event-kind keys in stable order; controls stack order. */
  kinds: string[];
  /**
   * Window-aware callback (preferred). Called with `{ since, until }` when
   * the auditor selects a preset, completes a click-drag brush, or clicks
   * a single bucket (which generates a 1-bucket window).
   */
  onWindowChange?: (window: HistogramWindow) => void;
  /**
   * Legacy single-edge callback (deprecated). Kept so unmigrated callers
   * still get a usable filter. Receives the bucket's start ts on click;
   * NOT called by the brush gesture. Delete once all callers are on
   * `onWindowChange`.
   */
  onBrush?: (sinceIso: string) => void;
  /**
   * Optional currently-active window (matches what the parent has in URL
   * state). When set, the chart renders only buckets whose ts falls
   * inside, AND highlights the matching preset button if any. Pure
   * display-side filtering — does not change the bucket data prop.
   */
  activeWindow?: HistogramWindow;
  /**
   * Chart variant. `"area"` (default) is the R3 RECOMMENDED layered-area
   * chart with hover tooltip — preserves total-volume shape + per-category
   * visibility. `"bars"` is the legacy stacked-bar variant; preserved as
   * an opt-in for callers/tests that have hard-coded bar geometry.
   */
  variant?: "area" | "bars";
}

/** Semantic family bucket — see top-of-file palette discussion. */
type Family = "network" | "denial" | "authoring" | "lifecycle" | "agent" | "read" | "system";

/**
 * Map a stack key to its semantic family. Pure; testable. Used both for
 * stable stack ordering AND for the per-segment `data-family` attribute
 * (downstream tests + a11y narration key on it).
 *
 * For category keys (R4 palette stacking — the new default), the family
 * is derived by collapsing the chart-token band into the existing
 * `Family` enum:
 *   - chart-denied                → denial
 *   - chart-subprocess            → network (closest semantic neighbor)
 *   - chart-file-write/read/search→ authoring (file-touching)
 *   - chart-network/mcp-tool/agent→ network/agent
 *   - chart-llm                   → network
 *   - chart-todo/chart-ui         → system
 *
 * For event_kind keys (legacy stack mode), the original mapping is
 * preserved.
 */
export function familyForKind(kind: string): Family {
  if (isKnownCategory(kind)) return familyForCategory(kind);
  if (kind === "tool_call" || kind === "llm_call") return "network";
  if (
    kind === "policy_denied" ||
    kind === "session_abort" ||
    kind === "egress_denied" ||
    kind.endsWith("_denied")
  ) {
    return "denial";
  }
  if (kind.startsWith("ui_policy_")) return "authoring";
  if (kind === "ui_login" || kind === "ui_session" || kind === "ui_logout") {
    return "lifecycle";
  }
  if (kind === "ui_chat" || kind.startsWith("ui_chat_skill_invoked_")) return "agent";
  if (kind === "ui_query" || kind === "ui_evidence_export" || kind === "ui_payload_access") {
    return "read";
  }
  return "system";
}

/** Category → Family, for stack ordering when the histogram is in
 *  category-stack mode (the default per design briefs). */
function familyForCategory(category: string): Family {
  switch (category) {
    case "policy_denied":
      return "denial";
    case "subprocess_exec":
    case "network_egress":
    case "mcp_tool_call":
    case "llm_call":
      return "network";
    case "file_write":
    case "notebook_edit":
    case "file_read":
    case "file_search":
      return "authoring";
    case "agent_dispatch":
      return "agent";
    case "todo_management":
    case "ui_event":
    case "unknown":
    default:
      return "system";
  }
}

/**
 * Tailwind class for a family. Each family pulls from a SINGLE design
 * token, so palette swaps in `tailwind.config.ts` propagate without code
 * change.
 */
export function colorClassForFamily(family: Family): string {
  switch (family) {
    case "network":   return "fill-r5e-accent text-r5e-accent";
    case "denial":    return "fill-r5e-danger text-r5e-danger";
    case "authoring": return "fill-r5e-warning text-r5e-warning";
    case "lifecycle": return "fill-r5e-success text-r5e-success";
    case "agent":     return "fill-r5e-accent-glow text-r5e-accent-glow";
    case "read":      return "fill-r5e-text text-r5e-text";
    case "system":    return "fill-r5e-muted text-r5e-muted";
  }
}

/**
 * Static-class lookup for category-stacked histogram segments. Delegates
 * to the shared `chartTokenClasses(token, 'histogram-fill')` resolver in
 * `~/lib/chartTokens`. The `histogram-fill` variant emits the
 * `fill-r5e-chart-*` + `text-r5e-chart-*` pair the SVG segments need
 * (Tailwind 3 JIT requires literal class strings — the variant cases
 * inside chartTokens.ts enumerate them explicitly).
 *
 * Pre-fix-pass-3 this was a local switch — the 4th parallel chart-token
 * resolver (after CategoryPill, FilterFacet, ToolCell). Caught by GAN
 * review of MR !86, finding F005. Constitution Principle VII required
 * folding it into chartTokens.ts as a new variant rather than maintaining
 * a 4th copy.
 */
function categoryColorClass(category: string): string {
  const cls = chartTokenClasses(categoryColorToken(category), "histogram-fill");
  return cls.text;
}

/**
 * Public per-stack-key color resolver. Per design briefs/02-dashboard.md
 * the stack keys ARE categories (R4 palette) — when a key matches a
 * known category, this resolver returns the `fill-r5e-chart-*` /
 * `text-r5e-chart-*` pair via `categoryColorClass` (static literals so
 * Tailwind JIT picks them up). Keys that aren't known categories fall
 * through to the legacy event_kind family mapping for backward compat
 * with callers still stacking by event_kind.
 */
export function colorClassForKind(kind: string): string {
  if (isKnownCategory(kind)) return categoryColorClass(kind);
  return colorClassForFamily(familyForKind(kind));
}

/**
 * Determinize stack order by family so the same kind always sits at
 * the same z-band of the bar regardless of dataset ordering. This
 * fixes the pre-#45 "tool_call slides up and down between buckets"
 * disorientation. Within a family we keep the caller-provided order.
 */
function stableKindOrder(kinds: string[]): string[] {
  const familyOrder: Family[] = [
    "denial", "authoring", "network", "agent", "lifecycle", "read", "system",
  ];
  const byFamily = new Map<Family, string[]>();
  for (const f of familyOrder) byFamily.set(f, []);
  for (const k of kinds) byFamily.get(familyForKind(k))!.push(k);
  return familyOrder.flatMap((f) => byFamily.get(f) ?? []);
}

const VIEWBOX_WIDTH = 800;
const VIEWBOX_HEIGHT = 120;
const Y_AXIS_GUTTER_PX = 28;
const X_AXIS_GUTTER_PX = 14;
const PLOT_WIDTH = VIEWBOX_WIDTH - Y_AXIS_GUTTER_PX;
const PLOT_HEIGHT = VIEWBOX_HEIGHT - X_AXIS_GUTTER_PX;
const BAR_GAP_PX = 1;

/** Truthy-window helper — empty-string treated as "no edge set". */
function isWindowSet(w?: HistogramWindow): boolean {
  return Boolean(w && (w.since || w.until));
}

/**
 * Identify the active preset, if any, by comparing window edges to the
 * preset-derived edges (rounded to the nearest minute). Used for the
 * preset-button "active" visual state.
 */
function matchedPreset(active?: HistogramWindow): HistogramPresetKey | null {
  if (!active) return null;
  if (!active.since && !active.until) return "all";
  // We can't perfectly match a wall-clock preset to a URL-state since the
  // user may have refreshed minutes after picking it. Heuristic: if `until`
  // is within 5min of "now" and the window length is within 10% of the
  // preset duration, claim a match. Otherwise return null (custom window).
  if (!active.since || !active.until) return null;
  const now = Date.now();
  const since = Date.parse(active.since);
  const until = Date.parse(active.until);
  if (Number.isNaN(since) || Number.isNaN(until)) return null;
  if (Math.abs(until - now) > 5 * 60 * 1000) return null;
  const length = until - since;
  const candidates: Array<[HistogramPresetKey, number]> = [
    ["1h", 60 * 60 * 1000],
    ["6h", 6 * 60 * 60 * 1000],
    ["24h", 24 * 60 * 60 * 1000],
    ["7d", 7 * 24 * 60 * 60 * 1000],
  ];
  for (const [key, ms] of candidates) {
    if (Math.abs(length - ms) / ms < 0.1) return key;
  }
  return null;
}

export function Histogram({
  buckets,
  kinds,
  onWindowChange,
  onBrush,
  activeWindow,
  variant = "area",
}: Props): JSX.Element {
  // Deterministic stack order — see `stableKindOrder` rationale.
  const stackOrder = useMemo(() => stableKindOrder(kinds), [kinds]);

  // Client-side window clamp. The receipts API does not honor `until`
  // server-side as of the F004 ship; rendering only the in-window
  // buckets is honest about that and gives the auditor immediate
  // feedback regardless of backend support.
  const filteredBuckets = useMemo(() => {
    if (!isWindowSet(activeWindow)) return buckets;
    const since = activeWindow!.since ? Date.parse(activeWindow!.since) : -Infinity;
    const until = activeWindow!.until ? Date.parse(activeWindow!.until) : Infinity;
    return buckets.filter((b) => {
      // Dashboard.tsx truncates ISO ts to "YYYY-MM-DDTHH" for hour-precision
      // bucket keys. `Date.parse` is implementation-defined on truncated
      // timestamps (some engines return NaN, some succeed). Normalize to a
      // full minute-precision form before parsing so the clamp is portable.
      const normalized = normalizeBucketTs(b.ts);
      const t = Date.parse(normalized);
      if (Number.isNaN(t)) return true; // can't parse → don't drop
      return t >= since && t <= until;
    });
  }, [buckets, activeWindow]);

  // Brush state — non-null while the user is drag-selecting.
  type BrushState = { startIdx: number; endIdx: number };
  const [brush, setBrush] = useState<BrushState | null>(null);
  const svgRef = useRef<SVGSVGElement | null>(null);

  // Resolve a viewBox-X to a bucket index. Uses bounding-rect math so
  // CSS scaling doesn't desync. Falls back gracefully when rect.width is
  // 0 (JSDOM, hidden parent) — yields index 0 so single-click still
  // fires meaningfully.
  function bucketIndexFromClientX(clientX: number): number {
    if (filteredBuckets.length === 0 || !svgRef.current) return 0;
    const rect = svgRef.current.getBoundingClientRect();
    if (!rect.width || rect.width <= 0) return 0;
    const localPx = Math.max(0, clientX - rect.left);
    const plotXPx = (localPx / rect.width) * VIEWBOX_WIDTH - Y_AXIS_GUTTER_PX;
    const ratio = Math.max(0, Math.min(1, plotXPx / PLOT_WIDTH));
    const idx = Math.floor(ratio * filteredBuckets.length);
    if (Number.isNaN(idx)) return 0;
    return Math.min(filteredBuckets.length - 1, Math.max(0, idx));
  }

  function emitWindow(window: HistogramWindow): void {
    onWindowChange?.(window);
  }

  function onPresetClick(preset: HistogramPresetKey): void {
    emitWindow(presetToWindow(preset));
  }

  function onMouseDown(e: ReactMouseEvent<SVGSVGElement>): void {
    if (filteredBuckets.length === 0) return;
    const idx = bucketIndexFromClientX(e.clientX);
    setBrush({ startIdx: idx, endIdx: idx });
  }

  function onMouseMove(e: ReactMouseEvent<SVGSVGElement>): void {
    if (!brush) return;
    const idx = bucketIndexFromClientX(e.clientX);
    if (idx !== brush.endIdx) setBrush({ ...brush, endIdx: idx });
  }

  function onMouseUp(e: ReactMouseEvent<SVGSVGElement>): void {
    if (!brush) return;
    const idx = bucketIndexFromClientX(e.clientX);
    const lo = Math.min(brush.startIdx, idx);
    const hi = Math.min(filteredBuckets.length - 1, Math.max(brush.startIdx, idx));
    if (lo === hi) {
      // Treat as single-click → 1-bucket window. `until` set to the next
      // bucket's ts (or, if last, fall back to the legacy single-edge
      // behavior so the parent can compute its own end).
      const sinceTs = filteredBuckets[lo]?.ts ?? null;
      const untilTs = filteredBuckets[lo + 1]?.ts ?? null;
      if (sinceTs !== null && onWindowChange) {
        emitWindow({ since: sinceTs, until: untilTs });
      } else if (sinceTs !== null && onBrush) {
        onBrush(sinceTs);
      }
    } else {
      const sinceTs = filteredBuckets[lo]?.ts ?? null;
      // For the closing edge, use the bucket AFTER the last selected one
      // (so the selected range is inclusive of its rightmost bucket).
      const untilTs = filteredBuckets[hi + 1]?.ts ?? filteredBuckets[hi]?.ts ?? null;
      if (sinceTs !== null) emitWindow({ since: sinceTs, until: untilTs });
    }
    setBrush(null);
  }

  function onMouseLeave(): void {
    if (brush) setBrush(null);
  }

  function onClearWindow(): void {
    emitWindow({ since: null, until: null });
  }

  const activePreset = matchedPreset(activeWindow);
  const windowSet = isWindowSet(activeWindow);

  // Empty-state.
  if (filteredBuckets.length === 0) {
    return (
      <div
        className="rounded border border-r5e-border bg-r5e-surface p-2"
        data-testid="histogram-root"
      >
        <PresetRow
          activePreset={activePreset}
          onPick={onPresetClick}
          onClear={onClearWindow}
          windowSet={windowSet}
        />
        <div
          className="flex h-[120px] items-center justify-center text-xs text-r5e-muted"
          data-testid="histogram-empty"
        >
          No receipts in window
        </div>
      </div>
    );
  }

  const maxTotal = Math.max(
    ...filteredBuckets.map((b) =>
      Object.values(b.counts).reduce((acc, n) => acc + n, 0),
    ),
    1,
  );
  const barWidth = Math.max(
    1,
    PLOT_WIDTH / filteredBuckets.length - BAR_GAP_PX,
  );

  // Brush rect coords (only while dragging).
  const brushRect = brush
    ? (() => {
        const lo = Math.min(brush.startIdx, brush.endIdx);
        const hi = Math.max(brush.startIdx, brush.endIdx);
        const colW = PLOT_WIDTH / filteredBuckets.length;
        const x = Y_AXIS_GUTTER_PX + lo * colW;
        const w = (hi - lo + 1) * colW;
        return { x, w };
      })()
    : null;

  // X axis ticks: first / mid / last bucket ts (formatted compactly).
  const firstTs = filteredBuckets[0]?.ts ?? "";
  const lastTs = filteredBuckets[filteredBuckets.length - 1]?.ts ?? "";
  const midTs = filteredBuckets[Math.floor(filteredBuckets.length / 2)]?.ts ?? "";

  return (
    <div
      className="rounded border border-r5e-border bg-r5e-surface p-2"
      data-testid="histogram-root"
    >
      <PresetRow
        activePreset={activePreset}
        onPick={onPresetClick}
        onClear={onClearWindow}
        windowSet={windowSet}
      />
      {variant === "area" ? (
        <HistogramAreaChart
          buckets={filteredBuckets}
          stackOrder={stackOrder}
          width={VIEWBOX_WIDTH}
          height={VIEWBOX_HEIGHT}
          yGutter={Y_AXIS_GUTTER_PX}
          xGutter={X_AXIS_GUTTER_PX}
          onMouseDown={onMouseDown}
          onMouseMove={onMouseMove}
          onMouseUp={onMouseUp}
          onMouseLeave={onMouseLeave}
          brushRect={brushRect}
          svgRef={svgRef}
        />
      ) : (
        <svg
          ref={svgRef}
          viewBox={`0 0 ${VIEWBOX_WIDTH} ${VIEWBOX_HEIGHT}`}
          preserveAspectRatio="none"
          role="img"
          aria-label="Receipt volume over time"
          className="h-[120px] w-full select-none"
          style={{ cursor: brush ? "ew-resize" : "crosshair" }}
          onMouseDown={onMouseDown}
          onMouseMove={onMouseMove}
          onMouseUp={onMouseUp}
          onMouseLeave={onMouseLeave}
          data-testid="histogram-svg"
          data-chart-variant="bars"
        >
          {/* Y-axis gridlines (0 + max) and labels. */}
          <line
            x1={Y_AXIS_GUTTER_PX}
            x2={VIEWBOX_WIDTH}
            y1={PLOT_HEIGHT}
            y2={PLOT_HEIGHT}
            className="stroke-r5e-border"
            strokeWidth={1}
          />
          <line
            x1={Y_AXIS_GUTTER_PX}
            x2={VIEWBOX_WIDTH}
            y1={0}
            y2={0}
            className="stroke-r5e-border"
            strokeWidth={1}
            strokeDasharray="2 3"
          />
          <text
            x={Y_AXIS_GUTTER_PX - 4}
            y={PLOT_HEIGHT}
            className="fill-r5e-muted font-mono text-[9px]"
            textAnchor="end"
            dominantBaseline="middle"
            data-testid="histogram-y-axis-min"
          >
            0
          </text>
          <text
            x={Y_AXIS_GUTTER_PX - 4}
            y={4}
            className="fill-r5e-muted font-mono text-[9px]"
            textAnchor="end"
            dominantBaseline="hanging"
            data-testid="histogram-y-axis-max"
          >
            {maxTotal}
          </text>

          {/* Bars */}
          {filteredBuckets.map((bucket, idx) => {
            const x = Y_AXIS_GUTTER_PX + (PLOT_WIDTH / filteredBuckets.length) * idx;
            let yCursor = PLOT_HEIGHT;
            return (
              <g key={bucket.ts}>
                {stackOrder.map((kind) => {
                  const count = bucket.counts[kind] ?? 0;
                  if (count === 0) return null;
                  const h = (count / maxTotal) * PLOT_HEIGHT;
                  yCursor -= h;
                  return (
                    <rect
                      key={kind}
                      data-testid={`histogram-segment-${kind}`}
                      data-kind={kind}
                      data-family={familyForKind(kind)}
                      x={x}
                      y={yCursor}
                      width={barWidth}
                      height={h}
                      className={colorClassForKind(kind)}
                      opacity={0.95}
                    >
                      <title>{`${kind} • ${count} @ ${bucket.ts}`}</title>
                    </rect>
                  );
                })}
              </g>
            );
          })}

          {/* Brush selection overlay (only while dragging) */}
          {brushRect && (
            <rect
              data-testid="histogram-brush-overlay"
              x={brushRect.x}
              y={0}
              width={brushRect.w}
              height={PLOT_HEIGHT}
              className="fill-r5e-accent stroke-r5e-accent"
              fillOpacity={0.15}
              strokeWidth={1}
              pointerEvents="none"
            />
          )}

          {/* X-axis ticks: first / mid / last */}
          {firstTs && (
            <text
              x={Y_AXIS_GUTTER_PX}
              y={VIEWBOX_HEIGHT - 2}
              className="fill-r5e-muted font-mono text-[9px]"
              textAnchor="start"
              data-testid="histogram-x-axis-first"
            >
              {compactTs(firstTs)}
            </text>
          )}
          {midTs && filteredBuckets.length > 2 && (
            <text
              x={Y_AXIS_GUTTER_PX + PLOT_WIDTH / 2}
              y={VIEWBOX_HEIGHT - 2}
              className="fill-r5e-muted font-mono text-[9px]"
              textAnchor="middle"
              data-testid="histogram-x-axis-mid"
            >
              {compactTs(midTs)}
            </text>
          )}
          {lastTs && (
            <text
              x={VIEWBOX_WIDTH - 2}
              y={VIEWBOX_HEIGHT - 2}
              className="fill-r5e-muted font-mono text-[9px]"
              textAnchor="end"
              data-testid="histogram-x-axis-last"
            >
              {compactTs(lastTs)}
            </text>
          )}
        </svg>
      )}

      {/* X-axis ticks (always rendered alongside both variants — small
          row beneath the chart so labels don't overlap area-chart fills). */}
      {variant === "area" && filteredBuckets.length > 0 && (
        <div className="mt-1 flex items-center justify-between px-1 font-mono text-[9px] text-r5e-muted">
          <span data-testid="histogram-x-axis-first">{compactTs(firstTs)}</span>
          {filteredBuckets.length > 2 && (
            <span data-testid="histogram-x-axis-mid">{compactTs(midTs)}</span>
          )}
          <span data-testid="histogram-x-axis-last">{compactTs(lastTs)}</span>
        </div>
      )}

      {/* Legend — grouped by family so visually-related kinds cluster. */}
      <div className="mt-2 flex flex-wrap gap-x-3 gap-y-1 px-1">
        {stackOrder.map((kind) => (
          <span
            key={kind}
            data-testid={`histogram-legend-${kind}`}
            data-family={familyForKind(kind)}
            className="flex items-center gap-1 text-[10px] text-r5e-muted"
          >
            <span
              aria-hidden="true"
              className={`inline-block h-2 w-2 rounded-sm bg-current ${colorClassForKind(kind)}`}
            />
            {kind}
          </span>
        ))}
      </div>
    </div>
  );
}

/**
 * Normalize a bucket-ts to a full minute-precision ISO string so
 * `Date.parse` is portable. Dashboard.tsx feeds us "YYYY-MM-DDTHH"
 * (hour-precision); we extend it to "YYYY-MM-DDTHH:00:00Z". If the
 * input is already minute-or-finer precision, return it unchanged.
 */
export function normalizeBucketTs(ts: string): string {
  // Hour-only form: "YYYY-MM-DDTHH" → 13 chars and matches the regex.
  const hourOnly = /^\d{4}-\d{2}-\d{2}T\d{2}$/;
  if (hourOnly.test(ts)) return `${ts}:00:00Z`;
  // Already-canonical or full ISO — return as-is.
  return ts;
}

/** Truncate an ISO ts to "MM-DD HH" for the inline x-axis ticks. */
function compactTs(ts: string): string {
  // Accept the dashboard's hour-precision bucket key ("YYYY-MM-DDTHH")
  // and full ISO timestamps. Render as "MM-DD HH:00".
  const m = ts.match(/(\d{4})-(\d{2})-(\d{2})[T ]?(\d{2})?/);
  if (!m) return ts;
  const [, , mo, d, h] = m;
  return h ? `${mo}-${d} ${h}:00` : `${mo}-${d}`;
}

interface PresetRowProps {
  activePreset: HistogramPresetKey | null;
  onPick: (preset: HistogramPresetKey) => void;
  onClear: () => void;
  windowSet: boolean;
}

function PresetRow({ activePreset, onPick, onClear, windowSet }: PresetRowProps): JSX.Element {
  return (
    <div
      className="mb-1 flex flex-wrap items-center gap-1 px-1"
      data-testid="histogram-preset-row"
      role="toolbar"
      aria-label="Histogram time-window presets"
    >
      <span className="mr-1 text-[10px] uppercase tracking-wider text-r5e-muted">
        Window:
      </span>
      {HISTOGRAM_PRESET_KEYS.map((preset) => {
        const isActive = activePreset === preset;
        return (
          <button
            key={preset}
            type="button"
            data-testid={`histogram-preset-${preset}`}
            data-active={isActive ? "true" : "false"}
            onClick={() => onPick(preset)}
            aria-pressed={isActive}
            className={
              isActive
                ? "rounded border border-r5e-accent bg-r5e-accent/15 px-2 py-0.5 text-[10px] font-semibold text-r5e-accent"
                : "rounded border border-r5e-border bg-r5e-surface px-2 py-0.5 text-[10px] text-r5e-muted hover:border-r5e-muted hover:text-r5e-text"
            }
          >
            {PRESET_LABELS[preset]}
          </button>
        );
      })}
      {windowSet && (
        <button
          type="button"
          data-testid="histogram-window-clear"
          onClick={onClear}
          className="ml-1 rounded border border-r5e-border bg-r5e-surface px-2 py-0.5 text-[10px] text-r5e-muted hover:border-r5e-danger hover:text-r5e-danger"
          title="Clear time-window filter"
        >
          Clear
        </button>
      )}
      <span className="ml-auto text-[10px] text-r5e-muted">
        Drag across bars to zoom into a range
      </span>
    </div>
  );
}
