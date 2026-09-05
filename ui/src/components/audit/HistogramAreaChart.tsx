// HistogramAreaChart — R3 RECOMMENDED chart variant.
//
// Per the R3 frame in `design/r5e-enterprise-audit-ui.pen`:
//   "Layered Area Chart with Hover" (the green-bordered RECOMMENDED
//   alternative to the stacked bars). Reasons:
//     - Preserves the total volume shape (visible top contour) so
//       traffic spikes are obvious.
//     - Individual category visibility — each layer's outline is
//       legible against the stacked area below it.
//     - Hover events as overlay (tooltip with per-category counts at
//       the cursor's bucket).
//     - Visual continuity over time — area fills "connect" buckets so
//       the auditor reads a trend, not a series of discrete bars.
//
// This module is the rendering core. The outer `Histogram` component
// retains brush + preset row + legend + window controls; the chart
// surface is swapped from stacked bars to layered areas.
//
// Both variants share the same `colorClassForKind` palette + `family`
// stack ordering from `Histogram.tsx`, so swap is purely visual —
// no API change for callers.

import type * as React from "react";
import { useMemo, useState, type CSSProperties } from "react";
import {
  colorClassForKind,
  familyForKind,
  type HistogramBucket,
} from "~/components/audit/Histogram";

interface Props {
  buckets: HistogramBucket[];
  /** Stack order — rendered bottom-to-top. */
  stackOrder: string[];
  /** Plot dimensions in viewBox units. */
  width: number;
  height: number;
  /** Reserved for the y-axis labels. */
  yGutter: number;
  /** Reserved for the x-axis labels. */
  xGutter: number;
  /** Click handler — emits the bucket's ts when the auditor clicks an area. */
  onBucketClick?: (bucket: HistogramBucket, idx: number) => void;
  /** Mouse handlers used by the parent to drive brush selection. */
  onMouseDown?: (e: React.MouseEvent<SVGSVGElement>) => void;
  onMouseMove?: (e: React.MouseEvent<SVGSVGElement>) => void;
  onMouseUp?: (e: React.MouseEvent<SVGSVGElement>) => void;
  onMouseLeave?: () => void;
  /** Brush rectangle (rendered in viewBox coords). */
  brushRect?: { x: number; w: number } | null;
  /** Optional ref to the SVG so the parent can measure it for brush math. */
  svgRef?: React.RefObject<SVGSVGElement>;
}

/**
 * Catmull-Rom spline through `points`, emitted as a chain of cubic
 * Bezier segments — produces a smooth curve that passes through every
 * data point. Standard centripetal CR-to-Bezier formula:
 *
 *   for the segment P1 → P2 (with neighbors P0, P3):
 *     C1 = P1 + (P2 - P0) / 6
 *     C2 = P2 - (P3 - P1) / 6
 *
 * Endpoints duplicate the boundary point so the curve naturally
 * tangents at the edges. The brief at design/briefs/02-dashboard.md
 * explicitly calls for "smooth interpolation between time points
 * (d3-shape curves OR a simple Catmull-Rom; either works, no extra
 * dep needed)" — this is the latter, dependency-free.
 */
function smoothCurve(
  points: Array<[number, number]>,
  mode: "open" | "continue" = "open",
): string {
  const n = points.length;
  if (n === 0) return "";
  const at = (i: number): [number, number] =>
    points[Math.max(0, Math.min(n - 1, i))]!;
  const segs: string[] = [];
  const p0 = at(0);
  if (mode === "open") {
    segs.push(`M ${p0[0].toFixed(2)} ${p0[1].toFixed(2)}`);
  } else {
    // "continue" mode: line-join from the current pen position into the
    // first point of this curve so the caller can stitch two curves
    // into a single closed path without leaving an interior straight.
    segs.push(`L ${p0[0].toFixed(2)} ${p0[1].toFixed(2)}`);
  }
  if (n === 1) return segs.join(" ");
  for (let i = 0; i < n - 1; i++) {
    const pPrev = at(i - 1);
    const pCur = at(i);
    const pNext = at(i + 1);
    const pAfterNext = at(i + 2);
    const c1x = pCur[0] + (pNext[0] - pPrev[0]) / 6;
    const c1y = pCur[1] + (pNext[1] - pPrev[1]) / 6;
    const c2x = pNext[0] - (pAfterNext[0] - pCur[0]) / 6;
    const c2y = pNext[1] - (pAfterNext[1] - pCur[1]) / 6;
    segs.push(
      `C ${c1x.toFixed(2)} ${c1y.toFixed(2)}, ${c2x.toFixed(2)} ${c2y.toFixed(2)}, ${pNext[0].toFixed(2)} ${pNext[1].toFixed(2)}`,
    );
  }
  return segs.join(" ");
}

/**
 * Build an SVG `path d` for one stacked layer using Catmull-Rom curves
 * along both the top and bottom edges, closed into a smooth area shape.
 * `cumBelow[i]` = sum of all earlier-stack-order kinds at bucket i.
 *
 * Pre-fix this function emitted a polyline `points` string with
 * straight line segments — visibly jagged when adjacent buckets had
 * different counts. Live verification on audit-dev (May 2026) caught
 * the divergence from the .pen `comp/histogram` canonical (which the
 * R3 frame marks as PROPOSED B / RECOMMENDED).
 */
function layerPath(
  thisCounts: number[],
  cumBelow: number[],
  maxTotal: number,
  plotWidth: number,
  plotHeight: number,
  yGutter: number,
): string {
  const n = thisCounts.length;
  if (n === 0) return "";
  const xStep = plotWidth / Math.max(1, n - 1);
  const baseY = plotHeight;
  const topPts: Array<[number, number]> = [];
  const botPts: Array<[number, number]> = [];
  for (let i = 0; i < n; i++) {
    const total = (cumBelow[i] ?? 0) + (thisCounts[i] ?? 0);
    const x = yGutter + i * xStep;
    topPts.push([x, baseY - (total / maxTotal) * plotHeight]);
    botPts.push([x, baseY - ((cumBelow[i] ?? 0) / maxTotal) * plotHeight]);
  }
  // Stitch into one closed path: top forward (Catmull-Rom), then the
  // bottom traversed right-to-left in `continue` mode (line-joins from
  // the current pen position so we don't redraw an interior segment),
  // then Z. The `L` emitted by smoothCurve(continue) at the seam is the
  // "drop down at the right edge" — single straight from last-top to
  // last-bottom.
  const topPath = smoothCurve(topPts, "open");
  const botPath = smoothCurve([...botPts].reverse(), "continue");
  return `${topPath} ${botPath} Z`;
}

/**
 * Build an SVG `path d` for the `denied` overlay: a single smooth
 * stroke line over time. Per the .pen canonical, denied is rendered
 * as a 2px coral STROKE on top of the area stack — explicit visual
 * call-out distinct from the stacked categories. Returns "" when the
 * series is identically zero so the path doesn't render.
 */
function deniedStrokePath(
  deniedCounts: number[],
  maxTotal: number,
  plotWidth: number,
  plotHeight: number,
  yGutter: number,
): string {
  const n = deniedCounts.length;
  if (n === 0) return "";
  let any = false;
  for (let i = 0; i < n; i++) {
    if ((deniedCounts[i] ?? 0) > 0) {
      any = true;
      break;
    }
  }
  if (!any) return "";
  const xStep = plotWidth / Math.max(1, n - 1);
  const baseY = plotHeight;
  const pts: Array<[number, number]> = [];
  for (let i = 0; i < n; i++) {
    const x = yGutter + i * xStep;
    const y = baseY - ((deniedCounts[i] ?? 0) / maxTotal) * plotHeight;
    pts.push([x, y]);
  }
  return smoothCurve(pts);
}

/**
 * `denied` family detector — mirrors the same predicate
 * `Histogram.tsx::familyForKind` uses for the "denial" family. Kept
 * inline here so this module doesn't have to import the family enum.
 */
function isDeniedKind(kind: string): boolean {
  return (
    kind === "policy_denied" ||
    kind === "session_abort" ||
    kind === "egress_denied" ||
    kind.endsWith("_denied")
  );
}

interface HoverState {
  bucketIdx: number;
  clientX: number;
  clientY: number;
}

export function HistogramAreaChart({
  buckets,
  stackOrder,
  width,
  height,
  yGutter,
  xGutter,
  onBucketClick,
  onMouseDown,
  onMouseMove,
  onMouseUp,
  onMouseLeave,
  brushRect,
  svgRef,
}: Props): JSX.Element {
  const plotWidth = width - yGutter;
  const plotHeight = height - xGutter;
  const [hover, setHover] = useState<HoverState | null>(null);

  const { layers, maxTotal, deniedPath } = useMemo(() => {
    const n = buckets.length;
    const counts: Record<string, number[]> = {};
    for (const k of stackOrder) {
      const arr = new Array<number>(n).fill(0);
      for (let i = 0; i < n; i++) {
        const bucket = buckets[i];
        arr[i] = bucket?.counts[k] ?? 0;
      }
      counts[k] = arr;
    }
    let mx = 1;
    for (let i = 0; i < n; i++) {
      let total = 0;
      for (const k of stackOrder) total += counts[k]?.[i] ?? 0;
      if (total > mx) mx = total;
    }
    // Denied is rendered separately as a coral STROKE LINE on top, NOT
    // as a stacked area layer (per the .pen `comp/histogram` canonical).
    // Aggregate ALL denied-shaped kinds into a single series so e.g.
    // policy_denied + egress_denied + custom *_denied all contribute
    // to the same stroke.
    const deniedCounts = new Array<number>(n).fill(0);
    for (const k of stackOrder) {
      if (!isDeniedKind(k)) continue;
      const arr = counts[k] ?? [];
      for (let i = 0; i < n; i++) deniedCounts[i] = (deniedCounts[i] ?? 0) + (arr[i] ?? 0);
    }

    // Render bottom-to-top: cumBelow accumulates earlier non-denied layers.
    const cumBelow = new Array<number>(n).fill(0);
    const layerSpecs: Array<{ kind: string; pts: string }> = [];
    for (const k of stackOrder) {
      // Skip denied kinds in the stack — they're drawn as a separate
      // stroke overlay below. Including them here would double-count
      // their contribution AND make the canonical's "denied as a
      // distinct red line over the area stack" treatment impossible.
      if (isDeniedKind(k)) continue;
      const layerCounts = counts[k] ?? [];
      const pts = layerPath(
        layerCounts,
        cumBelow,
        mx,
        plotWidth,
        plotHeight,
        yGutter,
      );
      layerSpecs.push({ kind: k, pts });
      for (let i = 0; i < n; i++) cumBelow[i] = (cumBelow[i] ?? 0) + (layerCounts[i] ?? 0);
    }

    const deniedPath = deniedStrokePath(
      deniedCounts,
      mx,
      plotWidth,
      plotHeight,
      yGutter,
    );

    return { layers: layerSpecs, maxTotal: mx, deniedPath };
  }, [buckets, stackOrder, plotWidth, plotHeight, yGutter]);

  function bucketIndexAt(clientX: number): number {
    if (!svgRef?.current || buckets.length === 0) return 0;
    const rect = svgRef.current.getBoundingClientRect();
    if (rect.width <= 0) return 0;
    const localPx = Math.max(0, clientX - rect.left);
    const plotXPx = (localPx / rect.width) * width - yGutter;
    const xStep = plotWidth / Math.max(1, buckets.length - 1);
    if (xStep <= 0) return 0;
    const idx = Math.round(plotXPx / xStep);
    return Math.max(0, Math.min(buckets.length - 1, idx));
  }

  function handlePointerMove(e: React.MouseEvent<SVGSVGElement>): void {
    onMouseMove?.(e);
    if (buckets.length === 0) return;
    const idx = bucketIndexAt(e.clientX);
    setHover({ bucketIdx: idx, clientX: e.clientX, clientY: e.clientY });
  }

  function handlePointerLeave(): void {
    setHover(null);
    onMouseLeave?.();
  }

  function handleClick(e: React.MouseEvent<SVGSVGElement>): void {
    if (buckets.length === 0 || !onBucketClick) return;
    const idx = bucketIndexAt(e.clientX);
    const bucket = buckets[idx];
    if (bucket) onBucketClick(bucket, idx);
  }

  const hoverBucket = hover ? buckets[hover.bucketIdx] : null;
  const xStep = plotWidth / Math.max(1, buckets.length - 1);

  return (
    <div className="relative">
      <svg
        ref={svgRef}
        viewBox={`0 0 ${width} ${height}`}
        preserveAspectRatio="none"
        role="img"
        aria-label="Receipt volume over time (layered area)"
        className="h-[120px] w-full select-none"
        style={{ cursor: brushRect ? "ew-resize" : "crosshair" } as CSSProperties}
        onMouseDown={onMouseDown}
        onMouseMove={handlePointerMove}
        onMouseUp={onMouseUp}
        onMouseLeave={handlePointerLeave}
        onClick={handleClick}
        data-testid="histogram-svg"
        data-chart-variant="area"
      >
        {/* Y-axis grid — 0 + max gridlines */}
        <line
          x1={yGutter}
          x2={width}
          y1={plotHeight}
          y2={plotHeight}
          className="stroke-r5e-border"
          strokeWidth={1}
        />
        <line
          x1={yGutter}
          x2={width}
          y1={0}
          y2={0}
          className="stroke-r5e-border"
          strokeWidth={1}
          strokeDasharray="2 3"
        />
        <text
          x={yGutter - 4}
          y={plotHeight}
          className="fill-r5e-muted font-mono text-[9px]"
          textAnchor="end"
          dominantBaseline="middle"
          data-testid="histogram-y-axis-min"
        >
          0
        </text>
        <text
          x={yGutter - 4}
          y={4}
          className="fill-r5e-muted font-mono text-[9px]"
          textAnchor="end"
          dominantBaseline="hanging"
          data-testid="histogram-y-axis-max"
        >
          {maxTotal}
        </text>

        {/* Layered area fills (bottom-to-top), Catmull-Rom smoothed.
            18% fill alpha matches the .pen `comp/histogram` canonical
            (e.g. `#C084FC18` for llm_call) — subtle translucent texture
            so the layer below stays legible AND the visual is calm
            enough that the operator's eye doesn't get pulled into one
            spike. Per-layer stroke is intentionally OMITTED — earlier
            implementations added a 0.75px outline that turned the
            chart into a stack of bordered shapes; the canonical relies
            on color alone to separate layers. */}
        {layers.map(({ kind, pts }) =>
          pts ? (
            <path
              key={kind}
              data-testid={`histogram-segment-${kind}`}
              data-kind={kind}
              data-family={familyForKind(kind)}
              d={pts}
              className={colorClassForKind(kind)}
              fillOpacity={0.18}
              stroke="none"
            />
          ) : null,
        )}

        {/* Denied stroke-line overlay (coral, 2px). Sits on top of the
            area stack — explicit visual call-out for denials, distinct
            from the stacked categories. The .pen canonical treats this
            as the chart's hero signal: the rest of the layers are
            ambient texture; this line is the "look here" cue. */}
        {deniedPath && (
          <path
            data-testid="histogram-denied-stroke"
            d={deniedPath}
            className="fill-none stroke-r5e-chart-denied"
            strokeWidth={2}
            strokeLinejoin="round"
            strokeLinecap="round"
          />
        )}

        {/* Hover vertical guideline */}
        {hover && (
          <line
            data-testid="histogram-hover-guide"
            x1={yGutter + hover.bucketIdx * xStep}
            x2={yGutter + hover.bucketIdx * xStep}
            y1={0}
            y2={plotHeight}
            className="stroke-r5e-text"
            strokeWidth={0.75}
            strokeDasharray="3 2"
            opacity={0.5}
            pointerEvents="none"
          />
        )}

        {/* Brush rectangle */}
        {brushRect && (
          <rect
            data-testid="histogram-brush-overlay"
            x={brushRect.x}
            y={0}
            width={brushRect.w}
            height={plotHeight}
            className="fill-r5e-accent stroke-r5e-accent"
            fillOpacity={0.15}
            strokeWidth={1}
            pointerEvents="none"
          />
        )}
      </svg>

      {/* Tooltip — absolute positioned, follows cursor */}
      {hover && hoverBucket && (
        <HoverTooltip
          bucket={hoverBucket}
          stackOrder={stackOrder}
          x={hover.clientX}
          y={hover.clientY}
        />
      )}
    </div>
  );
}

interface TooltipProps {
  bucket: HistogramBucket;
  stackOrder: string[];
  x: number;
  y: number;
}

function HoverTooltip({ bucket, stackOrder, x, y }: TooltipProps): JSX.Element {
  // The tooltip is absolutely positioned in the document; we render it via
  // a fixed-position div so it overlays without contributing to layout.
  // Keep the tooltip narrow and right-aligned so it doesn't fall off the
  // right edge near the chart's tail.
  return (
    <div
      data-testid="histogram-hover-tooltip"
      className="pointer-events-none fixed z-50 rounded border border-r5e-border bg-r5e-bg/95 px-2 py-1.5 font-mono text-[10px] text-r5e-text shadow-lg"
      style={{
        top: y + 12,
        left: x + 12,
        minWidth: 140,
      }}
    >
      <div className="mb-1 text-[9px] uppercase tracking-wider text-r5e-muted">
        {bucket.ts}
      </div>
      <ul className="space-y-0.5">
        {stackOrder
          .filter((k) => (bucket.counts[k] ?? 0) > 0)
          .map((k) => (
            <li
              key={k}
              data-testid={`histogram-tooltip-${k}`}
              className="flex items-center justify-between gap-2"
            >
              <span className="flex items-center gap-1">
                <span
                  aria-hidden="true"
                  className={`inline-block h-2 w-2 rounded-sm bg-current ${colorClassForKind(k)}`}
                />
                <span className="text-r5e-muted">{k}</span>
              </span>
              <span className="font-semibold text-r5e-text">{bucket.counts[k]}</span>
            </li>
          ))}
      </ul>
    </div>
  );
}
