// TimelinePage — F10 Investigation Timeline (NEW surface).
//
// Per `design/briefs/10-session-trace.md`:
//   `/admin/timeline` — distributed-tracing-for-agents. A SEPARATE surface
//   from the Audit Log (R1), accessed via drill-down from rows or directly
//   via URL params.
//
// The Timeline answers "tell me the story of what THIS principal/session/
// workstream did, in order, with policy decisions woven in" (Datadog APM
// shape) — vs R1's "show me all rows matching X across time" (SIEM shape).
//
// URL is the source of truth — every scope element is a query param so the
// page is shareable + bookmarkable:
//
//   /admin/timeline?principal=llm-agent-01
//   /admin/timeline?session_id=231b...
//   /admin/timeline?correlation_id=abc-...   (workstream-as-correlation)
//   /admin/timeline?run_id=<id>              (opens with that event selected)
//   /admin/timeline?since=...&until=...      (time-window override)
//
// ## Backend wire (demo target)
//
// The brief specifies dedicated endpoints `/v1/audit/timeline` and
// `/v1/audit/receipts/<run_id>/related` but acknowledges the implementation
// can adapt the existing `/v1/audit/receipts` payload. For the demo target
// this page derives lanes + density + related events client-side from the
// receipts list. Backend follow-up to add proper endpoints is filed in the
// MR description as a legitimate scope deferral.

import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { Activity } from "lucide-react";
import { Outlet, useOutlet, useSearchParams } from "react-router-dom";

import { EmptyState, ErrorState, Skeleton } from "~/components/shared/states";
import { TopBar } from "~/components/shared/TopBar";
import { DensityStrip } from "~/components/timeline/DensityStrip";
import { EventInspector } from "~/components/timeline/EventInspector";
import { ScopeChips } from "~/components/timeline/ScopeChips";
import { TraceLanes } from "~/components/timeline/TraceLanes";
import { useReceipts } from "~/hooks/useReceipts";
import { useReceiptDetail } from "~/hooks/useReceiptDetail";
import {
  densityFromEvents,
  eventFromRow,
  filterByScope,
  lanesFromEvents,
  relatedEventsFromEvents,
  timeWindowToMs,
  TIME_WINDOWS,
  type ActiveScope,
  type RelatedEvent,
  type TimeWindowKey,
  type TimelineEvent,
} from "~/lib/timeline";

const DEFAULT_WINDOW_KEY: TimeWindowKey = "24h";
/** Fallback canvas width before the ResizeObserver reports a real one
 *  (first paint, JSDOM tests, browsers without ResizeObserver). */
const FALLBACK_CANVAS_WIDTH_PX = 800;
/** Lower bound for the lanes canvas — narrower than this and the parent
 *  `overflow-x-auto` container scrolls horizontally instead of squishing
 *  dots together. Tuned so the 5-tick 1h tickInterval still has room to
 *  breathe at the narrowest sensible viewport. */
const MIN_CANVAS_WIDTH_PX = 360;
/** F005: NaN-safe URL → instant parse. `Date.parse` returns NaN for
 *  garbage input ("not-a-date") AND NaN !== null, so the prior asymmetric
 *  guard for `since` (`sinceMs !== null`) let NaN slip through and
 *  `new Date(NaN).toISOString()` blew up the page. This helper returns
 *  `null` for both missing input and unparseable input so all callers
 *  can use the same guard. */
function parseUrlInstant(s: string | null): number | null {
  if (!s) return null;
  const ms = Date.parse(s);
  return Number.isFinite(ms) ? ms : null;
}

/** F002: maximum number of pages we'll drain client-side when deriving
 *  lanes/density/related-events from `/v1/audit/receipts`. The default
 *  page size is 100, so 50 = up to 5,000 receipts per investigation
 *  scope before we surface a "truncated — narrow your scope" banner.
 *  Backend follow-up to add the dedicated `/v1/audit/timeline` endpoint
 *  (see brief 10-session-trace.md:191-...) lifts this ceiling entirely. */
const TIMELINE_PAGE_DRAIN_CEILING = 50;
/** Tailwind 2xl breakpoint in px — gates the always-visible inspector
 *  per brief 10-session-trace.md:123. Below this we render the
 *  inspector as a slide-over panel triggered by event selection so the
 *  lanes canvas isn't crushed when a 720px ReceiptDetail drawer is also
 *  mounted (worst case sidebar 220 + lanes + inspector 360 + drawer 720
 *  on a 1366px laptop = ~66px lanes). */
const INSPECTOR_ALWAYS_VISIBLE_BREAKPOINT_PX = 1440;

export default function TimelinePage(): JSX.Element {
  const [searchParams, setSearchParams] = useSearchParams();
  const outlet = useOutlet();

  // ---- URL → scope --------------------------------------------------------
  const principal = searchParams.get("principal");
  const sessionId = searchParams.get("session_id");
  const correlationId = searchParams.get("correlation_id");
  const runIdParam = searchParams.get("run_id");
  const sinceParam = searchParams.get("since");
  const untilParam = searchParams.get("until");
  const windowKeyParam = searchParams.get("window") as TimeWindowKey | null;
  const hasAnyScope =
    principal !== null ||
    sessionId !== null ||
    correlationId !== null ||
    runIdParam !== null;

  // Effective time window. If `since`/`until` set explicitly we honor them
  // and report the chosen window key as null (Custom). Otherwise we pick
  // the keyed window (default 24h) and compute since/until from "now".
  const windowKey: TimeWindowKey =
    windowKeyParam && TIME_WINDOWS.some((w) => w.key === windowKeyParam)
      ? windowKeyParam
      : DEFAULT_WINDOW_KEY;
  const windowMs = timeWindowToMs(windowKey);

  // Now-ish for the demo: anchored to wall clock so the window scrolls
  // when real data is wired up. F002 — when the receipts payload is
  // entirely older than the wall clock (dev-mocks corpus, or a quiet
  // production tenant) we anchor effective "now" to corpus-max so the
  // demo deep links don't return empty by default.
  const wallClockNowMs = useMemo(() => Date.now(), []);

  // ---- Receipts query (broad — we filter client-side per scope) -----------
  // F002: when no explicit since/until in URL, fetch BROAD (no since
  // filter) so we can derive the effective window from the data range.
  // The brief lists `/v1/audit/receipts` as the demo backend; the
  // gateway already paginates so an unbounded fetch is bounded by
  // page-size at the wire.
  const filterForFetch = useMemo(() => {
    const f: { since?: string; until?: string; principal_subject?: string } = {};
    if (sinceParam) f.since = sinceParam;
    if (untilParam) f.until = untilParam;
    return f;
  }, [sinceParam, untilParam]);

  const {
    data,
    isLoading,
    isError,
    refetch,
    fetchNextPage,
    hasNextPage,
    isFetchingNextPage,
  } = useReceipts(filterForFetch);

  // F002: drain ALL pages for the active scope before deriving lanes /
  // density / related-events. The Investigation Timeline IS an
  // investigation tool — derived shapes computed from a partial first
  // page would silently misrepresent "what was the agent doing right
  // before/after this" (see brief 10-session-trace.md:135-142). We cap
  // the drain at TIMELINE_PAGE_DRAIN_CEILING to avoid pathological
  // multi-thousand-page fetches if a tenant's window happens to span an
  // unusually busy period; the surface degrades gracefully via a
  // truncation banner if the cap fires.
  useEffect(() => {
    if (hasNextPage && !isFetchingNextPage) {
      const loadedPages = data?.pages.length ?? 0;
      if (loadedPages < TIMELINE_PAGE_DRAIN_CEILING) {
        void fetchNextPage();
      }
    }
  }, [hasNextPage, isFetchingNextPage, data?.pages.length, fetchNextPage]);

  const allRows = useMemo(
    () => data?.pages.flatMap((p) => p.receipts) ?? [],
    [data],
  );

  const drainTruncated =
    Boolean(hasNextPage) &&
    (data?.pages.length ?? 0) >= TIMELINE_PAGE_DRAIN_CEILING;

  // F005: when ?run_id= deep-links to a receipt OUTSIDE the current
  // window (e.g., R2 drawer "View in timeline" for a 30-day-old
  // receipt), the broad receipts list won't contain it. Fall back to
  // the dedicated GET /v1/audit/receipts/:run_id and re-center the
  // window around its timestamp.
  const targetedDetail = useReceiptDetail(
    runIdParam && !allRows.some((r) => r.run_id === runIdParam)
      ? runIdParam
      : undefined,
  );
  const targetedTimestampMs = useMemo(
    () => parseUrlInstant(targetedDetail.data?.signed_predicate?.timestamp ?? null),
    [targetedDetail.data],
  );

  // F002: derive an effective "now" for the timeline. Order of precedence:
  //   1. explicit ?until=  →  honor it
  //   2. wall clock if it's inside the data range (production with
  //      live data)
  //   3. corpus-max timestamp from allRows (dev-mocks demo, or a quiet
  //      tenant whose most-recent receipt is older than 24h)
  //   4. wall clock if there are no rows yet (loading / empty)
  // F005: if a targeted out-of-window receipt is loaded, use its ts as
  // the anchor instead.
  const corpusMinMs = useMemo(() => {
    if (allRows.length === 0) return null;
    let min = Number.POSITIVE_INFINITY;
    for (const r of allRows) {
      const ms = parseUrlInstant(r.signed_predicate.timestamp ?? null);
      if (ms === null) continue;
      if (ms < min) min = ms;
    }
    return Number.isFinite(min) ? min : null;
  }, [allRows]);
  const corpusMaxMs = useMemo(() => {
    if (allRows.length === 0) return null;
    let max = Number.NEGATIVE_INFINITY;
    for (const r of allRows) {
      const ms = parseUrlInstant(r.signed_predicate.timestamp ?? null);
      if (ms === null) continue;
      if (ms > max) max = ms;
    }
    return Number.isFinite(max) ? max : null;
  }, [allRows]);

  // F006: track whether the time window is anchored to the corpus extent
  // (rather than wall-clock now) so the chip can read e.g. "Last 24h
  // (anchored to data)" instead of silently lying to the auditor about
  // what window the chart represents.
  const corpusAnchored =
    !untilParam &&
    targetedTimestampMs === null &&
    corpusMaxMs !== null &&
    corpusMaxMs < wallClockNowMs;

  const effectiveNowMs = useMemo(() => {
    const untilMs = parseUrlInstant(untilParam);
    if (untilMs !== null) return untilMs;
    if (targetedTimestampMs !== null) return targetedTimestampMs;
    if (corpusMaxMs !== null && corpusMaxMs < wallClockNowMs) {
      return corpusMaxMs;
    }
    return wallClockNowMs;
  }, [untilParam, targetedTimestampMs, corpusMaxMs, wallClockNowMs]);

  const parsedSinceMs = parseUrlInstant(sinceParam);
  const parsedUntilMs = parseUrlInstant(untilParam);

  const sinceMs =
    parsedSinceMs !== null
      ? parsedSinceMs
      : windowMs !== null
        ? effectiveNowMs - windowMs
        : null;
  const untilMs = parsedUntilMs !== null ? parsedUntilMs : effectiveNowMs;

  // ---- Scope filter (driven by URL chips) ---------------------------------
  const sinceIso = sinceMs !== null ? new Date(sinceMs).toISOString() : null;
  const untilIso =
    untilMs !== null && Number.isFinite(untilMs)
      ? new Date(untilMs).toISOString()
      : null;
  const scopedRows = useMemo(
    () =>
      filterByScope(allRows, {
        principal,
        session_id: sessionId,
        correlation_id: correlationId,
        since: sinceIso,
        until: untilIso,
      }),
    [allRows, principal, sessionId, correlationId, sinceIso, untilIso],
  );

  // F008: project rows to TimelineEvents ONCE so lanes / density /
  // related-events / selectedEvent don't each re-walk eventFromRow per
  // row. eventFromRow is pure but called from three derived
  // selectors today; on a click that flips selectedRunId the related
  // walk hits allRows again. Materializing once at the parent collapses
  // those walks into one O(n) pass keyed on TanStack Query's stable
  // `data` reference. We project both the full corpus (for related
  // events + selection lookup) and the scoped subset (for lanes +
  // density) so each consumer reads from a memoized array.
  const allEvents = useMemo(
    () =>
      allRows
        .map((r) => eventFromRow(r))
        .filter((e): e is TimelineEvent => e !== null),
    [allRows],
  );
  const scopedEvents = useMemo(
    () =>
      scopedRows
        .map((r) => eventFromRow(r))
        .filter((e): e is TimelineEvent => e !== null),
    [scopedRows],
  );

  const topPrincipalSuggestions = useMemo(
    () =>
      lanesFromEvents(allEvents).slice(0, 3).map((lane) => ({
        label: lane.principal_label,
        subject: lane.principal_subject,
      })),
    [allEvents],
  );

  const lanes = useMemo(() => lanesFromEvents(scopedEvents), [scopedEvents]);
  const density = useMemo(
    () => densityFromEvents(scopedEvents),
    [scopedEvents],
  );

  // ---- Selection state ---------------------------------------------------
  // Init from `?run_id=` if present.
  const [selectedRunId, setSelectedRunId] = useState<string | null>(runIdParam);

  // Keep state in sync if the URL `run_id` changes (back/forward, deep
  // link). The user's most-recent click wins; we only consume the URL
  // value when the URL changes.
  useEffect(() => {
    setSelectedRunId(runIdParam);
  }, [runIdParam]);

  const defaultSelectedEvent = useMemo(() => {
    const candidates = hasAnyScope ? scopedEvents : allEvents;
    let latest: TimelineEvent | null = null;
    for (const ev of candidates) {
      if (!latest || ev.ts_ms > latest.ts_ms) latest = ev;
    }
    return latest;
  }, [allEvents, hasAnyScope, scopedEvents]);

  const selectedEvent: TimelineEvent | null = useMemo(() => {
    if (!selectedRunId) return defaultSelectedEvent;
    const ev = allEvents.find((e) => e.run_id === selectedRunId);
    if (ev) return ev;
    // F005: fall back to the targeted detail so EventInspector
    // populates even when the receipt is outside the visible lanes.
    if (
      targetedDetail.data &&
      targetedDetail.data.run_id === selectedRunId
    ) {
      // useReceiptDetail returns a richer shape; coerce to ReceiptRow
      // for eventFromRow which only reads signed_predicate +
      // outer_container. The shapes overlap on those keys.
      return eventFromRow(
        targetedDetail.data as unknown as Parameters<typeof eventFromRow>[0],
      );
    }
    return null;
  }, [allEvents, defaultSelectedEvent, selectedRunId, targetedDetail.data]);

  const related: RelatedEvent[] = useMemo(() => {
    if (!selectedEvent) return [];
    return relatedEventsFromEvents(allEvents, selectedEvent.run_id);
  }, [allEvents, selectedEvent]);

  function selectEvent(runId: string): void {
    setSelectedRunId(runId);
    setSearchParams(
      (prev) => {
        const next = new URLSearchParams(prev);
        next.set("run_id", runId);
        return next;
      },
      { replace: true },
    );
  }

  function clearScopeKey(key: string): void {
    setSearchParams(
      (prev) => {
        const next = new URLSearchParams(prev);
        next.delete(key);
        return next;
      },
      { replace: false },
    );
  }

  function setWindow(key: TimeWindowKey): void {
    setSearchParams(
      (prev) => {
        const next = new URLSearchParams(prev);
        next.set("window", key);
        // Drop explicit since/until so the keyed window takes over.
        next.delete("since");
        next.delete("until");
        return next;
      },
      { replace: false },
    );
  }

  // ---- Active scope summary -----------------------------------------------
  // F006: when the time window is anchored to corpus-max instead of wall-
  // clock now (because the data is older than 24h — quiet tenants or the
  // dev-mocks corpus), the pill must say so. Otherwise the auditor sees
  // "Last 24h" while looking at data days old. The pill becomes:
  //
  //   "Last 24h (anchored to data)" — when the keyed window is anchored
  //   "Custom" — when ?since/?until are explicit
  //   "Last 24h" — when wall-clock now is inside the data range
  const baseWindowLabel =
    TIME_WINDOWS.find((w) => w.key === windowKey)?.label ?? "Last 24h";
  const timeWindowLabel =
    sinceParam || untilParam
      ? "Custom"
      : corpusAnchored
        ? `${baseWindowLabel} (anchored to data)`
        : baseWindowLabel;

  const activeScope: ActiveScope = {
    principal,
    session_id: sessionId,
    correlation_id: correlationId,
    run_id: runIdParam,
    since: sinceIso,
    until: untilIso,
    time_window_label: timeWindowLabel,
  };

  // ---- Lane canvas axis bounds -------------------------------------------
  // F006: 'All' window should fit every receipt on the time axis.
  // When `windowMs===null` (key === 'all'), set startMs = min over
  // allRows timestamps, endMs = max. Otherwise keep the keyed-window
  // math so the axis stays anchored to the picked window.
  const startMs =
    windowMs === null && corpusMinMs !== null
      ? corpusMinMs
      : (sinceMs ?? effectiveNowMs - 24 * 60 * 60 * 1000);
  const endMs =
    windowMs === null && corpusMaxMs !== null
      ? corpusMaxMs
      : untilMs !== null && Number.isFinite(untilMs)
        ? untilMs
        : effectiveNowMs;

  // ---- Shared canvas width (F001) ----------------------------------------
  // Both DensityStrip and TraceLanes project timestamps onto the same
  // x-axis. If their widths drift apart, the density bins stop aligning
  // with the lane events directly below them. We measure the lanes
  // section once via ResizeObserver and pass the same width to both.
  const lanesSectionRef = useRef<HTMLDivElement | null>(null);
  const [measuredCanvasWidth, setMeasuredCanvasWidth] = useState<number>(
    FALLBACK_CANVAS_WIDTH_PX,
  );

  useLayoutEffect(() => {
    const node = lanesSectionRef.current;
    if (!node) return;
    // The ref is on `<main>`. Its OUTER width includes the px-4
    // padding (32px). The canvas portion sits inside:
    //   <main px-4 py-4>            (-32 horizontal padding)
    //     <section>                  (no padding of its own)
    //       <div overflow-x-auto px-3 py-2>  (-24 horizontal padding)
    //         <TraceLanes>           (label col + canvas)
    //         label col = 188px (w-44 = 176 + gap-3 = 12)
    //
    // So canvas budget = main.outerWidth - 32 - 24 - 188.
    // We use `clientWidth` on the ref (excludes scrollbar but
    // includes padding) for the initial measurement; ResizeObserver
    // reports `contentRect.width` which is the content-box width
    // (already excludes padding), so we adapt the math per branch.
    const MAIN_PADDING_PX = 32;
    const SCROLL_PADDING_PX = 24;
    const LABEL_COL_PX = 176 + 12;
    const FIXED_OVERHEAD = SCROLL_PADDING_PX + LABEL_COL_PX;
    const recomputeFromOuter = (outerWidth: number): void => {
      const next = Math.max(
        MIN_CANVAS_WIDTH_PX,
        outerWidth - MAIN_PADDING_PX - FIXED_OVERHEAD,
      );
      setMeasuredCanvasWidth(next);
    };
    const recomputeFromContent = (contentWidth: number): void => {
      // contentRect.width already excludes <main>'s padding.
      const next = Math.max(MIN_CANVAS_WIDTH_PX, contentWidth - FIXED_OVERHEAD);
      setMeasuredCanvasWidth(next);
    };
    recomputeFromOuter(node.getBoundingClientRect().width);
    if (typeof ResizeObserver === "undefined") return;
    const ro = new ResizeObserver((entries) => {
      for (const e of entries) {
        recomputeFromContent(e.contentRect.width);
      }
    });
    ro.observe(node);
    return () => ro.disconnect();
  }, []);

  // F004: click-to-pin time marker. The brief mandates that the time
  // axis support a pinned selection-time marker in addition to the
  // hover guideline. We stash the clicked x-coord here; TraceLanes
  // renders a sticky vertical bar at that x.
  const [pinnedX, setPinnedX] = useState<number | null>(null);
  const onPinX = useCallback(
    (x: number | null) => setPinnedX(x),
    [],
  );

  // F003: responsive inspector. Brief 10-session-trace.md:123 — "the
  // right panel slides in on click OR is always-visible at width
  // ≥1440px". Below that breakpoint the inspector renders as a
  // slide-over panel triggered by event selection (so a 1366px laptop
  // with sidebar 220 + lanes + inspector 360 + drawer 720 doesn't crush
  // the lanes canvas to ~66px). Track viewport width via a single
  // matchMedia listener, falling back to always-visible if matchMedia
  // is unavailable (JSDOM, very old browsers).
  const [isWideViewport, setIsWideViewport] = useState<boolean>(() => {
    if (typeof window === "undefined" || typeof window.matchMedia !== "function") {
      return true;
    }
    return window.matchMedia(
      `(min-width: ${INSPECTOR_ALWAYS_VISIBLE_BREAKPOINT_PX}px)`,
    ).matches;
  });
  useEffect(() => {
    if (typeof window === "undefined" || typeof window.matchMedia !== "function") {
      return;
    }
    const mq = window.matchMedia(
      `(min-width: ${INSPECTOR_ALWAYS_VISIBLE_BREAKPOINT_PX}px)`,
    );
    const onChange = (): void => setIsWideViewport(mq.matches);
    onChange();
    if (typeof mq.addEventListener === "function") {
      mq.addEventListener("change", onChange);
      return () => mq.removeEventListener("change", onChange);
    }
    // Safari < 14 fallback.
    mq.addListener(onChange);
    return () => mq.removeListener(onChange);
  }, []);

  // Below the breakpoint the inspector is a slide-over: only mount when
  // an event is actively selected. Above, it's always visible (the
  // brief's "always-visible" clause).
  const showInspectorPanel = isWideViewport || selectedRunId !== null;
  // When the receipt-detail nested drawer is mounted on a narrow
  // viewport, hide the inspector so the lanes canvas isn't crushed.
  const inspectorVisible = showInspectorPanel && !(outlet && !isWideViewport);
  const closeInspectorOverlay = (): void => {
    setSelectedRunId(null);
    setSearchParams(
      (prev) => {
        const next = new URLSearchParams(prev);
        next.delete("run_id");
        return next;
      },
      { replace: false },
    );
  };

  // ---------------------------------------------------------------------
  // Render
  // ---------------------------------------------------------------------
  return (
    <div className="flex min-h-0 flex-1 flex-col bg-r5e-bg font-sans text-r5e-text">
      <TopBar
        pageContent={
          <span className="flex items-center gap-2 text-sm font-semibold text-r5e-text">
            <Activity className="h-4 w-4" aria-hidden="true" />
            Investigation Timeline
            <span className="rounded border border-r5e-accent/40 bg-r5e-accent/10 px-1.5 py-0.5 text-[10px] font-mono uppercase tracking-wider text-r5e-accent">
              V2
            </span>
          </span>
        }
      />

      <ScopeChips
        scope={activeScope}
        windowKey={
          sinceParam || untilParam ? null : windowKey
        }
        onDismissPrincipal={() => clearScopeKey("principal")}
        onDismissSession={() => clearScopeKey("session_id")}
        onDismissCorrelation={() => clearScopeKey("correlation_id")}
        onDismissRunId={() => {
          setSelectedRunId(null);
          clearScopeKey("run_id");
        }}
        onWindowChange={setWindow}
      />

      <div className="relative flex min-h-0 flex-1 overflow-hidden">
        {/* Main pane: density strip + swim lanes */}
        <main
          ref={lanesSectionRef}
          className="flex flex-1 flex-col overflow-y-auto px-4 py-4"
        >
          {/* Density */}
          {isLoading ? (
            <div data-testid="timeline-loading-density" className="mb-4">
              <Skeleton.Histogram heightClass="h-[60px]" bars={24} />
            </div>
          ) : !hasAnyScope ? (
            // F004: hide the density strip entirely when no scope is set —
            // the empty-state below is the surface, not a near-empty
            // density bar above an instructive message.
            null
          ) : (
            <div
              className="mb-4"
              // F001: density and lanes share the SAME measured canvas
              // width so their x-axes can't drift apart. The density
              // strip has no label column, so we left-pad it by the
              // lane label-column width (176 + 12 = 188px) to align
              // the bins under the lane events. The strip's body fills
              // the remainder.
              style={{ paddingLeft: `${176 + 12}px` }}
            >
              <DensityStrip buckets={density} width={measuredCanvasWidth} />
            </div>
          )}

          {/* Swim lanes */}
          {isLoading && (
            <div data-testid="timeline-loading-lanes" className="flex flex-col gap-2">
              <Skeleton.Block className="h-9 w-full" />
              <Skeleton.Block className="h-9 w-full" />
              <Skeleton.Block className="h-9 w-full" />
              <Skeleton.Block className="h-9 w-full" />
            </div>
          )}
          {isError && (
            <ErrorState
              title="Couldn't load Timeline"
              body="The audit plane returned an error fetching the receipts that back this view."
              retry={{ onClick: () => void refetch() }}
            />
          )}
          {/* F004: empty state when NO scope is set (regardless of
              whether receipts are loaded) — the brief specifies an
              instructive prompt with example chips so the surface
              reads as a scoped investigation tool, not an alternate
              Audit Log. Falls through to the "no events match this
              scope" variant when scope IS set and lanes are empty. */}
          {!isLoading && !isError && (!hasAnyScope || lanes.length === 0) && (
            <TimelineEmptyState
              hasScope={hasAnyScope}
              suggestions={topPrincipalSuggestions}
              onPickPrincipal={(p) => {
                setSearchParams(
                  (prev) => {
                    const next = new URLSearchParams(prev);
                    next.set("principal", p);
                    return next;
                  },
                  { replace: false },
                );
              }}
            />
          )}
          {/* F002: truncation banner — fires only when the drain
              ceiling capped the fetch and there are still more pages on
              the wire. The investigation surface IS an investigation
              tool, so we surface the partial-data state explicitly
              rather than silently rendering an incomplete story. */}
          {!isLoading && !isError && drainTruncated && hasAnyScope && (
            <div
              data-testid="timeline-truncation-banner"
              className="mb-3 rounded border border-r5e-warning/40 bg-r5e-warning/10 px-3 py-2 text-[11px] text-r5e-warning"
            >
              Showing the first {TIMELINE_PAGE_DRAIN_CEILING * 100} receipts in
              this scope. Narrow your scope (principal, session, or
              workstream) for a complete view.
            </div>
          )}
          {!isLoading && !isError && hasAnyScope && lanes.length > 0 && (
            <section
              data-testid="timeline-lanes-section"
              className="rounded border border-r5e-border bg-r5e-surface/40"
            >
              <div className="border-b border-r5e-border px-3 py-2">
                <span className="text-[10px] font-mono uppercase tracking-wider text-r5e-muted">
                  Event traces · {lanes.length} principal{lanes.length === 1 ? "" : "s"}
                </span>
              </div>
              {/* F001: overflow-x-auto safety net — when the parent
                  is narrower than MIN_CANVAS_WIDTH_PX + the label
                  column, the canvas scrolls horizontally rather than
                  squishing dots into illegible clusters. */}
              <div className="overflow-x-auto px-3 py-2">
                <TraceLanes
                  lanes={lanes}
                  startMs={startMs}
                  endMs={endMs}
                  canvasWidth={measuredCanvasWidth}
                  selectedRunId={selectedRunId}
                  onSelect={selectEvent}
                  pinnedX={pinnedX}
                  onPinX={onPinX}
                />
              </div>
            </section>
          )}
        </main>

        {/* F003: responsive inspector. Always-visible side-by-side at
            ≥1440px. Below the breakpoint it renders as a slide-over
            with a backdrop, triggered when an event is selected. */}
        {inspectorVisible &&
          (isWideViewport ? (
            <aside
              data-testid="event-inspector-aside"
              className="w-[360px] shrink-0 border-l border-r5e-border bg-r5e-surface"
            >
              <EventInspector
                selected={selectedEvent}
                related={related}
                onSelectRelated={selectEvent}
              />
            </aside>
          ) : (
            <div
              data-testid="event-inspector-overlay"
              className="absolute inset-0 z-40 flex justify-end"
              role="dialog"
              aria-modal="true"
              aria-label="Event inspector"
            >
              <button
                type="button"
                data-testid="event-inspector-overlay-backdrop"
                aria-label="Close inspector"
                onClick={closeInspectorOverlay}
                className="absolute inset-0 bg-black/40"
              />
              <aside className="relative h-full w-[min(360px,calc(100vw-2rem))] border-l border-r5e-border bg-r5e-surface shadow-2xl">
                <EventInspector
                  selected={selectedEvent}
                  related={related}
                  onSelectRelated={selectEvent}
                />
              </aside>
            </div>
          ))}

        {/* F008: nested route slot — when the URL is
            /admin/timeline/receipts/:run_id, the ReceiptDetail drawer
            mounts here OVER the timeline (rather than routing back to
            /admin/dashboard and losing the investigation context).
            F003: at <1440px the drawer becomes a slide-over (full-
            width on the right) so it doesn't fight the lanes canvas
            for space. */}
        {outlet &&
          (isWideViewport ? (
            <aside
              data-testid="timeline-receipt-drawer"
              className="w-[720px] shrink-0 border-l border-r5e-border bg-r5e-surface"
            >
              <Outlet />
            </aside>
          ) : (
            <aside
              data-testid="timeline-receipt-drawer"
              className="absolute inset-y-0 right-0 z-50 w-[min(720px,100vw)] border-l border-r5e-border bg-r5e-surface shadow-2xl"
            >
              <Outlet />
            </aside>
          ))}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// TimelineEmptyState — instructive empty + pre-canned scope chips.
//
// F009: built on the shared <EmptyState /> primitive (Constitution
// Principle VII — extended on the Timeline as the second consumer
// rather than recreated). The pre-canned chip cluster goes through
// EmptyState's `children` slot.
//
// F011: chip subjects are CANONICAL — the strings `displayPrincipal()`
// would return for a backend-shaped principal. obo_human principals
// expose `subject` (e.g., `operator@example.com`); autonomous principals
// expose `spiffe_id` only (per identity_context_builder.ex:215), so
// the canonical form is `spiffe://r5e/agents/<id>`. The dev-mocks
// corpus carries both keys for autonomous principals so the same
// chip URL works in both worlds.
// ---------------------------------------------------------------------------

function TimelineEmptyState({
  hasScope,
  suggestions,
  onPickPrincipal,
}: {
  hasScope: boolean;
  suggestions: ReadonlyArray<{ label: string; subject: string }>;
  onPickPrincipal: (subject: string) => void;
}): JSX.Element {
  return (
    <EmptyState
      testId="timeline-empty"
      icon={<Activity className="h-10 w-10" aria-hidden="true" />}
      title={
        hasScope
          ? "No events match this scope"
          : "Choose a principal, session, or workstream to investigate"
      }
      body="The Investigation Timeline is the story of what an agent (or session, or workstream) did, in order, with policy decisions woven in. Drill in from the Audit Log or pick an example below."
    >
      <div className="flex flex-wrap items-center justify-center gap-2 pt-2">
        {suggestions.map((e) => (
          <button
            key={e.subject}
            type="button"
            data-testid={`timeline-empty-example-${e.subject}`}
            onClick={() => onPickPrincipal(e.subject)}
            className="rounded border border-r5e-border bg-r5e-surface px-3 py-1 text-xs text-r5e-text hover:border-r5e-accent hover:text-r5e-accent"
          >
            {e.label}
          </button>
        ))}
      </div>
    </EmptyState>
  );
}
