// Vitest unit tests for the audit-log Histogram (B8 + #45 UX pass).
//
// Asserts:
//   - B8 palette baseline: tool_call → fill-r5e-accent (NOT muted),
//     policy_denied → fill-r5e-danger, legend swatch matches segment.
//   - #45 family-grouped palette: every event_kind resolves to one of
//     SIX semantic families (network/denial/authoring/lifecycle/agent/
//     read/system) — NOT eight kinds collapsed onto two purples. Read-side
//     kinds (ui_query, ui_evidence_export) are now `r5e-text` (neutral),
//     not `r5e-accent` (purple); freeing the brand purple as a SIGNAL
//     color for the demo-money network calls.
//   - Stack determinism: stableKindOrder always groups by family in a
//     stable family-order regardless of input ordering.
//   - Preset window controls: clicking a preset emits `onWindowChange`
//     with a `[since, until]` window matching the requested duration
//     within ±2s of `now`.
//   - "All" preset emits `{ since: null, until: null }` — clears the
//     window.
//   - Active preset highlights when `activeWindow` matches a preset
//     duration (within tolerance).
//   - Window-clamped rendering: when `activeWindow` is set, buckets
//     outside the window do NOT render segments.
//   - Empty state still shows the preset row (so the auditor can recover
//     from a too-narrow window).

import { render, screen, fireEvent } from "@testing-library/react";
import { describe, expect, it, vi, afterEach, beforeEach } from "vitest";

import {
  Histogram,
  colorClassForKind,
  familyForKind,
  presetToWindow,
  HISTOGRAM_PRESET_KEYS,
  type HistogramBucket,
} from "~/components/audit/Histogram";

const bucket: HistogramBucket = {
  ts: "2026-04-29T12",
  counts: {
    tool_call: 5,
    llm_call: 2,
    policy_denied: 1,
    ui_login: 1,
    ui_query: 3,
    ui_policy_simulate: 1,
    ui_chat: 1,
    ui_retention_purge: 1,
  },
};

const kinds = Object.keys(bucket.counts);

describe("Histogram — B8 palette baseline", () => {
  it("renders a tool_call segment using fill-r5e-accent (NOT a grey/muted class)", () => {
    render(<Histogram buckets={[bucket]} kinds={kinds} />);
    const segment = screen.getByTestId("histogram-segment-tool_call");
    expect(segment).toHaveClass("fill-r5e-accent");
    expect(segment).not.toHaveClass("fill-r5e-muted");
  });

  it("renders policy_denied as a coral STROKE LINE overlay (NOT a stacked area segment)", () => {
    // Per the .pen `comp/histogram` canonical (R3 frame's PROPOSED B,
    // marked RECOMMENDED), denied is rendered as a 2px coral stroke
    // line on top of the area stack — explicit visual call-out for
    // the chart's hero signal — NOT mixed in as another stacked layer.
    // Live verification on audit-dev (May 2026) caught the divergence:
    // pre-fix, denied rendered as just-another-area-segment and got
    // visually lost. The new structure has `histogram-denied-stroke`
    // for the overlay and NO `histogram-segment-policy_denied`.
    render(<Histogram buckets={[bucket]} kinds={kinds} />);
    const stroke = screen.getByTestId("histogram-denied-stroke");
    expect(stroke).toHaveClass("stroke-r5e-chart-denied");
    expect(stroke).toHaveClass("fill-none");
    expect(screen.queryByTestId("histogram-segment-policy_denied")).toBeNull();
  });

  it("legend swatch uses the same color as the bar segment for tool_call", () => {
    render(<Histogram buckets={[bucket]} kinds={kinds} />);
    const legend = screen.getByTestId("histogram-legend-tool_call");
    expect(legend.textContent).toContain("tool_call");
    expect(legend.querySelector("span")?.className ?? "").toContain("text-r5e-accent");
  });
});

describe("colorClassForKind — semantic anchors per F002/F004 event_kind", () => {
  // Post-MR-86-fix-pass-2: when the histogram is fed CATEGORY keys (the
  // new default per design briefs/02-dashboard.md), the resolver returns
  // `fill-r5e-chart-*` tokens directly. When fed EVENT_KIND keys (legacy
  // mode, preserved for backward compat with non-Dashboard callers), the
  // resolver falls through to the family→r5e-* mapping below.

  it("tool_call (event_kind) → r5e-accent (legacy network family)", () => {
    // Not a known category → falls through to event_kind family mapping.
    expect(colorClassForKind("tool_call")).toContain("r5e-accent");
    expect(colorClassForKind("tool_call")).not.toContain("muted");
  });

  it("llm_call (category key) → r5e-chart-llm purple", () => {
    // Now a category key (KNOWN_CATEGORIES includes llm_call) — resolves
    // to the purple chart-llm token rather than the legacy r5e-accent.
    expect(colorClassForKind("llm_call")).toContain("r5e-chart-llm");
  });

  it("policy_denied (category key) → r5e-chart-denied red", () => {
    // policy_denied is in KNOWN_CATEGORIES → category palette.
    expect(colorClassForKind("policy_denied")).toContain("r5e-chart-denied");
  });

  it("event_kind denial shapes (NOT category keys) still use r5e-danger", () => {
    // session_abort + egress_denied aren't categories — they're
    // event_kinds. Backward-compat path remains.
    expect(colorClassForKind("session_abort")).toContain("r5e-danger");
    expect(colorClassForKind("egress_denied")).toContain("r5e-danger");
  });

  it("ui_policy_* uses r5e-warning so authoring activity stands apart from verdicts", () => {
    expect(colorClassForKind("ui_policy_simulate")).toContain("r5e-warning");
    expect(colorClassForKind("ui_policy_replay")).toContain("r5e-warning");
    expect(colorClassForKind("ui_policy_draft_created")).toContain("r5e-warning");
    expect(colorClassForKind("ui_policy_suggestion_generated")).toContain("r5e-warning");
  });

  it("ui_chat + audit-agent skill invocations use r5e-accent-glow", () => {
    expect(colorClassForKind("ui_chat")).toContain("r5e-accent-glow");
    expect(colorClassForKind("ui_chat_skill_invoked_query_receipts")).toContain("r5e-accent-glow");
  });

  it("ui_login / ui_session use r5e-success (lifecycle, friendly)", () => {
    expect(colorClassForKind("ui_login")).toContain("r5e-success");
    expect(colorClassForKind("ui_session")).toContain("r5e-success");
  });

  it("ui_retention_purge + unknown kinds fall back to r5e-muted", () => {
    expect(colorClassForKind("ui_retention_purge")).toContain("r5e-muted");
    expect(colorClassForKind("future_unknown_kind")).toContain("r5e-muted");
  });
});

describe("Histogram — #45 family-grouped palette (no four-purple collapse)", () => {
  it("read-side kinds (ui_query, ui_evidence_export) use r5e-text — NOT r5e-accent", () => {
    // Pre-#45 these collapsed onto fill-r5e-accent alongside tool_call;
    // the auditor couldn't visually separate "demo-money tool call"
    // from "auditor browsing the UI." The fix moves the read-side
    // kinds to the neutral text token.
    expect(colorClassForKind("ui_query")).toContain("r5e-text");
    expect(colorClassForKind("ui_query")).not.toContain("r5e-accent");
    expect(colorClassForKind("ui_evidence_export")).toContain("r5e-text");
    expect(colorClassForKind("ui_evidence_export")).not.toContain("r5e-accent");
    expect(colorClassForKind("ui_payload_access")).toContain("r5e-text");
  });

  it("the four-purple collapse is gone: only event_kinds in the legacy network family get r5e-accent", () => {
    // Post-MR-86-fix-pass-2: llm_call is now a CATEGORY key (resolves
    // to r5e-chart-llm). The remaining event_kind-only collapse guard
    // is just `tool_call` in the legacy network family.
    const eventKinds = [
      "tool_call",
      "session_abort",
      "egress_denied",
      "ui_login",
      "ui_session",
      "ui_logout",
      "ui_query",
      "ui_evidence_export",
      "ui_payload_access",
      "ui_chat",
      "ui_chat_skill_invoked_query_receipts",
      "ui_policy_simulate",
      "ui_policy_replay",
      "ui_policy_draft_created",
      "ui_policy_suggestion_generated",
      "ui_retention_purge",
      "future_unknown_kind",
    ];
    const accentMembers = eventKinds.filter((k) => {
      const tokens = colorClassForKind(k).split(/\s+/);
      return tokens.includes("fill-r5e-accent");
    });
    expect(accentMembers.sort()).toEqual(["tool_call"]);

    // r5e-accent-glow tightly bounded: ui_chat + ui_chat_skill_invoked_*.
    const accentGlowMembers = eventKinds.filter((k) => {
      const tokens = colorClassForKind(k).split(/\s+/);
      return tokens.includes("fill-r5e-accent-glow");
    });
    expect(accentGlowMembers.sort()).toEqual([
      "ui_chat",
      "ui_chat_skill_invoked_query_receipts",
    ]);
  });

  it("familyForKind groups kinds into the documented six families", () => {
    expect(familyForKind("tool_call")).toBe("network");
    expect(familyForKind("llm_call")).toBe("network");
    expect(familyForKind("policy_denied")).toBe("denial");
    expect(familyForKind("session_abort")).toBe("denial");
    expect(familyForKind("ui_policy_simulate")).toBe("authoring");
    expect(familyForKind("ui_login")).toBe("lifecycle");
    expect(familyForKind("ui_chat")).toBe("agent");
    expect(familyForKind("ui_query")).toBe("read");
    expect(familyForKind("ui_retention_purge")).toBe("system");
  });

  it("data-family attribute is set on each non-denied segment for downstream styling hooks", () => {
    // Note: `policy_denied` is NOT a segment anymore — see the
    // "denied as STROKE LINE overlay" test above for the new structure.
    // data-family still flows to area-stack segments for styling hooks.
    render(<Histogram buckets={[bucket]} kinds={kinds} />);
    expect(screen.getByTestId("histogram-segment-tool_call")).toHaveAttribute(
      "data-family",
      "network",
    );
  });
});

describe("Histogram — preset window controls", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-04-30T12:00:00.000Z"));
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it("renders all five preset buttons (1h, 6h, 24h, 7d, all)", () => {
    render(<Histogram buckets={[bucket]} kinds={kinds} />);
    for (const preset of HISTOGRAM_PRESET_KEYS) {
      expect(screen.getByTestId(`histogram-preset-${preset}`)).toBeInTheDocument();
    }
  });

  it("preset row is rendered even in the empty state", () => {
    render(<Histogram buckets={[]} kinds={[]} />);
    expect(screen.getByTestId("histogram-preset-row")).toBeInTheDocument();
    expect(screen.getByTestId("histogram-preset-1h")).toBeInTheDocument();
    expect(screen.getByTestId("histogram-empty")).toBeInTheDocument();
  });

  it("clicking 'Last 1h' emits a 1-hour window ending at now", () => {
    const onWindowChange = vi.fn();
    render(
      <Histogram buckets={[bucket]} kinds={kinds} onWindowChange={onWindowChange} />,
    );
    fireEvent.click(screen.getByTestId("histogram-preset-1h"));
    expect(onWindowChange).toHaveBeenCalledTimes(1);
    const arg = onWindowChange.mock.calls[0]?.[0];
    expect(arg?.since).toBe("2026-04-30T11:00:00.000Z");
    expect(arg?.until).toBe("2026-04-30T12:00:00.000Z");
  });

  it("clicking 'All' emits a cleared window", () => {
    const onWindowChange = vi.fn();
    render(
      <Histogram buckets={[bucket]} kinds={kinds} onWindowChange={onWindowChange} />,
    );
    fireEvent.click(screen.getByTestId("histogram-preset-all"));
    expect(onWindowChange).toHaveBeenCalledWith({ since: null, until: null });
  });

  it("highlights the matching preset button when activeWindow matches its duration", () => {
    render(
      <Histogram
        buckets={[bucket]}
        kinds={kinds}
        activeWindow={{
          since: "2026-04-30T06:00:00.000Z",
          until: "2026-04-30T12:00:00.000Z",
        }}
      />,
    );
    expect(screen.getByTestId("histogram-preset-6h")).toHaveAttribute("data-active", "true");
    expect(screen.getByTestId("histogram-preset-1h")).toHaveAttribute("data-active", "false");
  });

  it("'Clear' button appears when a window is set and emits a cleared window", () => {
    const onWindowChange = vi.fn();
    render(
      <Histogram
        buckets={[bucket]}
        kinds={kinds}
        onWindowChange={onWindowChange}
        activeWindow={{ since: "2026-04-30T11:00:00.000Z", until: null }}
      />,
    );
    const clearBtn = screen.getByTestId("histogram-window-clear");
    expect(clearBtn).toBeInTheDocument();
    fireEvent.click(clearBtn);
    expect(onWindowChange).toHaveBeenCalledWith({ since: null, until: null });
  });

  it("'Clear' button is hidden when no window is set", () => {
    render(<Histogram buckets={[bucket]} kinds={kinds} />);
    expect(screen.queryByTestId("histogram-window-clear")).not.toBeInTheDocument();
  });
});

describe("presetToWindow — pure helper", () => {
  it("'all' clears both edges", () => {
    expect(presetToWindow("all")).toEqual({ since: null, until: null });
  });

  it("'1h' is exactly 1 hour wide", () => {
    const now = new Date("2026-04-30T12:00:00.000Z");
    const w = presetToWindow("1h", now);
    expect(w.until).toBe("2026-04-30T12:00:00.000Z");
    expect(w.since).toBe("2026-04-30T11:00:00.000Z");
  });

  it("'7d' is exactly 7 days wide", () => {
    const now = new Date("2026-04-30T12:00:00.000Z");
    const w = presetToWindow("7d", now);
    expect(w.since).toBe("2026-04-23T12:00:00.000Z");
    expect(w.until).toBe("2026-04-30T12:00:00.000Z");
  });
});

describe("Histogram — window-clamped rendering", () => {
  const buckets: HistogramBucket[] = [
    { ts: "2026-04-30T08", counts: { tool_call: 1 } },
    { ts: "2026-04-30T09", counts: { tool_call: 2 } },
    { ts: "2026-04-30T10", counts: { tool_call: 3 } },
    { ts: "2026-04-30T11", counts: { tool_call: 4 } },
    { ts: "2026-04-30T12", counts: { tool_call: 5 } },
  ];

  it("renders all buckets when no activeWindow is set (bars variant)", () => {
    // Use legacy bars variant — one <rect> per bucket per kind, so the
    // count assertion below maps to bucket count.
    render(<Histogram buckets={buckets} kinds={["tool_call"]} variant="bars" />);
    const segments = document.querySelectorAll("[data-testid='histogram-segment-tool_call']");
    expect(segments.length).toBe(5);
  });

  it("client-side clamps to activeWindow when set (bars variant)", () => {
    render(
      <Histogram
        buckets={buckets}
        kinds={["tool_call"]}
        variant="bars"
        activeWindow={{
          since: "2026-04-30T10:00:00.000Z",
          until: "2026-04-30T11:30:00.000Z",
        }}
      />,
    );
    const segments = document.querySelectorAll("[data-testid='histogram-segment-tool_call']");
    // Only buckets at 10 and 11 fall in [10:00, 11:30]; 8, 9, 12 are clipped.
    expect(segments.length).toBe(2);
  });

  it("renders one polygon per kind in area variant (default)", () => {
    // Area variant is the R3 RECOMMENDED default. One <path> per kind,
    // not one per bucket per kind, so segment count == kind count.
    render(<Histogram buckets={buckets} kinds={["tool_call"]} />);
    const segments = document.querySelectorAll("[data-testid='histogram-segment-tool_call']");
    expect(segments.length).toBe(1);
    // Variant marker on the SVG.
    const svg = document.querySelector("[data-testid='histogram-svg']");
    expect(svg?.getAttribute("data-chart-variant")).toBe("area");
  });

  it("emits area segments as smooth-curved <path> elements (NOT polylines)", () => {
    // Live audit-dev verification (May 2026) caught the divergence
    // from the .pen `comp/histogram` canonical: the prior layerPolygon
    // emitted straight line segments between buckets, producing a
    // visibly jagged stack that didn't match the brief's "smooth
    // interpolation between time points (d3-shape curves OR a simple
    // Catmull-Rom)" requirement. Now: each layer is a <path d="M ... C
    // ..."> using Catmull-Rom-to-Bezier conversion. No <polygon>.
    render(<Histogram buckets={buckets} kinds={["tool_call"]} />);
    const seg = screen.getByTestId("histogram-segment-tool_call");
    expect(seg.tagName.toLowerCase()).toBe("path");
    expect(seg.getAttribute("d")).toMatch(/C/); // contains cubic-bezier control segments
    // Subtle 18% fill alpha (vs the prior 0.55) per the canonical's
    // translucent-area treatment.
    expect(seg.getAttribute("fill-opacity")).toBe("0.18");
    // Per-layer outline removed — earlier 0.75px stroke turned the
    // chart into bordered shapes and made the denied-stroke overlay
    // get visually lost.
    expect(seg.getAttribute("stroke")).toBe("none");
  });
});

describe("Histogram — y/x axis labels", () => {
  it("renders y-axis min (0) and max labels", () => {
    render(<Histogram buckets={[bucket]} kinds={kinds} />);
    expect(screen.getByTestId("histogram-y-axis-min")).toHaveTextContent("0");
    expect(screen.getByTestId("histogram-y-axis-max")).toBeInTheDocument();
  });

  it("renders first and last x-axis ticks", () => {
    const buckets: HistogramBucket[] = [
      { ts: "2026-04-30T08", counts: { tool_call: 1 } },
      { ts: "2026-04-30T10", counts: { tool_call: 2 } },
      { ts: "2026-04-30T12", counts: { tool_call: 3 } },
    ];
    render(<Histogram buckets={buckets} kinds={["tool_call"]} />);
    expect(screen.getByTestId("histogram-x-axis-first")).toHaveTextContent("04-30 08:00");
    expect(screen.getByTestId("histogram-x-axis-last")).toHaveTextContent("04-30 12:00");
  });
});

describe("Histogram — backwards-compat onBrush API", () => {
  it("still calls legacy onBrush on single-bucket click when onWindowChange is absent", () => {
    const onBrush = vi.fn();
    render(<Histogram buckets={[bucket]} kinds={kinds} onBrush={onBrush} />);
    // Simulate a click on the chart svg at coordinate that resolves to
    // bucket index 0. JSDOM doesn't lay out SVG, so we fire mousedown +
    // mouseup at the same coordinate to exercise the single-click path.
    const svg = screen.getByTestId("histogram-svg");
    fireEvent.mouseDown(svg, { clientX: 0 });
    fireEvent.mouseUp(svg, { clientX: 0 });
    // With no onWindowChange and one bucket, the single-click path falls
    // through to onBrush(ts) for the legacy path.
    expect(onBrush).toHaveBeenCalledWith(bucket.ts);
  });
});
