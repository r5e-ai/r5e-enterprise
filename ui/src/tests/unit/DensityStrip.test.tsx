// DensityStrip — top mini-histogram for the F10 Investigation Timeline.
//
// Asserts:
//   - Empty state when no buckets supplied.
//   - One bar per bucket; height proportional to total within bucket.
//   - Stacked-segment uses the R4 chart-* fill class for each category.

import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { DensityStrip } from "~/components/timeline/DensityStrip";
import type { DensityBucket } from "~/lib/timeline";

function bucket(ts: string, byCat: Record<string, number>): DensityBucket {
  const total = Object.values(byCat).reduce((a, b) => a + b, 0);
  return {
    ts,
    ts_ms: Date.parse(ts),
    count_by_category: byCat,
    total,
  };
}

describe("DensityStrip", () => {
  it("renders empty state when buckets is empty", () => {
    render(<DensityStrip buckets={[]} />);
    expect(screen.getByTestId("density-strip-empty")).toBeInTheDocument();
  });

  it("renders one bar per bucket", () => {
    render(
      <DensityStrip
        buckets={[
          bucket("2026-05-01T01:00:00Z", { subprocess_exec: 5 }),
          bucket("2026-05-01T02:00:00Z", { subprocess_exec: 3 }),
        ]}
      />,
    );
    const bars = screen.getAllByTestId("density-strip-bar");
    expect(bars).toHaveLength(2);
  });

  it("renders a chart-* segment for each non-zero category", () => {
    render(
      <DensityStrip
        buckets={[
          bucket("2026-05-01T01:00:00Z", {
            subprocess_exec: 4,
            file_read: 2,
          }),
        ]}
      />,
    );
    const sub = screen.getByTestId("density-segment-subprocess_exec");
    const read = screen.getByTestId("density-segment-file_read");
    expect(sub.className).toMatch(/bg-r5e-chart-subprocess/);
    expect(read.className).toMatch(/bg-r5e-chart-file-read/);
  });
});
