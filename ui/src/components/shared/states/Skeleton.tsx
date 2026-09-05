// Skeleton — shared loading-placeholder primitives.
//
// Per the R5 frame in `design/r5e-enterprise-audit-ui.pen`:
//   - Skeleton blocks are `r5e-surface` lightened with /50 opacity, with
//     a subtle pulse animation (Tailwind `animate-pulse`).
//   - Used as content shape placeholders in three flavors:
//       Skeleton.Block — generic rectangle (caller supplies w/h via
//                        className).
//       Skeleton.Line  — single text line (h-3 default).
//       Skeleton.Histogram — sized to match the audit log histogram so
//                            the layout doesn't reflow when data lands.
//
// Constitution Principle VII: replaces three inline implementations
// (PolicySimulator's EditorSkeleton, BlastRadiusPanel's PendingSkeleton,
// PolicySimulatorSuggestions' ListSkeleton).

interface BlockProps {
  className?: string;
  /** Test selector override. Default `skeleton-block`. */
  testId?: string;
}

function SkeletonBlock({ className = "h-4 w-full", testId = "skeleton-block" }: BlockProps): JSX.Element {
  return (
    <div
      data-testid={testId}
      aria-hidden="true"
      className={`animate-pulse rounded bg-r5e-surface/50 ${className}`}
    />
  );
}

function SkeletonLine({ className = "h-3 w-3/4", testId = "skeleton-line" }: BlockProps): JSX.Element {
  return <SkeletonBlock className={className} testId={testId} />;
}

interface HistogramProps {
  /** Number of pretend bars (defaults to 24 — matches default audit-log range). */
  bars?: number;
  /** Height in tailwind h-N tokens (defaults to h-[120px] like the live histogram). */
  heightClass?: string;
  testId?: string;
}

function SkeletonHistogram({
  bars = 24,
  heightClass = "h-[120px]",
  testId = "skeleton-histogram",
}: HistogramProps): JSX.Element {
  return (
    <div
      data-testid={testId}
      role="status"
      aria-label="Loading histogram"
      className={`flex w-full items-end gap-px rounded border border-r5e-border bg-r5e-surface px-2 py-2 ${heightClass}`}
    >
      {Array.from({ length: bars }).map((_, i) => (
        <div
          key={i}
          aria-hidden="true"
          className="animate-pulse rounded-sm bg-r5e-border/60"
          style={{
            // Bar heights vary so the skeleton looks like the dataset shape
            // rather than a uniform wall of slabs (R5 frame guidance).
            height: `${20 + ((i * 17) % 60)}%`,
            flex: 1,
          }}
        />
      ))}
    </div>
  );
}

interface RowsProps {
  rows?: number;
  testId?: string;
}

function SkeletonRows({ rows = 5, testId = "skeleton-rows" }: RowsProps): JSX.Element {
  return (
    <div
      data-testid={testId}
      role="status"
      aria-label="Loading rows"
      className="flex flex-col gap-2"
    >
      {Array.from({ length: rows }).map((_, i) => (
        <SkeletonBlock key={i} className="h-10 w-full" />
      ))}
    </div>
  );
}

/**
 * Composite Skeleton namespace — exported as `Skeleton.Block`, `.Line`,
 * `.Histogram`, `.Rows`. Callers `import { Skeleton } from
 * "~/components/shared/states/Skeleton"` and pick the shape they want.
 */
export const Skeleton = {
  Block: SkeletonBlock,
  Line: SkeletonLine,
  Histogram: SkeletonHistogram,
  Rows: SkeletonRows,
};
