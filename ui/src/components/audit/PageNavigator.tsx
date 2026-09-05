// PageNavigator — paged pagination footer (#32).
//
// Per the brief:
//   - Footer has page numbers (1, 2, 3, ..., last) + Previous/Next.
//   - Total count visible (e.g., "Page 2 of 17 — 169 total"). The total
//     count comes from the backend's `total_count` field; if absent we
//     show the loaded-row count instead and add a "+more on next page"
//     hint when more pages might exist.
//   - Page size is fixed (50) at the page-math layer; the picker doesn't
//     change it.
//
// The component is presentational. The Dashboard owns:
//   - the cursor cache (pageIndex → cursor) that maps page N to its
//     fetch param
//   - the "next page may need fetching" decision (calls `fetchNextPage`
//     on the infinite query when stepping forward past the loaded
//     window)

import type * as React from "react";
import { ChevronLeft, ChevronRight } from "lucide-react";

import {
  AUDIT_LOG_PAGE_SIZE,
  buildPageNav,
  type PageNavEntry,
} from "~/lib/auditLogColumns";

interface Props {
  /** 0-based current page. */
  currentPageIndex: number;
  /** Number of rows currently loaded into TanStack Query's page cache.
   *  Used to compute `pagesLoaded` when total_count is absent. */
  loadedCount: number;
  /** Backend-reported total count of rows matching the active filter.
   *  When `null`, the navigator omits "of N pages" and the total label;
   *  see brief: "If `total_count` doesn't exist on
   *  `audit_receipts_list_response.json` yet, file as a follow-up + show
   *  only 'Page N — X loaded' for now (no total)." */
  totalCount: number | null;
  /** True iff the infinite-query has more cursored pages to fetch. */
  hasMore: boolean;
  /** True while a fetchNextPage is in flight. */
  isFetching: boolean;
  /** Page size; defaults to AUDIT_LOG_PAGE_SIZE (50). */
  pageSize?: number;
  onPageChange: (nextPageIndex: number) => void;
}

export function PageNavigator({
  currentPageIndex,
  loadedCount,
  totalCount,
  hasMore,
  isFetching,
  pageSize = AUDIT_LOG_PAGE_SIZE,
  onPageChange,
}: Props): JSX.Element {
  const totalPages =
    totalCount === null
      ? // Without backend total: pagesLoaded is the upper bound the user
        // can step to without forcing another fetchNextPage.
        Math.max(1, Math.ceil(loadedCount / pageSize))
      : Math.max(1, Math.ceil(totalCount / pageSize));

  const canGoPrev = currentPageIndex > 0 && !isFetching;
  // With backend totals: bounded by totalPages.
  // Without: user can advance one beyond pagesLoaded if hasMore (will
  // trigger fetchNextPage in the parent).
  const canGoNext = isFetching
    ? false
    : totalCount === null
      ? hasMore || currentPageIndex < totalPages - 1
      : currentPageIndex < totalPages - 1;

  const entries: PageNavEntry[] = buildPageNav(totalPages, currentPageIndex);

  return (
    <footer
      className="flex items-center justify-between border-t border-r5e-border bg-r5e-surface/60 px-4 py-2 text-xs text-r5e-muted"
      data-testid="page-navigator"
    >
      <span data-testid="page-navigator-status">
        {totalCount === null ? (
          <>
            Page {currentPageIndex + 1} — {loadedCount} loaded
            {hasMore && (
              <span className="ml-1 text-r5e-muted/80">(more available)</span>
            )}
          </>
        ) : (
          <>
            Page {currentPageIndex + 1} of {totalPages} — {totalCount} total
          </>
        )}
      </span>

      <nav
        role="navigation"
        aria-label="Audit log pagination"
        className="flex items-center gap-1"
      >
        <PageButton
          ariaLabel="Previous page"
          disabled={!canGoPrev}
          onClick={() => onPageChange(currentPageIndex - 1)}
          testId="page-navigator-prev"
        >
          <ChevronLeft size={14} aria-hidden="true" />
          <span className="hidden sm:inline">Previous</span>
        </PageButton>

        <ul className="flex items-center gap-0.5">
          {entries.map((entry) =>
            entry.kind === "ellipsis" ? (
              <li
                key={`ellipsis-${entry.key}`}
                aria-hidden="true"
                className="px-2 text-r5e-muted"
              >
                …
              </li>
            ) : (
              <li key={entry.index}>
                <button
                  type="button"
                  aria-label={`Go to page ${entry.index + 1}`}
                  aria-current={
                    entry.index === currentPageIndex ? "page" : undefined
                  }
                  data-testid={`page-navigator-page-${entry.index + 1}`}
                  onClick={() => onPageChange(entry.index)}
                  disabled={isFetching}
                  className={`min-w-[1.75rem] rounded px-2 py-1 text-xs transition-colors focus:outline-none focus:ring-1 focus:ring-r5e-accent-glow ${
                    entry.index === currentPageIndex
                      ? "bg-r5e-accent/20 text-r5e-accent"
                      : "text-r5e-text hover:bg-r5e-surface"
                  } disabled:cursor-not-allowed disabled:opacity-50`}
                >
                  {entry.index + 1}
                </button>
              </li>
            ),
          )}
        </ul>

        <PageButton
          ariaLabel="Next page"
          disabled={!canGoNext}
          onClick={() => onPageChange(currentPageIndex + 1)}
          testId="page-navigator-next"
        >
          <span className="hidden sm:inline">Next</span>
          <ChevronRight size={14} aria-hidden="true" />
        </PageButton>
      </nav>
    </footer>
  );
}

function PageButton({
  children,
  ariaLabel,
  disabled,
  onClick,
  testId,
}: {
  children: React.ReactNode;
  ariaLabel: string;
  disabled: boolean;
  onClick: () => void;
  testId: string;
}): JSX.Element {
  return (
    <button
      type="button"
      aria-label={ariaLabel}
      data-testid={testId}
      disabled={disabled}
      onClick={onClick}
      className="flex items-center gap-1 rounded border border-r5e-border bg-r5e-surface px-2 py-1 text-xs text-r5e-text transition-colors hover:bg-r5e-surface/60 focus:outline-none focus:ring-2 focus:ring-r5e-accent-glow disabled:cursor-not-allowed disabled:opacity-50"
    >
      {children}
    </button>
  );
}
