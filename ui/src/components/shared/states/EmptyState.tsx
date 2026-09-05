// EmptyState — shared "no data" presentational primitive.
//
// Per the R5 frame in `design/r5e-enterprise-audit-ui.pen`:
//   - Title in `r5e-text` (sm semibold).
//   - Body line in `r5e-muted` (xs).
//   - Optional CTA button slot (e.g., "Clear all filters").
//   - Always centered in its container; the container provides the box.
//
// Constitution Principle VII: extracted on the third inline copy
// (PolicySimulatorSuggestions, Dashboard, ReceiptDetail had separate
// inline empty-state renderings before this primitive landed).
//
// Callers compose: <EmptyState title="No matching events"
//   body="No events match your current filters." action={{ label:
//   "Clear all filters", onClick: () => clearFilters() }} />

import type { ReactNode } from "react";

export interface EmptyStateAction {
  label: string;
  onClick: () => void;
}

interface Props {
  title: string;
  /** Sub-line describing why the surface is empty. */
  body?: string | ReactNode;
  /** Optional action button (the "do something to fix it" CTA). */
  action?: EmptyStateAction;
  /** Optional icon slot rendered above the title (44x44 by convention). */
  icon?: ReactNode;
  /** When true, renders flush with no centering. Used inside narrow drawers. */
  compact?: boolean;
  /** Test selector override. Default `empty-state`. */
  testId?: string;
  /**
   * Optional CTA cluster slot. Use this when the surface needs MORE than
   * the single `action` prop allows — e.g., the F10 Timeline's
   * pre-canned principal chips (Constitution Principle VII, extended on
   * the Timeline as the second consumer of EmptyState rather than
   * recreating the primitive). Renders BELOW `action`.
   */
  children?: ReactNode;
}

export function EmptyState({
  title,
  body,
  action,
  icon,
  compact,
  testId = "empty-state",
  children,
}: Props): JSX.Element {
  return (
    <div
      data-testid={testId}
      className={
        compact
          ? "flex flex-col items-start gap-2 px-3 py-4 text-left"
          : "flex h-full flex-col items-center justify-center gap-3 px-4 py-12 text-center"
      }
    >
      {icon ? (
        <div className="text-r5e-muted" aria-hidden="true">
          {icon}
        </div>
      ) : null}
      <div className="text-sm font-semibold text-r5e-text">{title}</div>
      {body ? (
        <div className="max-w-sm text-xs leading-relaxed text-r5e-muted">{body}</div>
      ) : null}
      {action ? (
        <button
          type="button"
          onClick={action.onClick}
          className="mt-2 rounded border border-r5e-border bg-r5e-surface px-3 py-1 text-xs text-r5e-text transition-colors hover:border-r5e-accent hover:text-r5e-accent"
        >
          {action.label}
        </button>
      ) : null}
      {children}
    </div>
  );
}
