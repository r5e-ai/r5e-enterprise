// ErrorState — shared error-banner primitive.
//
// Per the R5 frame in `design/r5e-enterprise-audit-ui.pen`:
//   - Container: `r5e-danger/10` background + `r5e-danger/40` border.
//   - Title in `r5e-danger` (sm semibold).
//   - Body line in `r5e-text` (xs).
//   - Optional retry button (`r5e-danger` outline).
//   - Optional secondary link (e.g., "View pipeline status").
//
// Used by ReceiptDetail (US2 fetch failure) and ReceiptDetail's
// payload tab (gone-shape) — extracted from the inline ErrorState
// implementations in those modules.
//
// Constitution Principle VII: third-copy extraction.

import type { ReactNode } from "react";

interface Props {
  /** Required short title — what failed. */
  title: string;
  /** One-line body — why it failed (or what the auditor can do). */
  body?: string | ReactNode;
  /** Underlying Error / API error message; rendered as monospace detail. */
  detail?: string | null;
  /** Primary retry CTA. */
  retry?: { label?: string; onClick: () => void };
  /** Secondary link/button (e.g., "View pipeline status"). */
  secondary?: { label: string; onClick: () => void };
  /** Compact variant (small banners inside cards). */
  compact?: boolean;
  testId?: string;
}

export function ErrorState({
  title,
  body,
  detail,
  retry,
  secondary,
  compact,
  testId = "error-state",
}: Props): JSX.Element {
  return (
    <div
      data-testid={testId}
      role="alert"
      className={
        compact
          ? "rounded border border-r5e-danger/40 bg-r5e-danger/10 px-3 py-2 text-xs"
          : "rounded border border-r5e-danger/40 bg-r5e-danger/10 px-4 py-3 text-sm"
      }
    >
      <div className="font-semibold text-r5e-danger">{title}</div>
      {body ? <div className="mt-1 text-r5e-text">{body}</div> : null}
      {detail ? (
        <div className="mt-2 break-all font-mono text-[11px] text-r5e-muted">{detail}</div>
      ) : null}
      {(retry || secondary) && (
        <div className="mt-3 flex items-center gap-2">
          {retry ? (
            <button
              type="button"
              data-testid={`${testId}-retry`}
              onClick={retry.onClick}
              className="rounded border border-r5e-danger px-3 py-1 text-xs font-medium text-r5e-danger transition-colors hover:bg-r5e-danger/15"
            >
              {retry.label ?? "Retry now"}
            </button>
          ) : null}
          {secondary ? (
            <button
              type="button"
              data-testid={`${testId}-secondary`}
              onClick={secondary.onClick}
              className="text-xs text-r5e-muted underline-offset-2 transition-colors hover:text-r5e-text hover:underline"
            >
              {secondary.label}
            </button>
          ) : null}
        </div>
      )}
    </div>
  );
}
