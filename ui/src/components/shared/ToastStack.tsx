// ToastStack — shared in-page toast presenter.
//
// Constitution Principle VII (Interface-First on Second Consumer): both
// Dashboard.tsx (live-tail events) and PolicySimulatorSuggestions.tsx
// (refresh / rate-limit / error notices) had grown the same fixed
// bottom-right toast presenter inline. Extracted here on the second
// consumer's landing.
//
// Each toast is a small object:
//
//   { id, tone, message }  // + optional onDismiss
//
// `tone` is decoupled from any one page's domain enum (live-tail's
// `trim|paused|...` versus suggestions' `rate_limited|error|success`) —
// callers map their domain kinds to a tone before passing in. This keeps
// the visual contract centralised while letting each page name its
// events in its own vocabulary.
//
// `onDismiss(id)` is optional. When provided the toast renders a × button
// that invokes `onDismiss(id)`; when omitted the toast is purely
// auto-dismissing (caller controls the lifetime via setTimeout).

import type { ReactNode } from "react";

export type ToastTone = "danger" | "warning" | "success" | "info" | "neutral";

/**
 * A single toast row. `id` is generic so callers can use whatever stable
 * key they have on hand — Dashboard uses a string event id (so identical
 * live-tail events de-dup), Suggestions uses a numeric Date.now()+random
 * collision-resistant id.
 *
 * `testId` is optional and stamps `data-testid` on the toast row. Callers
 * that want kind-discriminated assertions (e.g. e2e: assert a
 * `rate_limited` toast appeared) pass their domain kind through here so
 * tests don't have to reach for tone (which is a presentational concern).
 */
export interface ToastItem<Id extends string | number = string | number> {
  id: Id;
  tone: ToastTone;
  message: ReactNode;
  testId?: string;
}

interface Props<Id extends string | number> {
  toasts: ReadonlyArray<ToastItem<Id>>;
  /** When provided, each toast renders a × dismiss button. */
  onDismiss?: (id: Id) => void;
  /**
   * Optional test-id stamped on the wrapper div. Lets per-page tests
   * scope queries to their own toast stack without colliding across
   * pages mounted in the same DOM (e.g. Dashboard outlet + drawer).
   */
  testId?: string;
  /** Tailwind className passed through; lets the outer page tune width. */
  className?: string;
}

const TONE_CLASSES: Record<ToastTone, string> = {
  danger: "border-r5e-danger/60 bg-r5e-danger/10 text-r5e-danger",
  warning: "border-r5e-warning/60 bg-r5e-warning/10 text-r5e-warning",
  success: "border-r5e-success/60 bg-r5e-success/10 text-r5e-success",
  info: "border-r5e-accent/60 bg-r5e-accent/10 text-r5e-accent",
  neutral: "border-r5e-border bg-r5e-surface text-r5e-text",
};

export function ToastStack<Id extends string | number>({
  toasts,
  onDismiss,
  testId,
  className,
}: Props<Id>): JSX.Element | null {
  if (toasts.length === 0) return null;
  return (
    <div
      data-testid={testId}
      role="status"
      aria-live="polite"
      className={`pointer-events-none fixed bottom-4 right-4 z-50 flex flex-col gap-2 ${
        className ?? ""
      }`}
    >
      {toasts.map((t) => (
        <div
          key={String(t.id)}
          data-testid={t.testId}
          className={`pointer-events-auto rounded border px-3 py-2 text-xs shadow-md ${TONE_CLASSES[t.tone]}`}
        >
          <div className="flex items-start justify-between gap-2">
            <span className="flex-1">{t.message}</span>
            {onDismiss && (
              <button
                type="button"
                onClick={() => onDismiss(t.id)}
                aria-label="Dismiss notification"
                className="text-r5e-muted hover:text-r5e-text"
              >
                ×
              </button>
            )}
          </div>
        </div>
      ))}
    </div>
  );
}
