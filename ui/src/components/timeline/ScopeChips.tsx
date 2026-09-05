// ScopeChips — dismissable scope chips at the top of the Timeline.
//
// Per `design/briefs/10-session-trace.md`:
//   - Two scope chips inline at top:  [session=…×]  [principal=…×]  [time:Last 24h]
//   - When a chip is dismissed, the Timeline broadens (e.g., remove `session=`
//     to see all of `principal=…`'s sessions in the time window).
//   - Time picker top-right (Last 1h / 6h / 24h / 7d / All)
//   - Live toggle (mirrors R1 dashboard) — wired through but the brief lists
//     the toggle as cosmetic for the demo target; live tail in Phase-2.

import { X } from "lucide-react";

import type { ActiveScope, TimeWindowKey } from "~/lib/timeline";
import { TIME_WINDOWS } from "~/lib/timeline";

interface Props {
  scope: ActiveScope;
  /** Active time-window key (drives the segmented control). */
  windowKey: TimeWindowKey | null;
  onDismissPrincipal: () => void;
  onDismissSession: () => void;
  onDismissCorrelation: () => void;
  onDismissRunId: () => void;
  onWindowChange: (key: TimeWindowKey) => void;
}

export function ScopeChips({
  scope,
  windowKey,
  onDismissPrincipal,
  onDismissSession,
  onDismissCorrelation,
  onDismissRunId,
  onWindowChange,
}: Props): JSX.Element {
  const hasActiveScope =
    scope.principal !== null ||
    scope.session_id !== null ||
    scope.correlation_id !== null ||
    scope.run_id !== null;
  return (
    <div
      data-testid="scope-chips"
      className="flex flex-wrap items-center justify-between gap-3 border-b border-r5e-border bg-r5e-surface/40 px-4 py-3"
    >
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-[10px] font-mono uppercase tracking-wider text-r5e-muted">
          Active scope
        </span>
        {!hasActiveScope && (
          <span data-testid="scope-empty" className="text-xs text-r5e-muted">
            (none — pick a principal, session, or workstream below)
          </span>
        )}
        {scope.principal && (
          <ScopeChip
            label={`principal=${scope.principal}`}
            tone="accent"
            onDismiss={onDismissPrincipal}
            testId="scope-chip-principal"
          />
        )}
        {scope.session_id && (
          <ScopeChip
            label={`session=${truncate(scope.session_id)}`}
            tone="accent"
            onDismiss={onDismissSession}
            testId="scope-chip-session"
          />
        )}
        {scope.correlation_id && (
          <ScopeChip
            label={`workstream=${truncate(scope.correlation_id)}`}
            tone="accent"
            onDismiss={onDismissCorrelation}
            testId="scope-chip-correlation"
          />
        )}
        {scope.run_id && (
          <ScopeChip
            label={`run=${truncate(scope.run_id)}`}
            tone="muted"
            onDismiss={onDismissRunId}
            testId="scope-chip-run"
          />
        )}
        <span
          data-testid="scope-chip-time"
          className="inline-flex items-center gap-1 rounded border border-r5e-border bg-r5e-surface px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider text-r5e-muted"
        >
          time:{scope.time_window_label}
        </span>
      </div>

      <div data-testid="time-window-picker" className="flex items-center gap-1">
        {TIME_WINDOWS.map((w) => {
          const active = windowKey === w.key;
          return (
            <button
              key={w.key}
              type="button"
              data-testid={`time-window-${w.key}`}
              data-active={active ? "true" : "false"}
              onClick={() => onWindowChange(w.key)}
              className={
                active
                  ? "rounded border border-r5e-accent bg-r5e-accent/15 px-2 py-1 text-[10px] font-mono uppercase tracking-wider text-r5e-accent"
                  : "rounded border border-r5e-border px-2 py-1 text-[10px] font-mono uppercase tracking-wider text-r5e-muted hover:border-r5e-accent hover:text-r5e-accent"
              }
            >
              {w.label}
            </button>
          );
        })}
      </div>
    </div>
  );
}

function ScopeChip({
  label,
  tone,
  onDismiss,
  testId,
}: {
  label: string;
  tone: "accent" | "muted";
  onDismiss: () => void;
  testId: string;
}): JSX.Element {
  const toneClass =
    tone === "accent"
      ? "border-r5e-accent text-r5e-accent bg-r5e-accent/10"
      : "border-r5e-border text-r5e-muted bg-r5e-surface";
  return (
    <span
      data-testid={testId}
      className={`inline-flex items-center gap-1 rounded border px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider ${toneClass}`}
    >
      <span className="truncate" title={label}>
        {label}
      </span>
      <button
        type="button"
        aria-label={`Dismiss ${label}`}
        onClick={onDismiss}
        className="rounded p-0.5 hover:bg-r5e-bg/40"
      >
        <X className="h-3 w-3" aria-hidden="true" />
      </button>
    </span>
  );
}

function truncate(s: string, len = 12): string {
  if (s.length <= len) return s;
  return `${s.slice(0, len)}…`;
}
