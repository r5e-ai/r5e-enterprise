// LiveTailToggle — small toggle pill above the audit table that flips
// live-tail on/off (T068, FR-013).
//
// Per the pen-file Dashboard screen:
//   - When OFF: muted pill, dot in `r5e-muted`, label "Live-tail off".
//   - When ON: accent pill, pulsing dot in `r5e-success`, label
//     "Live-tail on".
//   - Optional `pendingCount` shows how many rows have arrived since the
//     user last interacted with the table (placeholder for future
//     "scroll-to-top" affordance).

interface Props {
  enabled: boolean;
  onToggle: (next: boolean) => void;
  pendingCount?: number;
}

export function LiveTailToggle({
  enabled,
  onToggle,
  pendingCount,
}: Props): JSX.Element {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={enabled}
      onClick={() => onToggle(!enabled)}
      className={`flex items-center gap-2 rounded-full border px-3 py-1 text-xs font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-r5e-accent-glow ${
        enabled
          ? "border-r5e-accent bg-r5e-accent/15 text-r5e-accent"
          : "border-r5e-border bg-r5e-surface text-r5e-muted hover:text-r5e-text"
      }`}
    >
      <span
        className={`inline-block h-2 w-2 rounded-full ${
          enabled ? "animate-pulse bg-r5e-success" : "bg-r5e-muted"
        }`}
      />
      <span>{enabled ? "Live-tail on" : "Live-tail off"}</span>
      {enabled && pendingCount !== undefined && pendingCount > 0 && (
        <span className="rounded bg-r5e-accent/30 px-1.5 py-0.5 font-mono text-[10px] text-r5e-text">
          +{pendingCount}
        </span>
      )}
    </button>
  );
}
