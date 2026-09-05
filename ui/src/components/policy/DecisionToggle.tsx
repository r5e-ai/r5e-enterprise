// DecisionToggle — column 02 DECISION row matching the canonical
// `MdEKl > drawer` Pencil frame's `decRow` element.
//
// Two-button mutually-exclusive toggle: Allow / Deny. The Deny variant
// carries the canonical's accent-pink border + pink-tinted bg + glow
// shadow when selected (the chart-denied red is reserved for actual
// denial events, not policy authoring).
//
// State is UI-only for now — the draft schema's Cedar source carries
// the verb (`permit` vs `forbid`); changing the toggle should
// eventually rewrite the Cedar source's leading keyword. Wired as
// presentational + controlled so the parent can decide what to do
// with the choice.

interface Props {
  value: PolicyDecisionVerdict;
  onChange: (next: PolicyDecisionVerdict) => void;
}

export type PolicyDecisionVerdict = "allow" | "deny";

export function DecisionToggle({ value, onChange }: Props): JSX.Element {
  return (
    <section
      data-testid="decision-toggle"
      className="flex flex-col gap-2 rounded-r5e-md border border-r5e-border-subtle bg-r5e-surface-card p-4"
    >
      <h4
        className="font-mono text-[11px] font-semibold uppercase text-r5e-foreground-secondary"
        style={{ letterSpacing: "0.08em" }}
      >
        DECISION
      </h4>
      <div className="flex gap-2.5">
        <DecisionButton
          label="Allow"
          tone="allow"
          active={value === "allow"}
          onSelect={() => onChange("allow")}
        />
        <DecisionButton
          label="Deny"
          tone="deny"
          active={value === "deny"}
          onSelect={() => onChange("deny")}
        />
      </div>
    </section>
  );
}

function DecisionButton({
  label,
  tone,
  active,
  onSelect,
}: {
  label: string;
  tone: "allow" | "deny";
  active: boolean;
  onSelect: () => void;
}): JSX.Element {
  // Per the canonical: the SELECTED Deny carries an outer pink glow
  // (effect.shadow #EC489961 8px blur). Unselected buttons share the
  // same neutral border-strong outline.
  const activeClass =
    tone === "deny"
      ? "border-r5e-accent-pink bg-[#EC489920] text-r5e-accent-pink shadow-[0_0_16px_-2px_#EC489961]"
      : "border-r5e-accent-green bg-[#28C84020] text-r5e-accent-green shadow-[0_0_16px_-2px_#28C84061]";
  const inactiveClass =
    "border-r5e-border-strong text-r5e-foreground-secondary hover:text-r5e-foreground-primary";
  return (
    <button
      type="button"
      data-testid={`decision-${tone}`}
      aria-pressed={active}
      onClick={onSelect}
      className={`flex h-7 items-center justify-center rounded-r5e-lg border px-4 font-mono text-[11px] uppercase transition-colors ${
        active ? activeClass : inactiveClass
      }`}
    >
      {label}
    </button>
  );
}
