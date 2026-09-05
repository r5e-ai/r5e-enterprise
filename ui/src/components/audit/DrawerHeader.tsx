// DrawerHeader — top of the Receipt Drawer (R2 redesign).
//
// Per `design/briefs/03-receipt-drawer.md`:
//   - "RECEIPT" mono caps eyebrow
//   - run_id mono, truncated to 36 chars
//   - Tier pill: warning (PARTIAL) or success (FULL)
//   - "Draft policy from receipt" (Sparkles icon, accent outline)
//   - "Export Evidence (.zip)" (Download icon, accent outline)
//   - Close button (X)
//
// Pure presentational; the page wires the navigate handlers via props.

import { Sparkles, X } from "lucide-react";

import { ExportEvidenceButton } from "~/components/audit/ExportEvidenceButton";
import { Pill } from "~/components/shared/Pill";

interface Props {
  runId: string | null | undefined;
  tierAdvisory: string | null | undefined;
  onClose: () => void;
  onDraftPolicy: () => void;
}

export function DrawerHeader({
  runId,
  tierAdvisory,
  onClose,
  onDraftPolicy,
}: Props): JSX.Element {
  return (
    <header
      className="relative z-10 flex shrink-0 items-start justify-between gap-3 border-b border-r5e-border bg-r5e-surface px-4 py-3"
      data-testid="drawer-header"
    >
      <div className="flex min-w-0 flex-col gap-1.5">
        <span
          className="font-mono text-[10px] font-semibold uppercase tracking-[0.1em] text-r5e-muted"
          data-testid="drawer-eyebrow"
        >
          Receipt
        </span>
        <code
          className="truncate font-mono text-xs text-r5e-text"
          data-testid="drawer-run-id"
          title={runId ?? undefined}
        >
          {runId ? truncateRunId(runId) : "(no run_id)"}
        </code>
        <TierCompletenessPill advisory={tierAdvisory ?? null} />
      </div>
      <div className="flex shrink-0 items-center gap-2">
        {runId && (
          <button
            type="button"
            data-testid="draft-policy-from-receipt"
            onClick={onDraftPolicy}
            className="flex h-7 items-center gap-1.5 rounded-md border border-r5e-accent px-2.5 text-[11px] font-semibold text-r5e-accent hover:bg-r5e-accent/10"
          >
            <Sparkles className="h-3.5 w-3.5" aria-hidden="true" />
            Draft policy from receipt
          </button>
        )}
        {runId && <ExportEvidenceButton runId={runId} />}
        <button
          type="button"
          onClick={onClose}
          aria-label="Close drawer"
          className="flex h-7 items-center justify-center rounded border border-r5e-border px-2 text-r5e-muted hover:text-r5e-text"
          data-testid="drawer-close"
        >
          <X className="h-3.5 w-3.5" aria-hidden="true" />
        </button>
      </div>
    </header>
  );
}

function truncateRunId(runId: string): string {
  if (runId.length <= 36) return runId;
  return `${runId.slice(0, 33)}…`;
}

function TierCompletenessPill({
  advisory,
}: {
  advisory: string | null;
}): JSX.Element | null {
  if (!advisory) return null;
  const isPartial = advisory === "partial";
  const isFull = advisory === "full";
  const tone = isPartial ? "warning" : isFull ? "success" : "neutral";
  const label = `Tier completeness: ${advisory}`;
  return (
    <Pill
      tone={tone}
      size="xs"
      outline
      testId="tier-completeness-advisory"
      className="self-start"
    >
      {label}
    </Pill>
  );
}
