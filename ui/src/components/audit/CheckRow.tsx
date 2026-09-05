// CheckRow — single row in the Verify ladder (R2 redesign).
//
// Per `design/briefs/03-receipt-drawer.md`:
//   - ✓ green or ✗ red (or pending dot, or running spinner)
//   - Label (heading)
//   - Detail (text-muted, mono where it's an ID/hash)
//   - Failed rows get a subtle red tint background
//
// Extracted out of VerifyLocallyButton so VerifyTab + any future verifier
// surface can reuse it (Constitution Principle VII).

export type CheckRowState = "pending" | "running" | "pass" | "fail";

interface Props {
  label: string;
  detail?: string;
  state: CheckRowState;
  testId?: string;
}

export function CheckRow({
  label,
  detail,
  state,
  testId,
}: Props): JSX.Element {
  const failed = state === "fail";
  return (
    <li
      data-testid={testId}
      data-state={state}
      className={`flex items-start gap-3 px-3 py-2.5 text-xs ${
        failed ? "bg-r5e-danger/5" : ""
      }`}
    >
      <StatusIcon state={state} />
      <div className="flex flex-1 flex-col gap-0.5">
        <span
          className={`font-medium ${failed ? "text-r5e-danger" : "text-r5e-text"}`}
        >
          {label}
        </span>
        {detail && (
          <span className="font-mono text-[10px] text-r5e-muted">{detail}</span>
        )}
      </div>
    </li>
  );
}

function StatusIcon({ state }: { state: CheckRowState }): JSX.Element {
  if (state === "pending") {
    return (
      <span
        aria-label="pending"
        className="mt-1 inline-block h-3 w-3 shrink-0 rounded-full border border-r5e-border bg-r5e-surface"
      />
    );
  }
  if (state === "running") {
    return (
      <span
        aria-label="running"
        className="mt-0.5 inline-block h-3 w-3 shrink-0 animate-spin rounded-full border-2 border-r5e-accent border-t-transparent"
      />
    );
  }
  if (state === "pass") {
    return (
      <svg
        aria-label="pass"
        viewBox="0 0 12 12"
        className="mt-1 h-3 w-3 shrink-0 text-r5e-success"
        fill="none"
        stroke="currentColor"
        strokeWidth="2"
      >
        <path
          d="M2 6.5L5 9.5L10 3"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      </svg>
    );
  }
  return (
    <svg
      aria-label="fail"
      viewBox="0 0 12 12"
      className="mt-1 h-3 w-3 shrink-0 text-r5e-danger"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
    >
      <path d="M2 2L10 10M10 2L2 10" strokeLinecap="round" />
    </svg>
  );
}
