// PolicyTab — read-only Cedar source viewer + decision rationale callout
// for the Receipt Drawer's POLICY tab (R2 redesign).
//
// Per `design/briefs/03-receipt-drawer.md`:
//   - Read-only Cedar source viewer (line-numbered, matched range highlighted).
//   - Below: decision rationale callout (best-effort — backend emits as
//     `outer_container.decision_rationale`; show what's there).
//
// Shape note: the F004 detail endpoint returns `matched_policy.source_excerpt`
// with `line_start` / `line_end`. Free-form `decision_rationale` is not yet
// codegen'd onto the receipt detail type, but if backend ever begins shipping
// it on `outer_container`, we render it under the source viewer. Until then,
// the callout falls back to a structured "DECISION: <decision>" line plus the
// matched-policy file/line hint.

import { Pill } from "~/components/shared/Pill";
import type { ReceiptDetail as ReceiptDetailData } from "~/hooks/useReceiptDetail";

interface Props {
  data: ReceiptDetailData;
}

export function PolicyTab({ data }: Props): JSX.Element {
  const matched = data.matched_policy;
  const hash = data.signed_predicate.policy_canonical_hash;
  const decision = data.outer_container.policy_decision;
  // Best-effort decision rationale: free-form string the gateway may emit on
  // `outer_container.decision_rationale`. Not yet present in the codegen'd
  // wire shape (the detail-response schema sweep is filed as #50); read
  // defensively so we never crash if backend starts shipping it.
  const rationale =
    typeof (data.outer_container as unknown as { decision_rationale?: unknown })
      .decision_rationale === "string"
      ? ((data.outer_container as unknown as { decision_rationale: string })
          .decision_rationale)
      : null;

  return (
    <div className="flex flex-col gap-3" data-testid="policy-tab">
      {hash && <PolicyHashChip hash={hash} />}
      {matched?.source_excerpt ? (
        <CedarSourceViewer matched={matched} />
      ) : (
        <div className="rounded border border-r5e-border bg-r5e-surface px-3 py-2 text-xs text-r5e-muted">
          No matched policy excerpt available for this receipt.
        </div>
      )}
      <DecisionRationale
        decision={decision}
        rationale={rationale}
        matchedFile={matched?.file ?? null}
        matchedLineStart={matched?.line_start ?? null}
        matchedLineEnd={matched?.line_end ?? null}
      />
    </div>
  );
}

function CedarSourceViewer({
  matched,
}: {
  matched: NonNullable<ReceiptDetailData["matched_policy"]>;
}): JSX.Element {
  const lines = (matched.source_excerpt ?? "").split("\n");
  const baseLine = matched.line_start ?? 1;
  const matchStart = matched.line_start ?? 1;
  const matchEnd = matched.line_end ?? matchStart;

  return (
    <div className="rounded border border-r5e-border bg-r5e-bg p-3">
      <div className="mb-2 font-mono text-[10px] font-semibold uppercase tracking-[0.1em] text-r5e-muted">
        {matched.file ?? "policy"} · lines {matchStart}–{matchEnd}
      </div>
      <pre className="overflow-x-auto font-mono text-[11px] leading-snug text-r5e-text">
        {lines.map((line, idx) => {
          const lineNo = baseLine + idx;
          const inMatch = lineNo >= matchStart && lineNo <= matchEnd;
          return (
            <div
              key={idx}
              data-line={lineNo}
              className={inMatch ? "bg-r5e-accent/15" : undefined}
            >
              <span className="mr-2 inline-block w-8 select-none text-right text-r5e-muted">
                {lineNo}
              </span>
              <span>{line}</span>
            </div>
          );
        })}
      </pre>
    </div>
  );
}

function DecisionRationale({
  decision,
  rationale,
  matchedFile,
  matchedLineStart,
  matchedLineEnd,
}: {
  decision: "allow" | "deny" | null;
  rationale: string | null;
  matchedFile: string | null;
  matchedLineStart: number | null;
  matchedLineEnd: number | null;
}): JSX.Element | null {
  if (!decision && !rationale && !matchedFile) return null;
  const tone = decision === "deny" ? "danger" : "success";
  return (
    <div
      className="rounded border border-r5e-border bg-r5e-surface px-3 py-2.5 text-xs"
      data-testid="policy-decision-rationale"
    >
      <div className="flex items-center gap-2">
        <span className="font-mono text-[10px] font-semibold uppercase tracking-[0.1em] text-r5e-muted">
          Decision
        </span>
        <Pill tone={tone} size="xs">
          {decision ?? "—"}
        </Pill>
      </div>
      {matchedFile && (
        <div className="mt-2 grid grid-cols-[140px_1fr] gap-x-3 gap-y-1 font-mono text-[11px]">
          <span className="text-[10px] uppercase tracking-[0.1em] text-r5e-muted">
            Matched in
          </span>
          <span className="truncate text-r5e-text" title={matchedFile}>
            {matchedFile}
            {matchedLineStart != null
              ? `:${matchedLineStart}${matchedLineEnd && matchedLineEnd !== matchedLineStart ? `–${matchedLineEnd}` : ""}`
              : ""}
          </span>
        </div>
      )}
      {rationale && (
        <p className="mt-2 whitespace-pre-wrap text-r5e-text">{rationale}</p>
      )}
    </div>
  );
}

function PolicyHashChip({ hash }: { hash: string }): JSX.Element {
  return (
    <div className="flex items-center gap-2 text-[10px] text-r5e-muted">
      <span className="font-mono uppercase tracking-[0.1em]">
        policy_canonical_hash
      </span>
      <code className="rounded bg-r5e-surface px-2 py-0.5 font-mono text-r5e-text">
        {hash.length > 32 ? `${hash.slice(0, 16)}…${hash.slice(-12)}` : hash}
      </code>
    </div>
  );
}
