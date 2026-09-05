// PredicateTab — JSON viewer for the signed_predicate envelope (R2 redesign).
//
// Per `design/briefs/03-receipt-drawer.md`:
//   - Syntax-highlighted JSON viewer
//   - For predicate-only receipts, this IS the entire audit content;
//     emphasize with a callout.

import type { ReceiptDetail as ReceiptDetailData } from "~/hooks/useReceiptDetail";
import { isPredicateOnlyUri } from "~/components/audit/PayloadTab";

interface Props {
  data: ReceiptDetailData;
}

export function PredicateTab({ data }: Props): JSX.Element {
  // The detail endpoint may inline a `predicate` sub-object on the
  // signed_predicate; if it's there, prefer that as the JSON body. Otherwise
  // fall back to the signed_predicate envelope itself.
  const predicate = data.signed_predicate.predicate ?? data.signed_predicate;
  const predicateOnly = isPredicateOnlyUri(data.signed_predicate.payload_uri);

  return (
    <div className="flex flex-col gap-3" data-testid="predicate-tab">
      {predicateOnly && (
        <div
          role="note"
          className="rounded border border-r5e-accent/40 bg-r5e-accent/10 px-3 py-2 text-xs text-r5e-text"
          data-testid="predicate-only-callout"
        >
          <p className="font-semibold text-r5e-accent">
            This is the complete signed payload for this receipt.
          </p>
          <p className="mt-1 text-r5e-muted">
            No separate payload bytes were stored — the signed_predicate IS the
            full audit content.
          </p>
        </div>
      )}
      <pre
        data-testid="predicate-json"
        className="max-h-[600px] overflow-auto rounded border border-r5e-border bg-r5e-bg p-3 font-mono text-[11px] leading-snug text-r5e-text"
      >
        {JSON.stringify(predicate, null, 2)}
      </pre>
    </div>
  );
}
