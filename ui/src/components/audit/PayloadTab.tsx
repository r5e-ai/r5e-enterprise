// PayloadTab — fetches + renders the receipt's payload (T079, US2 / FR-019).
//
// Per the pen-file Receipt Detail screen (Payload tab) + spec FR-019:
//   - For receipts WITH an external payload (s3:// or equivalent), the tab
//     shows a clear advisory:
//       "Fetching as <principal> — this access is itself attested"
//     followed by a "Fetch payload" CTA. The user MUST click through; we do
//     NOT auto-fetch on tab open. This makes the attested-access intent
//     explicit and lets the auditor decide before producing a `:ui_payload_access`
//     receipt of their own.
//   - AFTER fetch, the JSON payload renders in a monospace block; the advisory
//     stays visible so the auditor remembers their access was attested.
//   - For predicate-only receipts (issue #60: `recurse://import/...` and
//     `recurse://system/predicate-only/...`), there is no separate payload to
//     fetch — the signed_predicate IS the audit content. The SPA hides the
//     "Fetch payload" button entirely and renders a clean explanation banner
//     instead. The attested-access advisory is suppressed in this state
//     because no access is occurring (nothing to attest).
//   - "Cancel" before fetch → noop (closes nothing; the tab just stays in
//     pre-fetch state). "Retry" after a failed fetch is the same CTA reused.
//
// The PayloadBroker endpoint (`/v1/audit/payload?run_id=...`) emits a
// `:ui_payload_access` attestation server-side per FR-019 — the SPA does not
// need to do anything special to make this happen.

import { useMutation } from "@tanstack/react-query";
import { useState } from "react";

import { useAuth } from "~/hooks/useAuth";
import { receiptDetailPaths } from "~/hooks/useReceiptDetail";
import { ApiError, api, useApiErrorHandler } from "~/lib/api";

/**
 * Predicate-only URI scheme prefixes — must stay in sync with
 * `apps/recurse_gateway/lib/recurse_gateway/audit_plane/predicate_only_uri.ex`.
 *
 * `recurse://system/predicate-only/...` covers Gateway-internal system
 * events (`:ui_login` / `:ui_session` / `:ui_query`, etc.) where the
 * signed_predicate IS the full audit content.
 *
 * `recurse://import/...` covers receipts emitted by the JSONL session
 * importer (MR !80, e.g. `mix r5e.import.claude_code_session`). The
 * importer hashes the source-session entry into the receipt's
 * signed_predicate; no separate payload bytes are CAS-stashed, so the
 * Audit Plane returns 422 `ERR_PREDICATE_ONLY` if the SPA ever asks
 * (issue #60).
 */
const PREDICATE_ONLY_SCHEMES = [
  "recurse://system/predicate-only/",
  "recurse://import/",
] as const;

interface Props {
  runId: string;
  /**
   * The receipt's `signed_predicate.payload_uri`. When present and one of
   * the predicate-only schemes, the SPA suppresses the fetch UI and renders
   * the explanation banner instead. Optional so existing call sites that
   * don't yet thread it stay safe (the 422 fallback path still renders the
   * friendly explanation if the user manages to trigger a fetch).
   */
  payloadUri?: string | null;
}

export function PayloadTab({ runId, payloadUri }: Props): JSX.Element {
  const auth = useAuth();
  const principal = auth.status === "authenticated" ? auth.principal : "you";
  const [payload, setPayload] = useState<unknown | null>(null);
  const handleApiError = useApiErrorHandler();

  const mutation = useMutation<unknown, Error, void>({
    mutationFn: () => api.get<unknown>(receiptDetailPaths.payload(runId)),
    onSuccess: (data) => setPayload(data),
    onError: handleApiError,
  });

  const hasPayload = payload !== null;
  const predicateOnly = isPredicateOnlyUri(payloadUri);
  const fetchHit422PredicateOnly =
    mutation.isError &&
    mutation.error instanceof ApiError &&
    mutation.error.status === 422 &&
    mutation.error.error === "ERR_PREDICATE_ONLY";

  // Render the predicate-only explanation when EITHER (a) the receipt is
  // statically known to be predicate-only via its payload_uri, OR (b) the
  // user manually triggered a fetch and the backend returned the by-design
  // 422 ERR_PREDICATE_ONLY. Same UX for both paths so callers that don't
  // thread `payloadUri` still degrade gracefully (no red error toast).
  if (predicateOnly || fetchHit422PredicateOnly) {
    return (
      <div className="flex flex-col gap-3" data-testid="payload-tab">
        <div
          role="note"
          className="rounded border border-r5e-border bg-r5e-surface/40 px-3 py-3 text-xs text-r5e-text"
          data-testid="payload-predicate-only"
        >
          <p className="font-semibold text-r5e-muted">
            Predicate-only receipt
          </p>
          <p className="mt-1">
            The signed_predicate IS the full audit content for this receipt;
            no separate payload bytes were stored. (Common for receipts
            imported from a source-session JSONL.) See the Predicate tab for
            the full content.
          </p>
          {payloadUri && (
            <p
              className="mt-2 font-mono text-[10px] text-r5e-muted"
              data-testid="payload-predicate-only-uri"
            >
              payload_uri = <span className="break-all">{payloadUri}</span>
            </p>
          )}
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-3" data-testid="payload-tab">
      {/* Advisory — shown BEFORE and AFTER fetch (FR-019). */}
      <div
        role="note"
        className="rounded border border-r5e-warning/40 bg-r5e-warning/10 px-3 py-2 text-xs text-r5e-text"
        data-testid="payload-attested-access-notice"
      >
        <span className="font-semibold">Fetching as {principal}</span> — this
        access is itself attested. Each fetch emits a{" "}
        <code className="font-mono text-[10px]">:ui_payload_access</code>{" "}
        receipt visible in the audit log.
      </div>

      <div className="flex items-center gap-2">
        <button
          type="button"
          onClick={() => mutation.mutate()}
          disabled={mutation.isPending}
          className="rounded bg-r5e-accent px-3 py-1.5 text-xs font-semibold uppercase tracking-wider text-white hover:bg-r5e-accent/90 disabled:cursor-not-allowed disabled:opacity-50"
          data-testid="payload-fetch-button"
        >
          {mutation.isPending
            ? "Fetching…"
            : hasPayload
              ? "Re-fetch payload"
              : mutation.isError
                ? "Retry"
                : "Fetch payload"}
        </button>
        {hasPayload && (
          <button
            type="button"
            onClick={() => setPayload(null)}
            className="rounded border border-r5e-border px-3 py-1.5 text-xs text-r5e-muted hover:text-r5e-text"
          >
            Clear
          </button>
        )}
      </div>

      {mutation.isError && mutation.error instanceof ApiError && (
        <div
          role="alert"
          className="rounded border border-r5e-danger/60 bg-r5e-danger/10 px-3 py-2 text-xs text-r5e-danger"
        >
          {mutation.error.error_description}
        </div>
      )}

      {hasPayload && isPredicateOnlyMarker(payload) ? (
        <div
          role="note"
          className="rounded border border-r5e-border bg-r5e-surface/40 px-3 py-3 text-xs text-r5e-text"
          data-testid="payload-predicate-only"
        >
          <p className="font-semibold text-r5e-muted">No external payload</p>
          <p className="mt-1">
            {(payload as { explanation?: string }).explanation ??
              "This event has no separate payload — the signed_predicate IS the audit content. See the Predicate tab."}
          </p>
        </div>
      ) : (
        hasPayload && (
          <pre
            data-testid="payload-json"
            className="max-h-[480px] overflow-auto rounded border border-r5e-border bg-r5e-bg p-3 font-mono text-[11px] leading-snug text-r5e-text"
          >
            {JSON.stringify(payload, null, 2)}
          </pre>
        )
      )}
    </div>
  );
}

/**
 * True when the given URI uses one of the predicate-only schemes (system or
 * imported). When true, the SPA suppresses the fetch UI entirely — there is
 * no payload to fetch by design.
 */
export function isPredicateOnlyUri(uri: string | null | undefined): boolean {
  if (typeof uri !== "string" || uri.length === 0) return false;
  return PREDICATE_ONLY_SCHEMES.some((prefix) => uri.startsWith(prefix));
}

/**
 * The PayloadBroker returns a structured `{predicate_only: true, ...}` body
 * for events whose `payload_uri` is `recurse://system/predicate-only/<run_id>`
 * (i.e., `:ui_login` / `:ui_session` / `:ui_query` events whose audit content
 * is the signed_predicate itself, with no separate payload to fetch). The
 * SPA renders an explanatory message instead of bytes. (Issue #27 — preserved
 * for backwards compatibility with the deployed system-event 200 response;
 * issue #60 added the 422 path for imported receipts.)
 */
function isPredicateOnlyMarker(payload: unknown): boolean {
  return (
    typeof payload === "object" &&
    payload !== null &&
    (payload as { predicate_only?: unknown }).predicate_only === true
  );
}
