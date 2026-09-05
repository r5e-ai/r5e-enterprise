// ReferencedDataFooter — small footer rendered at the bottom of each
// completed assistant message (T118, Phase 6 US4).
//
// Per spec FR-039:
//   - Lists API calls (tool invocations) made on the user's behalf.
//   - Makes the user's auth context (principal subject + role) explicit so
//     auditors can see exactly whose token was used to fetch what.
//   - Each entry deep-links to its attested receipt when available.
//
// Per F5 redesign (`design/briefs/06-chat-drawer.md` + FR-038): the receipt
// link MUST open the receipt detail OVER the chat surface (background-
// location modal pattern) so the chat conversation context is preserved
// underneath. We therefore route through `receiptDetailPath()` with
// `state={{ backgroundLocation: location }}` rather than rendering raw
// `/admin/...` URLs — both for the basename-strip discipline and for the
// modal-overlay rendering wired up in `App.tsx <AppRoutes />`.

import { Link, useLocation } from "react-router-dom";

import type { ChatMessage } from "~/hooks/useChatConversation";
import { receiptDetailPath } from "~/lib/routes";

export interface ReferencedDataFooterProps {
  message: ChatMessage;
  /** The signed-in principal whose token was used. */
  principalSubject: string | null;
  /** The role attached to that principal for the active session. */
  principalRole: string | null;
}

export function ReferencedDataFooter({
  message,
  principalSubject,
  principalRole,
}: ReferencedDataFooterProps): JSX.Element | null {
  const location = useLocation();
  if (message.role !== "assistant") return null;
  if (message.toolCalls.length === 0 && !message.attestationRunId) return null;

  return (
    <footer
      data-testid="referenced-data-footer"
      className="mt-2 rounded border border-r5e-border/60 bg-r5e-bg/40 p-2 text-[10px] text-r5e-muted"
    >
      <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
        <span className="uppercase tracking-wider text-r5e-muted">
          Referenced data
        </span>
        <span className="text-r5e-muted">·</span>
        <span>
          fetched as{" "}
          <span className="font-mono text-r5e-text">
            {principalSubject ?? "unknown principal"}
          </span>
          {principalRole && (
            <span className="ml-1 rounded bg-r5e-accent/15 px-1 py-0.5 font-mono text-[9px] uppercase tracking-wider text-r5e-accent">
              {principalRole.replace(/_/g, " ")}
            </span>
          )}
        </span>
      </div>

      {message.toolCalls.length > 0 && (
        <ul
          data-testid="referenced-data-calls"
          className="mt-1 flex flex-col gap-0.5"
        >
          {message.toolCalls.map((call) => (
            <li key={call.id} className="flex flex-wrap items-center gap-2">
              <span className="font-mono text-r5e-text">{call.tool}</span>
              <span
                className={`uppercase tracking-wider ${
                  call.status === "success"
                    ? "text-r5e-success"
                    : call.status === "error"
                      ? "text-r5e-danger"
                      : "text-r5e-muted"
                }`}
              >
                {call.status}
              </span>
              {call.attestationRunId && (
                <Link
                  to={receiptDetailPath(call.attestationRunId)}
                  state={{ backgroundLocation: location }}
                  data-testid={`referenced-data-tool-receipt-${call.id}`}
                  className="font-mono text-r5e-accent hover:underline"
                >
                  receipt {call.attestationRunId.slice(0, 8)}…
                </Link>
              )}
            </li>
          ))}
        </ul>
      )}

      {message.attestationRunId && (
        <div
          data-testid="referenced-data-message-receipt"
          className="mt-1 flex items-center gap-2"
        >
          <span className="uppercase tracking-wider">Message attested as</span>
          <Link
            to={receiptDetailPath(message.attestationRunId)}
            state={{ backgroundLocation: location }}
            data-testid="referenced-data-message-receipt-link"
            className="font-mono text-r5e-accent hover:underline"
          >
            {message.attestationRunId.slice(0, 8)}…
          </Link>
        </div>
      )}
    </footer>
  );
}
