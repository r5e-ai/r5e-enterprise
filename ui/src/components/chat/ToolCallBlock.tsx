// ToolCallBlock — inline render of an Audit Agent tool invocation
// (T118 + F5 redesign per design/briefs/06-chat-drawer.md).
//
// Per the brief:
//   - Compact summary line by default: `[Tool: verify_receipt]` + truncated
//     request/response preview.
//   - Click chevron → expands inline showing full request + response JSON.
//   - The `attested_run_id` is shown as a link → opens that receipt's
//     drawer OVER the chat (background-location modal pattern; the chat
//     surface remains mounted underneath, conversation context preserved).
//   - Status icon: spinner (running) / check (success) / cross (error).
//
// Each tool invocation IS ITSELF an audited receipt — surfacing the
// attested_run_id is the "the chat itself is audited" recursion the
// design brief calls out. The `state.backgroundLocation` payload below is
// what wires the modal-overlay rendering; see App.tsx <AppRoutes /> for
// the matching <Routes /> block.

import { ChevronDown, ChevronRight } from "lucide-react";
import { useState } from "react";
import { Link, useLocation } from "react-router-dom";

import type { ToolCall } from "~/hooks/useChatConversation";
import { receiptDetailPath } from "~/lib/routes";

export interface ToolCallBlockProps {
  call: ToolCall;
}

const PREVIEW_MAX_CHARS = 80;

export function ToolCallBlock({ call }: ToolCallBlockProps): JSX.Element {
  const [open, setOpen] = useState(false);
  const location = useLocation();
  const argsPreview = preview(call.args);
  const resultPreview = preview(call.result);

  return (
    <div
      data-testid={`tool-call-block-${call.tool}`}
      className="my-2 rounded border border-r5e-border bg-r5e-bg/60 text-[11px]"
    >
      {/* Header / summary line — always visible. */}
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        data-testid={`tool-call-toggle-${call.tool}`}
        className="flex w-full items-center justify-between gap-2 rounded-t px-2 py-1.5 text-left transition-colors hover:bg-r5e-surface"
      >
        <div className="flex min-w-0 items-center gap-2">
          {open ? (
            <ChevronDown
              aria-hidden="true"
              className="h-3 w-3 shrink-0 text-r5e-muted"
            />
          ) : (
            <ChevronRight
              aria-hidden="true"
              className="h-3 w-3 shrink-0 text-r5e-muted"
            />
          )}
          <StatusIcon status={call.status} />
          <span
            className="font-mono text-r5e-accent"
            data-testid={`tool-call-name-${call.tool}`}
          >
            [Tool: {call.tool}]
          </span>
          {!open && resultPreview && (
            <span
              className="truncate text-r5e-muted"
              data-testid={`tool-call-preview-${call.tool}`}
            >
              · {resultPreview}
            </span>
          )}
          {!open && !resultPreview && argsPreview && (
            <span className="truncate text-r5e-muted">· {argsPreview}</span>
          )}
        </div>
        <StatusBadge status={call.status} />
      </button>

      {/* Expanded body — request, response, error detail, receipt link. */}
      {open && (
        <div
          data-testid={`tool-call-body-${call.tool}`}
          className="flex flex-col gap-2 border-t border-r5e-border/60 px-2 py-2"
        >
          <KvBlock label="request" value={call.args} testId={`tool-call-args-${call.tool}`} />
          {(call.status === "success" || call.status === "error") && (
            <KvBlock
              label="response"
              value={call.result}
              testId={`tool-call-result-${call.tool}`}
            />
          )}
          {call.status === "error" && call.errorMessage && (
            <div
              role="alert"
              className="rounded border border-r5e-danger/60 bg-r5e-danger/10 px-2 py-1 text-[10px] text-r5e-danger"
            >
              {call.errorMessage}
            </div>
          )}
          {call.attestationRunId && (
            <Link
              to={receiptDetailPath(call.attestationRunId)}
              state={{ backgroundLocation: location }}
              data-testid={`tool-call-receipt-${call.tool}`}
              title="Open the attested receipt for this tool call"
              className="self-start font-mono text-[10px] text-r5e-accent hover:underline"
            >
              attested_run_id={call.attestationRunId.slice(0, 12)}…
            </Link>
          )}
        </div>
      )}
    </div>
  );
}

function KvBlock({
  label,
  value,
  testId,
}: {
  label: string;
  value: unknown;
  testId: string;
}): JSX.Element {
  return (
    <div className="flex flex-col gap-1">
      <span className="text-[9px] uppercase tracking-wider text-r5e-muted">
        {label}
      </span>
      <pre
        data-testid={testId}
        className="max-h-48 overflow-auto rounded bg-r5e-surface p-2 font-mono text-[10px] leading-snug text-r5e-text"
      >
        {safeStringify(value)}
      </pre>
    </div>
  );
}

function StatusIcon({ status }: { status: ToolCall["status"] }): JSX.Element {
  switch (status) {
    case "running":
      return (
        <span
          aria-label="running"
          data-testid="tool-call-status-running"
          className="inline-block h-3 w-3 shrink-0 animate-spin rounded-full border-2 border-r5e-accent border-t-transparent"
        />
      );
    case "success":
      return (
        <span
          aria-label="success"
          data-testid="tool-call-status-success"
          className="inline-flex h-3 w-3 shrink-0 items-center justify-center rounded-full bg-r5e-success/20 text-[9px] text-r5e-success"
        >
          ✓
        </span>
      );
    case "error":
      return (
        <span
          aria-label="error"
          data-testid="tool-call-status-error"
          className="inline-flex h-3 w-3 shrink-0 items-center justify-center rounded-full bg-r5e-danger/20 text-[9px] text-r5e-danger"
        >
          ✕
        </span>
      );
  }
}

function StatusBadge({ status }: { status: ToolCall["status"] }): JSX.Element {
  const tone =
    status === "running"
      ? "text-r5e-muted"
      : status === "success"
        ? "text-r5e-success"
        : "text-r5e-danger";
  const label =
    status === "running" ? "running…" : status === "success" ? "ok" : "error";
  return (
    <span
      className={`shrink-0 text-[10px] uppercase tracking-wider ${tone}`}
    >
      {label}
    </span>
  );
}

function safeStringify(value: unknown): string {
  if (value === undefined) return "(no value)";
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}

function preview(value: unknown): string {
  if (value === undefined || value === null) return "";
  let text: string;
  if (typeof value === "string") {
    text = value;
  } else {
    try {
      text = JSON.stringify(value);
    } catch {
      return "";
    }
  }
  text = text.replace(/\s+/g, " ").trim();
  if (text.length <= PREVIEW_MAX_CHARS) return text;
  return `${text.slice(0, PREVIEW_MAX_CHARS - 1).trimEnd()}…`;
}
