// MessageBubble — renders one chat message in the Audit Agent surface
// (T118 + F5 redesign per design/briefs/06-chat-drawer.md).
//
// Layout per the brief:
//   - User: right-aligned, `bg-r5e-accent/10`, rounded; `[You · 11:38pm]`
//     timestamp shown above the bubble.
//   - Assistant: left-aligned, `bg-r5e-surface`; `[Audit Agent · 11:38pm]`
//     header with status. Body is a sequence of text + tool-call blocks +
//     more text, with the ReferencedDataFooter at the bottom of completed
//     messages and a pulsing-dots placeholder while the stream is open
//     and no tokens have arrived yet.

import type { ChatMessage } from "~/hooks/useChatConversation";
import { ReferencedDataFooter } from "~/components/chat/ReferencedDataFooter";
import { ToolCallBlock } from "~/components/chat/ToolCallBlock";
import { PulsingDots } from "~/components/shared/states";

export interface MessageBubbleProps {
  message: ChatMessage;
  /** Auth principal for the footer (FR-039). */
  principalSubject: string | null;
  principalRole: string | null;
}

export function MessageBubble({
  message,
  principalSubject,
  principalRole,
}: MessageBubbleProps): JSX.Element {
  const isUser = message.role === "user";
  const timestamp = formatClock(message.createdAt);

  // While the assistant is `thinking` and no tokens have streamed in yet,
  // render the pulsing-dots placeholder so the auditor sees activity.
  const showPulsingDots =
    !isUser &&
    message.status === "thinking" &&
    message.content.length === 0 &&
    message.toolCalls.length === 0;

  return (
    <div
      data-testid={`message-bubble-${message.role}`}
      className={`flex w-full flex-col ${isUser ? "items-end" : "items-start"}`}
    >
      {/* Header line — actor + timestamp. */}
      <div
        className={`flex max-w-[90%] items-center gap-2 px-1 pb-0.5 text-[10px] uppercase tracking-wider text-r5e-muted ${
          isUser ? "flex-row-reverse" : ""
        }`}
      >
        <span data-testid={`message-actor-${message.role}`}>
          {isUser ? "You" : "Audit Agent"}
        </span>
        <span aria-hidden="true">·</span>
        <span data-testid="message-timestamp">{timestamp}</span>
        {!isUser && <StatusPill status={message.status} />}
      </div>

      <div
        className={`max-w-[90%] rounded-lg px-3 py-2 text-xs leading-relaxed ${
          isUser
            ? "bg-r5e-accent/10 text-r5e-text"
            : "bg-r5e-surface text-r5e-text"
        }`}
      >
        {showPulsingDots && (
          <PulsingDots tone="muted" testId="message-pulsing-dots" />
        )}

        {message.content && (
          <div
            data-testid="message-content"
            className="whitespace-pre-wrap text-r5e-text"
          >
            {message.content}
            {message.status === "thinking" && !isUser && (
              <span
                aria-hidden="true"
                className="ml-1 inline-block h-2 w-2 animate-pulse rounded-full bg-r5e-accent align-middle"
              />
            )}
          </div>
        )}

        {!isUser && message.toolCalls.length > 0 && (
          <div data-testid="message-tool-calls" className="mt-2">
            {message.toolCalls.map((call) => (
              <ToolCallBlock key={call.id} call={call} />
            ))}
          </div>
        )}

        {!isUser && message.errors.length > 0 && (
          <ul
            role="alert"
            data-testid="message-errors"
            className="mt-2 space-y-1"
          >
            {message.errors.map((err, idx) => (
              <li
                key={`${err.error}-${idx}`}
                className="rounded border border-r5e-danger/60 bg-r5e-danger/10 px-2 py-1 text-[10px] text-r5e-danger"
              >
                <span className="font-mono">{err.error}</span> ·{" "}
                {err.error_description}
              </li>
            ))}
          </ul>
        )}

        {!isUser && message.status === "completed" && (
          <ReferencedDataFooter
            message={message}
            principalSubject={principalSubject}
            principalRole={principalRole}
          />
        )}
      </div>
    </div>
  );
}

function StatusPill({
  status,
}: {
  status: ChatMessage["status"];
}): JSX.Element | null {
  switch (status) {
    case "thinking":
      return (
        <span
          data-testid="message-status-thinking"
          className="rounded-full bg-r5e-accent/15 px-2 py-0.5 text-[9px] uppercase tracking-wider text-r5e-accent"
        >
          thinking…
        </span>
      );
    case "executing-tool":
      return (
        <span
          data-testid="message-status-executing-tool"
          className="rounded-full bg-r5e-warning/15 px-2 py-0.5 text-[9px] uppercase tracking-wider text-r5e-warning"
        >
          calling tool…
        </span>
      );
    case "failed":
      return (
        <span
          data-testid="message-status-failed"
          className="rounded-full bg-r5e-danger/15 px-2 py-0.5 text-[9px] uppercase tracking-wider text-r5e-danger"
        >
          failed
        </span>
      );
    case "completed":
    case "idle":
    default:
      return null;
  }
}

function formatClock(iso: string): string {
  try {
    const d = new Date(iso);
    return d.toLocaleTimeString(undefined, {
      hour: "numeric",
      minute: "2-digit",
    });
  } catch {
    return "";
  }
}
