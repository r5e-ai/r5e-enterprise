// ChatThread — shared message-list + composer + activity strip used by
// BOTH the slide-in <ChatDrawer /> and the standalone <ChatPage /> surfaces
// (F5 redesign per `design/briefs/06-chat-drawer.md`).
//
// Why a shared component:
//   - The brief mandates "two surfaces sharing the same <ChatThread>".
//   - Avoids drift between the drawer and standalone page (Constitution
//     Principle VII: extract on the second consumer).
//
// What lives here:
//   - The conversation body (loading / empty / error states + message list).
//   - The activity strip (agent thinking / tool-running / failed pulse).
//   - The composer (auto-grow textarea, Cmd/Ctrl+Enter to submit, Send/Stop).
//
// What does NOT live here:
//   - Header (different per surface — drawer has close button + tagline,
//     standalone has TopBar + history dropdown + "New chat").
//   - URL routing (drawer uses ?chat=open; standalone is its own route).
//
// Caller is responsible for:
//   - Reading conversation id from the URL.
//   - Promoting freshly-minted conversation ids back to the URL.
//   - Wiring useAuth → principalSubject/principalRole for the footer.

import { useEffect, useRef, useState } from "react";

import { MessageBubble } from "~/components/chat/MessageBubble";
import {
  EmptyState as SharedEmptyState,
  ErrorState as SharedErrorState,
  PulsingDots,
  Skeleton,
} from "~/components/shared/states";
import {
  type MessageStatus,
  type UseChatConversationResult,
} from "~/hooks/useChatConversation";
import { slug } from "~/lib/strings";

/** Suggested kickoff prompts shown until the user sends their first message. */
export const CHAT_SUGGESTION_CARDS: ReadonlyArray<string> = [
  "Why was Alice's last bash_exec denied?",
  "Show me all denials in the last hour.",
  "Find similar receipts to the most recent deny.",
  "Suggest a policy pattern for the busiest principal.",
];

export interface ChatThreadProps {
  /** Live conversation state from `useChatConversation`. */
  chat: UseChatConversationResult;
  /** Auth principal subject (for the ReferencedDataFooter on each agent message). */
  principalSubject: string | null;
  /** Auth principal role (for the ReferencedDataFooter on each agent message). */
  principalRole: string | null;
  /**
   * When true the conversation surface fills the full height of its
   * container (used by the standalone <ChatPage />). When false the
   * drawer's flex column governs height.
   */
  fullHeight?: boolean;
  /** Test selector for the outer thread wrapper. */
  testId?: string;
}

/**
 * The shared conversation surface. Wraps:
 *   - <ConversationBody />  (skeleton / suggestions / messages / error)
 *   - <ActivityStrip />     (animated agent state above the composer)
 *   - <ChatComposer />      (textarea + Send/Stop + keyboard shortcuts)
 */
export function ChatThread({
  chat,
  principalSubject,
  principalRole,
  fullHeight = false,
  testId = "chat-thread",
}: ChatThreadProps): JSX.Element {
  return (
    <div
      data-testid={testId}
      className={
        fullHeight
          ? "flex h-full min-h-0 flex-1 flex-col"
          : "flex min-h-0 flex-1 flex-col"
      }
    >
      <ConversationBody
        chat={chat}
        principalSubject={principalSubject}
        principalRole={principalRole}
      />
      <ActivityStrip status={chat.activityStatus} />
      <ChatComposer
        isStreaming={chat.isStreaming}
        onSubmit={(text) => void chat.sendMessage(text)}
        onStop={chat.abort}
      />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Conversation body — skeleton / suggestions / messages / error.
// ---------------------------------------------------------------------------

function ConversationBody({
  chat,
  principalSubject,
  principalRole,
}: {
  chat: UseChatConversationResult;
  principalSubject: string | null;
  principalRole: string | null;
}): JSX.Element {
  const scrollRef = useRef<HTMLDivElement | null>(null);
  const messages = chat.state.messages;

  // Auto-scroll to the latest message on update.
  useEffect(() => {
    const el = scrollRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [messages]);

  // Direct prop callback — replaces the previous `chat:prefill` window
  // CustomEvent dance. Per the brief, clicking a suggestion submits it
  // immediately as a user message, so we call `chat.sendMessage` directly.
  // SuggestedPromptCards and ChatComposer are siblings inside the same
  // <ChatThread />, so a window event was strictly weaker than a direct
  // prop callback (extra coupling, stale-closure window during streaming
  // toggles, untestable in isolation).
  const handleSuggestionClick = (text: string): void => {
    void chat.sendMessage(text);
  };

  return (
    <div
      ref={scrollRef}
      data-testid="chat-message-list"
      className="flex-1 overflow-y-auto px-4 py-4"
    >
      {chat.isLoadingHistory && (
        <div
          data-testid="chat-history-loading"
          className="flex flex-col gap-3"
          aria-label="Loading conversation"
        >
          <Skeleton.Block className="h-12 w-2/3" />
          <Skeleton.Block className="h-16 w-3/4 self-end" />
          <Skeleton.Block className="h-20 w-2/3" />
        </div>
      )}

      {chat.isHistoryError && (
        <SharedErrorState
          testId="chat-history-error"
          title="Couldn't load this conversation."
          body="The audit plane returned an error while fetching message history."
          retry={{ label: "Retry", onClick: () => void chat.refetchHistory() }}
        />
      )}

      {!chat.isLoadingHistory &&
        !chat.isHistoryError &&
        messages.length === 0 && (
          <SuggestedPromptCards onClick={handleSuggestionClick} />
        )}

      {messages.length > 0 && (
        <div className="flex flex-col gap-3">
          {messages.map((m) => (
            <MessageBubble
              key={m.localId}
              message={m}
              principalSubject={principalSubject}
              principalRole={principalRole}
            />
          ))}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Suggested prompts — initial empty state.
// ---------------------------------------------------------------------------

function SuggestedPromptCards({
  onClick,
}: {
  onClick: (text: string) => void;
}): JSX.Element {
  return (
    <div
      data-testid="chat-suggested-prompts"
      className="flex flex-col gap-4"
    >
      <SharedEmptyState
        testId="chat-empty-state"
        compact
        title="Hello! I'm your audit assistant."
        body="Ask about a denial, find similar receipts, or draft a policy pattern."
      />
      <ul className="flex flex-col gap-2" data-testid="chat-prompt-cards">
        {CHAT_SUGGESTION_CARDS.map((text) => (
          <li key={text}>
            <button
              type="button"
              data-testid={`chat-prompt-card-${slug(text, 40)}`}
              onClick={() => onClick(text)}
              className="w-full rounded-md border border-r5e-border bg-r5e-surface-elevated px-3 py-3 text-left text-xs leading-relaxed text-r5e-text shadow-sm transition-all hover:-translate-y-px hover:border-r5e-accent hover:shadow-md"
            >
              {text}
            </button>
          </li>
        ))}
      </ul>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Activity strip — surfaces the live agent status (FR-041).
// ---------------------------------------------------------------------------

function ActivityStrip({
  status,
}: {
  status: MessageStatus;
}): JSX.Element | null {
  if (status === "idle" || status === "completed") return null;
  const map: Record<Exclude<MessageStatus, "idle" | "completed">, string> = {
    thinking: "Agent is thinking…",
    "executing-tool": "Agent is calling a tool…",
    failed: "Agent failed — see message above for details.",
  };
  const tone =
    status === "failed"
      ? "border-r5e-danger/60 bg-r5e-danger/10 text-r5e-danger"
      : status === "executing-tool"
        ? "border-r5e-warning/60 bg-r5e-warning/10 text-r5e-warning"
        : "border-r5e-accent/40 bg-r5e-accent/5 text-r5e-accent";
  return (
    <div
      role="status"
      data-testid="chat-activity-strip"
      data-status={status}
      className={`mx-4 mb-2 flex items-center gap-2 rounded border px-3 py-1.5 text-[11px] ${tone}`}
    >
      <PulsingDots tone="current" testId="chat-pulsing-dots" />
      <span>{map[status]}</span>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Composer — auto-grow textarea + Cmd/Ctrl+Enter submit + Send/Stop button.
// ---------------------------------------------------------------------------

const COMPOSER_MIN_ROWS = 1;
const COMPOSER_MAX_ROWS = 4;

function ChatComposer({
  isStreaming,
  onSubmit,
  onStop,
}: {
  isStreaming: boolean;
  onSubmit: (text: string) => void;
  onStop: () => void;
}): JSX.Element {
  const [value, setValue] = useState("");
  const textareaRef = useRef<HTMLTextAreaElement | null>(null);

  // Auto-grow up to COMPOSER_MAX_ROWS lines, then scroll. We measure the
  // intrinsic scrollHeight after a reset to single-line so the height
  // collapses when the user deletes text.
  useEffect(() => {
    const el = textareaRef.current;
    if (!el) return;
    el.style.height = "auto";
    const lineHeight = parseFloat(getComputedStyle(el).lineHeight) || 16;
    const minPx = lineHeight * COMPOSER_MIN_ROWS + 16; // +py-2
    const maxPx = lineHeight * COMPOSER_MAX_ROWS + 16;
    const next = Math.max(minPx, Math.min(maxPx, el.scrollHeight));
    el.style.height = `${next}px`;
    el.style.overflowY = el.scrollHeight > maxPx ? "auto" : "hidden";
  }, [value]);

  function submit(): void {
    const trimmed = value.trim();
    if (!trimmed || isStreaming) return;
    onSubmit(trimmed);
    setValue("");
  }

  return (
    <form
      data-testid="chat-composer"
      onSubmit={(e) => {
        e.preventDefault();
        submit();
      }}
      className="flex shrink-0 items-end gap-2 border-t border-r5e-border bg-r5e-surface px-4 py-3"
    >
      <label htmlFor="chat-input" className="sr-only">
        Message
      </label>
      <textarea
        id="chat-input"
        ref={textareaRef}
        data-testid="chat-input"
        value={value}
        onChange={(e) => setValue(e.target.value)}
        onKeyDown={(e) => {
          // Cmd/Ctrl+Enter submits; bare Enter inserts a newline (per brief).
          // Browsers report the platform modifier as either metaKey (macOS)
          // or ctrlKey (Linux/Windows), so we accept both.
          if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) {
            e.preventDefault();
            submit();
          }
        }}
        rows={COMPOSER_MIN_ROWS}
        disabled={isStreaming}
        placeholder="Ask the audit agent…"
        aria-label="Ask the audit agent"
        className="flex-1 resize-none rounded border border-r5e-border bg-r5e-bg px-3 py-2 text-xs leading-relaxed text-r5e-text placeholder:text-r5e-muted focus:border-r5e-accent focus:outline-none disabled:opacity-50"
      />
      {isStreaming ? (
        <button
          type="button"
          data-testid="chat-stop"
          onClick={onStop}
          aria-label="Stop generating"
          className="rounded border border-r5e-danger/60 bg-r5e-danger/10 px-3 py-2 text-xs font-semibold text-r5e-danger transition-colors hover:bg-r5e-danger/20"
        >
          Stop
        </button>
      ) : (
        <button
          type="submit"
          data-testid="chat-send"
          disabled={value.trim().length === 0}
          aria-label="Send message"
          className="rounded bg-r5e-accent px-3 py-2 text-xs font-semibold text-r5e-text hover:bg-r5e-accent-glow disabled:cursor-not-allowed disabled:opacity-50"
        >
          Send
        </button>
      )}
    </form>
  );
}
