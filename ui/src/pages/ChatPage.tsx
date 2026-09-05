// ChatPage — standalone full-page Audit Agent chat surface at /admin/chat.
//
// Per `design/briefs/06-chat-drawer.md` (F5 redesign):
//   - Mounted at `/admin/chat` as a full-page route inside <AuthenticatedShell />.
//   - Uses the same shared <ChatThread /> component as <ChatDrawer />, so
//     conversation rendering, composer, and streaming behavior are identical
//     across both surfaces (Constitution Principle VII).
//   - TopBar shows: ✦ Sparkles + "Audit Agent · Chat" + tagline on the left;
//     "New chat" button + history dropdown on the right.
//   - Message thread fills the viewport (flex-1, h-full) below the TopBar.
//   - Conversation persists server-side; `?conversation=<uuid>` resumes a
//     prior conversation. Click a row in the history dropdown to switch
//     conversations; click "New chat" to clear the URL and start fresh.

import { ChevronDown, MessageSquarePlus, Sparkles } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { useLocation, useNavigate, useSearchParams } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";

import { ChatThread } from "~/components/chat/ChatThread";
import { TopBar } from "~/components/shared/TopBar";
import { useAuth } from "~/hooks/useAuth";
import {
  conversationKey,
  useChatConversation,
} from "~/hooks/useChatConversation";
import { useChatConversations, type ChatConversationSummary } from "~/hooks/useChatConversations";
import { truncate } from "~/lib/strings";

export default function ChatPage(): JSX.Element {
  const auth = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [searchParams, setSearchParams] = useSearchParams();
  const queryClient = useQueryClient();

  const conversationId = searchParams.get("conversation");
  const chat = useChatConversation(conversationId);
  const history = useChatConversations();

  // Promote a freshly-minted conversation id into the URL once the SSE
  // stream emits it (so reloads land on the same conversation).
  useEffect(() => {
    if (!conversationId && chat.state.id) {
      const next = new URLSearchParams(searchParams);
      next.set("conversation", chat.state.id);
      navigate(`${location.pathname}?${next.toString()}`, { replace: true });
    }
  }, [
    conversationId,
    chat.state.id,
    location.pathname,
    navigate,
    searchParams,
  ]);

  // F5 deep-link consumption: SuggestionCard's "Explain →" link routes to
  // `/admin/chat?chat=open&seed=<urlencoded-prompt>` — the auditor wants
  // the chat to land seeded with the explain prompt and submit it. We
  // strip `seed` from the URL after consumption so a subsequent reload
  // doesn't re-submit it. `?chat=open` is harmless on this surface (it's
  // the drawer-overlay flag; ChatPage is a full page) so we leave it.
  // This stays a one-shot effect via a ref guard so we don't loop on
  // setSearchParams → re-render.
  const seedSentRef = useRef<string | null>(null);
  useEffect(() => {
    const seed = searchParams.get("seed");
    if (!seed || seedSentRef.current === seed) return;
    seedSentRef.current = seed;
    void chat.sendMessage(seed);
    const next = new URLSearchParams(searchParams);
    next.delete("seed");
    setSearchParams(next, { replace: true });
    // Reset the dedupe ref AFTER the URL is stripped so a fresh
    // navigation back to `/admin/chat?seed=<same-prompt>` (e.g. clicking
    // the same `Explain →` deep-link from another surface twice in a
    // row) re-fires the seed instead of silently no-opping. Without this
    // the second click does nothing visible — the URL has no `seed=`
    // after consumption, the ref still holds the previous value, and
    // navigating back with the same seed early-exits on the equality
    // check above (F008 from MR !93 fix-pass-2 GAN).
    seedSentRef.current = null;
  }, [searchParams, chat, setSearchParams]);

  const principalSubject =
    auth.status === "authenticated" ? auth.principal : null;
  const principalRole = auth.status === "authenticated" ? auth.role : null;

  function handleNewChat(): void {
    // Abort any in-flight SSE first — otherwise the controller keeps
    // mirror-writing the just-aborted placeholder back into the cache
    // (`mirrorKey` write inside `useChatConversation.sendMessage`),
    // which is the exact stale-flash bug F005 closes. abort() is a
    // no-op when no stream is open.
    chat.abort();
    // Belt-and-suspenders alongside the placeholder-removal in
    // useChatConversation's `conversation_id` handler: if any prior
    // streamed conversation populated `conversationKey(null)` and
    // somehow survived (timing edge case, abort during promotion, etc.),
    // wipe it before navigating so the freshly-mounted hook reads an
    // empty cache rather than flashing stale messages. We use the
    // exported `conversationKey(null)` rather than reproducing the
    // triple inline (Constitution Principle VII — F006).
    queryClient.removeQueries({ queryKey: conversationKey(null) });
    const next = new URLSearchParams(searchParams);
    next.delete("conversation");
    setSearchParams(next, { replace: false });
  }

  function handleSelectConversation(id: string): void {
    const next = new URLSearchParams(searchParams);
    next.set("conversation", id);
    setSearchParams(next, { replace: false });
  }

  return (
    <>
      <TopBar
        pageContent={<ChatPageHeader />}
        actions={
          <>
            <button
              type="button"
              data-testid="chat-page-new"
              onClick={handleNewChat}
              className="flex items-center gap-1 rounded border border-r5e-border px-3 py-1.5 text-xs text-r5e-text transition-colors hover:border-r5e-accent hover:text-r5e-accent"
            >
              <MessageSquarePlus aria-hidden="true" className="h-3.5 w-3.5" />
              New chat
            </button>
            <HistoryDropdown
              activeId={conversationId}
              conversations={history.conversations}
              isLoading={history.isLoading}
              isError={history.isError}
              onSelect={handleSelectConversation}
            />
          </>
        }
      />
      <main
        data-testid="chat-page"
        className="flex min-h-0 flex-1 flex-col bg-r5e-bg"
      >
        <ChatThread
          chat={chat}
          principalSubject={principalSubject}
          principalRole={principalRole}
          fullHeight
          testId="chat-page-thread"
        />
      </main>
    </>
  );
}

// ---------------------------------------------------------------------------
// TopBar left slot — Sparkles + page title + tagline.
// ---------------------------------------------------------------------------

function ChatPageHeader(): JSX.Element {
  return (
    <div
      data-testid="chat-page-header"
      className="flex flex-col gap-0.5"
    >
      <h1 className="flex items-center gap-2 text-sm font-semibold text-r5e-text">
        <Sparkles aria-hidden="true" className="h-4 w-4 text-r5e-accent" />
        Audit Agent · Chat
      </h1>
      <p className="text-[11px] leading-tight text-r5e-muted">
        Ask questions about receipts, denials, and policy decisions.
      </p>
    </div>
  );
}

// ---------------------------------------------------------------------------
// History dropdown — past conversations.
// ---------------------------------------------------------------------------

function HistoryDropdown({
  activeId,
  conversations,
  isLoading,
  isError,
  onSelect,
}: {
  activeId: string | null;
  conversations: ChatConversationSummary[];
  isLoading: boolean;
  isError: boolean;
  onSelect: (id: string) => void;
}): JSX.Element {
  const [open, setOpen] = useState(false);

  // Close on outside click — basic implementation; a full popover would use
  // a portal but the dropdown is contained inside the TopBar so a simple
  // document listener is sufficient.
  useEffect(() => {
    if (!open) return;
    function handler(e: MouseEvent): void {
      const target = e.target as HTMLElement;
      if (!target.closest('[data-testid="chat-history-dropdown"]')) {
        setOpen(false);
      }
    }
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, [open]);

  // Hide entirely if we have no history AND fetch failed — the brief says
  // the dropdown is informational, not a hard requirement for the surface.
  if (isError && conversations.length === 0) {
    return <></>;
  }

  return (
    <div
      data-testid="chat-history-dropdown"
      className="relative"
    >
      <button
        type="button"
        data-testid="chat-history-toggle"
        aria-expanded={open}
        aria-haspopup="listbox"
        onClick={() => setOpen((o) => !o)}
        className="flex items-center gap-1 rounded border border-r5e-border px-3 py-1.5 text-xs text-r5e-text transition-colors hover:border-r5e-accent hover:text-r5e-accent"
      >
        History
        <ChevronDown aria-hidden="true" className="h-3.5 w-3.5" />
      </button>
      {open && (
        <div
          data-testid="chat-history-list"
          role="listbox"
          aria-label="Past conversations"
          className="absolute right-0 top-full z-30 mt-1 max-h-80 w-72 overflow-y-auto rounded border border-r5e-border bg-r5e-surface py-1 text-xs shadow-xl"
        >
          {isLoading && (
            <div
              data-testid="chat-history-loading-row"
              className="px-3 py-2 text-r5e-muted"
            >
              Loading conversations…
            </div>
          )}
          {!isLoading && conversations.length === 0 && (
            <div
              data-testid="chat-history-empty-row"
              className="px-3 py-2 text-r5e-muted"
            >
              No past conversations.
            </div>
          )}
          {!isLoading &&
            conversations.map((c) => (
              <button
                key={c.id}
                type="button"
                role="option"
                aria-selected={c.id === activeId}
                data-testid={`chat-history-row-${c.id}`}
                onClick={() => {
                  onSelect(c.id);
                  setOpen(false);
                }}
                className={`flex w-full flex-col items-start gap-0.5 px-3 py-2 text-left transition-colors ${
                  c.id === activeId
                    ? "bg-r5e-accent/15 text-r5e-text"
                    : "text-r5e-text hover:bg-r5e-bg"
                }`}
              >
                <span className="line-clamp-1 text-[11px] leading-tight">
                  {truncate(c.last_user_message_excerpt ?? "(untitled conversation)")}
                </span>
                <span className="text-[10px] text-r5e-muted">
                  {formatTimestamp(c.last_message_at ?? c.started_at)}
                </span>
              </button>
            ))}
        </div>
      )}
    </div>
  );
}

function formatTimestamp(iso: string): string {
  try {
    const d = new Date(iso);
    return d.toLocaleString(undefined, {
      month: "short",
      day: "numeric",
      hour: "numeric",
      minute: "2-digit",
    });
  } catch {
    return iso;
  }
}
