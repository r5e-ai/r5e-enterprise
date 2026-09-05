// ChatDrawer — slide-in 480px right-rail overlay for the Audit Agent chat.
//
// Per `design/briefs/06-chat-drawer.md` (F5 redesign) + spec FR-036/037/039:
//   - 480px right-rail drawer, mounted in <AuthenticatedShell /> so it's
//     reachable from every authenticated route.
//   - Drawer state lives in the URL (`?chat=open`) so it survives reloads
//     and is shareable. `useChatDrawer()` exposes `isOpen` + toggle helpers.
//   - The drawer wraps the shared <ChatThread />; the standalone full-page
//     surface (<ChatPage />) wraps the same component (Constitution
//     Principle VII: extract on the second consumer).
//   - Header shows ✦ Sparkles + "Chat with Audit Agent" + tagline + close.
//   - Conversation persists server-side; `?conversation=<uuid>` resumes
//     a prior conversation. Freshly-minted ids are promoted into the URL
//     once the SSE stream emits the conversation_id event.

import { Sparkles, X } from "lucide-react";
import { useEffect } from "react";
import { useLocation, useNavigate, useSearchParams } from "react-router-dom";

import { ChatThread } from "~/components/chat/ChatThread";
import { useAuth } from "~/hooks/useAuth";
import { useChatConversation } from "~/hooks/useChatConversation";
import { useChatDrawer } from "~/hooks/useChatDrawer";

// ---------------------------------------------------------------------------
// The drawer itself.
// ---------------------------------------------------------------------------

export default function ChatDrawer(): JSX.Element | null {
  const auth = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [searchParams] = useSearchParams();
  const drawer = useChatDrawer();

  // The conversation id is sticky in the URL so refresh/share works.
  const conversationId = searchParams.get("conversation");
  const chat = useChatConversation(conversationId);

  // Promote a freshly-minted conversation id into the URL once the SSE
  // stream emits it (so reloads land on the same conversation).
  useEffect(() => {
    if (!conversationId && chat.state.id) {
      const next = new URLSearchParams(searchParams);
      next.set("conversation", chat.state.id);
      navigate(`${location.pathname}?${next.toString()}`, { replace: true });
    }
  }, [conversationId, chat.state.id, location.pathname, navigate, searchParams]);

  // The drawer renders ONLY when `?chat=open` is present. The standalone
  // route `/admin/chat` is its own page (<ChatPage />) and does NOT mount
  // the drawer overlay — that would double-render the conversation surface.
  if (!drawer.isOpen) return null;
  // BrowserRouter mounts under basename="/admin", so location.pathname
  // arrives basename-stripped — the standalone chat route surfaces here as
  // "/chat", not "/admin/chat". (Comparing against `routes.chat` would
  // never match and was dead code.)
  if (location.pathname === "/chat") return null;

  const principalSubject =
    auth.status === "authenticated" ? auth.principal : null;
  const principalRole = auth.status === "authenticated" ? auth.role : null;

  // Closing the drawer mid-stream MUST abort the SSE connection. Without
  // this the in-flight controller keeps writing tokens into the cache for
  // a surface the user can no longer see — and the `mirrorKey` write on
  // `conversation_id` events would silently leak state past the close
  // (F005 from MR !93 fix-pass-2 GAN). `chat.abort()` is a no-op when no
  // stream is open, so it's safe to call on every close.
  const handleClose = (): void => {
    chat.abort();
    drawer.close();
  };

  return (
    <>
      {/* Backdrop — clicking it closes the drawer. */}
      <div
        aria-hidden="true"
        onClick={handleClose}
        data-testid="chat-drawer-backdrop"
        className="fixed inset-0 z-30 bg-black/40"
      />

      <aside
        role="complementary"
        aria-label="Audit Agent chat"
        data-testid="chat-drawer"
        className="fixed inset-y-0 right-0 z-40 flex w-[480px] flex-col border-l border-r5e-border bg-r5e-bg text-r5e-text shadow-xl"
      >
        <ChatHeader onClose={handleClose} />
        <ChatThread
          chat={chat}
          principalSubject={principalSubject}
          principalRole={principalRole}
          testId="chat-drawer-thread"
        />
      </aside>
    </>
  );
}

// ---------------------------------------------------------------------------
// Drawer header — Sparkles + title + close button (per the brief).
// ---------------------------------------------------------------------------

function ChatHeader({ onClose }: { onClose: () => void }): JSX.Element {
  return (
    <header
      data-testid="chat-drawer-header"
      className="flex shrink-0 items-start justify-between border-b border-r5e-border bg-r5e-surface px-4 py-3"
    >
      <div className="flex flex-col gap-0.5">
        <h2 className="flex items-center gap-2 text-sm font-semibold text-r5e-text">
          <Sparkles
            aria-hidden="true"
            className="h-4 w-4 text-r5e-accent"
            data-testid="chat-drawer-sparkles"
          />
          Chat with Audit Agent
        </h2>
        <p className="text-[11px] leading-tight text-r5e-muted">
          Ask questions about receipts, denials, and policy decisions.
        </p>
      </div>
      <button
        type="button"
        onClick={onClose}
        aria-label="Close chat drawer"
        data-testid="chat-drawer-close"
        className="rounded border border-r5e-border p-1 text-r5e-muted transition-colors hover:border-r5e-text hover:text-r5e-text"
      >
        <X aria-hidden="true" className="h-4 w-4" />
      </button>
    </header>
  );
}
