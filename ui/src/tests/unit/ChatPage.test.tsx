// Vitest unit tests for the F5 standalone <ChatPage /> route surface.
//
// Per design/briefs/06-chat-drawer.md:
//   - Standalone full-page chat at `/admin/chat` (TopBar + thread).
//   - "New chat" button clears `?conversation=` from the URL.
//   - History dropdown lists past conversations; clicking a row sets
//     `?conversation=<id>` so the thread loads that history.
//   - The page mounts the SHARED <ChatThread /> via `chat-page-thread`.

import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

import ChatPage from "~/pages/ChatPage";

// ---- Mocks ----------------------------------------------------------------

vi.mock("~/hooks/useAuth", () => ({
  useAuth: () => ({
    status: "authenticated",
    role: "tenant_auditor",
    principal: "alice@corp",
    tenantId: "tenant-a",
  }),
}));

const sendMessageMock = vi.fn().mockResolvedValue(undefined);
const abortMock = vi.fn();
const refetchHistoryMock = vi.fn().mockResolvedValue({});

vi.mock("~/hooks/useChatConversation", () => ({
  useChatConversation: () => ({
    state: { id: null, messages: [] },
    isLoadingHistory: false,
    isHistoryError: false,
    isStreaming: false,
    activityStatus: "idle",
    lastError: null,
    sendMessage: sendMessageMock,
    abort: abortMock,
    refetchHistory: refetchHistoryMock,
  }),
}));

// Mirror the `GET /v1/chat/conversations` envelope per
// `specs/004-audit-console/contracts/audit_api_extensions.md` —
// `last_message_at` and `last_user_message_excerpt` are the canonical
// fields; the legacy `updated_at` / `title` / `preview` mirror was a hook
// bug fixed alongside this MR.
const conversationsState = {
  conversations: [
    {
      id: "conv-old-1",
      started_at: "2026-04-30T18:30:00Z",
      last_message_at: "2026-04-30T18:35:00Z",
      last_user_message_excerpt: "Why was Alice's bash denied?",
      deleted: false,
    },
    {
      id: "conv-old-2",
      started_at: "2026-04-29T11:00:00Z",
      last_message_at: "2026-04-29T11:05:00Z",
      last_user_message_excerpt: "Show me all denials in the last hour.",
      deleted: false,
    },
  ],
  isLoading: false,
  isError: false,
  refetch: () => Promise.resolve({}),
};

vi.mock("~/hooks/useChatConversations", () => ({
  useChatConversations: () => conversationsState,
}));

// ---- Helpers --------------------------------------------------------------

function renderAt(path: string) {
  // ChatPage now reads `useQueryClient` directly (added in MR !93's
  // fix-pass to support the `handleNewChat` placeholder-cache wipe), so
  // tests must wrap with a QueryClientProvider. Each test gets its own
  // client so cache state never leaks across cases.
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter basename="/admin" initialEntries={[path]}>
        <ChatPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("ChatPage — F5 standalone chat surface", () => {
  it("renders the page header with sparkles + title + tagline", () => {
    renderAt("/admin/chat");
    const header = screen.getByTestId("chat-page-header");
    expect(header).toHaveTextContent(/Audit Agent/i);
    expect(header).toHaveTextContent(/Ask questions about receipts/i);
  });

  it("renders the shared <ChatThread /> via chat-page-thread", () => {
    renderAt("/admin/chat");
    expect(screen.getByTestId("chat-page-thread")).toBeInTheDocument();
  });

  it("renders 'New chat' button + History dropdown in TopBar actions", () => {
    renderAt("/admin/chat");
    expect(screen.getByTestId("chat-page-new")).toBeInTheDocument();
    expect(screen.getByTestId("chat-history-toggle")).toBeInTheDocument();
  });

  it("History dropdown opens on click and lists past conversations", () => {
    renderAt("/admin/chat");
    fireEvent.click(screen.getByTestId("chat-history-toggle"));
    const list = screen.getByTestId("chat-history-list");
    expect(list).toBeInTheDocument();
    expect(screen.getByTestId("chat-history-row-conv-old-1")).toHaveTextContent(
      /Why was Alice/i,
    );
    expect(screen.getByTestId("chat-history-row-conv-old-2")).toHaveTextContent(
      /Show me all denials/i,
    );
  });
});
