// Vitest unit tests for the F5 shared <ChatThread /> component.
//
// Asserts the brief's contract points (design/briefs/06-chat-drawer.md):
//   - Empty conversation → suggested-prompt cards visible.
//   - Clicking a suggested-prompt card submits as a user message by
//     invoking `chat.sendMessage` directly (lifted-state pattern; the
//     previous `chat:prefill` window CustomEvent dance was retired in MR
//     !93's fix-pass per Constitution Principle VII feedback).
//   - Composer: Cmd/Ctrl+Enter submits, bare Enter inserts a newline.
//   - Composer: Send disabled when empty; Stop replaces Send while streaming.
//   - History fetch error → ErrorState with Retry button.
//   - History loading → 3 skeleton blocks.

import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { MemoryRouter } from "react-router-dom";

import { ChatThread } from "~/components/chat/ChatThread";
import type { UseChatConversationResult } from "~/hooks/useChatConversation";

function makeChat(
  overrides: Partial<UseChatConversationResult> = {},
): UseChatConversationResult {
  const refetchHistory = vi.fn().mockResolvedValue({});
  const sendMessage = vi.fn().mockResolvedValue(undefined);
  const abort = vi.fn();
  return {
    state: { id: null, messages: [] },
    isLoadingHistory: false,
    isHistoryError: false,
    isStreaming: false,
    activityStatus: "idle",
    lastError: null,
    sendMessage,
    abort,
    refetchHistory,
    ...overrides,
  };
}

function renderThread(chat: UseChatConversationResult) {
  return render(
    <MemoryRouter basename="/admin" initialEntries={["/admin/chat"]}>
      <ChatThread
        chat={chat}
        principalSubject="alice@corp"
        principalRole="tenant_auditor"
      />
    </MemoryRouter>,
  );
}

describe("ChatThread — F5 Audit Agent shared surface", () => {
  it("renders four suggested-prompt cards when the conversation is empty", () => {
    renderThread(makeChat());
    const prompts = screen.getByTestId("chat-suggested-prompts");
    expect(prompts).toBeInTheDocument();
    const cards = screen.getAllByRole("button", {
      name: /(denied|hour|similar|busiest)/i,
    });
    expect(cards.length).toBeGreaterThanOrEqual(4);
  });

  it("hides the suggested-prompt cards once the conversation has messages", () => {
    const chat = makeChat({
      state: {
        id: "conv-1",
        messages: [
          {
            localId: "u-1",
            role: "user",
            content: "hello",
            toolCalls: [],
            status: "completed",
            errors: [],
            createdAt: "2026-05-01T12:00:00Z",
          },
        ],
      },
    });
    renderThread(chat);
    expect(screen.queryByTestId("chat-suggested-prompts")).toBeNull();
    expect(screen.getByTestId("message-bubble-user")).toBeInTheDocument();
  });

  it("clicking a suggested-prompt card submits as a user message", () => {
    const chat = makeChat();
    renderThread(chat);
    const firstCard = screen.getAllByRole("button")[0]!;
    fireEvent.click(firstCard);
    expect(chat.sendMessage).toHaveBeenCalledTimes(1);
    expect(chat.sendMessage).toHaveBeenCalledWith(
      expect.stringMatching(/.+/),
    );
  });

  it("composer Send is disabled when input is empty", () => {
    renderThread(makeChat());
    const send = screen.getByTestId("chat-send");
    expect(send).toBeDisabled();
  });

  it("composer Cmd+Enter submits the typed message", () => {
    const chat = makeChat();
    renderThread(chat);
    const input = screen.getByTestId("chat-input") as HTMLTextAreaElement;
    fireEvent.change(input, { target: { value: "what was denied?" } });
    fireEvent.keyDown(input, { key: "Enter", metaKey: true });
    expect(chat.sendMessage).toHaveBeenCalledWith("what was denied?");
  });

  it("composer Ctrl+Enter submits the typed message (Windows/Linux)", () => {
    const chat = makeChat();
    renderThread(chat);
    const input = screen.getByTestId("chat-input") as HTMLTextAreaElement;
    fireEvent.change(input, { target: { value: "explain that deny" } });
    fireEvent.keyDown(input, { key: "Enter", ctrlKey: true });
    expect(chat.sendMessage).toHaveBeenCalledWith("explain that deny");
  });

  it("composer bare Enter does NOT submit (allows newline insertion)", () => {
    const chat = makeChat();
    renderThread(chat);
    const input = screen.getByTestId("chat-input") as HTMLTextAreaElement;
    fireEvent.change(input, { target: { value: "line one" } });
    fireEvent.keyDown(input, { key: "Enter" });
    expect(chat.sendMessage).not.toHaveBeenCalled();
  });

  it("Stop button replaces Send while streaming + cancels the stream", () => {
    const chat = makeChat({ isStreaming: true });
    renderThread(chat);
    expect(screen.queryByTestId("chat-send")).toBeNull();
    const stop = screen.getByTestId("chat-stop");
    fireEvent.click(stop);
    expect(chat.abort).toHaveBeenCalledTimes(1);
  });

  it("renders 3 skeleton blocks during initial history load", () => {
    renderThread(makeChat({ isLoadingHistory: true }));
    expect(screen.getByTestId("chat-history-loading")).toBeInTheDocument();
    // 3 Skeleton.Block instances per the brief.
    expect(screen.getAllByTestId("skeleton-block")).toHaveLength(3);
  });

  it("renders ErrorState with retry on history fetch failure", () => {
    const chat = makeChat({ isHistoryError: true });
    renderThread(chat);
    const err = screen.getByTestId("chat-history-error");
    expect(err).toBeInTheDocument();
    const retry = screen.getByTestId("chat-history-error-retry");
    fireEvent.click(retry);
    expect(chat.refetchHistory).toHaveBeenCalledTimes(1);
  });

  it("activity strip surfaces 'thinking' status", () => {
    const chat = makeChat({
      activityStatus: "thinking",
      state: {
        id: "c1",
        messages: [
          {
            localId: "u-1",
            role: "user",
            content: "hi",
            toolCalls: [],
            status: "completed",
            errors: [],
            createdAt: "2026-05-01T12:00:00Z",
          },
        ],
      },
    });
    renderThread(chat);
    const strip = screen.getByTestId("chat-activity-strip");
    expect(strip).toHaveAttribute("data-status", "thinking");
  });
});
