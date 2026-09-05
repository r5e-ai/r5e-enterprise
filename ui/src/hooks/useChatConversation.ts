// useChatConversation — TanStack-Query-backed hook for the Audit Agent
// chat surface (T119, Phase 6 US4).
//
// Per `contracts/audit_api_extensions.md` §"Chat (Audit Agent)" + spec
// FR-036 / FR-037 / FR-038 / FR-040 / FR-041 / FR-041a:
//   - `useChatConversation(conversationId | null)` returns the message list
//     for the conversation (or empty for a new conversation), plus a
//     `sendMessage` mutator that streams the agent's reply via SSE.
//   - Streaming updates the cache incrementally as `agent_token`,
//     `tool_call_start`, `tool_call_result`, `message_complete` events
//     arrive — TanStack Query is the source of truth, the component
//     re-renders on each cache write.
//   - The current `Message` shape is built up locally during a streaming
//     turn; on `message_complete` the cache entry is finalized.
//   - Conversation history is persisted server-side per FR-041a; this hook
//     fetches it via `GET /v1/chat/conversations/{id}` when a conversation
//     id is provided. Reload of the page replays history from the server.
//   - The hook never throws on transient `error` events — they are pushed
//     into the active message's `errors` list so the UI can surface them.

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";

import { api } from "~/lib/api";
import { apiPaths } from "~/lib/apiPaths";
import {
  ChatStreamError,
  sendChatMessage,
  type ChatErrorEvent,
} from "~/lib/chat_stream";

export type MessageStatus =
  | "idle"
  | "thinking"
  | "executing-tool"
  | "completed"
  | "failed";

export type ToolCallStatus = "running" | "success" | "error";

export interface ToolCall {
  /** Stable id for React keys; assigned client-side from the call order. */
  id: string;
  tool: string;
  args: unknown;
  status: ToolCallStatus;
  result?: unknown;
  /**
   * The attested run_id emitted by the per-tool `:ui_chat_skill_invoked_*`
   * event. Clicking this opens Receipt Detail per FR-038.
   */
  attestationRunId?: string | null;
  errorMessage?: string | null;
}

export interface ChatMessage {
  /** Stable client-side id; replaced by `message_id` from `message_complete`. */
  localId: string;
  serverId?: string;
  role: "user" | "assistant";
  content: string;
  toolCalls: ToolCall[];
  /** Set once `message_complete` arrives. */
  attestationRunId?: string | null;
  status: MessageStatus;
  errors: ChatErrorEvent[];
  createdAt: string;
}

export interface ConversationState {
  id: string | null;
  messages: ChatMessage[];
}

interface ConversationFetchEnvelope {
  id: string;
  started_at: string;
  messages: Array<{
    id: string;
    role: "user" | "agent";
    content: string;
    tool_calls: Array<{
      tool_name: string;
      args: unknown;
      result: unknown;
      attested_run_id: string | null;
    }>;
    attested_run_id: string | null;
    sequence: number;
    created_at: string;
  }>;
}

/**
 * Canonical TanStack-Query cache key shape for a chat conversation. Exported
 * so external consumers (e.g. `ChatPage.handleNewChat` clearing the
 * placeholder cache) don't reproduce the triple inline — any future change
 * to the key shape (tenant prefix, sentinel rename, additional segment) is
 * picked up automatically by every consumer.
 */
export const conversationKey = (id: string | null) =>
  ["chat", "conversation", id ?? "new"] as const;

function envelopeToState(envelope: ConversationFetchEnvelope): ConversationState {
  return {
    id: envelope.id,
    messages: envelope.messages.map((m, idx) => ({
      localId: `srv-${envelope.id}-${m.id}`,
      serverId: m.id,
      role: m.role === "agent" ? "assistant" : "user",
      content: m.content,
      toolCalls: m.tool_calls.map((tc, i) => ({
        id: `srv-${envelope.id}-${m.id}-${i}`,
        tool: tc.tool_name,
        args: tc.args,
        status: "success",
        result: tc.result,
        attestationRunId: tc.attested_run_id,
      })),
      attestationRunId: m.attested_run_id,
      status: "completed",
      errors: [],
      createdAt: m.created_at ?? `${envelope.started_at}-${idx}`,
    })),
  };
}

export interface UseChatConversationResult {
  state: ConversationState;
  isLoadingHistory: boolean;
  isHistoryError: boolean;
  /** True while a `sendMessage` SSE stream is open. */
  isStreaming: boolean;
  /** The latest assistant message's status, suitable for the activity strip. */
  activityStatus: MessageStatus;
  /** Most recent `error` event fired during the live stream (if any). */
  lastError: ChatStreamError | ChatErrorEvent | null;
  sendMessage: (content: string) => Promise<void>;
  /** Abort an in-flight stream (drawer close, route change). */
  abort: () => void;
  /** Re-run the history query (hooked up to the F5 ErrorState retry CTA). */
  refetchHistory: () => Promise<unknown>;
}

export function useChatConversation(
  conversationId: string | null,
): UseChatConversationResult {
  const queryClient = useQueryClient();

  const historyQuery = useQuery<ConversationState>({
    queryKey: conversationKey(conversationId),
    queryFn: async () => {
      if (!conversationId) {
        return { id: null, messages: [] };
      }
      const envelope = await api.get<ConversationFetchEnvelope>(
        apiPaths.chat.conversationDetail(conversationId),
      );
      return envelopeToState(envelope);
    },
    staleTime: 10_000,
    retry: false,
  });

  const cachedState: ConversationState = useMemo(
    () => historyQuery.data ?? { id: conversationId, messages: [] },
    [historyQuery.data, conversationId],
  );

  const [isStreaming, setIsStreaming] = useState(false);
  const [activityStatus, setActivityStatus] = useState<MessageStatus>("idle");
  const [lastError, setLastError] = useState<
    ChatStreamError | ChatErrorEvent | null
  >(null);

  const abortRef = useRef<AbortController | null>(null);

  const writeState = useCallback(
    (
      key: ReturnType<typeof conversationKey>,
      updater: (prev: ConversationState) => ConversationState,
    ) => {
      queryClient.setQueryData<ConversationState>(key, (old) =>
        updater(old ?? { id: conversationId, messages: [] }),
      );
    },
    [queryClient, conversationId],
  );

  const sendMessage = useCallback(
    async (content: string): Promise<void> => {
      if (!content.trim()) return;
      if (isStreaming) return;

      setLastError(null);
      setIsStreaming(true);

      const startKey = conversationKey(conversationId);
      const userLocalId = `local-user-${Date.now()}`;
      const assistantLocalId = `local-asst-${Date.now() + 1}`;
      const activeKey = startKey;
      // Tension between two requirements during a "new conversation" stream:
      //   (a) The active hook is subscribed to `conversationKey(null)`
      //       until the parent surface promotes the freshly-minted id into
      //       the URL — so live writes MUST keep landing on the placeholder
      //       for the in-flight UI to update.
      //   (b) Once the URL is promoted and the component re-mounts on
      //       `conversationKey(<newId>)`, the placeholder MUST be wiped —
      //       otherwise a "New chat" click within `staleTime: 10_000` re-
      //       mounts on the still-populated placeholder and flashes the
      //       prior conversation's messages before the queryFn re-runs.
      // Strategy: mirror writes to BOTH keys during the stream
      // (preserves live-UI behaviour) + drop the placeholder in `finally`
      // once the stream settles AND the new-id mirror is populated.
      // ChatPage.handleNewChat ALSO wipes the placeholder defensively so
      // edge cases (abort during promotion, network failure mid-stream)
      // can't pollute future "New chat" remounts.
      let mirrorKey: ReturnType<typeof conversationKey> | null = null;

      // Optimistically append the user message + a placeholder assistant
      // message so the UI updates immediately on submit.
      writeState(startKey, (prev) => ({
        ...prev,
        messages: [
          ...prev.messages,
          {
            localId: userLocalId,
            role: "user",
            content,
            toolCalls: [],
            status: "completed",
            errors: [],
            createdAt: new Date().toISOString(),
          },
          {
            localId: assistantLocalId,
            role: "assistant",
            content: "",
            toolCalls: [],
            status: "thinking",
            errors: [],
            createdAt: new Date().toISOString(),
          },
        ],
      }));
      setActivityStatus("thinking");

      const controller = new AbortController();
      abortRef.current = controller;

      const updateAssistant = (
        mutator: (msg: ChatMessage) => ChatMessage,
      ): void => {
        const updater = (prev: ConversationState): ConversationState => ({
          ...prev,
          messages: prev.messages.map((m) =>
            m.localId === assistantLocalId ? mutator(m) : m,
          ),
        });
        writeState(activeKey, updater);
        if (mirrorKey) writeState(mirrorKey, updater);
      };

      try {
        const stream = sendChatMessage(
          { conversation_id: conversationId, content },
          { signal: controller.signal },
        );

        for await (const event of stream) {
          switch (event.type) {
            case "conversation_id": {
              const newId = event.data.conversation_id;
              if (!conversationId && newId) {
                // Promote: keep writing to the placeholder key (the active
                // hook is still subscribed there until the parent surface
                // updates the URL) AND mirror writes to the new key so the
                // post-navigation re-mount reads live data immediately.
                // The placeholder is wiped in `finally` once the stream
                // has settled — see the comment on `mirrorKey` above.
                const newKey = conversationKey(newId);
                const promoted: ConversationState | undefined =
                  queryClient.getQueryData<ConversationState>(activeKey);
                if (promoted) {
                  const promotedNext: ConversationState = {
                    ...promoted,
                    id: newId,
                  };
                  queryClient.setQueryData<ConversationState>(
                    activeKey,
                    promotedNext,
                  );
                  queryClient.setQueryData<ConversationState>(
                    newKey,
                    promotedNext,
                  );
                  mirrorKey = newKey;
                }
              } else {
                writeState(activeKey, (prev) => ({ ...prev, id: newId }));
              }
              break;
            }
            case "agent_token": {
              setActivityStatus("thinking");
              updateAssistant((m) => ({
                ...m,
                content: m.content + event.data.delta,
                status: "thinking",
              }));
              break;
            }
            case "tool_call_start": {
              setActivityStatus("executing-tool");
              updateAssistant((m) => ({
                ...m,
                status: "executing-tool",
                toolCalls: [
                  ...m.toolCalls,
                  {
                    id: `tc-${m.toolCalls.length}-${event.data.tool_name}`,
                    tool: event.data.tool_name,
                    args: event.data.args,
                    status: "running",
                    attestationRunId: event.data.attested_run_id ?? null,
                  },
                ],
              }));
              break;
            }
            case "tool_call_result": {
              // Per `audit_api_extensions.md` §POST /v1/chat/messages, the
              // `tool_call_result` envelope carries `{tool_name, result,
              // attested_run_id}` only — no `outcome` field. Tool failures
              // are delivered out-of-band as `event: error` carrying the
              // canonical flat error envelope. Treat every `tool_call_result`
              // as a success transition; the `case "error"` branch below
              // promotes the matching running tool call to `status: "error"`.
              // (The `outcome` field IS attested in the per-tool server-side
              // event_kind per `audit_agent_tools.md` — but that lives on the
              // ledger, not on the SSE wire.)
              setActivityStatus("thinking");
              updateAssistant((m) => {
                const idx = [...m.toolCalls]
                  .reverse()
                  .findIndex(
                    (tc) =>
                      tc.tool === event.data.tool_name && tc.status === "running",
                  );
                const realIdx =
                  idx === -1 ? -1 : m.toolCalls.length - 1 - idx;
                const next = [...m.toolCalls];
                if (realIdx >= 0) {
                  const target = next[realIdx]!;
                  next[realIdx] = {
                    ...target,
                    status: "success",
                    result: event.data.result,
                    attestationRunId:
                      event.data.attested_run_id ?? target.attestationRunId,
                  };
                } else {
                  next.push({
                    id: `tc-orphan-${next.length}`,
                    tool: event.data.tool_name,
                    args: undefined,
                    status: "success",
                    result: event.data.result,
                    attestationRunId: event.data.attested_run_id ?? null,
                  });
                }
                return { ...m, toolCalls: next, status: "thinking" };
              });
              break;
            }
            case "message_complete": {
              setActivityStatus("completed");
              updateAssistant((m) => ({
                ...m,
                serverId: event.data.message_id,
                attestationRunId: event.data.attested_run_id ?? null,
                status: "completed",
              }));
              break;
            }
            case "error": {
              // Recoverable per the contract — record it and keep streaming.
              // ALSO: per audit_api_extensions §"Per-event errors", a tool
              // failure is delivered as `event: error` while the matching
              // `tool_call_start` is still in `status: "running"`. We
              // promote the most-recent running tool call (if any) to
              // `status: "error"` with the envelope's `error_description`
              // surfaced inline via `errorMessage` — without this transition
              // the tool block stays stuck on the spinner forever.
              setLastError(event.data);
              const errorDescription = event.data.error_description;
              updateAssistant((m) => {
                const reverseIdx = [...m.toolCalls]
                  .reverse()
                  .findIndex((tc) => tc.status === "running");
                const realIdx =
                  reverseIdx === -1
                    ? -1
                    : m.toolCalls.length - 1 - reverseIdx;
                const nextCalls =
                  realIdx >= 0
                    ? m.toolCalls.map((tc, i) =>
                        i === realIdx
                          ? {
                              ...tc,
                              status: "error" as const,
                              errorMessage: errorDescription,
                            }
                          : tc,
                      )
                    : m.toolCalls;
                return {
                  ...m,
                  toolCalls: nextCalls,
                  errors: [...m.errors, event.data],
                };
              });
              break;
            }
          }
        }
      } catch (err) {
        // Initial-response failure (auth, 403, etc.) OR stream abort.
        if (err instanceof ChatStreamError) {
          setLastError(err);
          updateAssistant((m) => ({
            ...m,
            status: "failed",
            errors: [
              ...m.errors,
              {
                error: err.error,
                error_description: err.error_description,
                correlation_id: err.correlation_id,
                attested_run_id: err.attested_run_id,
              },
            ],
          }));
          setActivityStatus("failed");
        } else if ((err as Error)?.name === "AbortError") {
          updateAssistant((m) => ({
            ...m,
            status: m.status === "completed" ? m.status : "failed",
          }));
          setActivityStatus("idle");
        } else {
          const message =
            err instanceof Error ? err.message : "Unknown stream failure";
          setLastError({
            error: "stream_failure",
            error_description: message,
            correlation_id: "unknown",
          });
          updateAssistant((m) => ({ ...m, status: "failed" }));
          setActivityStatus("failed");
        }
      } finally {
        setIsStreaming(false);
        abortRef.current = null;
        // Drop the placeholder key once promotion has happened — the
        // mirrored data lives on `mirrorKey` (the new id), and leaving the
        // placeholder populated would let a subsequent "New chat" click
        // re-mount on it within the 10s staleTime and flash the just-
        // completed conversation. Only safe to do once `mirrorKey` is set
        // (i.e. promotion actually occurred); for resumed conversations
        // (`conversationId !== null` from the URL) the placeholder was
        // never written to in the first place.
        if (mirrorKey) {
          queryClient.removeQueries({ queryKey: startKey });
        }
      }
    },
    [conversationId, isStreaming, queryClient, writeState],
  );

  const abort = useCallback((): void => {
    abortRef.current?.abort();
  }, []);

  // Lifecycle cleanup (F005). The SSE consumer holds an AbortController
  // that the parent surface (ChatPage / ChatDrawer) cannot directly see.
  // We MUST tear it down on unmount (drawer close, route change, parent
  // surface swap) — otherwise the stream keeps writing into a cache
  // entry no live consumer is rendering. The drawer-close + handleNewChat
  // call sites also call `abort()` explicitly to short-circuit the
  // mirror-write race; this effect is the safety net for paths that
  // route-change via other means (programmatic navigate(), back/forward).
  //
  // We do NOT key this on `conversationId`. The promotion path
  // (`?conversation=<newId>` getting set after the SSE emits the
  // conversation_id event) re-renders the hook with a fresh `conversationId`
  // arg DURING the active stream — aborting on that boundary would tear
  // down the very stream that just promoted the id, losing every event
  // that follows (tool_call_start, tool_call_result, message_complete,
  // and importantly `error` events). Instead, the mirror-key write logic
  // inside `sendMessage` keeps the live UI synced to whichever key the
  // re-mounted hook subscribes to.
  useEffect(() => {
    return () => {
      abortRef.current?.abort();
    };
  }, []);

  const refetchHistory = useCallback(
    () => historyQuery.refetch(),
    [historyQuery],
  );

  return useMemo<UseChatConversationResult>(
    () => ({
      state: cachedState,
      isLoadingHistory: historyQuery.isLoading,
      isHistoryError: historyQuery.isError,
      isStreaming,
      activityStatus,
      lastError,
      sendMessage,
      abort,
      refetchHistory,
    }),
    [
      cachedState,
      historyQuery.isLoading,
      historyQuery.isError,
      isStreaming,
      activityStatus,
      lastError,
      sendMessage,
      abort,
      refetchHistory,
    ],
  );
}
