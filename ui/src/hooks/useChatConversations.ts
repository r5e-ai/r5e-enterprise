// useChatConversations — list past conversations for the standalone
// <ChatPage /> history dropdown (F5 redesign).
//
// Per `design/briefs/06-chat-drawer.md` §"Conversation persistence":
//   - Conversations are stored server-side (per the F004 spec — conversations
//     are stored attestations themselves).
//   - The auditor can resume the latest conversation OR start a new one.
//   - The history dropdown lists past conversations (truncated titles +
//     timestamps) — that's what this hook backs.
//
// Per `contracts/audit_api_extensions.md` the list endpoint is
// `GET /v1/chat/conversations`. The backend response shape is intentionally
// thin (id + started_at + first user message preview) so we can render a
// dropdown without paying for full message hydration.
//
// If/when the endpoint isn't yet wired in a given environment, the hook
// surfaces the error to the caller — the standalone page falls back to
// hiding the dropdown rather than blocking the surface.

import { useQuery } from "@tanstack/react-query";

import { api } from "~/lib/api";
import { apiPaths } from "~/lib/apiPaths";

/**
 * A row in the history dropdown. Field names mirror the
 * `GET /v1/chat/conversations` envelope in
 * `specs/004-audit-console/contracts/audit_api_extensions.md`:
 *
 *   { id, started_at, last_message_at, last_user_message_excerpt }
 *
 * The legacy `title` / `preview` / `updated_at` aliases were never wired on
 * the backend (chat_handler.ex emits the contract names) — keeping them as
 * Conversation hook fields would render every row as "(untitled
 * conversation)" against a real audit plane.
 */
export interface ChatConversationSummary {
  id: string;
  /** ISO 8601 timestamp the conversation was first opened. */
  started_at: string;
  /** ISO 8601 timestamp of the most recent message; used for sorting. */
  last_message_at?: string | null;
  /** Truncated first user-message body — falls back to "(untitled…)". */
  last_user_message_excerpt?: string | null;
  /** Whether the conversation was soft-deleted (forensic-read flag). */
  deleted?: boolean | null;
}

interface ConversationsListEnvelope {
  conversations: ChatConversationSummary[];
}

const QUERY_KEY = ["chat", "conversations", "list"] as const;

export interface UseChatConversationsResult {
  conversations: ChatConversationSummary[];
  isLoading: boolean;
  isError: boolean;
  refetch: () => Promise<unknown>;
}

export function useChatConversations(): UseChatConversationsResult {
  const query = useQuery<ConversationsListEnvelope>({
    queryKey: QUERY_KEY,
    queryFn: () => api.get<ConversationsListEnvelope>(apiPaths.chat.conversations),
    staleTime: 30_000,
    retry: false,
  });

  const conversations = (query.data?.conversations ?? [])
    .slice()
    .filter((c) => !c.deleted)
    .sort((a, b) => {
      const aTime = a.last_message_at ?? a.started_at;
      const bTime = b.last_message_at ?? b.started_at;
      return bTime.localeCompare(aTime);
    });

  return {
    conversations,
    isLoading: query.isLoading,
    isError: query.isError,
    refetch: () => query.refetch(),
  };
}
