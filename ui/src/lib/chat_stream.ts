// Chat SSE streaming consumer (T119 — Phase 6 US4).
//
// Per `contracts/audit_api_extensions.md` §"Chat (Audit Agent)":
//   - The chat surface POSTs `{conversation_id, content}` to
//     `/v1/chat/messages` and receives a `text/event-stream` response.
//   - Native `EventSource` only supports GET, so we read the response body
//     as a `ReadableStream<Uint8Array>` and parse the SSE wire format
//     (`event: <type>\ndata: <json>\n\n`) ourselves.
//   - Seven event types are emitted by the backend:
//       * conversation_id      — once at start, carries the conversation uuid
//       * agent_token          — streaming agent text deltas
//       * tool_call_start      — the agent invoked a tool
//       * tool_call_result     — a tool returned (success or error)
//       * message_complete     — the assistant message finished cleanly
//       * error                — recoverable error (connection stays open)
//       * (server may close)   — stream end, no event payload
//   - Recoverable errors are surfaced as `error` events without closing
//     the stream; fatal errors close the stream after emitting `error`.
//
// This module is intentionally framework-free so it can be exercised in
// vitest without React. The hook in `~/hooks/useChatConversation.ts` is the
// React adapter that wires this consumer into TanStack Query's cache.

/* eslint-disable @typescript-eslint/no-explicit-any */

import { apiPaths } from "~/lib/apiPaths";

/** SSE event payloads emitted by `POST /v1/chat/messages`. */
export interface ConversationIdEvent {
  conversation_id: string;
}

export interface AgentTokenEvent {
  delta: string;
}

export interface ToolCallStartEvent {
  tool_name: string;
  args: unknown;
  attested_run_id?: string | null;
}

export interface ToolCallResultEvent {
  tool_name: string;
  result: unknown;
  attested_run_id?: string | null;
  // NOTE: `outcome` is intentionally NOT on the wire envelope. Per
  // `audit_api_extensions.md` §POST /v1/chat/messages, tool failures are
  // delivered out-of-band as `event: error` carrying the canonical flat
  // error envelope (`priv/schemas/error_envelope.json`). The `outcome`
  // field IS attested on the per-tool server-side `event_kind`
  // (`audit_agent_tools.md`) — but that lives on the ledger, not on the
  // SSE wire.
}

export interface MessageCompleteEvent {
  message_id: string;
  attested_run_id?: string | null;
}

/** F001 envelope shape, mirrored from `~/lib/api.ts`. */
export interface ChatErrorEvent {
  error: string;
  error_description: string;
  correlation_id: string;
  attested_run_id?: string | null;
}

export type ChatStreamEvent =
  | { type: "conversation_id"; data: ConversationIdEvent }
  | { type: "agent_token"; data: AgentTokenEvent }
  | { type: "tool_call_start"; data: ToolCallStartEvent }
  | { type: "tool_call_result"; data: ToolCallResultEvent }
  | { type: "message_complete"; data: MessageCompleteEvent }
  | { type: "error"; data: ChatErrorEvent };

export interface SendMessageInput {
  /** `null` to start a new conversation; uuid to continue an existing one. */
  conversation_id: string | null;
  content: string;
}

export interface ChatStreamOptions {
  /** Override for tests (defaults to global `fetch`). */
  fetchImpl?: typeof fetch;
  /** Allow callers to abort an in-flight stream (drawer close, route change). */
  signal?: AbortSignal;
  /** Request URL override; defaults to `/v1/chat/messages`. */
  path?: string;
}

const CHAT_PATH = apiPaths.chat.messages;

/**
 * Open an SSE stream for `POST /v1/chat/messages` and yield each parsed event
 * as it arrives. Backpressure is implicit — the consumer awaits each event
 * before pulling the next chunk. The async iterator terminates when the
 * server closes the stream OR the abort signal fires.
 *
 * Caller responsibility:
 *   - Build the `Message` shape incrementally from emitted events.
 *   - Handle non-200 initial responses (auth, 403, 404) by checking the
 *     thrown `ChatStreamError`.
 */
export async function* sendChatMessage(
  input: SendMessageInput,
  options: ChatStreamOptions = {},
): AsyncGenerator<ChatStreamEvent, void, void> {
  const fetchImpl = options.fetchImpl ?? fetch;
  const path = options.path ?? CHAT_PATH;

  const response = await fetchImpl(path, {
    method: "POST",
    credentials: "include",
    headers: {
      "Content-Type": "application/json",
      Accept: "text/event-stream",
    },
    body: JSON.stringify(input),
    signal: options.signal,
  });

  if (!response.ok) {
    let envelope: Partial<ChatErrorEvent> = {};
    try {
      envelope = (await response.json()) as Partial<ChatErrorEvent>;
    } catch {
      /* non-JSON body — synthesize below */
    }
    throw new ChatStreamError({
      error: envelope.error ?? "unknown_error",
      error_description: envelope.error_description ?? `HTTP ${response.status}`,
      correlation_id: envelope.correlation_id ?? "unknown",
      attested_run_id: envelope.attested_run_id ?? null,
      status: response.status,
    });
  }

  if (!response.body) {
    throw new ChatStreamError({
      error: "no_stream_body",
      error_description: "Server returned 200 with no readable body",
      correlation_id: "unknown",
      attested_run_id: null,
      status: response.status,
    });
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder("utf-8");
  let buffer = "";

  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });

      // Parse all complete events in the buffer (split on the SSE event
      // delimiter \n\n). The trailing fragment may be a partial event;
      // keep it in the buffer for the next chunk.
      let delimiterIdx: number;
      while ((delimiterIdx = buffer.indexOf("\n\n")) !== -1) {
        const raw = buffer.slice(0, delimiterIdx);
        buffer = buffer.slice(delimiterIdx + 2);
        const parsed = parseSseEvent(raw);
        if (parsed) yield parsed;
      }
    }
    // Flush any trailing event without the delimiter (rare; some servers
    // omit the trailing \n\n on stream close).
    if (buffer.trim().length > 0) {
      const parsed = parseSseEvent(buffer);
      if (parsed) yield parsed;
    }
  } finally {
    try {
      reader.releaseLock();
    } catch {
      /* ignore */
    }
  }
}

/**
 * Parse a single SSE event block of the form:
 *
 *   event: <type>
 *   data: <json>
 *
 * Returns `null` when the block is malformed (no event/data line) so the
 * consumer can keep going — drift between SPA and API mid-deploy must not
 * tear down the chat surface.
 */
export function parseSseEvent(raw: string): ChatStreamEvent | null {
  if (!raw.trim()) return null;
  const lines = raw.split("\n");
  let eventName: string | null = null;
  const dataLines: string[] = [];
  for (const line of lines) {
    if (line.startsWith(":")) continue; // comment / heartbeat
    if (line.startsWith("event:")) {
      eventName = line.slice("event:".length).trim();
    } else if (line.startsWith("data:")) {
      dataLines.push(line.slice("data:".length).replace(/^ /, ""));
    }
  }
  if (!eventName || dataLines.length === 0) return null;
  let data: any;
  try {
    data = JSON.parse(dataLines.join("\n"));
  } catch {
    return null;
  }
  switch (eventName) {
    case "conversation_id":
      return { type: "conversation_id", data: data as ConversationIdEvent };
    case "agent_token":
      return { type: "agent_token", data: data as AgentTokenEvent };
    case "tool_call_start":
      return { type: "tool_call_start", data: data as ToolCallStartEvent };
    case "tool_call_result":
      return { type: "tool_call_result", data: data as ToolCallResultEvent };
    case "message_complete":
      return { type: "message_complete", data: data as MessageCompleteEvent };
    case "error":
      return { type: "error", data: data as ChatErrorEvent };
    default:
      // Unknown event type — forward-compat: ignore so a future event class
      // doesn't tear down the existing conversation.
      return null;
  }
}

export interface ChatStreamErrorEnvelope extends ChatErrorEvent {
  status: number;
}

export class ChatStreamError extends Error {
  readonly error: string;
  readonly error_description: string;
  readonly correlation_id: string;
  readonly attested_run_id: string | null;
  readonly status: number;

  constructor(envelope: ChatStreamErrorEnvelope) {
    super(envelope.error_description);
    this.name = "ChatStreamError";
    this.error = envelope.error;
    this.error_description = envelope.error_description;
    this.correlation_id = envelope.correlation_id;
    this.attested_run_id = envelope.attested_run_id ?? null;
    this.status = envelope.status;
  }
}

// Exposed for unit tests.
export const __test = { parseSseEvent };
