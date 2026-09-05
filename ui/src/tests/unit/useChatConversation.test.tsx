// Vitest unit tests for `useChatConversation` covering the SSE error
// path that MR !93 fix-pass-2 GAN flagged (F004).
//
// Per `audit_api_extensions.md` §POST /v1/chat/messages:
//   - `tool_call_result` carries `{tool_name, result, attested_run_id}` —
//     no `outcome` field.
//   - Tool failures are delivered out-of-band as `event: error` with the
//     canonical flat error envelope.
//
// The hook MUST therefore promote the most-recent running tool call to
// `status: "error"` when an `error` event arrives — without that
// transition the tool block stays stuck on the spinner forever.
//
// Test strategy: pass a non-null `conversationId` so the placeholder /
// mirror-key promotion machinery is bypassed (those code paths are
// independently exercised by ChatPage.test.tsx). All cache writes land
// on the same key the hook's queryFn populates, so the in-test
// `result.current.state.messages` reflects every streamed event by the
// time `sendMessage` resolves.

import { act, renderHook, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { FC, PropsWithChildren } from "react";

import { conversationKey, useChatConversation } from "~/hooks/useChatConversation";

function makeStreamingResponse(events: string[]): Response {
  const encoder = new TextEncoder();
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      for (const event of events) {
        controller.enqueue(encoder.encode(event));
      }
      controller.close();
    },
  });
  return new Response(stream, {
    status: 200,
    headers: { "content-type": "text/event-stream" },
  });
}

function makeWrapper(client: QueryClient): FC<PropsWithChildren> {
  return function Wrapper({ children }) {
    return (
      <QueryClientProvider client={client}>{children}</QueryClientProvider>
    );
  };
}

// Seed an empty `{id, messages: []}` envelope under the conversation key
// so the hook's `useQuery({queryFn: api.get(...)})` resolves immediately
// and any optimistic writes we layer on top survive (rather than being
// clobbered by the queryFn microtask resolution under test timing).
function seedHistoryCache(
  client: QueryClient,
  conversationId: string,
): void {
  client.setQueryData(conversationKey(conversationId), {
    id: conversationId,
    messages: [],
  });
}

describe("useChatConversation — SSE error → tool-call transition (F004)", () => {
  it("transitions a running tool call to status='error' when event:error arrives mid-stream", async () => {
    const realFetch = globalThis.fetch;
    globalThis.fetch = vi.fn().mockResolvedValue(
      makeStreamingResponse([
        'event: tool_call_start\ndata: {"tool_name":"query_receipts","args":{"limit":5},"attested_run_id":"r1"}\n\n',
        'event: error\ndata: {"error":"ERR_UPSTREAM_UNAVAILABLE","error_description":"Receipt store timed out","correlation_id":"cid-1"}\n\n',
      ]),
    ) as unknown as typeof fetch;

    try {
      const client = new QueryClient({
        defaultOptions: { queries: { retry: false } },
      });
      const conversationId = "conv-test-1";
      seedHistoryCache(client, conversationId);

      const { result } = renderHook(
        () => useChatConversation(conversationId),
        { wrapper: makeWrapper(client) },
      );

      await act(async () => {
        await result.current.sendMessage("Why was Alice's bash denied?");
      });

      await waitFor(() => {
        const finalMsg = result.current.state.messages.at(-1);
        expect(finalMsg).toBeDefined();
        expect(finalMsg!.toolCalls).toHaveLength(1);
        expect(finalMsg!.toolCalls[0]!.status).toBe("error");
        expect(finalMsg!.toolCalls[0]!.errorMessage).toBe(
          "Receipt store timed out",
        );
        // The error envelope is also recorded on the message's errors
        // list (existing behavior — not a regression).
        expect(finalMsg!.errors).toHaveLength(1);
      });
    } finally {
      globalThis.fetch = realFetch;
    }
  });

  it("treats every tool_call_result as success (the contract envelope has no `outcome` field)", async () => {
    const realFetch = globalThis.fetch;
    globalThis.fetch = vi.fn().mockResolvedValue(
      makeStreamingResponse([
        'event: tool_call_start\ndata: {"tool_name":"verify_receipt","args":{"run_id":"r1"},"attested_run_id":"r1"}\n\n',
        // tool_call_result with NO `outcome` (the contract shape) → must
        // transition to success regardless of what the `result` payload
        // looks like.
        'event: tool_call_result\ndata: {"tool_name":"verify_receipt","result":{"valid":false},"attested_run_id":"r1"}\n\n',
      ]),
    ) as unknown as typeof fetch;

    try {
      const client = new QueryClient({
        defaultOptions: { queries: { retry: false } },
      });
      const conversationId = "conv-test-2";
      seedHistoryCache(client, conversationId);

      const { result } = renderHook(
        () => useChatConversation(conversationId),
        { wrapper: makeWrapper(client) },
      );

      await act(async () => {
        await result.current.sendMessage("trace this");
      });

      await waitFor(() => {
        const finalMsg = result.current.state.messages.at(-1);
        expect(finalMsg).toBeDefined();
        expect(finalMsg!.toolCalls).toHaveLength(1);
        expect(finalMsg!.toolCalls[0]!.status).toBe("success");
      });
    } finally {
      globalThis.fetch = realFetch;
    }
  });
});
