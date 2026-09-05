// Wave C — tags helper unit tests.
//
// Asserts the contract that powers the Dashboard redesign:
//   1. categoryColorToken is total over KNOWN_CATEGORIES (every known
//      category resolves to a chart-* token).
//   2. Unknown / null / undefined categories fall through to the
//      neutral chart-ui band — never silently styled like a real
//      category.
//   3. categoryFromRow honors the deny-supersedes-classification rule
//      (R4 Rule 01): any row with policy_decision="deny" reads as
//      `policy_denied` regardless of the extractor's category, so
//      denials are visually unmissable.
//   4. displaySummary leads with `tags.display_summary` when present;
//      falls back to `tool_summary` then `tool_name`; finally to a
//      synthesized event_kind label. Never echoes raw arguments.

import { describe, expect, it } from "vitest";

import {
  KNOWN_CATEGORIES,
  categoryColorToken,
  categoryFromRow,
  displaySummary,
  llmCallParseFacts,
  llmCallToolSummary,
  tagsOf,
} from "~/lib/tags";

describe("tags#categoryColorToken", () => {
  it("returns chart-denied for policy_denied (R4 Rule 01)", () => {
    expect(categoryColorToken("policy_denied")).toBe("chart-denied");
  });

  it("returns a stable chart-* token for every KNOWN_CATEGORIES entry", () => {
    for (const cat of KNOWN_CATEGORIES) {
      const token = categoryColorToken(cat);
      expect(token).toMatch(/^chart-/);
    }
  });

  it("falls back to chart-ui for null/undefined/unknown", () => {
    expect(categoryColorToken(null)).toBe("chart-ui");
    expect(categoryColorToken(undefined)).toBe("chart-ui");
    expect(categoryColorToken("does_not_exist")).toBe("chart-ui");
  });

  it("groups file_write + notebook_edit on the same band (R4)", () => {
    expect(categoryColorToken("file_write")).toBe(categoryColorToken("notebook_edit"));
  });

  it("file_search uses chart-search slate band (NOT chart-file-read green)", () => {
    // Per design/briefs/01-shared-systems.md R4 palette table. Pre-fix
    // file_search drifted onto chart-file-read; caught by GAN review of
    // MR !86, finding F001. (chartTokens.test.ts asserts the full lockstep.)
    expect(categoryColorToken("file_search")).toBe("chart-search");
    expect(categoryColorToken("file_read")).toBe("chart-file-read");
  });

  it("keeps subprocess + network on distinct bands (R4 Rule 03 — adjacency)", () => {
    expect(categoryColorToken("subprocess_exec")).not.toBe(categoryColorToken("network_egress"));
  });
});

describe("tags#categoryFromRow — R4 Rule 01 (deny supersedes)", () => {
  function row(opts: {
    decision?: "allow" | "deny" | null;
    eventKind?: string | null;
    tags?: Record<string, unknown> | null;
  }) {
    return {
      signed_predicate: { event_kind: opts.eventKind ?? "tool_call" },
      outer_container: {
        policy_decision: opts.decision ?? "allow",
        tags: opts.tags ?? null,
      },
    };
  }

  it("denies dominate even when extractor classified as subprocess_exec", () => {
    expect(
      categoryFromRow(
        row({ decision: "deny", tags: { category: "subprocess_exec" } }),
      ),
    ).toBe("policy_denied");
  });

  it("respects extractor category when decision is allow", () => {
    expect(
      categoryFromRow(
        row({ decision: "allow", tags: { category: "subprocess_exec" } }),
      ),
    ).toBe("subprocess_exec");
  });

  it("falls back to event_kind hint when tags are absent", () => {
    expect(categoryFromRow(row({ eventKind: "llm_call", tags: null }))).toBe("llm_call");
    expect(categoryFromRow(row({ eventKind: "ui_query", tags: null }))).toBe("ui_event");
    expect(categoryFromRow(row({ eventKind: "mcp_tool_call", tags: null }))).toBe("mcp_tool_call");
  });

  it("returns 'unknown' for an unclassified tool_call without tags", () => {
    expect(categoryFromRow(row({ eventKind: "tool_call", tags: null }))).toBe("unknown");
  });
});

describe("tags#displaySummary", () => {
  const baseInputs = {
    tags: null as Record<string, unknown> | null,
    toolName: null,
    toolSummary: null,
    eventKind: "tool_call",
    principal: "alice@example.com",
    decision: "allow" as "allow" | "deny" | null,
    upstreamStatusCode: null,
  };

  it("LEADS with tags.display_summary when present", () => {
    expect(
      displaySummary({
        ...baseInputs,
        tags: { display_summary: "Bash: git status" },
        toolName: "Bash",
        toolSummary: "stale legacy summary that should be ignored",
      }),
    ).toBe("Bash: git status");
  });

  it("falls back to tool_summary when display_summary is absent", () => {
    expect(
      displaySummary({
        ...baseInputs,
        tags: null,
        toolSummary: "Edit: hello.txt",
      }),
    ).toBe("Edit: hello.txt");
  });

  it("falls back to 'Tool call: <name>' when both are absent", () => {
    expect(
      displaySummary({ ...baseInputs, toolName: "Bash", toolSummary: null }),
    ).toBe("Tool call: Bash");
  });

  it("synthesizes a policy_denied summary with HTTP status", () => {
    expect(
      displaySummary({
        ...baseInputs,
        eventKind: "policy_denied",
        decision: "deny",
        upstreamStatusCode: 403,
      }),
    ).toBe("Policy denied (HTTP 403) • alice@example.com");
  });

  it("synthesizes an llm_call verdict label", () => {
    expect(
      displaySummary({
        ...baseInputs,
        eventKind: "llm_call",
        decision: "allow",
      }),
    ).toBe("LLM call (allow) • alice@example.com");
  });
});

describe("tags#tagsOf", () => {
  it("returns null for missing tags", () => {
    expect(tagsOf({ outer_container: { tags: null } })).toBe(null);
  });

  it("returns the tags object when present", () => {
    const tags = { category: "subprocess_exec", display_summary: "Bash: ls" };
    expect(tagsOf({ outer_container: { tags } })).toEqual(tags);
  });
});

// Spec 012 S4 — receipt ROW copy for LLM-proxy calls (plan §13): "No tool
// calls" or "N tool calls · <decision>", nothing else. Recognition facts
// belong to the detail view (`llmCallParseFacts`).
describe("tags#llmCallToolSummary", () => {
  it('reads "No tool calls" when no intents were extracted', () => {
    expect(
      llmCallToolSummary({ tool_use_intent_count: 0, parse_events_unhandled: 0, decision_summary: "no tools" }),
    ).toBe("No tool calls");
  });

  it("never carries a recognition caveat on the row", () => {
    expect(
      llmCallToolSummary({
        tool_use_intent_count: 0,
        parse_events_unhandled: 2,
        parse_unhandled_types: ["block:widget", "event:telemetry"],
      }),
    ).toBe("No tool calls");
    expect(
      llmCallToolSummary({
        tool_use_intent_count: 1,
        parse_events_unhandled: 1,
        decision_summary: "all allow",
      }),
    ).toBe("1 tool call · all allow");
  });

  it("names the count and decision when intents were extracted", () => {
    expect(
      llmCallToolSummary({ tool_use_intent_count: 1, parse_events_unhandled: 0, decision_summary: "all allow" }),
    ).toBe("1 tool call · all allow");
    expect(
      llmCallToolSummary({ tool_use_intent_count: 2, parse_events_unhandled: 0, decision_summary: "1 allow, 1 deny" }),
    ).toBe("2 tool calls · 1 allow, 1 deny");
  });


  it("falls back to the pre-S4 label for rows without the counts", () => {
    expect(llmCallToolSummary(null)).toBe("LLM proxy call attested");
    expect(llmCallToolSummary({ category: "llm_call" })).toBe("LLM proxy call attested");
  });

  it("is what displaySummary renders for llm_call_attested rows", () => {
    expect(
      displaySummary({
        tags: { tool_use_intent_count: 0, parse_events_unhandled: 0 },
        toolName: null,
        toolSummary: null,
        eventKind: "llm_call_attested",
        principal: "claude-code:0000",
        decision: "allow",
        upstreamStatusCode: 200,
      }),
    ).toBe("No tool calls • claude-code:0000");
  });
});

describe("tags#llmCallParseFacts", () => {
  it("is empty when everything was recognised", () => {
    expect(llmCallParseFacts(null)).toEqual([]);
    expect(llmCallParseFacts({ tool_use_intent_count: 0, parse_events_unhandled: 0 })).toEqual([]);
  });

  it("states unrecognized events with their types, as a plain fact", () => {
    expect(
      llmCallParseFacts({
        tool_use_intent_count: 0,
        parse_events_unhandled: 2,
        parse_unhandled_types: ["block:widget", "event:telemetry"],
      }),
    ).toEqual(["2 events unrecognized (block:widget, event:telemetry)"]);
    expect(llmCallParseFacts({ parse_events_unhandled: 1 })).toEqual(["1 event unrecognized"]);
  });

  it("states a parser failure", () => {
    expect(llmCallParseFacts({ parse_events_unhandled: 0, parse_status: "failed" })).toEqual([
      "Parser stopped before the end of the response; the rest was forwarded unread",
    ]);
  });
});
