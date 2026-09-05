// Spec 012 S6c — proxy receipts as the dashboard reads them: the decision
// a row states, the cells a denial gets, the call kind behind the rail's
// default filter and the session grouping.

import { describe, expect, it } from "vitest";

import type { ReceiptRow } from "~/hooks/useReceipts";
import {
  ALL_CALL_KINDS,
  DEFAULT_CALL_KIND,
  callKindFromParam,
  callKindOf,
  groupRowsBySession,
  sessionIdOf,
} from "~/lib/receiptView";
import {
  categoryFromRow,
  effectiveDecision,
  toolKindFromToolName,
  viewTagsOf,
} from "~/lib/tags";

function row(
  runId: string,
  eventKind: string,
  tags: Record<string, unknown> | null,
  opts: { decision?: "allow" | "deny" | null; timestamp?: string; toolName?: string | null } = {},
): ReceiptRow {
  return {
    run_id: runId,
    signed_predicate: {
      run_id: runId,
      session_id: runId,
      turn_id: null,
      event_kind: eventKind,
      machine_identity: null,
      principal: { kind: "obo_human", subject: "claude-code:abc" },
      tenant_id: "01TEN_LOCAL",
      policy_canonical_hash: null,
      payload_hash: null,
      payload_uri: null,
      correlation_id: null,
      signer_kms_key_id: null,
      signer_key_version: null,
      timestamp: opts.timestamp ?? "2026-09-02T21:15:50.000000Z",
      tool_name: opts.toolName ?? null,
      tool_summary: null,
    },
    outer_container: {
      verification_level: "global_inclusion_verified",
      tier_completeness_advisory: "partial",
      session_chain_epoch: 0,
      session_chain_root: null,
      policy_decision: opts.decision === undefined ? "allow" : opts.decision,
      outcome: "success",
      upstream_status_code: null,
      commit_retry_exhausted: false,
      tags,
    },
  };
}

// Tags the S4 emitter writes on a `tool_use_denied` receipt
// (`AttestationEmitter.denied_commit_opts/3`).
const deniedTags = {
  kind: "agent_turn",
  model: "claude-opus-5",
  tool_name: "Bash",
  call_id: "toolu_01M3C6x2M2gCpWD14JxxjQtj",
  cedar_rule_id: "policy6",
  deny_reason: "denied_by_cedar_policy",
  client_session_id: "3f8fc437-ccc5-4ce9-8b07-436226bd7ca4",
  principal_source: "client_metadata",
};

describe("effectiveDecision", () => {
  it("reads a tool_use_denied row as deny although its outer container says allow", () => {
    expect(effectiveDecision(row("d", "tool_use_denied", deniedTags))).toBe("deny");
    expect(effectiveDecision(row("d", "tool_use_denied", null))).toBe("deny");
  });

  it("keeps the parent call's own decision", () => {
    const parent = row("p", "llm_call_attested", { kind: "agent_turn", decision_summary: "all deny" });
    expect(effectiveDecision(parent)).toBe("allow");
    expect(effectiveDecision(row("x", "llm_call", null, { decision: "deny" }))).toBe("deny");
    expect(effectiveDecision(row("x", "ui_query", null, { decision: null }))).toBeNull();
  });

  it("paints the denial category from the effective decision", () => {
    expect(categoryFromRow(row("d", "tool_use_denied", deniedTags))).toBe("policy_denied");
  });
});

describe("viewTagsOf", () => {
  it("derives TOOL / COMMAND / SUBJECT for a proxy denial from its tags", () => {
    const tags = viewTagsOf(row("d", "tool_use_denied", deniedTags));
    expect(tags?.tool_kind).toBe("bash");
    expect(tags?.verb).toBe("policy6");
    expect(tags?.argument_body).toBe(
      "denied_by_cedar_policy · call toolu_01M3C6x2M2gCpWD14JxxjQtj",
    );
    expect(tags?.tool_name).toBe("Bash");
  });

  it("names the MCP server for an mcp__ tool", () => {
    const tags = viewTagsOf(
      row("d", "tool_use_denied", { ...deniedTags, tool_name: "mcp__linear__save_issue" }),
    );
    expect(tags?.tool_kind).toBe("mcp");
    expect(tags?.semantic_args?.server).toBe("linear");
  });

  it("falls back to the row's tool_name column, and to nothing when the row has neither", () => {
    expect(viewTagsOf(row("d", "tool_use_denied", null, { toolName: "Read" }))?.tool_kind).toBe("read");
    expect(viewTagsOf(row("d", "tool_use_denied", null))).toBeNull();
  });

  it("passes extractor-tagged rows through untouched", () => {
    const extractor = { category: "subprocess_exec", tool_kind: "bash", verb: "git", argument_body: "status" };
    expect(viewTagsOf(row("t", "tool_call", extractor))).toEqual(extractor);
    expect(viewTagsOf(row("p", "llm_call_attested", { kind: "agent_turn" }))).toEqual({ kind: "agent_turn" });
  });
});

describe("toolKindFromToolName", () => {
  it("mirrors the extractor's tool_kind vocabulary", () => {
    expect(toolKindFromToolName("Bash")).toBe("bash");
    expect(toolKindFromToolName("Write")).toBe("edit");
    expect(toolKindFromToolName("MultiEdit")).toBe("edit");
    expect(toolKindFromToolName("NotebookEdit")).toBe("notebook_edit");
    expect(toolKindFromToolName("Glob")).toBe("search");
    expect(toolKindFromToolName("WebSearch")).toBe("webfetch");
    expect(toolKindFromToolName("Task")).toBe("agent");
    expect(toolKindFromToolName("TodoWrite")).toBe("todo");
    expect(toolKindFromToolName("mcp__x__y")).toBe("mcp");
    expect(toolKindFromToolName("Frobnicate")).toBe("unknown");
    expect(toolKindFromToolName(null)).toBeNull();
  });
});

describe("callKindOf / callKindFromParam", () => {
  it("reads tags.kind on proxy rows and folds a denial into the agent turn", () => {
    expect(callKindOf(row("p", "llm_call_attested", { kind: "session_title" }))).toBe("session_title");
    expect(callKindOf(row("p", "llm_call_attested", { kind: "side_query" }))).toBe("side_query");
    expect(callKindOf(row("p", "llm_call_attested", { kind: "agent_turn" }))).toBe("agent_turn");
    expect(callKindOf(row("p", "llm_call_attested", null))).toBe("agent_turn");
    expect(callKindOf(row("d", "tool_use_denied", null))).toBe("agent_turn");
    expect(callKindOf(row("u", "ui_query", null))).toBe("ui_query");
    expect(callKindOf(row("u", "ui_evidence_export", null))).toBe("ui_query");
    expect(callKindOf(row("t", "tool_call", { tool_kind: "bash" }))).toBe("other");
  });

  it("defaults to agent_turn, clears on `all`, and rejects unknown values", () => {
    expect(callKindFromParam(null)).toBe(DEFAULT_CALL_KIND);
    expect(callKindFromParam("")).toBe(DEFAULT_CALL_KIND);
    expect(callKindFromParam(ALL_CALL_KINDS)).toBeNull();
    expect(callKindFromParam("side_query")).toBe("side_query");
    expect(callKindFromParam("bogus")).toBe(DEFAULT_CALL_KIND);
  });
});

describe("groupRowsBySession", () => {
  const a1 = row("a1", "llm_call_attested", { client_session_id: "A" }, { timestamp: "2026-09-02T10:00:04Z" });
  const b1 = row("b1", "llm_call_attested", { client_session_id: "B" }, { timestamp: "2026-09-02T10:00:03Z" });
  const a2 = row("a2", "llm_call_attested", { client_session_id: "A" }, { timestamp: "2026-09-02T10:00:02Z" });
  const dA = row("dA", "tool_use_denied", null, { timestamp: "2026-09-02T10:00:02Z" });
  const b2 = row("b2", "llm_call_attested", { client_session_id: "B" }, { timestamp: "2026-09-02T10:00:01Z" });

  it("makes one session's calls contiguous, newest session first, rows timestamp DESC inside", () => {
    const out = groupRowsBySession([a1, b1, a2, dA, b2]).map((r) => r.run_id);
    expect(out).toEqual(["a1", "a2", "b1", "b2", "dA"]);
  });

  it("leaves a run without session ids in timestamp order", () => {
    const u1 = row("u1", "ui_query", null, { timestamp: "2026-09-02T10:00:09Z" });
    const u2 = row("u2", "ui_query", null, { timestamp: "2026-09-02T10:00:08Z" });
    expect(groupRowsBySession([u2, u1]).map((r) => r.run_id)).toEqual(["u1", "u2"]);
  });

  it("exposes the session id the chips render", () => {
    expect(sessionIdOf(a1)).toBe("A");
    expect(sessionIdOf(dA)).toBeNull();
  });
});
