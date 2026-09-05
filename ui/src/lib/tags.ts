// Tag-shape helpers for the audit-console redesign (Wave C).
//
// The Claude-Code extractor pipeline emits a `tags` map on
// `outer_container.tags` for every tool_call receipt (see
// `apps/recurse_gateway/lib/recurse_gateway/extractors/claude_code_jsonl.ex`,
// `Recurse.Gateway.Extractors.ClaudeCodeJsonl.extract/1`). Top-level
// keys are stable; `semantic_args` is the per-category flex space.
//
// The shape is JSON-Schema'd as `additionalProperties: true` on the
// receipts list response (see
// `apps/recurse_gateway/priv/schemas/audit_receipts_list_response.json`),
// because the per-category `semantic_args` envelope varies. This module
// gives the SPA a typed view for the stable keys while keeping the
// flex-space loose.
//
// **R4 palette** (semantic-mapping). Categories map to `r5e-chart-*`
// design tokens authored in `ui/design-tokens.json`
// and codegen'd into `tailwind.config.ts` via `pnpm gen:tailwind`.
// `policy_denied` always maps to danger (the redesign's #1 visual law:
// denials must jump out).
//
// Issue #64 (resolved by extractor v2 / issue #62 — landed 2026-04-30):
// `tool_kind`, `verb`, and `argument_body` are now top-level typed
// properties of the tags object. The schema (audit_receipts_list_response.json)
// has them; codegen emits them; this interface mirrors them.

import type { ChartToken } from "~/lib/chartTokens";

/**
 * Stable top-level keys of `outer_container.tags`. `semantic_args` is
 * the per-category flex space and stays loose. Mirrors the extractor's
 * `extract/1` return shape; new keys MUST be added here AND to the
 * backend's `@type tags()` typespec in lockstep.
 */
export interface ReceiptTags {
  /** Tool category — drives the row's color stripe + facet bucket. */
  category?: string | null;
  /**
   * Coarse tool family for facets/Cedar attribute lookups: `bash`,
   * `edit`, `read`, `search`, `webfetch`, `mcp`, `agent`, `todo`,
   * `notebook_edit`, `unknown`. Stable across extractors. (#64 / #62)
   */
  tool_kind?: string | null;
  /**
   * Action verb. Bash → first command token; Edit/Write → `patch`; Read
   * → `cat`; Glob → `glob`; Grep → `grep`; WebFetch → `get`; MCP →
   * tool name; Task → `dispatch`; TodoWrite → `todo`. (#64 / #62)
   */
  verb?: string | null;
  /**
   * Structured action subject (arguments minus the verb). (#64 / #62)
   */
  argument_body?: string | null;
  /** 1-line, redacted, semantic description ("Bash: git status"). */
  display_summary?: string | null;
  /** Scope axis — what the action targets (e.g. "file_outside_workdir"). */
  scope_kind?: string | null;
  /** Scope value — the literal target (path, host, pattern, …). */
  scope_value?: string | null;
  /** Resources affected (file paths, hostnames, tool names). */
  target_resources?: string[] | null;
  /**
   * Per-category structured args. Keys vary by category; the redesign's
   * drawer renders them as a flat key/value table when present.
   */
  semantic_args?: Record<string, unknown> | null;
  /**
   * LLM-proxy call receipts (`llm_call_attested`, spec 012 S4): number of
   * tool_use intents the parser extracted from the response.
   */
  tool_use_intent_count?: number | null;
  /** `"no tools" | "all allow" | "all deny" | "N allow, M deny"`. */
  decision_summary?: string | null;
  /** Events the parser saw / could not classify (spec 012 plan §11). */
  parse_events_total?: number | null;
  parse_events_unhandled?: number | null;
  /** Discriminators the parser could not classify (`event:x`, `block:x`, `delta:x`). */
  parse_unhandled_types?: string[] | null;
  /** Recognizer identity: module name, source hash, wire format. */
  parser_module?: string | null;
  parser_version?: string | null;
  parser_format?: string | null;
  /** `"ok"`, or `"failed"` when the proxy stopped calling the parser after it raised. */
  parse_status?: string | null;
  /** Betas the client requested (`anthropic-beta`), recorded separately from the format. */
  parse_betas_requested?: string[] | null;
  /**
   * How the principal id was obtained: `jwt` | `client_metadata` |
   * `mtls_svid` | `anonymous`. `client_metadata` is client-asserted,
   * corroborated only by the upstream accepting the presented bearer.
   */
  principal_source?: string | null;
  principal_source_note?: string | null;
  /** The upstream's `anthropic-organization-id` response header, when present. */
  upstream_org_id?: string | null;
  /**
   * LLM-proxy call kind (spec 012 plan §9 D2): `agent_turn` |
   * `session_title` | `side_query`. Present on `llm_call_attested` rows
   * and on `tool_use_denied` rows written by the S4 emitter.
   */
  kind?: string | null;
  /** The client's own session id (Claude Code's `session_id`); the wrap the dashboard groups by. */
  client_session_id?: string | null;
  /**
   * `tool_use_denied` rows (S4 emitter `denied_commit_opts`): the tool the
   * suppressed `tool_use` block named, its provider call id, the Cedar
   * rule that fired and the deny reason. No extractor fields on these
   * rows; `viewTagsOf` derives the table's TOOL / COMMAND / SUBJECT cells.
   */
  tool_name?: string | null;
  call_id?: string | null;
  cedar_rule_id?: string | null;
  deny_reason?: string | null;
}

/** Pull tags from a receipt row, normalizing absence. */
export function tagsOf(row: { outer_container: { tags: unknown } }): ReceiptTags | null {
  const t = row.outer_container?.tags;
  if (!t || typeof t !== "object") return null;
  return t as ReceiptTags;
}

/**
 * Categories the extractor emits today. Out-of-list values render with
 * the "system" palette and an explicit "(unknown category)" pill —
 * never silently styled like a known category.
 *
 * Sourced from `claude_code_jsonl.ex` extractor cases. New categories
 * MUST be added here AND to `categoryColor/1` below; tests assert the
 * lists stay in sync.
 */
export const KNOWN_CATEGORIES = [
  "subprocess_exec",
  "file_write",
  "file_read",
  "file_search",
  "notebook_edit",
  "network_egress",
  "mcp_tool_call",
  "agent_dispatch",
  "todo_management",
  // Synthesized from event_kind for non-extracted rows
  "policy_denied",
  "llm_call",
  // Fallback bands
  "ui_event",
  "unknown",
] as const;

export type KnownCategory = (typeof KNOWN_CATEGORIES)[number];

/**
 * Map a category to the design-token color name (without the `r5e-`
 * prefix). Caller chooses whether to use it as `text-r5e-chart-...`,
 * `bg-r5e-chart-.../15`, `border-r5e-chart-...`, etc.
 *
 * Pure; testable. The denial-supersedes rule lives at the row level
 * (see `categoryFromRow/1`): when `policy_decision === "deny"` the row
 * paints with `chart-denied` regardless of whatever category the
 * extractor saw.
 */
export function categoryColorToken(category: string | null | undefined): ChartToken {
  switch (category) {
    case "subprocess_exec":
      return "chart-subprocess";
    case "file_write":
    case "notebook_edit":
      return "chart-file-write";
    case "file_read":
      return "chart-file-read";
    case "file_search":
      // Slate-blue per design/briefs/01-shared-systems.md (R4 palette
      // table). Pre-fix this fell through to `chart-file-read` (green) —
      // caught by GAN review of MR !86, finding F001 (palette drift).
      return "chart-search";
    case "network_egress":
      return "chart-network";
    case "mcp_tool_call":
      return "chart-mcp-tool";
    case "agent_dispatch":
      return "chart-agent";
    case "llm_call":
      return "chart-llm";
    case "policy_denied":
      return "chart-denied";
    case "todo_management":
      // Slate-grey per design/briefs/01-shared-systems.md. Pre-fix this
      // fell through to `chart-ui` (also slate) which masked the drift
      // visually — caught by GAN review of MR !86, finding F001.
      return "chart-todo";
    case "ui_event":
      return "chart-ui";
    case "unknown":
    case null:
    case undefined:
    default:
      return "chart-ui";
  }
}

/**
 * Resolve the row's effective category for the redesign — combines the
 * extractor's `tags.category` (preferred), falling back to a
 * derived-from-event_kind hint, with a denial supersede so the row
 * stripe always reads RED for `deny` (R4 Rule 01: policy_denied is
 * always rendered as an overlay/highlight).
 */
export function categoryFromRow(row: {
  signed_predicate: { event_kind: string | null };
  outer_container: { policy_decision: "allow" | "deny" | null; tags: unknown };
}): string {
  if (effectiveDecision(row) === "deny") return "policy_denied";
  const tags = tagsOf(row);
  if (tags?.category) return tags.category;
  const ek = row.signed_predicate.event_kind ?? "";
  if (ek === "policy_denied") return "policy_denied";
  if (ek === "llm_call") return "llm_call";
  // 009 LLM-proxy tool governance: the parent call attestation reads as an
  // LLM call; a tool-use denial reads as a policy denial (red band) even
  // though its outer_container.policy_decision is the PARENT call's "allow".
  if (ek === "llm_call_attested") return "llm_call";
  if (ek === "tool_use_denied") return "policy_denied";
  // !119 — bundle activation is a system/config UI-band event.
  if (ek === "policy_bundle_activated") return "ui_event";
  if (ek === "mcp_tool_call") return "mcp_tool_call";
  if (ek === "tool_call") return "unknown";
  if (ek.startsWith("ui_")) return "ui_event";
  return "unknown";
}

/**
 * Event kinds that ARE a denial. The ledger commit for these rows leaves
 * `outer_container.policy_decision` at its default, the parent call's
 * "allow" (spec 012 S6 finding), so every decision read in the console
 * goes through `effectiveDecision` rather than the outer container.
 */
export const DENIAL_EVENT_KINDS: ReadonlySet<string> = new Set([
  "tool_use_denied",
  "policy_denied",
  "egress_denied",
]);

/** The decision the row states: outer-container deny, or a denial kind. */
export function effectiveDecision(row: {
  signed_predicate: { event_kind: string | null };
  outer_container: { policy_decision: "allow" | "deny" | null };
}): "allow" | "deny" | null {
  if (row.outer_container.policy_decision === "deny") return "deny";
  if (DENIAL_EVENT_KINDS.has(row.signed_predicate.event_kind ?? "")) return "deny";
  return row.outer_container.policy_decision;
}

/**
 * Claude Code tool name → the extractor's `tool_kind` vocabulary
 * (`Recurse.Gateway.Extractors.ClaudeCodeJsonl.do_extract/2`). Used for
 * rows the extractor never saw (proxy denials carry only the name).
 */
export function toolKindFromToolName(name: string | null | undefined): string | null {
  if (!name) return null;
  if (name.startsWith("mcp__")) return "mcp";
  switch (name) {
    case "Bash":
      return "bash";
    case "Edit":
    case "Write":
    case "MultiEdit":
      return "edit";
    case "NotebookEdit":
      return "notebook_edit";
    case "Read":
      return "read";
    case "Glob":
    case "Grep":
      return "search";
    case "WebFetch":
    case "WebSearch":
      return "webfetch";
    case "Task":
    case "Agent":
      return "agent";
    case "TodoWrite":
      return "todo";
    default:
      return "unknown";
  }
}

function stringOr(v: unknown): string | null {
  return typeof v === "string" && v.length > 0 ? v : null;
}

/**
 * Tags as the table cells read them. Extractor-tagged rows pass through.
 * A `tool_use_denied` row carries `tool_name`, `call_id`, `cedar_rule_id`
 * and `deny_reason` (no `tool_kind` / `verb` / `argument_body`), so the
 * cells are derived: TOOL from the tool name, COMMAND the rule that
 * fired, SUBJECT the reason and the provider call id. The receipts
 * endpoint returns no argument bytes or hash for a denial, so nothing
 * more is shown. A denial without tags (rows written before the S4
 * emitter) returns null and the cells stay empty.
 */
export function viewTagsOf(row: {
  signed_predicate: { event_kind: string | null; tool_name: string | null };
  outer_container: { tags: unknown };
}): ReceiptTags | null {
  const tags = tagsOf(row);
  if (tags?.tool_kind) return tags;
  if (row.signed_predicate.event_kind !== "tool_use_denied") return tags;
  const toolName = stringOr(tags?.tool_name) ?? stringOr(row.signed_predicate.tool_name);
  if (!toolName) return tags;
  const rule = stringOr(tags?.cedar_rule_id);
  const reason = stringOr(tags?.deny_reason);
  const callId = stringOr(tags?.call_id);
  const subject = [reason, callId ? `call ${callId}` : null].filter(Boolean).join(" · ");
  const mcpServer = toolName.startsWith("mcp__") ? (toolName.split("__")[1] ?? null) : null;
  return {
    ...(tags ?? {}),
    tool_name: toolName,
    tool_kind: toolKindFromToolName(toolName),
    verb: rule ?? reason,
    argument_body: subject.length > 0 ? subject : null,
    semantic_args: mcpServer
      ? { ...(tags?.semantic_args ?? {}), server: mcpServer }
      : (tags?.semantic_args ?? null),
  };
}

/**
 * Derive the row's leading-summary string. Honors the extractor's
 * pre-redacted `display_summary` first; falls back to the legacy
 * `tool_summary`/`tool_name` shape (B7); finally to a synthesized
 * `<event_kind> · <principal>` only for non-extracted rows. Never
 * echoes raw arguments — backend already applied PII redaction; the
 * SPA renders only what backend emitted.
 *
 * The fallback chain is structured so adding new emitter shapes is
 * additive (new branches before the bare-event_kind floor).
 */
export interface DisplaySummaryInputs {
  tags: ReceiptTags | null;
  toolName: string | null;
  toolSummary: string | null;
  eventKind: string;
  principal: string;
  decision: "allow" | "deny" | null;
  upstreamStatusCode: number | null;
}

/**
 * Receipt ROW copy for an LLM-proxy call (spec 012 S4 / plan §13).
 *
 * The parser recorded what it read; the row states it and nothing else:
 * "No tool calls", or "N tool calls · <decision summary>". A recorded
 * response with no tool call is a response with no tool call. Parser
 * completeness (`parse_*`) is a fact for the receipt DETAIL view
 * (`llmCallParseFacts`), the drift panel and the verifier's not-checked
 * block — never a caveat next to a row. Older rows without the counts
 * fall back to the pre-S4 label.
 */
export function llmCallToolSummary(tags: ReceiptTags | null): string {
  const intents = tags?.tool_use_intent_count;
  if (typeof intents !== "number") return "LLM proxy call attested";
  if (intents === 0) return "No tool calls";
  const calls = `${intents} tool call${intents === 1 ? "" : "s"}`;
  const decision = tags?.decision_summary;
  return decision && decision !== "no tools" ? `${calls} · ${decision}` : calls;
}

/**
 * Plain fact lines about recognition for the receipt DETAIL view (the
 * drawer): what the parser could not classify, and whether it stopped
 * reading. Empty when the response was fully recognised. Facts, not
 * caveats: no hedging sentence is attached (plan §13).
 */
export function llmCallParseFacts(tags: ReceiptTags | null): string[] {
  if (!tags) return [];
  const facts: string[] = [];
  const unhandled = tags.parse_events_unhandled ?? 0;
  if (typeof unhandled === "number" && unhandled > 0) {
    const types = (tags.parse_unhandled_types ?? []).filter(
      (t): t is string => typeof t === "string" && t.length > 0,
    );
    const typeList = types.length > 0 ? ` (${types.join(", ")})` : "";
    facts.push(`${unhandled} event${unhandled === 1 ? "" : "s"} unrecognized${typeList}`);
  }
  if (tags.parse_status === "failed") {
    facts.push("Parser stopped before the end of the response; the rest was forwarded unread");
  }
  return facts;
}

export function displaySummary(inputs: DisplaySummaryInputs): string {
  const { tags, toolName, toolSummary, eventKind, principal, decision, upstreamStatusCode } = inputs;
  const ds = tags?.display_summary;
  if (ds && ds.length > 0) return ds;
  if (toolSummary && toolSummary.length > 0) return toolSummary;
  if (eventKind === "tool_call") {
    if (toolName && toolName.length > 0) return `Tool call: ${toolName}`;
    return "Tool call (detail in receipt)";
  }
  if (eventKind === "policy_denied") {
    return `Policy denied${upstreamStatusCode ? ` (HTTP ${upstreamStatusCode})` : ""} • ${principal}`;
  }
  if (eventKind === "llm_call") {
    const verdict = decision === "deny" ? "denied" : "allow";
    return `LLM call (${verdict}) • ${principal}`;
  }
  if (eventKind === "llm_call_attested") {
    return `${llmCallToolSummary(tags)} • ${principal}`;
  }
  if (eventKind === "tool_use_denied") {
    if (toolName && toolName.length > 0) return `Tool use DENIED: ${toolName} • ${principal}`;
    return `Tool use DENIED • ${principal}`;
  }
  if (eventKind === "policy_bundle_activated") return `Policy bundle activated • ${principal}`;
  if (eventKind === "ui_login") return `UI login • ${principal}`;
  if (eventKind === "ui_session") return `UI session • ${principal}`;
  if (eventKind === "ui_query") return `UI query • ${principal}`;
  if (eventKind === "ui_evidence_export") return `Evidence export • ${principal}`;
  if (eventKind === "ui_payload_access") return `Payload access • ${principal}`;
  if (eventKind === "ui_retention_purge") return `Retention purge`;
  if (eventKind.startsWith("ui_policy_")) {
    const stage = eventKind.replace(/^ui_policy_/, "");
    return `Policy ${stage.replace(/_/g, " ")} • ${principal}`;
  }
  if (eventKind.startsWith("ui_chat")) {
    const skill = eventKind.replace(/^ui_chat_skill_invoked_/, "").replace(/^ui_chat$/, "chat");
    return `Audit chat: ${skill.replace(/_/g, " ")} • ${principal}`;
  }
  return `${eventKind} • ${principal}`;
}
