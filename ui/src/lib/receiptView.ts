// receiptView — how the dashboard reads LLM-proxy receipts as a stream of
// calls (spec 012 plan §10: group by session, default to `agent_turn`).
//
// Claude Code makes several model calls per prompt: the agent turn, a
// session-title call and a side query. The proxy records which kind each
// was on the receipt's unsigned `tags.kind` (`RequestKind.classify/1`) and
// the client's own session id on `tags.client_session_id`. The console's
// own reads (`ui_*` event kinds) are receipts too. This module derives the
// two axes the table uses to keep a session readable: the call kind for
// the filter rail and the session id for grouping.

import type { ReceiptRow } from "~/hooks/useReceipts";
import { tagsOf } from "~/lib/tags";

/** Call kinds the rail offers. `other` collects everything that is not a proxy call or a console read. */
export const CALL_KINDS = ["agent_turn", "session_title", "side_query", "ui_query", "other"] as const;
export type CallKind = (typeof CALL_KINDS)[number];

/** Selected when the URL carries no `kind` parameter. */
export const DEFAULT_CALL_KIND: CallKind = "agent_turn";
/** URL search parameter for the kind filter. */
export const CALL_KIND_PARAM = "kind";
/** `?kind=all` — no kind filter (the only way to clear the default). */
export const ALL_CALL_KINDS = "all";

type KindSource = {
  signed_predicate: { event_kind: string | null };
  outer_container: { tags: unknown };
};

/**
 * The call kind of a row. Proxy rows read `tags.kind`; a `tool_use_denied`
 * row belongs to the agent turn whose `tool_use` block it suppressed (only
 * a tool-bearing request classifies as `agent_turn`, and only those carry
 * `tool_use` blocks); a proxy row written before `kind` was recorded is
 * an agent turn, which is also the classifier's default.
 */
export function callKindOf(row: KindSource): CallKind {
  const tagged = tagsOf(row)?.kind;
  if (tagged === "agent_turn" || tagged === "session_title" || tagged === "side_query") {
    return tagged;
  }
  const ek = row.signed_predicate.event_kind ?? "";
  if (ek === "tool_use_denied" || ek === "llm_call_attested") return "agent_turn";
  if (ek.startsWith("ui_")) return "ui_query";
  return "other";
}

/**
 * Resolve the `kind` URL parameter: absent → the default, `all` → no
 * filter (`null`), a known kind → that kind, anything else → the default.
 */
export function callKindFromParam(param: string | null): CallKind | null {
  if (param === null || param === "") return DEFAULT_CALL_KIND;
  if (param === ALL_CALL_KINDS) return null;
  return (CALL_KINDS as readonly string[]).includes(param) ? (param as CallKind) : DEFAULT_CALL_KIND;
}

/** `tags.client_session_id` when the row carries one. */
export function sessionIdOf(row: { outer_container: { tags: unknown } }): string | null {
  const s = tagsOf(row)?.client_session_id;
  return typeof s === "string" && s.length > 0 ? s : null;
}

function byTimestampDesc(a: ReceiptRow, b: ReceiptRow): number {
  const ta = a.signed_predicate.timestamp ?? "";
  const tb = b.signed_predicate.timestamp ?? "";
  if (ta === tb) return a.run_id.localeCompare(b.run_id);
  return ta < tb ? 1 : -1;
}

/**
 * Regroup timestamp-DESC rows so every call of one client session is
 * contiguous. Groups are ordered by their newest row; rows inside a group
 * stay timestamp DESC. A row without a session id is a group of one and
 * keeps its place, so a denial that carries no tags still sits next to
 * the parent call it was extracted from (same instant).
 */
export function groupRowsBySession(rows: readonly ReceiptRow[]): ReceiptRow[] {
  const ordered = rows.slice().sort(byTimestampDesc);
  const groups = new Map<string, ReceiptRow[]>();
  const order: string[] = [];
  ordered.forEach((row, i) => {
    const key = sessionIdOf(row) ?? `row:${i}`;
    let group = groups.get(key);
    if (!group) {
      group = [];
      groups.set(key, group);
      order.push(key);
    }
    group.push(row);
  });
  return order.flatMap((key) => groups.get(key) ?? []);
}
