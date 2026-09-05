import type { ReceiptRow } from "~/hooks/useReceipts";
import type { ReceiptDetail } from "~/hooks/useReceiptDetail";
import { sessionIdOf } from "~/lib/receiptView";
import { categoryFromRow, effectiveDecision, tagsOf } from "~/lib/tags";

type ReceiptChipSource = Pick<ReceiptRow, "signed_predicate" | "outer_container"> |
  Pick<ReceiptDetail, "signed_predicate" | "outer_container">;

export interface RowChipModel {
  category: string;
  decision: "allow" | "deny" | null;
  /** The client's session id (`tags.client_session_id`), when the row carries one. */
  session: string | null;
  scope_kind: string | null;
  scope_value: string | null;
  target_resources: string[];
}

export function chipsForRow(row: ReceiptChipSource): RowChipModel {
  const tags = tagsOf(row as { outer_container: { tags: unknown } });
  const targetResources = Array.isArray(tags?.target_resources)
    ? tags.target_resources.filter((r): r is string => typeof r === "string")
    : [];

  return {
    category: categoryFromRow({
      signed_predicate: {
        event_kind: row.signed_predicate.event_kind,
      },
      outer_container: {
        policy_decision: row.outer_container.policy_decision,
        tags: row.outer_container.tags,
      },
    }),
    decision: effectiveDecision(row),
    session: sessionIdOf(row as { outer_container: { tags: unknown } }),
    scope_kind: typeof tags?.scope_kind === "string" ? tags.scope_kind : null,
    scope_value: typeof tags?.scope_value === "string" ? tags.scope_value : null,
    target_resources: targetResources,
  };
}

export function compactTargetResources(
  chips: RowChipModel,
  limit = 2,
): { visible: string[]; hiddenCount: number } {
  const visible = chips.target_resources.slice(0, Math.max(0, limit));
  return {
    visible,
    hiddenCount: Math.max(0, chips.target_resources.length - visible.length),
  };
}
