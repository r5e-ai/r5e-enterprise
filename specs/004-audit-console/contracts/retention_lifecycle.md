# Contract: Console Retention Lifecycle

**Feature**: F004 | **Spec**: FR-029a, FR-035a, FR-041a, FR-041b | **Research**: D7 | **Glossary**: Console Retention Configuration

This contract defines the retention semantics for the three new F004 data classes — **Policy Drafts**, **Policy Suggestions**, and **Chat Conversations** — plus the soft-delete + grace-window + hard-delete lifecycle, the Oban.Cron purge schedule, and the attested `:ui_retention_purge` event emission. **Receipts emitted FOR these data classes are NEVER affected by F004 retention** — they live under F002's audit retention setting (typically 7 years).

---

## Tier-config block

The operator-configurable retention windows live under `console.retention.*` in the deployment's tier-config YAML:

```yaml
console:
  retention:
    policy_drafts_days: 365         # FR-029a default
    policy_suggestions_days: 180    # FR-035a default
    chat_history_days: 30           # FR-041a default
    grace_window_days: 30           # soft-delete-to-hard-delete window; default 30, configurable 7–90
    purge_schedule_cron: "0 3 * * *"  # 03:00 UTC daily; configurable but rejected if more frequent than hourly
```

**Validation**: at boot, `Recurse.Gateway.Config` validates:
- All `*_days` values are integers ≥ 1 and ≤ 3650 (10 years).
- `grace_window_days` is in `[7, 90]`.
- `purge_schedule_cron` is parseable + has interval ≥ 1 hour.

Invalid config = boot failure with clear message. Defaults are used when keys are absent.

---

## Defaults (per Q3 clarification)

| Data class | Default retention | Rationale |
|---|---|---|
| `policy_drafts` | 365 days | Drafts represent operator intent; year-long window matches typical compliance audit cycles. |
| `policy_suggestions` | 180 days | Suggestions are time-sensitive (drift); 6-month window keeps the surface fresh without losing recent context. |
| `chat_history` | 30 days | Conversation transcripts are diagnostic, not evidentiary; the receipts they emit are the durable record (subject to F002 audit retention). |
| `grace_window` | 30 days | Operator-recoverable window post-soft-delete; allows recovery from misconfigured retention edits. |

---

## Lifecycle states

### Policy Drafts

States: `draft → adopted → archived → expired → purged`

Transitions:

- `draft → adopted`: when the draft is referenced by a deployed policy bundle (post-F004 — F004 ships drafts only, not deploy; this transition is forward-stub for F005+). **Adopted drafts are exempt from retention** — they remain visible indefinitely so the audit trail of "what draft became this deployed policy" never breaks.
- `draft → archived`: when an operator calls `DELETE /v1/policy/drafts/{id}` (soft-archive). The row remains queryable with `?status=archived`.
- `archived → expired` (soft-delete): when `now > archived_at + (console.retention.policy_drafts_days)` AND `status == "archived"`. The Oban purge job sets `deleted_at = now`. Row remains queryable via `?with_deleted=true`.
- `draft → expired` (no archive): a draft never explicitly archived but older than retention. Same soft-delete with `deleted_at = now`.
- `expired → purged` (hard-delete): when `now > deleted_at + grace_window_days`. Row hard-deleted from `policy_drafts`. **Cedar source content is irrecoverable** post-purge.

**Adoption exemption check**: a draft with `adopted_as_policy_id != NULL` is never eligible for soft-delete or purge. The deployed policy is the durable record.

### Policy Suggestions

States: `pending → adopted_as_draft|dismissed → expired → purged`

Transitions:

- `pending → adopted_as_draft`: `POST /v1/policy/suggestions/{id}/adopt`. Suggestion's `adopted_as_draft_id` populates; the suggestion is **exempt from retention** for as long as the resulting draft is exempt (chained exemption — adopted drafts that are themselves promoted to deployed policies keep their generating suggestion queryable too).
- `pending → dismissed`: `POST /v1/policy/suggestions/{id}/dismiss`. Soft-state; `dismissed_at` populated.
- `pending|dismissed → expired` (soft-delete): when `now > generated_at + console.retention.policy_suggestions_days` AND `status NOT IN [adopted_as_draft]`.
- `expired → purged` (hard-delete): `now > deleted_at + grace_window_days`.

### Chat Conversations + Chat Messages

States: `active → archived → expired → purged`

Per FR-041b: "When chat history retention expires for a conversation, the conversation transcript MUST be archived (soft-delete with last-N-messages preserved on read-only basis) and eventually purged."

Transitions:

- `chat_messages` retention is per-message (`created_at`-driven), not per-conversation. The Oban job soft-deletes individual messages when `now > created_at + chat_history_days`.
- A conversation row (`chat_conversations`) is auto-archived when ALL its messages are soft-deleted (or hard-deleted). Archive sets `archived_at = now` on `chat_conversations`.
- After conversation archive, an additional 90 days passes before hard-delete of the conversation row (for audit trail).
- **Last-N-messages preserved on read-only basis** (per FR-041b): the most recent 5 messages of an archived conversation (configurable via `console.retention.chat_history_preserved_messages`, default 5) are retained as read-only past the per-message expiry, allowing post-archive forensic queries. They are still soft-deleted but with a `pinned_until` timestamp = `archived_at + 365 days`.

### Receipts emitted FOR these data classes

**NEVER affected by F004 retention.** A `:ui_chat_skill_invoked_explain_denial` receipt emitted by an audit-agent tool call lives in the F002 attestations table for the full F002 retention period (typically 7 years). The fact that the underlying `chat_messages.tool_calls` JSONB blob containing the LLM input/output is purged after 30 days does NOT alter the receipt — the receipt's `signed_predicate` carries `input_hash` and `output_hash` (per `audit_agent_tools.md`), so the receipt is verifiable post-purge even though the original input/output is gone.

---

## Oban.Cron job schedule

Per D7, three jobs run at the configured schedule (default 03:00 UTC daily):

```elixir
defmodule Recurse.Gateway.SuggestionEngine.RetentionPurger.PolicyDrafts do
  use Oban.Worker, queue: :retention, max_attempts: 3

  @impl Oban.Worker
  def perform(_job) do
    soft_delete_expired_drafts()
    hard_delete_purged_drafts()
    emit_purge_attestation(:policy_drafts, ...counts...)
  end
end
```

Three separate workers (one per data class) so failures in one don't block the others. Oban's `unique` constraint prevents double-firing.

---

## Soft-delete column

Each affected table gains a `deleted_at TIMESTAMP WITH TIME ZONE NULL` column. All queries default-filter `WHERE deleted_at IS NULL`; the SPA's archive view explicitly toggles to `?with_deleted=true` to surface soft-deleted rows.

| Table | Soft-delete column | Hard-delete trigger |
|---|---|---|
| `policy_drafts` | `deleted_at` | `now > deleted_at + grace_window_days` |
| `policy_suggestions` | `deleted_at` | same |
| `chat_messages` | `deleted_at` | same |
| `chat_conversations` | `archived_at` | `now > archived_at + 90 days` |

Hard-deletes use `DELETE FROM ... WHERE deleted_at < now() - interval '? days'` in batches of 1,000 to avoid long-running transactions.

---

## `:ui_retention_purge` attestation

Per cycle, each purge job emits ONE attested receipt with:

```json
{
  "event_kind": "ui_retention_purge",
  "principal": {"kind": "system", "subject": "system:retention_purger", "recurse_role": "system"},
  "signed_predicate": {
    "data_class": "policy_drafts|policy_suggestions|chat_history",
    "soft_deleted_count": 47,
    "hard_deleted_count": 12,
    "policy_canonical_hash": "sha256:...",
    "tenant_id": "...",
    "started_at": "2026-04-24T03:00:00Z",
    "completed_at": "2026-04-24T03:00:08Z",
    "duration_ms": 8200
  }
}
```

The attestation provides operator-visible evidence of the purge cycle. Auditors can replay the purge via the `recurse-verify` flow against the receipt; the attestation's `principal.kind == "system"` distinguishes machine-driven purges from operator-initiated archives.

A separate `retention_purge_runs` table records per-run metadata (job_id, cron_schedule, hostname, error if any) for operator dashboards (Day-2+; not surfaced in the F004 SPA).

---

## Recovery semantics

During the grace window (`deleted_at` set, but not yet hard-deleted):

| Action | Available |
|---|---|
| `GET /v1/policy/drafts/{id}?with_deleted=true` | ✅ Returns the draft with `deleted_at` populated. |
| `POST /v1/policy/drafts/{id}/restore` (Day-2+ endpoint) | ❌ NOT in F004 — operator recovery requires DB-level intervention. F004 ships the soft-delete safety net; restore UX is Day-2. |
| Audit-agent `find_similar_receipts` on a soft-deleted draft's source receipt | ✅ Receipt itself is not affected. |

The grace window's role: prevent operator misconfiguration. When `console.retention.policy_drafts_days = 1` is set by mistake and the next cron cycle soft-deletes 200 drafts, the operator has 30 days to fix the config and submit a CASCADE recovery via DB intervention before hard-delete.

---

## Property-test surfaces

(In `property_test_surface_catalog_f004.md` — but listed here for cross-reference.)

- **Adoption exemption**: an `adopted` draft is NEVER soft-deleted regardless of `created_at` age.
- **Soft-delete idempotence**: running the purge job twice in quick succession produces the same final state (no double-deletion, no errors).
- **Receipts unaffected**: after a complete F004 retention cycle (every data class purged), the count of attestations in the F002 ledger is unchanged.
- **Chat last-N preservation**: a chat conversation with 100 messages → after retention expiry, exactly 5 (default) messages are pinned-readable; the other 95 are soft-deleted.

---

## Failure modes

| Failure | Behavior |
|---|---|
| Oban job crashes mid-cycle | Job retried up to `max_attempts: 3`; partial work is idempotent (each iteration filters by `deleted_at IS NULL`). |
| DB connection pool exhausted | Job fails the cycle; emit `:ui_retention_purge` with `outcome: "pool_exhausted"` and counts of 0; retry next scheduled cycle. |
| Tier-config invalid (negative days) | Boot failure; the Gateway never starts with broken retention config. |
| Adopted-draft exemption check race (draft adopted between query and delete) | Use `WHERE adopted_as_policy_id IS NULL` in the soft-delete UPDATE; the row will not match if adoption raced ahead, no harm done. |

---

## Out of scope

- Operator-driven manual purge (one-off "purge all suggestions older than 7 days"). Day-2 endpoint.
- Retention by data attribute (e.g., "purge drafts authored by alice@corp"). All retention is time-based per data class.
- Cross-tenant retention policies. Single-tenant per deployment in F004.
- Soft-delete for the suggestions metadata in `policy_suggestion_runs` (the operator-visible job log table). Job logs are kept indefinitely; volume is low (one row per cycle).
