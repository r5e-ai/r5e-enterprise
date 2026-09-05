defmodule Recurse.Providers.Repo.Migrations.F004ChatMessages do
  @moduledoc """
  F004 Audit Console — `chat_messages` table.

  Individual messages within an audit-agent conversation. See
  specs/004-audit-console/data-model.md §1.4 for field-by-field rationale.

  PII: `content` is free-form user/agent text (maximally PII); `tool_calls`
  JSONB may embed principal subjects in tool arguments. Retention purging via
  `console.retention.chat_history_days` (default 30); archived conversations'
  messages go away 90 days post-archive. The receipts FOR each message
  (`:ui_chat`, `:ui_chat_skill_invoked_*`) remain in F002 audit log for 7
  years — explicit FR-041a decision.

  FKs:
    - conversation_id → chat_conversations.id (delete_all). On conversation
      hard-delete, the messages cascade.
    - attested_run_id is a SOFT reference (no DB FK) — receipts outlive chat
      messages (7-year vs 30-day retention).

  Indices follow §1.4:
    - UNIQUE (conversation_id, sequence) — NON-PARTIAL: sequence numbers must
      not be reused after a soft-delete; uniqueness must hold across both live
      and soft-deleted rows. Doubles as the concurrency guard for racing writers.
    - partial (attested_run_id) WHERE attested_run_id IS NOT NULL
      → "link a message back to its receipt" from Receipt Detail
    - composite (conversation_id, inserted_at DESC) WHERE deleted_at IS NULL
      → default-read transcript fetch path
    - partial (deleted_at) WHERE deleted_at IS NOT NULL
      → quarterly hard-delete scan (D7 / §5.2)
  """
  use Ecto.Migration

  def change do
    create table(:chat_messages, primary_key: false) do
      add :id, :binary_id, primary_key: true, null: false

      add :conversation_id,
          references(:chat_conversations, type: :binary_id, on_delete: :delete_all),
          null: false

      add :role, :string, null: false
      add :content, :text, null: false
      add :tool_calls, :map
      add :attested_run_id, :binary_id
      add :sequence, :integer, null: false
      add :deleted_at, :utc_datetime_usec

      timestamps(type: :utc_datetime_usec)
    end

    create constraint(
             :chat_messages,
             :chat_messages_role_check,
             check: "role IN ('user', 'agent', 'tool_call', 'tool_result')"
           )

    create constraint(
             :chat_messages,
             :chat_messages_sequence_positive,
             check: "sequence > 0"
           )

    # UNIQUE (conversation_id, sequence) — non-partial. Sequence numbers must
    # not be reused after soft-delete; the unique invariant must hold across
    # both live and soft-deleted rows. Doubles as the concurrency guard.
    create unique_index(:chat_messages, [:conversation_id, :sequence],
             name: :chat_messages_conversation_sequence_unique_index
           )

    # "Link a message back to its receipt" from Receipt Detail.
    create index(:chat_messages, [:attested_run_id],
             name: :chat_messages_attested_run_id_index,
             where: "attested_run_id IS NOT NULL"
           )

    # Default-read transcript fetch path; also covers D7 purge worker scan.
    create index(:chat_messages, [:conversation_id, :inserted_at],
             name: :chat_messages_conversation_inserted_at_index,
             where: "deleted_at IS NULL"
           )

    # Quarterly hard-delete scan (D7 / §5.2).
    create index(:chat_messages, [:deleted_at],
             name: :chat_messages_deleted_at_purge_index,
             where: "deleted_at IS NOT NULL"
           )
  end
end
