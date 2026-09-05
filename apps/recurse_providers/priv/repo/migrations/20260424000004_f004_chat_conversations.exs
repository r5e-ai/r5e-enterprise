defmodule Recurse.Providers.Repo.Migrations.F004ChatConversations do
  @moduledoc """
  F004 Audit Console — `chat_conversations` table (audit-agent transcript root).

  Per-principal conversations with the audit agent. See
  specs/004-audit-console/data-model.md §1.3 for field-by-field rationale.

  PII: `principal_subject` is PII by definition. Retention purging via
  `console.retention.chat_history_days` (default 30) — soft-delete + 30-day
  grace hard-delete. Conversation lifecycle is implicit (no `status` enum):
  active while archived_at IS NULL; archived when set; hard-deleted 90 days
  post-archive (D7). Note that the receipts FOR each chat message remain in
  the F002 audit log unchanged for 7-year retention (FR-041b).

  Indices follow §1.3:
    - composite (tenant_id, principal_subject, last_message_at DESC)
      WHERE deleted_at IS NULL
      → "list my conversations, most recent first" — chat drawer history
    - composite (tenant_id, last_message_at DESC) — INTENTIONALLY NON-PARTIAL
      → retention-purge worker scan reads BOTH live and already-soft-deleted
      rows so it can age them into hard-delete
    - partial (deleted_at) WHERE deleted_at IS NOT NULL
      → quarterly hard-delete scan (D7 / §5.2)
  """
  use Ecto.Migration

  def change do
    create table(:chat_conversations, primary_key: false) do
      add :id, :binary_id, primary_key: true, null: false

      add :tenant_id,
          references(:tenants, column: :tenant_id, type: :string, on_delete: :restrict),
          null: false

      add :principal_subject, :string, null: false, size: 255
      add :started_at, :utc_datetime_usec, null: false
      add :last_message_at, :utc_datetime_usec, null: false
      add :archived_at, :utc_datetime_usec
      add :deleted_at, :utc_datetime_usec

      timestamps(type: :utc_datetime_usec)
    end

    # "List my conversations, most recent first" — per-principal partial composite.
    create index(:chat_conversations, [:tenant_id, :principal_subject, :last_message_at],
             name: :chat_conversations_tenant_principal_last_message_at_index,
             where: "deleted_at IS NULL"
           )

    # Retention-purge worker scan. INTENTIONALLY NON-PARTIAL per §1.3 — the
    # purge worker reads both live and already-soft-deleted rows so it can age
    # them into hard-delete in a single sweep.
    create index(:chat_conversations, [:tenant_id, :last_message_at],
             name: :chat_conversations_tenant_last_message_at_index
           )

    # Quarterly hard-delete scan (D7 / §5.2).
    create index(:chat_conversations, [:deleted_at],
             name: :chat_conversations_deleted_at_purge_index,
             where: "deleted_at IS NOT NULL"
           )
  end
end
