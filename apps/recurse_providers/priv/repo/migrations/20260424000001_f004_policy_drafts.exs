defmodule Recurse.Providers.Repo.Migrations.F004PolicyDrafts do
  @moduledoc """
  F004 Audit Console — `policy_drafts` table.

  Operator-authored Cedar rules, not yet deployed. See
  specs/004-audit-console/data-model.md §1.1 for the field-by-field rationale,
  including the soft-reference to `attestations.run_id` (no DB-level FK because
  receipts cross 7-year retention while drafts cross 365-day retention).

  Indices follow the use-cases enumerated in §1.1:
    - composite (tenant_id, status, inserted_at DESC) WHERE deleted_at IS NULL
      → operator dashboard "active drafts" list
    - partial (source_receipt_run_id) WHERE NOT NULL
      → reverse-lookup from Receipt Detail
    - partial (tenant_id, author_principal_subject, inserted_at DESC)
      WHERE deleted_at IS NULL
      → "drafts I authored" filter
    - partial (deleted_at) WHERE deleted_at IS NOT NULL
      → quarterly hard-delete scan (D7 / §5.2)

  Lifecycle (`status`): :draft → :adopted_as_draft | :archived (one-way).
  Enforced at the application layer (`Recurse.Gateway.Admin.PolicyDrafts`),
  not by DB constraint.
  """
  use Ecto.Migration

  def change do
    create table(:policy_drafts, primary_key: false) do
      add :id, :binary_id, primary_key: true, null: false

      add :tenant_id,
          references(:tenants, column: :tenant_id, type: :string, on_delete: :restrict),
          null: false

      add :author_principal_subject, :string, null: false, size: 255
      add :source_receipt_run_id, :binary_id
      add :cedar_source, :text, null: false
      add :scope_metadata, :map, null: false
      add :condition_metadata, :map, null: false
      add :status, :string, null: false
      add :archived_at, :utc_datetime_usec
      add :last_blast_radius_at, :utc_datetime_usec
      add :last_blast_radius_summary, :map
      add :deleted_at, :utc_datetime_usec

      timestamps(type: :utc_datetime_usec)
    end

    create constraint(
             :policy_drafts,
             :policy_drafts_status_check,
             check: "status IN ('draft', 'adopted_as_draft', 'archived')"
           )

    # "Active drafts, most recent first" hot-path for the operator dashboard.
    create index(:policy_drafts, [:tenant_id, :status, :inserted_at],
             name: :policy_drafts_tenant_status_inserted_at_index,
             where: "deleted_at IS NULL"
           )

    # Reverse-lookup: which drafts did this receipt seed? (US3 back-link.)
    create index(:policy_drafts, [:source_receipt_run_id],
             name: :policy_drafts_source_receipt_run_id_index,
             where: "source_receipt_run_id IS NOT NULL"
           )

    # "Drafts I authored" lens for the operator dashboard.
    create index(
             :policy_drafts,
             [:tenant_id, :author_principal_subject, :inserted_at],
             name: :policy_drafts_tenant_author_inserted_at_index,
             where: "deleted_at IS NULL"
           )

    # Quarterly hard-delete scan (D7 / §5.2). Tiny — only soft-deleted rows.
    create index(:policy_drafts, [:deleted_at],
             name: :policy_drafts_deleted_at_purge_index,
             where: "deleted_at IS NOT NULL"
           )
  end
end
