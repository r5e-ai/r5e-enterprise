defmodule Recurse.Providers.Repo.Migrations.F004PolicySuggestions do
  @moduledoc """
  F004 Audit Console — `policy_suggestions` table.

  Auto-generated proposed Cedar rules from the heuristic (D3) and LLM (D4)
  suggestion engines. See specs/004-audit-console/data-model.md §1.2 for
  field-by-field rationale.

  PII-class columns (per §1.2 "PII handling"): `dismissed_by`,
  `pattern_summary`, `proposed_cedar` (the latter two may embed principal
  subjects). Retention purging via `console.retention.policy_suggestions_days`
  (default 180), soft-delete + 30-day-grace hard-delete.

  FKs:
    - tenant_id → tenants.tenant_id (restrict)
    - generation_run_id → policy_suggestion_runs.id (restrict) — job-log
      rows outlive individual suggestions
    - adopted_as_draft_id → policy_drafts.id (nilify_all) — draft retention-
      purge MUST NOT cascade-delete the suggestion's audit trail

  Indices follow §1.2:
    - composite (tenant_id, status, generated_at DESC) WHERE deleted_at IS NULL
      → "active suggestions list" hot-path on the Suggestions surface (US5)
    - (generation_run_id) → "list suggestions by job run" for the operator
      job log (FR-034 / FR-030a manual refresh traceability)
    - composite (tenant_id, source, generated_at DESC) WHERE deleted_at IS NULL
      → Source Label filter (heuristic-only / llm-only)
    - partial (adopted_as_draft_id) WHERE adopted_as_draft_id IS NOT NULL
      → reverse-lookup "which suggestion became this draft?"
    - partial (deleted_at) WHERE deleted_at IS NOT NULL
      → quarterly hard-delete scan (D7 / §5.2)
  """
  use Ecto.Migration

  def change do
    create table(:policy_suggestions, primary_key: false) do
      add :id, :binary_id, primary_key: true, null: false

      add :tenant_id,
          references(:tenants, column: :tenant_id, type: :string, on_delete: :restrict),
          null: false

      add :source, :string, null: false
      add :confidence_score, :integer, null: false
      add :pattern_summary, :text, null: false
      add :proposed_cedar, :text, null: false
      add :blast_radius_snapshot, :map

      add :generation_run_id,
          references(:policy_suggestion_runs, type: :binary_id, on_delete: :restrict),
          null: false

      add :status, :string, null: false
      add :dismissed_by, :string, size: 255
      add :dismissed_at, :utc_datetime_usec

      add :adopted_as_draft_id,
          references(:policy_drafts, type: :binary_id, on_delete: :nilify_all)

      add :generated_at, :utc_datetime_usec, null: false
      add :deleted_at, :utc_datetime_usec

      timestamps(type: :utc_datetime_usec)
    end

    create constraint(
             :policy_suggestions,
             :policy_suggestions_source_check,
             check: "source IN ('heuristic', 'llm')"
           )

    create constraint(
             :policy_suggestions,
             :policy_suggestions_status_check,
             check: "status IN ('active', 'adopted_as_draft', 'dismissed')"
           )

    create constraint(
             :policy_suggestions,
             :policy_suggestions_confidence_score_range,
             check: "confidence_score >= 0 AND confidence_score <= 100"
           )

    # "Active suggestions" hot-path on the Suggestions surface (US5).
    create index(:policy_suggestions, [:tenant_id, :status, :generated_at],
             name: :policy_suggestions_tenant_status_generated_at_index,
             where: "deleted_at IS NULL"
           )

    # "List suggestions by job run" (FR-034 / FR-030a). Non-partial — always non-NULL.
    create index(:policy_suggestions, [:generation_run_id],
             name: :policy_suggestions_generation_run_id_index
           )

    # Source Label filter (heuristic-only / llm-only).
    create index(:policy_suggestions, [:tenant_id, :source, :generated_at],
             name: :policy_suggestions_tenant_source_generated_at_index,
             where: "deleted_at IS NULL"
           )

    # Reverse-lookup "which suggestion became this draft?" from draft detail.
    create index(:policy_suggestions, [:adopted_as_draft_id],
             name: :policy_suggestions_adopted_as_draft_id_index,
             where: "adopted_as_draft_id IS NOT NULL"
           )

    # Quarterly hard-delete scan (D7 / §5.2).
    create index(:policy_suggestions, [:deleted_at],
             name: :policy_suggestions_deleted_at_purge_index,
             where: "deleted_at IS NOT NULL"
           )
  end
end
