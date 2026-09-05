defmodule Recurse.Providers.Repo.Migrations.F004PolicySuggestionRuns do
  @moduledoc """
  F004 Audit Console — `policy_suggestion_runs` job-log table.

  Operator-visible job log for the suggestion engine (D3 heuristic hourly,
  D4 LLM daily, D7 retention sweeps, FR-030a manual refreshes). See
  specs/004-audit-console/data-model.md §1.5 for column-by-column rationale.

  Ordered BEFORE `policy_suggestions` so the FK from suggestion → run can be
  declared in the same migration as `policy_suggestions` (next migration).

  Indices follow §1.5:
    - composite (tenant_id, source, scheduled_at DESC) WHERE deleted_at IS NULL
      → operator job-log paginated view
    - composite (tenant_id, completed_at DESC) WHERE completed_at IS NOT NULL
      AND deleted_at IS NULL → "latest successful run" timestamp
    - partial (tenant_id) WHERE started_at IS NOT NULL AND completed_at IS NULL
      AND deleted_at IS NULL → "what's currently running?" diagnostic
    - partial (deleted_at) WHERE deleted_at IS NOT NULL
      → quarterly hard-delete scan (D7 / §5.2)

  Lifecycle is implicit in the (started_at, completed_at, error) tuple — no
  status enum. See §1.5 "Lifecycle" for the queued/running/completed/failed/
  stalled state machine.
  """
  use Ecto.Migration

  def change do
    create table(:policy_suggestion_runs, primary_key: false) do
      add :id, :binary_id, primary_key: true, null: false

      add :tenant_id,
          references(:tenants, column: :tenant_id, type: :string, on_delete: :restrict),
          null: false

      add :source, :string, null: false
      add :requested_by_principal_subject, :string, size: 255
      add :scheduled_at, :utc_datetime_usec, null: false
      add :started_at, :utc_datetime_usec
      add :completed_at, :utc_datetime_usec
      add :suggestions_generated_count, :integer, null: false, default: 0
      add :llm_token_spend, :integer, null: false, default: 0
      add :error, :text
      add :deleted_at, :utc_datetime_usec

      timestamps(type: :utc_datetime_usec)
    end

    create constraint(
             :policy_suggestion_runs,
             :policy_suggestion_runs_source_check,
             check: "source IN ('heuristic', 'llm')"
           )

    create constraint(
             :policy_suggestion_runs,
             :policy_suggestion_runs_suggestions_count_nonneg,
             check: "suggestions_generated_count >= 0"
           )

    create constraint(
             :policy_suggestion_runs,
             :policy_suggestion_runs_llm_token_spend_nonneg,
             check: "llm_token_spend >= 0"
           )

    # Operator job-log paginated view ("last 30 days of heuristic runs").
    create index(:policy_suggestion_runs, [:tenant_id, :source, :scheduled_at],
             name: :policy_suggestion_runs_tenant_source_scheduled_at_index,
             where: "deleted_at IS NULL"
           )

    # "Latest successful run" lookup driving Suggestions surface "last updated".
    create index(:policy_suggestion_runs, [:tenant_id, :completed_at],
             name: :policy_suggestion_runs_tenant_completed_at_index,
             where: "completed_at IS NOT NULL AND deleted_at IS NULL"
           )

    # "What's currently running?" operator diagnostic.
    create index(:policy_suggestion_runs, [:tenant_id],
             name: :policy_suggestion_runs_in_flight_index,
             where: "started_at IS NOT NULL AND completed_at IS NULL AND deleted_at IS NULL"
           )

    # Quarterly hard-delete scan (D7 / §5.2).
    create index(:policy_suggestion_runs, [:deleted_at],
             name: :policy_suggestion_runs_deleted_at_purge_index,
             where: "deleted_at IS NOT NULL"
           )
  end
end
