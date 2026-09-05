defmodule Recurse.Gateway.Admin.PolicySuggestions.PolicySuggestionRun do
  @moduledoc """
  Ecto schema for the `policy_suggestion_runs` table — operator-visible job log
  for the suggestion engine (D3 hourly heuristic, D4 daily LLM, D7 retention
  sweeps, FR-030a manual refreshes).

  Cross-references:
    * `specs/004-audit-console/data-model.md` §1.5 (column rationale, indices,
      lifecycle, PII handling).
    * Migration — `apps/recurse_providers/priv/repo/migrations/20260424000002_f004_policy_suggestion_runs.exs`.
    * Glossary cluster — **Policy** (entry: *Policy Suggestion Run*).

  AD-001 c' note: lives under the Gateway admin context. Talks to
  `Recurse.Providers.Repo` via the parent context module
  `Recurse.Gateway.Admin.PolicySuggestions` (T125, separate phase).

  Lifecycle is implicit in the (started_at, completed_at, error) tuple — no
  status enum. See data-model §1.5 "Lifecycle" for the
  queued/running/completed/failed/stalled state machine.
  """

  use Ecto.Schema

  import Ecto.Changeset

  @source_values [:heuristic, :llm]

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @derive {Jason.Encoder,
           only: [
             :id,
             :tenant_id,
             :source,
             :requested_by_principal_subject,
             :scheduled_at,
             :started_at,
             :completed_at,
             :suggestions_generated_count,
             :llm_token_spend,
             :error,
             :deleted_at,
             :inserted_at,
             :updated_at
           ]}

  schema "policy_suggestion_runs" do
    field(:tenant_id, :string)
    field(:source, Ecto.Enum, values: @source_values)
    field(:requested_by_principal_subject, :string)
    field(:scheduled_at, :utc_datetime_usec)
    field(:started_at, :utc_datetime_usec)
    field(:completed_at, :utc_datetime_usec)
    field(:suggestions_generated_count, :integer, default: 0)
    field(:llm_token_spend, :integer, default: 0)
    field(:error, :string)
    field(:deleted_at, :utc_datetime_usec)

    timestamps(type: :utc_datetime_usec)
  end

  @type t :: %__MODULE__{}

  @required_fields [:tenant_id, :source, :scheduled_at]

  @optional_fields [
    :requested_by_principal_subject,
    :started_at,
    :completed_at,
    :suggestions_generated_count,
    :llm_token_spend,
    :error,
    :deleted_at
  ]

  @doc """
  Cast + validate a PolicySuggestionRun row per data-model §1.5.

  Validations:
    * `requested_by_principal_subject` ≤ 255 chars when set.
    * `suggestions_generated_count` ≥ 0.
    * `llm_token_spend` ≥ 0 (unit is **tokens**, not dollars; cost roll-up
      happens at the operator-visible layer).
    * `scheduled_at <= started_at <= completed_at` (when set) via
      `validate_timestamps_ordered/1` — cheap guard against clock skew writes.
    * Tenant FK constraint (DB-enforced).
  """
  @spec changeset(t() | %__MODULE__{}, map()) :: Ecto.Changeset.t()
  def changeset(run, attrs) do
    run
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_length(:requested_by_principal_subject, max: 255)
    |> validate_number(:suggestions_generated_count, greater_than_or_equal_to: 0)
    |> validate_number(:llm_token_spend, greater_than_or_equal_to: 0)
    |> validate_timestamps_ordered()
    |> foreign_key_constraint(:tenant_id)
  end

  # Enforce `scheduled_at <= started_at <= completed_at` when the latter two
  # are non-NULL. Tolerates either or both being NULL (queued/running rows).
  defp validate_timestamps_ordered(changeset) do
    scheduled_at = get_field(changeset, :scheduled_at)
    started_at = get_field(changeset, :started_at)
    completed_at = get_field(changeset, :completed_at)

    changeset
    |> check_pair(:started_at, scheduled_at, started_at, "must be >= scheduled_at")
    |> check_pair(:completed_at, started_at, completed_at, "must be >= started_at")
    |> check_pair(:completed_at, scheduled_at, completed_at, "must be >= scheduled_at")
  end

  defp check_pair(changeset, _field, nil, _later, _msg), do: changeset
  defp check_pair(changeset, _field, _earlier, nil, _msg), do: changeset

  defp check_pair(changeset, field, earlier, later, msg) do
    if DateTime.compare(later, earlier) == :lt do
      add_error(changeset, field, msg)
    else
      changeset
    end
  end
end
