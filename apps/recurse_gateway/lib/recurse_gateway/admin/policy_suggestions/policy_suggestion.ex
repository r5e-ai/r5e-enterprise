defmodule Recurse.Gateway.Admin.PolicySuggestions.PolicySuggestion do
  @moduledoc """
  Ecto schema for the `policy_suggestions` table — auto-generated proposed
  Cedar rules from the heuristic (D3) and LLM (D4) suggestion engines.

  Cross-references:
    * `specs/004-audit-console/data-model.md` §1.2 (column rationale, indices,
      lifecycle, PII handling).
    * Migration — `apps/recurse_providers/priv/repo/migrations/20260424_f004_policy_suggestions.exs`
      (Wave 1A, sibling task).
    * Glossary cluster — **Policy** (entries: *Policy Suggestion*, *Source Label*,
      *Confidence Score*).

  AD-001 c' note: lives under the Gateway admin context, NOT on
  `PostgresMerkleLedger`. Talks to `Recurse.Providers.Repo` via the parent
  context module `Recurse.Gateway.Admin.PolicySuggestions` (T125, separate
  phase).

  Lifecycle is `:active → :adopted_as_draft | :dismissed` (one-way; enforced at
  the application layer, not by DB constraint). Cross-field invariants tied to
  `status` are enforced here via `validate_lifecycle_consistency/1`.
  """

  use Ecto.Schema

  import Ecto.Changeset

  @source_values [:heuristic, :llm]
  @status_values [:active, :adopted_as_draft, :dismissed]

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @derive {Jason.Encoder,
           only: [
             :id,
             :tenant_id,
             :source,
             :confidence_score,
             :pattern_summary,
             :proposed_cedar,
             :blast_radius_snapshot,
             :generation_run_id,
             :status,
             :dismissed_by,
             :dismissed_at,
             :adopted_as_draft_id,
             :generated_at,
             :deleted_at,
             :inserted_at,
             :updated_at
           ]}

  schema "policy_suggestions" do
    field(:tenant_id, :string)
    field(:source, Ecto.Enum, values: @source_values)
    field(:confidence_score, :integer)
    field(:pattern_summary, :string)
    field(:proposed_cedar, :string)
    field(:blast_radius_snapshot, :map)
    field(:generation_run_id, :binary_id)
    field(:status, Ecto.Enum, values: @status_values)
    field(:dismissed_by, :string)
    field(:dismissed_at, :utc_datetime_usec)
    field(:adopted_as_draft_id, :binary_id)
    field(:generated_at, :utc_datetime_usec)
    field(:deleted_at, :utc_datetime_usec)

    timestamps(type: :utc_datetime_usec)
  end

  @type t :: %__MODULE__{}

  @required_fields [
    :tenant_id,
    :source,
    :confidence_score,
    :pattern_summary,
    :proposed_cedar,
    :generation_run_id,
    :status,
    :generated_at
  ]

  @optional_fields [
    :blast_radius_snapshot,
    :dismissed_by,
    :dismissed_at,
    :adopted_as_draft_id,
    :deleted_at
  ]

  @doc """
  Cast + validate a PolicySuggestion row per data-model §1.2.

  Validations:
    * `confidence_score` ∈ 0..100.
    * `pattern_summary` ≤ 200 chars (D4 contract).
    * `proposed_cedar` ≤ 500 chars (D4 contract).
    * `dismissed_by` ≤ 255 chars when set.
    * Cross-field invariants via `validate_lifecycle_consistency/1`:
        - `status = :dismissed` ⇒ `dismissed_by` AND `dismissed_at` non-NULL.
        - `status = :adopted_as_draft` ⇒ `adopted_as_draft_id` non-NULL.
        - `status = :active` ⇒ all three lifecycle columns NULL.
    * Tenant + run + draft FK constraints (DB-enforced).
  """
  @spec changeset(t() | %__MODULE__{}, map()) :: Ecto.Changeset.t()
  def changeset(suggestion, attrs) do
    suggestion
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_inclusion(:confidence_score, 0..100)
    |> validate_length(:pattern_summary, max: 200)
    |> validate_length(:proposed_cedar, max: 500)
    |> validate_length(:dismissed_by, max: 255)
    |> validate_lifecycle_consistency()
    |> foreign_key_constraint(:tenant_id)
    |> foreign_key_constraint(:generation_run_id)
    |> foreign_key_constraint(:adopted_as_draft_id)
  end

  # Cross-field invariant tied to `status` per data-model §1.2.
  defp validate_lifecycle_consistency(changeset) do
    status = get_field(changeset, :status)
    dismissed_by = get_field(changeset, :dismissed_by)
    dismissed_at = get_field(changeset, :dismissed_at)
    adopted_as_draft_id = get_field(changeset, :adopted_as_draft_id)

    case status do
      :dismissed ->
        changeset
        |> require_present(:dismissed_by, dismissed_by)
        |> require_present(:dismissed_at, dismissed_at)

      :adopted_as_draft ->
        require_present(changeset, :adopted_as_draft_id, adopted_as_draft_id)

      :active ->
        changeset
        |> require_absent(:dismissed_by, dismissed_by)
        |> require_absent(:dismissed_at, dismissed_at)
        |> require_absent(:adopted_as_draft_id, adopted_as_draft_id)

      _other ->
        changeset
    end
  end

  defp require_present(changeset, _field, value) when not is_nil(value), do: changeset

  defp require_present(changeset, field, _nil_value) do
    add_error(changeset, field, "is required when status implies it")
  end

  defp require_absent(changeset, _field, nil), do: changeset

  defp require_absent(changeset, field, _value) do
    add_error(changeset, field, "must be NULL when status is :active")
  end
end
