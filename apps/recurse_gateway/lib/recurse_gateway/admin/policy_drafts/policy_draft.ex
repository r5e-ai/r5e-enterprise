defmodule Recurse.Gateway.Admin.PolicyDrafts.PolicyDraft do
  @moduledoc """
  Ecto schema for the `policy_drafts` table — operator-authored Cedar rules
  not yet deployed.

  Cross-references:
    * `specs/004-audit-console/data-model.md` §1.1 (column-by-column rationale,
      indices, lifecycle, PII handling).
    * Migration — `apps/recurse_providers/priv/repo/migrations/20260424000001_f004_policy_drafts.exs`.
    * Glossary cluster — **Policy** (entry: *Policy Draft*).

  AD-001 c' note (per data-model §3): UI state lives in Gateway admin contexts,
  not on `Recurse.Providers.Impls.PostgresMerkleLedger`. This schema talks to
  `Recurse.Providers.Repo` directly via the parent context module
  `Recurse.Gateway.Admin.PolicyDrafts` (T085, separate phase).

  The `tenant_id` column is referenced as a plain `:string` field rather than a
  `belongs_to` association: the F002 `Tenant` schema lives in the
  `:recurse_providers` app and we deliberately keep this schema's compile-time
  graph free of provider-impl modules. The FK constraint is enforced at the DB
  layer (migration §1) and surfaced through `foreign_key_constraint/2`.

  The `source_receipt_run_id` column is a **soft reference** to
  `attestations.run_id` — receipts cross 7-year retention while drafts cross
  365-day retention, so a hard FK would force awkward on-delete semantics. The
  join is enforced at query time, not at write time.
  """

  use Ecto.Schema

  import Ecto.Changeset

  @status_values [:draft, :adopted_as_draft, :archived]

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @derive {Jason.Encoder,
           only: [
             :id,
             :tenant_id,
             :author_principal_subject,
             :source_receipt_run_id,
             :cedar_source,
             :scope_metadata,
             :condition_metadata,
             :status,
             :archived_at,
             :last_blast_radius_at,
             :last_blast_radius_summary,
             :deleted_at,
             :inserted_at,
             :updated_at
           ]}

  schema "policy_drafts" do
    field(:tenant_id, :string)
    field(:author_principal_subject, :string)
    field(:source_receipt_run_id, :binary_id)
    field(:cedar_source, :string)
    field(:scope_metadata, :map)
    # `condition_metadata` is JSONB at the DB layer (migration `:map`) and
    # represents an array of condition objects per data-model.md §1.1. We
    # type it as `{:array, :map}` here so Ecto's cast layer accepts a list
    # of maps; the changeset's `validate_condition_metadata_shape/1` enforces
    # the per-element `:kind` invariant.
    field(:condition_metadata, {:array, :map})
    field(:status, Ecto.Enum, values: @status_values)
    field(:archived_at, :utc_datetime_usec)
    field(:last_blast_radius_at, :utc_datetime_usec)
    field(:last_blast_radius_summary, :map)
    field(:deleted_at, :utc_datetime_usec)

    timestamps(type: :utc_datetime_usec)
  end

  @type t :: %__MODULE__{}

  @required_fields [
    :tenant_id,
    :author_principal_subject,
    :cedar_source,
    :scope_metadata,
    :condition_metadata,
    :status
  ]

  @optional_fields [
    :source_receipt_run_id,
    :archived_at,
    :deleted_at,
    :last_blast_radius_at,
    :last_blast_radius_summary
  ]

  @doc """
  Cast + validate a PolicyDraft row per data-model §1.1.

  Validations:
    * `cedar_source` ≤ 16 KB (single rule is almost never >500 bytes; 16 KB is
      generous headroom with a ceiling).
    * `author_principal_subject` ≤ 255 chars.
    * `status` ∈ #{inspect(@status_values)}.
    * `scope_metadata` matches `%{scope_kind: atom, scope_value: binary}` shape.
    * `condition_metadata` is a list of `%{kind: atom, ...}` maps.
    * Tenant FK constraint (DB-enforced; surfaced as changeset error).

  Status transitions are enforced at the application layer
  (`Recurse.Gateway.Admin.PolicyDrafts.update/2`), NOT here — see
  data-model §1.1 "Lifecycle" for the state machine.
  """
  @spec changeset(t() | %__MODULE__{}, map()) :: Ecto.Changeset.t()
  def changeset(draft, attrs) do
    draft
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_length(:cedar_source, max: 16_384)
    |> validate_length(:author_principal_subject, max: 255)
    |> validate_inclusion(:status, @status_values)
    |> validate_scope_metadata_shape()
    |> validate_condition_metadata_shape()
    |> foreign_key_constraint(:tenant_id)
  end

  # `scope_metadata` must be a map of the shape:
  #   %{scope_kind: :principal | :role | :group | :tenant, scope_value: binary}
  #
  # Atoms/strings both accepted in JSONB round-tripping (Ecto stores atoms as
  # strings on read), so we accept either keying for `scope_kind` and either
  # an atom or a binary `scope_value`. Actual scope semantics live in
  # contracts/blast_radius_algorithm.md; this guard only protects against
  # garbage JSONB.
  @scope_kinds ~w(principal role group tenant)
  defp validate_scope_metadata_shape(changeset) do
    case get_field(changeset, :scope_metadata) do
      nil -> changeset
      metadata when is_map(metadata) -> check_scope_metadata(changeset, metadata)
      _other -> add_error(changeset, :scope_metadata, "must be a map")
    end
  end

  defp check_scope_metadata(changeset, metadata) do
    kind = metadata[:scope_kind] || metadata["scope_kind"]
    value = metadata[:scope_value] || metadata["scope_value"]

    case scope_metadata_error(kind, value) do
      nil -> changeset
      message -> add_error(changeset, :scope_metadata, message)
    end
  end

  defp scope_metadata_error(nil, _value),
    do: "must include :scope_kind and :scope_value keys"

  defp scope_metadata_error(_kind, nil),
    do: "must include :scope_kind and :scope_value keys"

  defp scope_metadata_error(kind, value) do
    cond do
      to_string(kind) not in @scope_kinds ->
        "scope_kind must be one of #{Enum.join(@scope_kinds, ", ")}"

      not is_binary(value) and not is_atom(value) ->
        "scope_value must be a string"

      true ->
        nil
    end
  end

  # `condition_metadata` must be a list (possibly empty) of maps, each with at
  # least a `:kind` (or `"kind"`) atom/string key. Per-kind shape validation is
  # the suggestion-engine's responsibility (it owns the condition semantics).
  defp validate_condition_metadata_shape(changeset) do
    case get_field(changeset, :condition_metadata) do
      nil ->
        changeset

      conditions when is_list(conditions) ->
        if Enum.all?(conditions, &valid_condition_entry?/1) do
          changeset
        else
          add_error(
            changeset,
            :condition_metadata,
            "every entry must be a map with a :kind key"
          )
        end

      _other ->
        add_error(changeset, :condition_metadata, "must be a list of maps")
    end
  end

  defp valid_condition_entry?(entry) when is_map(entry) do
    kind = entry[:kind] || entry["kind"]
    not is_nil(kind) and (is_atom(kind) or is_binary(kind))
  end

  defp valid_condition_entry?(_other), do: false
end
