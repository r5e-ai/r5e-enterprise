defmodule Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.SessionEpoch do
  @moduledoc """
  Ecto schema for the `session_epochs` table — one row per session epoch.
  Under F002's 1-run-1-session heuristic every row has `epoch_index = 0` and
  `event_count = 1`; the fields remain so later (Governance) tier shapes can
  exercise multi-epoch semantics without schema migration.

  Cross-references:
    * `specs/002-standalone-gateway-vertical-slice/data-model.md` §SessionEpoch.
    * Migration — `priv/repo/migrations/20260423100000_f002_initial_schemas.exs`.

  `epoch_root` is the raw 32-byte SHA-256 of the in-session attestation chain
  (enforced by `session_epochs_epoch_root_len` check). `global_ledger_sequence`
  FKs back to `global_ledger_entries.sequence` once the epoch is
  globally-committed (wired in the merkle-ledger migration).
  """

  use Ecto.Schema

  import Ecto.Changeset

  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Session

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @derive {Jason.Encoder,
           only: [
             :id,
             :session_id,
             :epoch_index,
             :epoch_start_at,
             :epoch_end_at,
             :committed_at,
             :global_ledger_sequence,
             :event_count,
             :inserted_at,
             :updated_at
           ]}

  schema "session_epochs" do
    belongs_to(:session, Session,
      foreign_key: :session_id,
      references: :session_id,
      type: :binary_id
    )

    field(:epoch_index, :integer)
    field(:epoch_root, :binary)
    field(:epoch_start_at, :utc_datetime_usec)
    field(:epoch_end_at, :utc_datetime_usec)
    field(:committed_at, :utc_datetime_usec)
    field(:global_ledger_sequence, :integer)
    field(:event_count, :integer, default: 0)

    timestamps(type: :utc_datetime_usec)
  end

  @type t :: %__MODULE__{}

  @cast_fields [
    :session_id,
    :epoch_index,
    :epoch_root,
    :epoch_start_at,
    :epoch_end_at,
    :committed_at,
    :global_ledger_sequence,
    :event_count
  ]

  @required_fields [:session_id, :epoch_index, :epoch_root, :epoch_start_at]

  @doc """
  Cast + validate a SessionEpoch row. The 32-byte `epoch_root` length
  invariant is enforced at the DB layer; this changeset keeps the field
  required without re-duplicating the byte-length check.
  """
  @spec changeset(t() | %__MODULE__{}, map()) :: Ecto.Changeset.t()
  def changeset(epoch, attrs) do
    epoch
    |> cast(attrs, @cast_fields)
    |> validate_required(@required_fields)
  end
end
