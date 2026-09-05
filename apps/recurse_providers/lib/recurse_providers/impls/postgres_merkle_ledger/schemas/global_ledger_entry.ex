defmodule Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.GlobalLedgerEntry do
  @moduledoc """
  Ecto schema for the `global_ledger_entries` table — one row per
  globally-committed session epoch root. The monotonic `sequence` column
  doubles as the RFC 9162 tree index.

  Cross-references:
    * `specs/002-standalone-gateway-vertical-slice/data-model.md`
      §global_ledger_entries.
    * Migration — `priv/repo/migrations/20260423100001_f002_merkle_ledger_tables.exs`.

  The DB column is `BIGSERIAL PRIMARY KEY` (declared as `:bigserial` in the
  migration). Ecto's default `@primary_key` is `:id` with `autogenerate: true`
  — we override with `{:sequence, :id, autogenerate: true}` so the schema's
  PK matches the migration column name. `:id` on the Ecto side maps to the
  Postgres `BIGSERIAL` type because `Ecto.Adapters.Postgres` renders the
  `:id` primitive as `bigserial` in migrations; for the schema side we only
  need to tell Ecto the PK is a DB-generated integer.
  """

  use Ecto.Schema

  import Ecto.Changeset

  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.{Session, SessionEpoch, Tenant}

  @primary_key {:sequence, :id, autogenerate: true}
  @foreign_key_type :binary_id
  @derive {Jason.Encoder,
           only: [
             :sequence,
             :tenant_id,
             :session_id,
             :session_epoch_id,
             :committed_at
           ]}

  schema "global_ledger_entries" do
    belongs_to(:tenant, Tenant,
      foreign_key: :tenant_id,
      references: :tenant_id,
      type: :string
    )

    belongs_to(:session, Session,
      foreign_key: :session_id,
      references: :session_id,
      type: :binary_id
    )

    belongs_to(:session_epoch, SessionEpoch,
      foreign_key: :session_epoch_id,
      references: :id,
      type: :binary_id
    )

    field(:session_epoch_root, :binary)
    field(:committed_at, :utc_datetime_usec)
  end

  @type t :: %__MODULE__{}

  @cast_fields [
    :tenant_id,
    :session_id,
    :session_epoch_id,
    :session_epoch_root,
    :committed_at
  ]

  @required_fields @cast_fields

  @doc """
  Cast + validate a GlobalLedgerEntry row. The `sequence` PK is auto-assigned
  by Postgres; callers never supply it. The 32-byte length invariant on
  `session_epoch_root` is enforced at the DB layer.
  """
  @spec changeset(t() | %__MODULE__{}, map()) :: Ecto.Changeset.t()
  def changeset(entry, attrs) do
    entry
    |> cast(attrs, @cast_fields)
    |> validate_required(@required_fields)
  end
end
