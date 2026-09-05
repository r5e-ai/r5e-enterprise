defmodule Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.MerkleNode do
  @moduledoc """
  Ecto schema for the `merkle_nodes` table — append-only binary Merkle-tree
  node storage. Stores nodes for both per-session epoch trees AND the global
  ledger tree under different `tree_id` namespaces.

  Cross-references:
    * `specs/002-standalone-gateway-vertical-slice/data-model.md` §merkle_nodes.
    * Migration — `priv/repo/migrations/20260423100001_f002_merkle_ledger_tables.exs`.

  Primary key is composite `(tree_id, level, position)` — Ecto expresses this
  by disabling the default `@primary_key` and marking each component field
  with `primary_key: true`. Append-only is enforced by the
  `enforce_append_only_merkle_nodes` trigger — no UPDATE, no DELETE — not by
  application code.

  `hash` is the raw 32-byte SHA-256 digest (check constraint
  `merkle_nodes_hash_len`), NOT a hex encoding.
  """

  use Ecto.Schema

  import Ecto.Changeset

  @primary_key false
  @derive {Jason.Encoder, only: [:tree_id, :level, :position, :inserted_at]}

  schema "merkle_nodes" do
    field(:tree_id, :string, primary_key: true)
    field(:level, :integer, primary_key: true)
    field(:position, :integer, primary_key: true)
    field(:hash, :binary)
    field(:inserted_at, :utc_datetime_usec)
  end

  @type t :: %__MODULE__{
          tree_id: String.t(),
          level: non_neg_integer(),
          position: non_neg_integer(),
          hash: binary(),
          inserted_at: DateTime.t()
        }

  @required_fields [:tree_id, :level, :position, :hash, :inserted_at]

  @doc """
  Cast + validate a MerkleNode row. All fields required on insert; updates
  are rejected at the DB layer by the append-only trigger.
  """
  @spec changeset(t() | %__MODULE__{}, map()) :: Ecto.Changeset.t()
  def changeset(node, attrs) do
    node
    |> cast(attrs, @required_fields)
    |> validate_required(@required_fields)
  end
end
