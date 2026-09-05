defmodule Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Tenant do
  @moduledoc """
  Ecto schema for the `tenants` table — single-tenant marker per F002 FR-019.

  Cross-references:
    * `specs/002-standalone-gateway-vertical-slice/data-model.md` §Tenant.
    * Migration — `priv/repo/migrations/20260423100000_f002_initial_schemas.exs`.

  The `tenant_id` column is a Crockford ULID string and serves as the primary
  key; it matches the Tier Configuration Model's `tenant_id` (FR-031). F002
  ships a single `:standalone_gateway` tier; the other enum values are reserved
  for later phases and defended via a DB check constraint.
  """

  use Ecto.Schema

  import Ecto.Changeset

  @tier_values [:standalone_gateway, :managed_saas, :vpc_runner, :appliance]

  @primary_key {:tenant_id, :string, autogenerate: false}
  @foreign_key_type :string
  @derive {Jason.Encoder, only: [:tenant_id, :display_name, :tier, :created_at]}

  schema "tenants" do
    field(:display_name, :string)
    field(:tier, Ecto.Enum, values: @tier_values)
    field(:created_at, :utc_datetime_usec)
  end

  @type t :: %__MODULE__{
          tenant_id: String.t(),
          display_name: String.t(),
          tier: atom(),
          created_at: DateTime.t()
        }

  @required_fields [:tenant_id, :display_name, :tier, :created_at]

  @doc """
  Cast + validate the full Tenant payload. Consumers assemble rows via a seed
  fixture on first `mix ecto.migrate`; no runtime mutation surface in F002.
  """
  @spec changeset(t() | %__MODULE__{}, map()) :: Ecto.Changeset.t()
  def changeset(tenant, attrs) do
    tenant
    |> cast(attrs, @required_fields)
    |> validate_required(@required_fields)
  end
end
