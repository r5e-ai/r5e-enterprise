defmodule Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Session do
  @moduledoc """
  Ecto schema for the `sessions` table — bounded unit per F001 FR-036 / F002
  FR-016. Under the "1 run = 1 session" heuristic one row is emitted per
  Gateway-traversing call; the `interim_commit_*` columns stay for later
  (Governance) tier shapes but are effectively dead code in Standalone.

  Cross-references:
    * `specs/002-standalone-gateway-vertical-slice/data-model.md` §Session.
    * Migration — `priv/repo/migrations/20260423100000_f002_initial_schemas.exs`.

  Enum fidelity matches the DB check constraints:
    * `state` follows the F001 FR-044 state machine.
    * `session_scope` is `:discovery_session` only in F002 (check constraint).
    * `principal_kind` is F001 FR-026's three-way.
  """

  use Ecto.Schema

  import Ecto.Changeset

  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Tenant

  @state_values [
    :active,
    :interim_committed,
    :commit_retry,
    :commit_retry_exhausted,
    :aborted,
    :cancelled,
    :committed
  ]

  @session_scope_values [:discovery_session]
  @principal_kind_values [:obo_human, :service_account, :autonomous]

  @primary_key {:session_id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @derive {Jason.Encoder,
           only: [
             :session_id,
             :tenant_id,
             :session_scope,
             :state,
             :session_start,
             :session_end,
             :agent_spiffe_id,
             :principal_kind,
             :interim_commit_event_count,
             :interim_commit_threshold_minutes,
             :inserted_at,
             :updated_at
           ]}

  schema "sessions" do
    belongs_to(:tenant, Tenant,
      foreign_key: :tenant_id,
      references: :tenant_id,
      type: :string
    )

    field(:session_scope, Ecto.Enum, values: @session_scope_values)
    field(:state, Ecto.Enum, values: @state_values)
    field(:session_start, :utc_datetime_usec)
    field(:session_end, :utc_datetime_usec)
    field(:agent_spiffe_id, :string)
    field(:principal_kind, Ecto.Enum, values: @principal_kind_values)
    field(:principal_canonical, :binary)
    field(:interim_commit_event_count, :integer, default: 10_000)
    field(:interim_commit_threshold_minutes, :integer, default: 60)

    timestamps(type: :utc_datetime_usec)
  end

  @type t :: %__MODULE__{}

  @cast_fields [
    :tenant_id,
    :session_scope,
    :state,
    :session_start,
    :session_end,
    :agent_spiffe_id,
    :principal_kind,
    :principal_canonical,
    :interim_commit_event_count,
    :interim_commit_threshold_minutes
  ]

  @required_fields [
    :tenant_id,
    :session_scope,
    :state,
    :session_start,
    :principal_kind,
    :principal_canonical
  ]

  @doc """
  Minimal cast + validate for Session rows. Full state-machine transition
  validation lives in `Recurse.Shared.Session.StateMachine` (F001) — this
  changeset only guards required fields + enum membership.
  """
  @spec changeset(t() | %__MODULE__{}, map()) :: Ecto.Changeset.t()
  def changeset(session, attrs) do
    session
    |> cast(attrs, @cast_fields)
    |> validate_required(@required_fields)
  end
end
