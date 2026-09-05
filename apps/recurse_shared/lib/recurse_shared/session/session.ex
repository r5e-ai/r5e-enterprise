defmodule Recurse.Shared.Session.Session do
  @moduledoc """
  In-memory Session struct per FR-036.

  A session is a bounded unit of agent activity — the atomic commit
  unit to the global ledger. Every attestation belongs to exactly one
  session.

  ## Fields

    * `session_id` — ULID
    * `tenant_id` — deployment tenant ULID (always equals the BEAM's
      configured tenant in Phase 1 per FR-019)
    * `session_start` — RFC 3339 UTC string
    * `session_end` — RFC 3339 UTC string or `nil` until a terminal
      state is reached
    * `session_scope` — `:managed_agent_container` (Governance shapes)
      or `:discovery_session` (Standalone Gateway). `:appliance_byo_vm`
      is rejected per Constitution Reconciliation §3.
    * `state` — FR-044 lifecycle state atom (see
      `Recurse.Shared.Session.StateMachine` for the full set and
      allowed transitions).
    * `epochs` — ordered list of `%Recurse.Shared.Session.Epoch{}`
      covering the session's history.
  """

  alias Recurse.Shared.Session.Epoch

  @type scope :: :managed_agent_container | :discovery_session

  @type state ::
          :active
          | :interim_committed
          | :commit_retry
          | :commit_retry_exhausted
          | :aborted
          | :cancelled
          | :committed

  @type t :: %__MODULE__{
          session_id: String.t(),
          tenant_id: String.t(),
          session_start: String.t(),
          session_end: String.t() | nil,
          session_scope: scope(),
          state: state(),
          epochs: [Epoch.t()]
        }

  @enforce_keys [:session_id, :tenant_id, :session_start, :session_scope, :state]
  defstruct session_id: nil,
            tenant_id: nil,
            session_start: nil,
            session_end: nil,
            session_scope: nil,
            state: :active,
            epochs: []

  @doc """
  Valid `session_scope` atoms.
  """
  @spec scopes() :: [scope()]
  def scopes, do: [:managed_agent_container, :discovery_session]
end
