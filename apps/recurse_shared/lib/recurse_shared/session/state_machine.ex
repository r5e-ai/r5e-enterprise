defmodule Recurse.Shared.Session.StateMachine do
  @moduledoc """
  Session lifecycle state validator per FR-044.

  States:

    * `:active` — session in progress; events being emitted
    * `:interim_committed` — an interim epoch root just landed in the
      global ledger
    * `:commit_retry` — a commit attempt failed; bounded backoff in
      progress (per FR-040)
    * `:commit_retry_exhausted` — retries hit the bound; alert fires
    * `:aborted` — explicit abort by operator or Runtime
    * `:cancelled` — caller-initiated graceful cancellation per FR-029
    * `:committed` — final epoch committed; all events at
      `:global_inclusion_verified`; session closed (terminal)

  Allowed transitions (per FR-044):

    * `:active` ↔ `:interim_committed`
    * `:active` → `:commit_retry` → `:commit_retry_exhausted` | `:interim_committed`
    * any state → `:cancelled` | `:aborted`
    * `:interim_committed` → `:committed` (final)

  Terminal states (`:committed`, `:cancelled`, `:aborted`) have no
  outgoing transitions.

  Property-tested in `test/session/state_machine_property_test.exs` for
  the invariant "any `{from, to}` pair not in the allow-table returns
  `{:error, :invalid_transition}`".
  """

  @type state :: Recurse.Shared.Session.Session.state()

  @states [
    :active,
    :interim_committed,
    :commit_retry,
    :commit_retry_exhausted,
    :aborted,
    :cancelled,
    :committed
  ]

  @terminal_states [:committed, :cancelled, :aborted]

  # Explicit allow-table of (from, to) transitions per FR-044.
  @transitions [
    # active ↔ interim_committed
    {:active, :interim_committed},
    {:interim_committed, :active},
    # active → commit_retry → (exhausted | interim_committed)
    {:active, :commit_retry},
    {:commit_retry, :commit_retry_exhausted},
    {:commit_retry, :interim_committed},
    # interim_committed → committed (terminal)
    {:interim_committed, :committed},
    # any non-terminal state → cancelled | aborted
    {:active, :cancelled},
    {:active, :aborted},
    {:interim_committed, :cancelled},
    {:interim_committed, :aborted},
    {:commit_retry, :cancelled},
    {:commit_retry, :aborted},
    {:commit_retry_exhausted, :cancelled},
    {:commit_retry_exhausted, :aborted}
  ]

  @doc """
  All valid session states.
  """
  @spec states() :: [state()]
  def states, do: @states

  @doc """
  Terminal states (no outgoing transitions).
  """
  @spec terminal_states() :: [state()]
  def terminal_states, do: @terminal_states

  @doc """
  All allowed `{from, to}` transition pairs.
  """
  @spec transitions() :: [{state(), state()}]
  def transitions, do: @transitions

  @doc """
  Whether a transition from `from` to `to` is allowed.

  Returns `false` for `from == to` (self-loops are not transitions),
  for unknown states, and for any pair not in the FR-044 allow-table.
  """
  @spec can_transition?(state(), state()) :: boolean()
  def can_transition?(from, to) when from in @states and to in @states do
    {from, to} in @transitions
  end

  def can_transition?(_, _), do: false

  @doc """
  Attempt a transition. Returns `{:ok, to}` on success, or
  `{:error, :invalid_transition}` on failure.
  """
  @spec transition(state(), state()) :: {:ok, state()} | {:error, :invalid_transition}
  def transition(from, to) do
    if can_transition?(from, to), do: {:ok, to}, else: {:error, :invalid_transition}
  end
end
