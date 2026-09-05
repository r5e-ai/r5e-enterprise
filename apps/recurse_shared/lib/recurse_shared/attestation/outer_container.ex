defmodule Recurse.Shared.Attestation.OuterContainer do
  @moduledoc """
  Mutable outer-container state per FR-021.

  Lives OUTSIDE the signed DSSE payload. These fields mutate as commits
  land; placing them inside the signed predicate would either require
  re-signing (we do not) or invalidate the signature.

  ## Fields

    * `verification_level` — `:signed` | `:local_inclusion_verified` |
      `:global_inclusion_verified` per FR-038. Transitions monotonically;
      never regresses (enforced by Ecto changeset at persistence time).
    * `tier_completeness_advisory` — `:complete` | `:partial` per FR-038.
      Deployment-shape coverage; does NOT transition.
    * `session_chain_epoch` — non-negative integer identifying the epoch
      containing this event's local-inclusion proof.
    * `session_chain_root` — Merkle root bytes (SHA-256) of the epoch.
    * `inclusion_proof_local` — RFC 9162 TransItem bytes; present when
      `verification_level >= :local_inclusion_verified`.
    * `inclusion_proof_global` — RFC 9162 TransItem bytes; present only
      when `verification_level == :global_inclusion_verified`.
    * `commit_retry_exhausted` — bool; surfaces SC-015 backoff-exhaustion.
    * `session_state` — current `Recurse.Shared.Session.StateMachine` state
      per FR-044. Queryable via Audit Plane; mutates as the session
      advances. Source of truth alignment: `attestation.schema.json`
      contains this enum, the canonical state list lives in
      `StateMachine.states/0`, and `data-model.md` `attestations`
      outer-container columns include it.
  """

  @type verification_level ::
          :signed | :local_inclusion_verified | :global_inclusion_verified

  @type tier_completeness :: :complete | :partial

  @type t :: %__MODULE__{
          verification_level: verification_level(),
          tier_completeness_advisory: tier_completeness(),
          session_chain_epoch: non_neg_integer(),
          session_chain_root: binary() | nil,
          inclusion_proof_local: binary() | nil,
          inclusion_proof_global: binary() | nil,
          commit_retry_exhausted: boolean(),
          session_state: Recurse.Shared.Session.Session.state()
        }

  @enforce_keys [
    :verification_level,
    :tier_completeness_advisory,
    :session_chain_epoch,
    :session_state
  ]
  defstruct verification_level: :signed,
            tier_completeness_advisory: :complete,
            session_chain_epoch: 0,
            session_chain_root: nil,
            inclusion_proof_local: nil,
            inclusion_proof_global: nil,
            commit_retry_exhausted: false,
            session_state: :active

  @verification_levels [:signed, :local_inclusion_verified, :global_inclusion_verified]
  @tier_completeness_values [:complete, :partial]

  @doc """
  Valid `verification_level` values in monotonic order.
  """
  @spec verification_levels() :: [verification_level()]
  def verification_levels, do: @verification_levels

  @doc """
  Valid `tier_completeness_advisory` values.
  """
  @spec tier_completeness_values() :: [tier_completeness()]
  def tier_completeness_values, do: @tier_completeness_values

  @doc """
  Whether a proposed `verification_level` transition is monotonic.

  `:signed` → `:local_inclusion_verified` → `:global_inclusion_verified`.
  Same-level transitions are allowed (idempotent).
  """
  @spec can_advance_verification?(verification_level(), verification_level()) :: boolean()
  def can_advance_verification?(from, to)
      when from in @verification_levels and to in @verification_levels do
    level_index(to) >= level_index(from)
  end

  defp level_index(:signed), do: 0
  defp level_index(:local_inclusion_verified), do: 1
  defp level_index(:global_inclusion_verified), do: 2
end
