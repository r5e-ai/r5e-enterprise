defmodule Recurse.Shared.IdentityContext do
  @moduledoc """
  Immutable `(machine_identity, principal, tenant_id, correlation_id)`
  tuple per FR-026 / SC-016.

  The `IdentityContext` is **resolved exactly once at Gateway ingress**
  by combining inbound machine-auth (FR-011 / FR-017 / FR-025) with the
  `PrincipalProvider`'s validation of the OBO / service-account
  assertion. Once constructed it propagates **by reference** through
  Cedar policy evaluation, attestation envelope construction, downstream
  auth injection (FR-047), and any cross-application coordination.

  ## Immutability invariant (SC-016)

  This module deliberately exposes **only** `new/1` and `resolved?/1`.
  There are no `put_*`, `update_*`, or `with_*` helpers. Any attempt to
  mutate — e.g., re-building a struct at a downstream plane with
  different fields — is a defense-in-depth violation. Static analysis
  (a custom Credo check planned in `Recurse.Credo.ProviderNeutrality`
  and its sibling `IdentityContext` check in Feature 002+) rejects any
  Gateway/Runtime business-logic function with an
  `IdentityContext -> IdentityContext` signature.

  The property test in `test/identity_context_property_test.exs` asserts
  that no public function other than `new/1` and `resolved?/1` exists on
  this module.

  Phase-1 note: tenancy is BEAM-per-customer (Constitution Reconciliation
  §2), so `tenant_id` always equals the deployment's configured tenant.
  It's carried through anyway as a defense-in-depth check per FR-020.
  """

  alias Recurse.Shared.Principal

  @type machine_identity :: String.t() | {:observed_identity, map()}

  @type t :: %__MODULE__{
          machine_identity: machine_identity(),
          principal: Principal.t(),
          tenant_id: String.t(),
          correlation_id: String.t(),
          resolved_at_usec: non_neg_integer()
        }

  @enforce_keys [:machine_identity, :principal, :tenant_id, :correlation_id, :resolved_at_usec]
  defstruct [:machine_identity, :principal, :tenant_id, :correlation_id, :resolved_at_usec]

  @doc """
  Construct a new `IdentityContext`.

  Accepts a map with all four inputs; `resolved_at_usec` is bound at
  construction time (POSIX microseconds).

  Required keys:
    * `:machine_identity` — SPIFFE ID string or `{:observed_identity, claims}`
    * `:principal` — `%Recurse.Shared.Principal{}`
    * `:tenant_id` — deployment tenant ULID
    * `:correlation_id` — ULID string
  """
  @spec new(map()) :: t()
  def new(%{
        machine_identity: machine_identity,
        principal: %Principal{} = principal,
        tenant_id: tenant_id,
        correlation_id: correlation_id
      })
      when is_binary(tenant_id) and is_binary(correlation_id) do
    %__MODULE__{
      machine_identity: machine_identity,
      principal: principal,
      tenant_id: tenant_id,
      correlation_id: correlation_id,
      resolved_at_usec: System.system_time(:microsecond)
    }
  end

  @doc """
  Whether the context is resolved (i.e., all required fields are
  populated). In Phase 1 this is always `true` if `new/1` returned —
  the `@enforce_keys` guarantee makes a partially-populated struct
  impossible to construct via the public API.

  Returns `false` for anything that is not an `%IdentityContext{}`
  struct — useful as a pattern-match-free guard at module boundaries.
  """
  @spec resolved?(any()) :: boolean()
  def resolved?(%__MODULE__{
        machine_identity: mi,
        principal: %Principal{},
        tenant_id: t,
        correlation_id: c,
        resolved_at_usec: r
      })
      when not is_nil(mi) and is_binary(t) and is_binary(c) and is_integer(r),
      do: true

  def resolved?(_), do: false
end
