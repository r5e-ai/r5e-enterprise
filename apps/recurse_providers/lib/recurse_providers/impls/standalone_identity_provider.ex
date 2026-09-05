defmodule Recurse.Providers.Impls.StandaloneIdentityProvider do
  @moduledoc """
  Intentional no-op implementation of `Recurse.Providers.IdentityProvider`
  for F002 Standalone Gateway.

  **Status:** architecturally no-op — NOT a stub. Standalone Gateway has no
  Recurse-managed SPIFFE; customer agents run elsewhere and redirect
  traffic to the Gateway (Discovery-tier shape per Constitution §II).

  Contract:
    * Contract doc — `specs/002-standalone-gateway-vertical-slice/contracts/provider_impls.md`
      (§ `StandaloneIdentityProvider`).
    * Behaviour — `Recurse.Providers.IdentityProvider` (F001).

  Return shape discipline — all non-lifecycle callbacks return
  `{:error, {:not_applicable, :standalone_gateway}}`. This is DISTINCT from
  the other F002 impls' `:not_implemented_yet` sentinel: it's a permanent
  architectural decision, not a stub that will be filled in. Keeping the
  behaviour-conformant shell satisfies Constitution Principle V
  (every dependency fronted by a Provider Interface) while guaranteeing
  the Gateway never accidentally wanders down a SPIFFE-lookup path in
  Standalone deployments.
  """

  @behaviour Recurse.Providers.IdentityProvider

  @typedoc "Opaque state — intentionally inert."
  @type state :: %{stub: true, reason: :standalone_gateway_has_no_spiffe}

  @not_applicable {:not_applicable, :standalone_gateway}

  @doc """
  No-op init — returns an inert state marker. The Standalone Gateway
  supervision tree still starts this provider so the Provider-Interface
  registry is complete, but no callback below will produce real data.
  """
  @impl true
  @spec init(Recurse.Providers.IdentityProvider.config()) :: {:ok, state()} | {:error, term()}
  def init(_config) do
    {:ok, %{stub: true, reason: :standalone_gateway_has_no_spiffe}}
  end

  @doc """
  Not applicable — Standalone Gateway has no X.509 SVID to fetch.
  """
  @impl true
  @spec fetch_x509_svid(state()) ::
          {:ok, Recurse.Providers.IdentityProvider.x509_svid()} | {:error, term()}
  def fetch_x509_svid(_state), do: {:error, @not_applicable}

  @doc """
  Not applicable — Standalone Gateway has no JWT SVID to fetch.
  """
  @impl true
  @spec fetch_jwt_svid(state(), audience :: String.t()) ::
          {:ok, Recurse.Providers.IdentityProvider.jwt_svid()} | {:error, term()}
  def fetch_jwt_svid(_state, _audience), do: {:error, @not_applicable}

  @doc """
  Not applicable — Standalone Gateway has no trust bundle to fetch.
  """
  @impl true
  @spec fetch_trust_bundle(state()) ::
          {:ok, Recurse.Providers.IdentityProvider.trust_bundle()} | {:error, term()}
  def fetch_trust_bundle(_state), do: {:error, @not_applicable}

  @doc """
  Not applicable — mTLS SVID validation is skipped in Standalone
  (Discovery-tier identity is carried via `X-Observed-Identity` header,
  validated by `JwtPrincipalProvider` not here).
  """
  @impl true
  @spec validate_x509_svid(state(), cert :: binary()) ::
          {:ok, Recurse.Providers.IdentityProvider.spiffe_id()}
          | {:error, Recurse.Providers.IdentityProvider.validation_failure()}
  def validate_x509_svid(_state, _cert), do: {:error, :not_applicable}

  @doc """
  Not applicable — no Runtime, no agent netns to provision.
  """
  @impl true
  @spec provision_workload_svid(
          state(),
          netns_id :: String.t(),
          workload_attestation :: map()
        ) ::
          {:ok,
           %{
             spiffe_id: Recurse.Providers.IdentityProvider.spiffe_id(),
             workload_handle: binary()
           }}
          | {:error, term()}
  def provision_workload_svid(_state, _netns_id, _workload_attestation) do
    {:error, @not_applicable}
  end

  @doc """
  Advertises an empty capability list — this impl does not support any
  SPIFFE operation by design.
  """
  @impl true
  @spec capabilities(state()) :: [Recurse.Providers.IdentityProvider.capability()]
  def capabilities(_state), do: []

  @doc """
  Always `:ok` — this impl has no external dependency to be unhealthy.
  """
  @impl true
  @spec healthcheck(state()) :: :ok | {:degraded, term()} | {:down, term()}
  def healthcheck(_state), do: :ok

  @doc """
  No-op shutdown.
  """
  @impl true
  @spec terminate(state(), reason :: term()) :: :ok
  def terminate(_state, _reason), do: :ok
end
