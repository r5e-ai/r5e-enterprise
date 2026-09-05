defmodule Recurse.Providers.IdentityProvider do
  @moduledoc """
  Provider Interface — IdentityProvider.

  Spec source: FR-003, FR-025. Machine-identity (SPIFFE SVID) lifecycle ONLY.
  The SPIFFE format is committed per Constitution Principle V — no engine swap.
  This interface abstracts WHERE SVIDs come from (our SPIRE / customer's SPIRE /
  federated trust domains), not the identity format itself.

  This is distinct from `Recurse.Providers.PrincipalProvider` (acting-as
  identity per FR-026), which handles human OBO / service-account / autonomous
  identity formats that vary per customer IdP. The two layers together realise
  the two-layer identity model recorded in `integration_customer_authn.md`:
  every attestation composes a machine identity (this interface) with a
  principal identity (PrincipalProvider).

  Reference implementations (Feature 002+ per task T066):

  - `SpireIdentity` — standard SPIRE workload-API client (default for
    Recurse-hosted SPIRE)
  - `CustomerSpireIdentity` — federated to customer's SPIRE
  - `FederatedSpireIdentity` — multi-trust-domain federation (Phase-2-friendly)

  Per Phase-1 research recommendation 3, the SPIRE workload-API client is
  implemented as a Rustler NIF wrapping the Rust `spiffe` crate (0.13.0). The earlier `spire-workload-api` name was a placeholder that does not exist on crates.io; see research D7.
  """

  @type config :: map()
  @type state :: term()

  @typedoc "SPIFFE ID string (e.g. `spiffe://example.org/workload/foo`)."
  @type spiffe_id :: String.t()

  @typedoc "X.509 SVID material plus its expiry."
  @type x509_svid :: %{
          cert_chain: [binary()],
          private_key: binary(),
          expires_at: DateTime.t()
        }

  @typedoc "JWT SVID plus its expiry."
  @type jwt_svid :: %{token: String.t(), expires_at: DateTime.t()}

  @typedoc "Trust bundle for a given SPIFFE trust domain."
  @type trust_bundle :: %{trust_domain: String.t(), x509_authorities: [binary()]}

  @typedoc "Failure modes produced by `validate_x509_svid/2`."
  @type validation_failure :: :invalid_chain | :wrong_trust_domain | :expired | term()

  @typedoc """
  Optional-feature capability flags an implementation declares via `capabilities/1`.
  """
  @type capability ::
          :x509_svid
          | :jwt_svid
          | :trust_bundle
          | :workload_attestation
          | :federation

  @doc """
  Initialize the provider with deployment-time configuration.
  """
  @callback init(config) :: {:ok, state} | {:error, term()}

  @doc """
  Fetch the current X.509 SVID for the calling workload — the Gateway/Runtime
  node itself, or an agent process whose netns has been provisioned with
  SPIRE workload-API access.
  """
  @callback fetch_x509_svid(state) :: {:ok, x509_svid} | {:error, term()}

  @doc """
  Fetch a JWT SVID with the requested audience.
  """
  @callback fetch_jwt_svid(state, audience :: String.t()) ::
              {:ok, jwt_svid} | {:error, term()}

  @doc """
  Fetch the trust bundle for the configured trust domain.
  """
  @callback fetch_trust_bundle(state) :: {:ok, trust_bundle} | {:error, term()}

  @doc """
  Validate an X.509 SVID against this trust domain. Used by the Gateway at
  mTLS termination on the Data Plane (FR-025).
  """
  @callback validate_x509_svid(state, cert :: binary()) ::
              {:ok, spiffe_id} | {:error, validation_failure}

  @doc """
  Provision an SVID for a new agent netns. Called by the Runtime at spawn time.

  Returns the SPIFFE ID assigned to the netns and a handle the Runtime can
  pass to the in-netns spiffe-helper shim per FR-045a.
  """
  @callback provision_workload_svid(
              state,
              netns_id :: String.t(),
              workload_attestation :: map()
            ) ::
              {:ok, %{spiffe_id: spiffe_id, workload_handle: binary()}}
              | {:error, term()}

  @doc """
  Optional-feature capability flags. See `t:capability/0` for allowed values.
  """
  @callback capabilities(state) :: [capability]

  @doc """
  Healthcheck for `/healthz` aggregation (FR-014).
  """
  @callback healthcheck(state) :: :ok | {:degraded, term()} | {:down, term()}

  @doc """
  Graceful shutdown — close workload-API connections, cancel rotation timers.
  """
  @callback terminate(state, reason :: term()) :: :ok
end
