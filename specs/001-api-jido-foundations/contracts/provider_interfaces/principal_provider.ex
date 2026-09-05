defmodule Recurse.Providers.PrincipalProvider do
  @moduledoc """
  Provider Interface — PrincipalProvider.

  Spec source: FR-003, FR-026, FR-047. Acting-as principal validation: validates and produces
  the principal a machine is acting as (`obo_human` / `service_account` / `autonomous`),
  AND performs RFC 8693 OAuth Token Exchange for downstream auth injection.

  The principal format VARIES per customer IdP — this is the interface that adapts.
  Cedar policy evaluation receives the canonical principal claim per FR-026 regardless of source.

  Phase-1 IdP capability matrix (per FR-047):
  - Okta — certified
  - Microsoft Entra (Azure AD) — certified
  - Auth0 — certified
  - Other OIDC + RFC 8693 IdPs — best-effort via custom impl; not certified in v1.0
  - SAML-only IdPs — NOT supported in v1.0
  - Custom / proprietary IdPs without RFC 8693 — NOT supported in v1.0

  Reference implementations:
  - `OktaPrincipal` — Okta OIDC + token exchange
  - `EntraPrincipal` — Microsoft Entra (Azure AD)
  - `Auth0Principal` — Auth0
  - `ServiceAccountPrincipal` — signed service-account assertions (no IdP needed)
  - `AutonomousPrincipal` — SPIFFE-to-principal mapping for agent-to-agent flows
  """

  alias Recurse.Shared.Principal
  alias Recurse.Shared.IdentityContext

  @type config :: map()
  @type state :: term()

  @type raw_token :: String.t()
  @type validation_failure :: :invalid_signature | :expired | :wrong_audience | :wrong_issuer | :replay | term()

  @callback init(config) :: {:ok, state} | {:error, term()}

  @doc """
  Validate an OBO token / service-account assertion / autonomous-claim and return the
  canonical Principal struct. This is invoked at Gateway ingress per FR-026 to construct
  the IdentityContext.

  Returns `{:ok, %Principal{}}` on success, `{:error, validation_failure}` on rejection.
  Rejection MUST fail closed at the caller — no Recurse internals leaked to the client.
  """
  @callback validate(state, raw_token, expected_audience :: String.t()) ::
              {:ok, Principal.t()} | {:error, validation_failure}

  @doc """
  Determine the principal kind a given token will produce. Used for routing tokens to the
  right validation path before invoking validate/3.
  """
  @callback inspect_kind(state, raw_token) :: {:ok, Principal.kind()} | {:error, term()}

  @doc """
  Indicates whether this PrincipalProvider supports RFC 8693 token exchange for the
  downstream auth-injection flow per FR-047. Implementations that support it MUST also
  implement `Recurse.Providers.SecretsProvider.exchange_for_downstream_token/4` correctly
  (those two interfaces compose for the FR-047 flow).
  """
  @callback supports_rfc8693?(state) :: boolean()

  @doc """
  Capability flags. `:obo_human` / `:service_account` / `:autonomous` declare which Principal
  kinds this implementation handles; `:rfc8693_exchange` declares OBO token-exchange capability.
  """
  @callback capabilities(state) :: [
              :obo_human
              | :service_account
              | :autonomous
              | :rfc8693_exchange
              | :token_introspection
            ]

  @callback healthcheck(state) :: :ok | {:degraded, term()} | {:down, term()}

  @callback terminate(state, term()) :: :ok
end
