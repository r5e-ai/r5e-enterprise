defmodule Recurse.Providers.PrincipalProvider do
  @moduledoc """
  Provider Interface — PrincipalProvider.

  Spec source: FR-003, FR-026, FR-047. Acting-as principal validation: validates
  and produces the principal a machine is acting as (`obo_human` /
  `service_account` / `autonomous`), AND advertises whether the corresponding
  RFC 8693 OAuth Token Exchange path is supported for downstream auth injection.

  The principal format VARIES per customer IdP — this is the interface that
  adapts. Cedar policy evaluation receives the canonical principal claim per
  FR-026 regardless of source.

  **Composition with SecretsProvider (FR-047):** when `supports_rfc8693?/1`
  returns `true`, the paired `Recurse.Providers.SecretsProvider` MUST implement
  `exchange_for_downstream_token/4` correctly. Together these two interfaces
  fulfil FR-047; the Gateway chains them at downstream-call time.

  Phase-1 IdP capability matrix (per FR-047):

  - Okta — certified
  - Microsoft Entra (Azure AD) — certified
  - Auth0 — certified
  - Other OIDC + RFC 8693 IdPs — best-effort via custom impl; not certified in v1.0
  - SAML-only IdPs — NOT supported in v1.0
  - Custom / proprietary IdPs without RFC 8693 — NOT supported in v1.0

  Reference implementations (Feature 002+ per task T067):

  - `OktaPrincipal` — Okta OIDC + token exchange
  - `EntraPrincipal` — Microsoft Entra (Azure AD)
  - `Auth0Principal` — Auth0
  - `ServiceAccountPrincipal` — signed service-account assertions (no IdP needed)
  - `AutonomousPrincipal` — SPIFFE-to-principal mapping for agent-to-agent flows
  """

  @type config :: map()
  @type state :: term()

  @typedoc "Raw token string passed to `validate/3` — OBO JWT, SA assertion, etc."
  @type raw_token :: String.t()

  @typedoc "Failure modes produced by `validate/3`."
  @type validation_failure ::
          :invalid_signature
          | :expired
          | :wrong_audience
          | :wrong_issuer
          | :replay
          | term()

  @typedoc """
  Optional-feature capability flags an implementation declares via `capabilities/1`.

  - `:obo_human` / `:service_account` / `:autonomous` declare which Principal
    kinds this implementation handles.
  - `:rfc8693_exchange` declares OBO token-exchange capability (composes with
    SecretsProvider per FR-047).
  - `:token_introspection` declares RFC 7662 introspection support.
  """
  @type capability ::
          :obo_human
          | :service_account
          | :autonomous
          | :rfc8693_exchange
          | :token_introspection

  @doc """
  Initialize the provider with deployment-time configuration.
  """
  @callback init(config) :: {:ok, state} | {:error, term()}

  @doc """
  Validate an OBO token / service-account assertion / autonomous claim and
  return the canonical `Recurse.Shared.Principal.t()` struct.

  This is invoked at Gateway ingress per FR-026 to construct the
  `Recurse.Shared.IdentityContext.t()`.

  Returns `{:ok, principal}` on success, `{:error, validation_failure}` on
  rejection. Rejection MUST fail closed at the caller — no Recurse internals
  are leaked to the client (FR-010).
  """
  @callback validate(
              state,
              raw_token,
              expected_audience :: String.t()
            ) ::
              {:ok, Recurse.Shared.Principal.t()}
              | {:error, validation_failure}

  @doc """
  Determine the principal kind a given token will produce, without performing
  full validation. Used for routing tokens to the right validation path before
  invoking `validate/3`.
  """
  @callback inspect_kind(state, raw_token) ::
              {:ok, Recurse.Shared.Principal.kind()} | {:error, term()}

  @doc """
  Indicates whether this PrincipalProvider supports RFC 8693 token exchange
  for the downstream auth-injection flow per FR-047.

  Implementations that return `true` MUST be paired with a
  `Recurse.Providers.SecretsProvider` whose `exchange_for_downstream_token/4`
  is correctly implemented — the two interfaces compose for the FR-047 flow.
  """
  @callback supports_rfc8693?(state) :: boolean()

  @doc """
  Optional-feature capability flags. See `t:capability/0` for allowed values.
  """
  @callback capabilities(state) :: [capability]

  @doc """
  Healthcheck for `/healthz` aggregation (FR-014).
  """
  @callback healthcheck(state) :: :ok | {:degraded, term()} | {:down, term()}

  @doc """
  Graceful shutdown — close IdP connections, cancel JWKS refresh timers.
  """
  @callback terminate(state, reason :: term()) :: :ok
end
