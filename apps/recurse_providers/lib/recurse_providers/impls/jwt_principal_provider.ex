defmodule Recurse.Providers.Impls.JwtPrincipalProvider do
  @moduledoc """
  `Recurse.Providers.PrincipalProvider` impl backed by the
  `X-Observed-Identity` JWT minted by the Standalone Identity Broker
  (F002 FR-007 / FR-009).

  **Status (F002 T044)**: real JWT validation delegates to Gateway-side
  `Recurse.Gateway.Identity.JwtValidator`. Signature / temporal / audience /
  issuer checks happen there; this provider is the thin adapter that
  pulls the validated `principal` custom claim out of the claims map and
  materializes a `Recurse.Shared.Principal.t()`.

  Contract:
    * Contract doc — `specs/002-standalone-gateway-vertical-slice/contracts/provider_impls.md`
      (§ `JwtPrincipalProvider`).
    * Behaviour — `Recurse.Providers.PrincipalProvider` (F001).

  ## Config schema (`init/1`)

      %{
        trusted_issuers: ["https://recurse-broker.corp.example"],
        expected_audience: "recurse-gateway-prod",
        # Optional: how to resolve JWK by kid. One of:
        #   * `[{kid, JWK}, ...]` — static list (test fixtures)
        #   * `%{kid => JWK}` — static map
        #   * `{:cache, ModuleName}` — delegate to a JwksCache GenServer
        # Defaults to `{:cache, Recurse.Gateway.Identity.JwksCache}`.
        known_kids: ...,
        # Optional: replay-cache callback. Signature:
        #   (jti :: String.t()) -> :ok | {:error, :token_replayed}
        jti_check: ...
      }

  ## Capabilities

  `:obo_human`, `:service_account`, `:autonomous` — all three Principal
  kinds the broker can mint. `:rfc8693_exchange` is deliberately NOT
  advertised in F002 (downstream auth injection lands in F003+).

  Property tests: Surface N at `apps/recurse_gateway/test/identity/jwt_validator_property_test.exs`.
  """

  @behaviour Recurse.Providers.PrincipalProvider

  alias Recurse.Shared.Principal

  @type state :: %{
          required(:config) => map(),
          required(:trusted_issuers) => [String.t()],
          required(:expected_audience) => String.t(),
          required(:known_kids) => term(),
          optional(:jti_check) => (String.t() -> :ok | {:error, :token_replayed})
        }

  # ---------------------------------------------------------------------------
  # The impl delegates signature / temporal / audience / issuer checks to
  # this module (Gateway-side pure validator). Kept as an attribute so
  # tests can swap it via `Application.put_env/3` without touching code.
  # ---------------------------------------------------------------------------

  @default_validator Recurse.Gateway.Identity.JwtValidator
  @default_jwks_cache Recurse.Gateway.Identity.JwksCache

  @doc """
  Store validated deployment-time config in opaque state. Validation is
  deliberately minimal — richer boot-time validation is the responsibility
  of the config loader (F002 T009 + tier-config hash check).
  """
  @impl true
  @spec init(Recurse.Providers.PrincipalProvider.config()) :: {:ok, state()} | {:error, term()}
  def init(config) when is_map(config) do
    with {:ok, trusted_issuers} <- fetch_trusted_issuers(config),
         {:ok, expected_audience} <- fetch_expected_audience(config) do
      state = %{
        config: config,
        trusted_issuers: trusted_issuers,
        expected_audience: expected_audience,
        known_kids: Map.get(config, :known_kids, {:cache, @default_jwks_cache}),
        jti_check: Map.get(config, :jti_check)
      }

      {:ok, state}
    end
  end

  defp fetch_trusted_issuers(%{trusted_issuers: [_ | _] = issuers}), do: {:ok, issuers}
  defp fetch_trusted_issuers(_), do: {:error, :missing_trusted_issuers}

  defp fetch_expected_audience(%{expected_audience: aud}) when is_binary(aud) and aud != "",
    do: {:ok, aud}

  defp fetch_expected_audience(_), do: {:error, :missing_expected_audience}

  @doc """
  Validate `raw_token` (a compact-serialized JWS) against the expected
  audience + issuer allowlist; on success, return the principal extracted
  from the `principal` custom claim.

  The behaviour's `expected_audience` arg wins over any `state`-embedded
  audience — matches the behaviour's "Gateway passes the per-request
  audience" semantics.

  Failure modes are mapped to the behaviour's `validation_failure` type:

    - `:invalid_signature`
    - `:expired` (from validator's `:token_expired`)
    - `:wrong_audience` (from validator's `:invalid_audience`)
    - `:wrong_issuer` (from validator's `:invalid_issuer`)
    - `:replay` (from validator's `:token_replayed`)
    - other validator atoms pass through unchanged.
  """
  @impl true
  @spec validate(
          state(),
          Recurse.Providers.PrincipalProvider.raw_token(),
          expected_audience :: String.t()
        ) ::
          {:ok, Recurse.Shared.Principal.t()}
          | {:error, Recurse.Providers.PrincipalProvider.validation_failure()}
  def validate(state, raw_token, expected_audience) when is_binary(raw_token) do
    validator = validator_module()

    opts = %{
      audience: expected_audience,
      # No single-issuer pin here — we post-filter against the
      # `trusted_issuers` allowlist below. This lets the same
      # provider state serve multiple brokers in future.
      known_kids: Map.get(state, :known_kids),
      jti_check: Map.get(state, :jti_check)
    }

    with {:ok, claims} <- validator.validate(raw_token, opts),
         :ok <- check_issuer_allowlist(claims, state.trusted_issuers),
         {:ok, principal} <- principal_from_claims(claims) do
      {:ok, principal}
    else
      {:error, reason} -> {:error, map_error(reason)}
    end
  end

  defp validator_module do
    Application.get_env(:recurse_providers, :jwt_validator_module, @default_validator)
  end

  defp check_issuer_allowlist(claims, trusted_issuers) do
    case Map.get(claims, "iss") do
      iss when is_binary(iss) ->
        if iss in trusted_issuers, do: :ok, else: {:error, :invalid_issuer}

      _ ->
        {:error, :invalid_issuer}
    end
  end

  defp map_error(:token_expired), do: :expired
  defp map_error(:invalid_audience), do: :wrong_audience
  defp map_error(:invalid_issuer), do: :wrong_issuer
  defp map_error(:token_replayed), do: :replay
  defp map_error(other), do: other

  # The principal claim shape is FR-009-authoritative. Same dispatch as
  # `IdentityContextBuilder` — keep this module and that one in sync if
  # the broker evolves.
  defp principal_from_claims(%{"principal" => %{"kind" => "obo_human"} = claim}) do
    with {:ok, issuer} <- fetch_binary(claim, "issuer"),
         {:ok, subject} <- fetch_binary(claim, "subject") do
      {:ok,
       Principal.obo_human(%{
         issuer: issuer,
         subject: subject,
         display_name: Map.get(claim, "display_name"),
         groups: Map.get(claim, "groups")
       })}
    else
      _ -> {:error, :malformed_principal}
    end
  end

  defp principal_from_claims(%{"principal" => %{"kind" => "service_account"} = claim}) do
    with {:ok, issuer} <- fetch_binary(claim, "issuer"),
         {:ok, account_id} <- fetch_binary(claim, "account_id") do
      {:ok,
       Principal.service_account(%{
         issuer: issuer,
         account_id: account_id,
         scope: Map.get(claim, "scope")
       })}
    else
      _ -> {:error, :malformed_principal}
    end
  end

  defp principal_from_claims(%{"principal" => %{"kind" => "autonomous"} = claim}) do
    case fetch_binary(claim, "spiffe_id") do
      {:ok, spiffe_id} -> {:ok, Principal.autonomous(%{spiffe_id: spiffe_id})}
      _ -> {:error, :malformed_principal}
    end
  end

  defp principal_from_claims(_), do: {:error, :malformed_principal}

  defp fetch_binary(map, key) do
    case Map.fetch(map, key) do
      {:ok, value} when is_binary(value) and value != "" -> {:ok, value}
      _ -> :error
    end
  end

  @doc """
  Decode the JWT payload WITHOUT verifying the signature to read
  `principal.kind`. Used by routers that need to dispatch to different
  validation paths per kind before committing to a full verify.

  Never trust the returned kind for authorization decisions — that's
  what `validate/3` is for.
  """
  @impl true
  @spec inspect_kind(state(), Recurse.Providers.PrincipalProvider.raw_token()) ::
          {:ok, Recurse.Shared.Principal.kind()} | {:error, term()}
  def inspect_kind(_state, raw_token) when is_binary(raw_token) do
    with [_h, p, _s] <- String.split(raw_token, "."),
         {:ok, payload_bytes} <- Base.url_decode64(p, padding: false),
         {:ok, %{"principal" => %{"kind" => kind_str}}} <- decode_json(payload_bytes),
         {:ok, kind} <- kind_string_to_atom(kind_str) do
      {:ok, kind}
    else
      _ -> {:error, :malformed_token}
    end
  end

  defp decode_json(bytes) do
    JSON.decode(bytes)
  rescue
    _ -> :error
  end

  defp kind_string_to_atom("obo_human"), do: {:ok, :obo_human}
  defp kind_string_to_atom("service_account"), do: {:ok, :service_account}
  defp kind_string_to_atom("autonomous"), do: {:ok, :autonomous}
  defp kind_string_to_atom(_), do: :error

  @doc """
  F002 Standalone Gateway does NOT implement RFC 8693 token exchange —
  downstream auth injection (FR-047) lands in F003+. Always `false`.
  """
  @impl true
  @spec supports_rfc8693?(state()) :: boolean()
  def supports_rfc8693?(_state), do: false

  @doc """
  Advertise the Principal kinds this impl produces from validated JWTs.
  `:rfc8693_exchange` is NOT advertised in F002 per FR-047 scope.
  """
  @impl true
  @spec capabilities(state()) :: [Recurse.Providers.PrincipalProvider.capability()]
  def capabilities(_state), do: [:obo_human, :service_account, :autonomous]

  @doc """
  Healthcheck: probes the JWKS cache freshness for each trusted issuer
  when a cache is configured. Surfaces stale / down JWKS as degraded /
  down.

  Minimal implementation: returns `:ok` if a `{:cache, module}` was
  configured and its process is alive; `{:degraded, :no_cache}`
  otherwise (manual `known_kids` mode — fine for tests, degraded for
  production).
  """
  @impl true
  @spec healthcheck(state()) :: :ok | {:degraded, term()} | {:down, term()}
  def healthcheck(state) do
    case Map.get(state, :known_kids) do
      {:cache, module} ->
        if Process.whereis(module), do: :ok, else: {:down, :cache_not_running}

      _ ->
        {:degraded, :no_cache}
    end
  end

  @doc """
  No impl-owned state — the JwksCache GenServer is supervised separately.
  """
  @impl true
  @spec terminate(state(), reason :: term()) :: :ok
  def terminate(_state, _reason), do: :ok
end
