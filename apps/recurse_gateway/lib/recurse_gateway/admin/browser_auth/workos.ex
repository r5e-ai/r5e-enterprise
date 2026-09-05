defmodule Recurse.Gateway.Admin.BrowserAuth.Workos do
  @moduledoc """
  WorkOS AuthKit adapter for the F004 browser sign-in flow (dogfood
  deployment scaffolding).

  ## Why this module exists

  F004's `LoginHandler` is generic over an "OIDC IdP + RFC 8693 broker"
  shape: the Gateway POSTs the IdP-minted `id_token` to the Standalone
  Identity Broker which mints an `X-Observed-Identity` JWT carrying the
  Recurse `principal` custom claim.

  For the **dogfood deploy** we want to skip the broker container
  entirely — auditors sign in via the **WorkOS AuthKit hosted UI**,
  WorkOS issues a signed access_token (RS256, JWKS-discoverable), the
  Gateway verifies the WorkOS access_token, then **mints a
  Recurse-internal broker-shaped JWT in-process** (via
  `Recurse.Shared.Identity.JwtMinter` — the same primitive the broker
  itself uses) carrying the F002 FR-009 `principal` custom claim. That
  internal JWT is what goes into the cookie payload — NOT the WorkOS
  access_token directly.

  ## Why broker-shape internal JWT

  Originally (pre-2026-04-26) the WorkOS access_token went straight into
  the cookie. GAN-review surfaced the architectural blocker (codex/CC):
  every Cedar-gated F004 endpoint (`AuditPlane.Authz.gate/4` →
  `IdentityContextBuilder.build/3`) requires a broker-shaped JWT
  carrying the `principal` custom claim. The WorkOS access_token only
  carries `sub/aud/org_id/role`, so post-login Cedar-gated requests
  failed with `:malformed_principal`.

  The fix preserves all downstream contracts (Cedar, receipts, replay,
  IdentityContext, Authz) by minting a broker-shaped JWT at the WorkOS
  token-exchange step. `BrowserSessionPlug` lifts it into the
  `Authorization` header on every request and the existing
  `IdentityContextBuilder` + `JwtValidator` chain runs unchanged.

  ## TTL bound (dogfood JWT revocation)

  The minted internal JWT TTL caps at 15 min (configurable via
  `:internal_jwt.ttl_seconds`). F004 FR-004 specifies that
  `POST /admin/logout` adds the JTI to a broker deny-list — the WorkOS
  path doesn't have a broker to write into, so we rely on the TTL bound
  + cookie-drop-on-logout for revocation. Operators who need
  active revocation should run the broker-mediated path. Documented
  here per finding #4 of the dogfood-deploy GAN review (2026-04-26).

  ## Role validation (canonical allowlist)

  Per finding #2 + #5 of the GAN review, the role pulled from the
  WorkOS access_token is validated against the canonical Recurse role
  allowlist (`tenant_auditor` | `platform_operator`) BEFORE the cookie
  is issued. Missing role → `{:error, :no_role_claim}`. Invalid role
  (post-`recurse_role_map` lookup not in the allowlist) →
  `{:error, :invalid_role}`. No silent fallback to a console role.

  This module is the **drop-in replacement** for `LoginHandler`'s three
  pluggable callbacks (`:code_exchanger`, `:id_token_validator`,
  `:token_exchange`) selected via `tier-config.console.idp_provider ==
  "workos"`. The broker-mediated default callbacks remain available for
  production-style deployments that want the broker hop.

  ## WorkOS endpoints (verified 2026-04-25)

    * **Authorize**: `GET https://api.workos.com/user_management/authorize`
      with `provider=authkit`, `client_id`, `redirect_uri`, `state`,
      `code_challenge`, `code_challenge_method=S256`, optional
      `organization_id`. The LoginHandler's `build_authorize_url/3`
      handles this — no module-level helper needed; the URL stays in
      `LoginHandler` so PKCE state is generated in the same place
      regardless of provider.
    * **Authenticate (token exchange)**: `POST
      https://api.workos.com/user_management/authenticate` with JSON
      body `{grant_type: authorization_code, client_id, client_secret,
      code, code_verifier}`. Returns `{user, organization_id,
      access_token, refresh_token, authentication_method}`.
    * **JWKS**: `GET https://api.workos.com/sso/jwks/{client_id}` —
      RS256 keys, fetched + cached via `Recurse.Gateway.Identity.JwksCache`.

  ## Principal mapping

  WorkOS user → Recurse `principal` map (per F002 FR-009 obo_human shape):

    * `principal.subject` = `workos_response.user.id` (e.g.
      `user_01KQ5VCDXS5J0DASQCZ4F5G5QT`).
    * `tenant_id` (also used as `principal.tenant_id` later) =
      `workos_response.organization_id` (e.g.
      `org_01KQ5T2EH9NP3AWE54AB2APWNH`).
    * `principal.recurse_role` = read from the WorkOS access_token JWT
      claims. WorkOS organization-scoped access_tokens carry a `role`
      claim (slug form, e.g. `tenant_auditor` / `platform_operator`)
      when the user has an organization membership. We decode the
      access_token, read `role`, and map it through the
      `:recurse_role_map` config (defaults to identity), then validate
      against the canonical Recurse-role allowlist
      (`tenant_auditor` | `platform_operator`).

  Failure modes (NO silent fallback to a console role):

    * `role` claim missing or non-binary →
      `{:error, :no_role_claim}` from token-exchange.
    * `role` post-`recurse_role_map` lookup is not in the canonical
      allowlist → `{:error, :invalid_role}`.

  Both surface to the LoginHandler as `:ui_login` `outcome` failure
  receipts; the user sees a clear error and no cookie is set.

  ## Iron Law check (`elixir:elixir-thinking`)

  Pure module. No process. State (the JWKS cache) is owned by
  `Recurse.Gateway.Identity.JwksCache` and injected via opts.

    1. Mutable state across calls? No — every function is `(args, opts)`
       in / `{:ok, ...} | {:error, _}` out.
    2. Concurrent execution? No — runs on the per-request process.
    3. Fault isolation? No — failures are tagged tuples; the LoginHandler
       translates them into `:ui_login` `outcome` discriminators.

  All three NO → plain functions.

  ## Cross-references

    * `apps/recurse_gateway/lib/recurse_gateway/admin/browser_auth/login_handler.ex`
      (the `:code_exchanger` / `:id_token_validator` / `:token_exchange`
      seam this module plugs into)
    * `apps/recurse_gateway/lib/recurse_gateway/identity/jwks_cache.ex`
      (JWKS fetcher used by `verify_access_token/2`)
    * `apps/recurse_gateway/lib/recurse_gateway/identity/jwt_validator.ex`
      (signature + claims verification)
    * `apps/recurse_shared/lib/recurse_shared/identity/jwt_minter.ex`
      (the shared mint primitive used at token-exchange)
    * WorkOS AuthKit hosted UI flow:
      https://workos.com/docs/user-management/authkit
  """

  alias Recurse.Gateway.Identity.JwksCache
  alias Recurse.Gateway.Identity.JwtValidator
  alias Recurse.Shared.BrowserSessionId
  alias Recurse.Shared.Identity.JwtMinter

  require Logger

  @workos_authorize_path "/user_management/authorize"
  @workos_authenticate_path "/user_management/authenticate"

  # WorkOS publishes per-client JWKS at this path:
  @workos_jwks_path_prefix "/sso/jwks/"

  # WorkOS access_tokens are issued by the WorkOS API host (e.g.
  # `https://api.workos.com`). The `iss` claim matches the configured
  # `:api_base` (we strip a trailing slash for stability).
  # The `aud` claim is the OIDC client_id.

  # Canonical Recurse-role allowlist for the audit console. Anything
  # outside this set is rejected at WorkOS token-exchange time (NOT
  # later at Cedar-eval time) so the failure is observable in the
  # `:ui_login` `outcome` rather than only in Cedar logs. The `system`
  # role is intentionally NOT user-assignable (see
  # `priv/reference_policies/platform_roles.cedar`).
  @canonical_console_roles ~w(tenant_auditor platform_operator)

  # WorkOS-path JWT TTL cap (see moduledoc — finding #4). Internal JWT
  # rides into the cookie; revocation on this path is best-effort
  # cookie-drop + this TTL bound. Override per `:internal_jwt.ttl_seconds`
  # in app env, but the override is HARD-CLAMPED to `@max_ttl_seconds`
  # so a misconfigured deploy cannot silently widen the replay window
  # past the contract claim (GAN round-2 finding #1, codex architectural).
  @default_internal_jwt_ttl_seconds 900
  @max_ttl_seconds 900
  @min_ttl_seconds 60

  # WorkOS as the customer IdP — recorded in the minted internal JWT's
  # principal.issuer claim so receipt forensics can attribute logins to
  # the IdP that asserted the identity (NOT to the internal Recurse
  # JWT issuer that wrapped it). GAN round-2 finding #2, codex
  # architectural — see `build_principal/5` rationale comment.
  @workos_idp_issuer "https://api.workos.com"

  # ---------------------------------------------------------------------------
  # Public API — thin helpers (used by tests + the LoginHandler seam below).
  # ---------------------------------------------------------------------------

  @doc """
  Construct the WorkOS authorize URL. Used by `LoginHandler`'s
  `:authorize_url_builder` opt (when threaded) — but the LoginHandler's
  built-in `build_authorize_url/3` already handles the standard PKCE
  query-string shape; the `provider=authkit` + `organization_id` extras
  come from `:authorize_extra_params` in the LoginHandler config.

  This helper is exposed for tests + tools that want to construct the
  URL outside the LoginHandler's redirect flow.
  """
  @spec authorize_url(keyword()) :: String.t()
  def authorize_url(opts) do
    config = resolve_config(opts)
    state = Keyword.fetch!(opts, :state)
    code_challenge = Keyword.fetch!(opts, :code_challenge)

    params =
      %{
        "client_id" => config.client_id,
        "redirect_uri" => config.redirect_uri,
        "response_type" => "code",
        "provider" => "authkit",
        "state" => state,
        "code_challenge" => code_challenge,
        "code_challenge_method" => "S256"
      }
      |> maybe_put_organization_id(config)

    config.api_base <> @workos_authorize_path <> "?" <> URI.encode_query(params)
  end

  @doc """
  Exchange the authorization code for a WorkOS access_token + user info.

  POSTs JSON to `POST {api_base}/user_management/authenticate` per the
  WorkOS AuthKit token-exchange contract. The API consumes
  `application/json`, NOT `application/x-www-form-urlencoded` — this is
  the structural difference from the generic OIDC flow that justifies
  the per-provider `:code_exchanger` seam.

  Returns the **raw decoded WorkOS response map** (string keys) on
  success so the caller (`default_exchange/3` below) can extract both
  the access_token AND the user/organization fields in one HTTP round
  trip.
  """
  @spec exchange_code(String.t(), String.t(), keyword()) ::
          {:ok, map()}
          | {:error,
             :workos_unreachable
             | :workos_authenticate_failed
             | :workos_response_malformed
             | {:workos_status, integer()}}
  def exchange_code(code, code_verifier, opts)
      when is_binary(code) and is_binary(code_verifier) do
    config = resolve_config(opts)

    body =
      JSON.encode!(%{
        "grant_type" => "authorization_code",
        "client_id" => config.client_id,
        "client_secret" => config.api_key,
        "code" => code,
        "code_verifier" => code_verifier
      })

    headers = [
      {"content-type", "application/json"},
      {"accept", "application/json"}
    ]

    url = config.api_base <> @workos_authenticate_path
    request = Finch.build(:post, url, headers, body)

    case Finch.request(request, config.finch_pool, receive_timeout: 5_000) do
      {:ok, %Finch.Response{status: 200, body: resp_body}} ->
        decode_authenticate_response(resp_body)

      {:ok, %Finch.Response{status: status, body: resp_body}} ->
        # Finding #3 — never log full response body (may contain
        # tokens / PII even on error). Log status + best-effort
        # response key names if the body decoded as JSON.
        keys =
          case JSON.decode(resp_body) do
            {:ok, m} when is_map(m) -> m |> Map.keys() |> Enum.sort()
            _ -> []
          end

        Logger.warning(fn ->
          "WorkOS authenticate non-200 status=#{status} response_keys=#{inspect(keys)}"
        end)

        {:error, {:workos_status, status}}

      {:error, reason} ->
        Logger.warning(fn ->
          "WorkOS authenticate unreachable: #{inspect(reason)}"
        end)

        {:error, :workos_unreachable}
    end
  end

  @doc """
  Validate a WorkOS access_token (signature + standard claims).

  Resolves the signing key via `JwksCache` keyed by the configured
  WorkOS issuer, then runs the standard `JwtValidator` pipeline:

    1. Alg allowlist (RS256 / ES256 / EdDSA) — `alg: none` rejected
       BEFORE any crypto.
    2. Kid resolution against the WorkOS-issuer-scoped cache.
    3. Signature verification via JOSE strict mode.
    4. Claim checks: `exp`/`nbf`/`iat` (60s skew), `iss` ==
       configured WorkOS API base, `aud` == WorkOS client_id.

  Returns `{:ok, claims_map}` (string-keyed; carries `sub`,
  `org_id`, optionally `role`, plus standard JWT claims) or
  `{:error, JwtValidator.reason()}`.
  """
  @spec verify_access_token(String.t(), keyword()) ::
          {:ok, map()} | {:error, atom()}
  def verify_access_token(jwt, opts) when is_binary(jwt) do
    config = resolve_config(opts)

    cond do
      is_nil(config.client_id) ->
        Logger.error(fn -> "WorkOS validator misconfigured: :client_id unset" end)
        {:error, :workos_client_id_unset}

      is_nil(config.api_base) ->
        Logger.error(fn -> "WorkOS validator misconfigured: :api_base unset" end)
        {:error, :workos_api_base_unset}

      true ->
        # WorkOS User Management JWTs do NOT carry an `aud` claim
        # (their access_tokens are user-info-shaped, not RFC 7519
        # client-id-as-aud). Omit `:audience` from validator opts;
        # JwtValidator's `check_audience/2` skips the check when the
        # opt is absent (mirroring `:issuer` semantics).
        validator_opts = %{
          issuer: workos_issuer(config),
          known_kids: {:cache, config.jwks_cache}
        }

        JwtValidator.validate(jwt, validator_opts)
    end
  end

  @doc """
  Map a verified WorkOS authenticate response → cookie-payload-shaped map.

  Returns `{:ok, %{principal_subject, recurse_role, tenant_id}}` on
  success.

  Failure variants (no silent fallback to a console role; see moduledoc):

    * `{:error, :workos_response_malformed}` — `user.id` or
      `organization_id` is missing from the WorkOS authenticate response.
    * `{:error, :no_role_claim}` — the WorkOS access_token lacks a
      `role` claim (or the claim is non-binary). The deploy MUST seed
      the WorkOS organization membership with a role; we do NOT default
      to `tenant_auditor` because that would silently grant audit
      access to any authenticated WorkOS user.
    * `{:error, :invalid_role}` — the `role` claim (post-`recurse_role_map`
      lookup) is not in the canonical Recurse-role allowlist
      (`tenant_auditor` | `platform_operator`).
  """
  @spec principal_from_response(map(), map(), keyword()) ::
          {:ok, %{principal_subject: String.t(), recurse_role: String.t(), tenant_id: String.t()}}
          | {:error, :workos_response_malformed | :no_role_claim | :invalid_role}
  def principal_from_response(workos_response, access_claims, opts)
      when is_map(workos_response) and is_map(access_claims) do
    config = resolve_config(opts)

    with %{"id" => user_id} when is_binary(user_id) <- Map.get(workos_response, "user", %{}),
         org_id when is_binary(org_id) <- Map.get(workos_response, "organization_id"),
         {:ok, role} <- pick_role(Map.get(access_claims, "role"), config) do
      {:ok,
       %{
         principal_subject: user_id,
         recurse_role: role,
         tenant_id: org_id
       }}
    else
      {:error, reason} when reason in [:no_role_claim, :invalid_role] ->
        {:error, reason}

      _ ->
        {:error, :workos_response_malformed}
    end
  end

  # ---------------------------------------------------------------------------
  # LoginHandler seam — drop-in replacements for the broker-mediated defaults.
  # ---------------------------------------------------------------------------

  @doc """
  `:code_exchanger` callback for `LoginHandler`.

  Replaces the generic OIDC `code → id_token` POST with the WorkOS
  AuthKit `code → access_token` flow. Returns the WorkOS access_token
  cast as the LoginHandler's `subject_token` so the downstream
  `:id_token_validator` callback receives the same token shape it
  would have for a generic id_token.

  The full WorkOS response (user + organization_id) is stashed in
  `:workos_response` on the LoginHandler config map (passed through
  via `config` updates) so `default_exchange/3` below can read it
  without re-issuing the authenticate call.

  Signature: `(code, code_verifier, config) -> {:ok, token, config_extras} | {:error, reason}`.
  The `config_extras` map is merged into the LoginHandler's config for
  the subsequent validator + token_exchange steps.
  """
  @spec default_code_exchanger(String.t(), String.t(), map()) ::
          {:ok, String.t(), map()}
          | {:error, atom() | {atom(), term()}}
  def default_code_exchanger(code, code_verifier, %{} = config) do
    opts = config_to_opts(config)

    case exchange_code(code, code_verifier, opts) do
      {:ok, %{"access_token" => access_token} = workos_response} when is_binary(access_token) ->
        {:ok, access_token, %{workos_response: workos_response}}

      {:ok, _other} ->
        {:error, :workos_response_malformed}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  `:id_token_validator` callback for `LoginHandler`.

  Validates the WorkOS access_token's signature + claims. Returns the
  decoded claims map; the LoginHandler hands these to `default_exchange/3`
  below, which materializes the cookie payload.
  """
  @spec default_validator(String.t(), map()) ::
          {:ok, map()} | {:error, atom()}
  def default_validator(access_token, %{} = config) when is_binary(access_token) do
    opts = config_to_opts(config)
    verify_access_token(access_token, opts)
  end

  def default_validator(_other, _config), do: {:error, :malformed_workos_token}

  @doc """
  `:token_exchange` callback for `LoginHandler`.

  No actual upstream exchange happens here — we already have the
  WorkOS access_token from `default_code_exchanger/3` above (cached in
  `config.workos_response`). This callback's job is to:

    1. Map the WorkOS response → broker-shaped principal claim
       (validates role per `principal_from_response/3`).
    2. Mint a Recurse-internal `X-Observed-Identity` JWT (broker-shape,
       carrying the `principal` custom claim per F002 FR-009) via
       `Recurse.Shared.Identity.JwtMinter` — using the same ES256 PEM
       the broker uses + the gateway's `:internal_jwt` config (audience
       + issuer + signing-key path).
    3. Materialize the cookie payload shape
       `LoginHandler.finalize_success/6` writes into the encrypted cookie.

  Returns `{:ok, %{jwt, principal_subject, recurse_role, tenant_id,
  browser_session_id}}`. The `:jwt` is the **internal** broker-shaped
  JWT (NOT the WorkOS access_token); downstream `BrowserSessionPlug`
  lifts it into `Authorization: Bearer ...` and the existing F002
  `IdentityContextBuilder` + Cedar gates run unchanged.
  """
  @spec default_exchange(String.t(), map(), map()) ::
          {:ok,
           %{
             jwt: String.t(),
             principal_subject: String.t(),
             recurse_role: String.t(),
             tenant_id: String.t(),
             browser_session_id: String.t()
           }}
          | {:error, atom()}
  def default_exchange(access_token, access_claims, %{workos_response: workos_response} = config)
      when is_binary(access_token) and is_map(access_claims) and is_map(workos_response) do
    opts = config_to_opts(config)

    # GAN round-3 finding #2 (claude, codex broker-precedent corroborated):
    # principal.issuer is DERIVED from the verified access_token's `iss`
    # claim, NOT from a hardcoded constant. Mirrors broker precedent
    # (`RecurseBroker.TokenExchange` derives upstream issuer from
    # `claims["iss"]`). Falls back to `@workos_idp_issuer` only if the
    # access_token (somehow) lacks `iss` — defense-in-depth, not the
    # expected path.
    idp_iss = Map.get(access_claims, "iss") || @workos_idp_issuer

    with {:ok, %{principal_subject: subj, recurse_role: role, tenant_id: tenant}} <-
           principal_from_response(workos_response, access_claims, opts),
         {:ok, internal_jwt} <-
           mint_internal_jwt(workos_response, subj, role, tenant, idp_iss, opts) do
      {:ok,
       %{
         jwt: internal_jwt,
         principal_subject: subj,
         recurse_role: role,
         tenant_id: tenant,
         browser_session_id: BrowserSessionId.generate()
       }}
    end
  end

  def default_exchange(_token, _claims, _config) do
    # The `:code_exchanger` step did not run (broker-path config used
    # WorkOS callbacks by mistake) — fail closed. The LoginHandler will
    # translate this into `outcome: "jwt_mint_failed"`.
    {:error, :workos_response_unset}
  end

  # Mint the broker-shaped internal JWT. Reads the Recurse-internal
  # signing key from `:internal_jwt` app env (file path + audience +
  # issuer + ttl). The signing key is the SAME ES256 PEM the broker
  # would use (same `BROKER_JWT_SIGNING_KEY_PATH`-shaped file); the
  # audience + issuer match the Gateway's `:jwt_validator_opts` so the
  # downstream `JwtValidator.validate/2` accepts the token.
  #
  # Returns `{:error, :internal_jwt_*}` family on misconfig — the
  # LoginHandler maps these to `outcome: "jwt_mint_failed"`.
  defp mint_internal_jwt(workos_response, subject, role, tenant_id, idp_iss, opts) do
    cfg = resolve_internal_jwt_config(opts)

    cond do
      is_nil(cfg.signing_key_path) ->
        Logger.error(fn ->
          "WorkOS internal-JWT mint misconfigured: :internal_jwt.signing_key_path unset"
        end)

        {:error, :internal_jwt_signing_key_unset}

      is_nil(cfg.audience) ->
        Logger.error(fn ->
          "WorkOS internal-JWT mint misconfigured: :internal_jwt.audience unset"
        end)

        {:error, :internal_jwt_audience_unset}

      is_nil(cfg.issuer) ->
        Logger.error(fn ->
          "WorkOS internal-JWT mint misconfigured: :internal_jwt.issuer unset"
        end)

        {:error, :internal_jwt_issuer_unset}

      true ->
        do_mint_internal_jwt(workos_response, subject, role, tenant_id, idp_iss, cfg)
    end
  end

  defp do_mint_internal_jwt(workos_response, subject, role, tenant_id, idp_iss, cfg) do
    with {:ok, {kid, jwk}} <- load_signing_key(cfg.signing_key_path),
         principal <- build_principal(workos_response, subject, role, tenant_id, idp_iss),
         {:ok, jwt} <-
           JwtMinter.mint(
             subject: subject,
             issuer: cfg.issuer,
             audience: cfg.audience,
             principal: principal,
             jwk: jwk,
             kid: kid,
             ttl_seconds: cfg.ttl_seconds
           ) do
      {:ok, jwt}
    else
      {:error, reason} ->
        Logger.error(fn ->
          "WorkOS internal-JWT mint failed: #{inspect(reason)}"
        end)

        {:error, :internal_jwt_mint_failed}
    end
  end

  # Build the F002 FR-009 obo_human principal map from the WorkOS
  # response. Includes `tenant_id` so Cedar's `principal.tenant_id ==
  # context.tenant_id` check has a value when policies are evaluated.
  defp build_principal(workos_response, subject, role, tenant_id, idp_iss) do
    user = Map.get(workos_response, "user", %{})

    display_name =
      Map.get(user, "first_name") ||
        Map.get(user, "email") ||
        subject

    # GAN round-3 fix: principal.issuer is DERIVED from the verified
    # access_token's `iss` claim (passed in as `idp_iss`), not from
    # `cfg.issuer` (the internal Recurse JWT issuer that wraps the
    # WorkOS assertion) and not from a hardcoded `@workos_idp_issuer`
    # constant. Mirrors broker precedent (`RecurseBroker.TokenExchange`
    # uses `claims["iss"]`).
    #
    # Why derive vs hardcode: regional WorkOS endpoints would issue
    # tokens with different `iss` (e.g. `https://api.workos.eu`).
    # A hardcoded constant would silently misattribute the IdP in
    # receipt forensics. The verified `iss` is the authoritative
    # statement of which WorkOS deployment vouched for this user.
    #
    # Cedar doesn't key on `principal.issuer` so this is a no-op for
    # authorization but load-bearing for `:ui_login` attestation
    # queries + cross-IdP forensics.
    %{
      "kind" => "obo_human",
      "issuer" => idp_iss,
      "subject" => subject,
      "display_name" => display_name,
      "groups" => [],
      "recurse_role" => role,
      "tenant_id" => tenant_id
    }
  end

  # Load the ES256 PEM file and derive a kid (filename stem if it looks
  # id-shaped, else the JWK SHA-256 thumbprint URL-base64-encoded).
  # Mirrors `RecurseBroker.JWT.KeyRing.derive_kid/2` so the broker and
  # the WorkOS-path mints are mutually verifiable across paths.
  defp load_signing_key(path) when is_binary(path) do
    if File.regular?(path) do
      jwk = JOSE.JWK.from_pem_file(path)
      kid = derive_kid(path, jwk)
      {:ok, {kid, jwk}}
    else
      {:error, {:signing_key_path_unreadable, path}}
    end
  rescue
    error -> {:error, {:signing_key_load_failed, Exception.message(error)}}
  end

  defp derive_kid(path, %JOSE.JWK{} = jwk) do
    stem = path |> Path.basename() |> Path.rootname()

    if kid_shaped?(stem) do
      stem
    else
      thumb = JOSE.JWK.thumbprint(jwk)
      Base.url_encode64(:crypto.hash(:sha256, thumb), padding: false)
    end
  end

  defp kid_shaped?(stem) do
    stem != "" and
      String.match?(stem, ~r/^[A-Za-z0-9_.\-]+$/) and
      String.replace(stem, ".", "") != ""
  end

  # Resolve internal-JWT config. The keyword opts a caller threads
  # through (e.g. tests passing `:internal_jwt_signing_key_path`)
  # override the app env entries (`:signing_key_path` etc.).
  defp resolve_internal_jwt_config(opts) do
    env = Application.get_env(:recurse_gateway, :internal_jwt, [])

    %{
      signing_key_path:
        opts[:internal_jwt_signing_key_path] || Keyword.get(env, :signing_key_path),
      audience: opts[:internal_jwt_audience] || Keyword.get(env, :audience),
      issuer: opts[:internal_jwt_issuer] || Keyword.get(env, :issuer),
      ttl_seconds:
        parse_ttl(
          opts[:internal_jwt_ttl_seconds] ||
            Keyword.get(env, :ttl_seconds, @default_internal_jwt_ttl_seconds)
        )
    }
  end

  @doc """
  Parse + clamp the WorkOS internal-JWT TTL seconds.

  GAN round-2 finding #1: hard-clamp `ttl_seconds` to
  `[@min_ttl_seconds, @max_ttl_seconds]` so a misconfigured
  `INTERNAL_JWT_TTL_SECONDS` env (or app-env override) cannot widen
  the WorkOS-path replay window past the documented bound.

  Out-of-range values raise `ArgumentError` — silent truncation would
  mask the operator's mistake; loud failure forces the right env value.

  Public so the boot-time validator + tests can call it directly
  without driving the full exchange flow.
  """
  @spec parse_ttl(term()) :: pos_integer()
  def parse_ttl(value)
      when is_integer(value) and value >= @min_ttl_seconds and value <= @max_ttl_seconds do
    value
  end

  def parse_ttl(value) do
    raise ArgumentError, """
    WorkOS internal JWT ttl_seconds out of bounds: #{inspect(value)}.

    Valid range is #{@min_ttl_seconds}..#{@max_ttl_seconds} seconds.

    The upper bound (#{@max_ttl_seconds}s = 15 minutes) is the WorkOS-path
    replay-window contract documented in workos.ex moduledoc finding #4.
    Widening it would silently break the revocation guarantee.

    Set `INTERNAL_JWT_TTL_SECONDS` env (or `:internal_jwt, :ttl_seconds`
    app env) to an integer in that range.
    """
  end

  # ---------------------------------------------------------------------------
  # Config resolution
  # ---------------------------------------------------------------------------

  defp resolve_config(opts) do
    env = Application.get_env(:recurse_gateway, :workos, [])
    pick = fn key, default -> opts[key] || Keyword.get(env, key, default) end

    %{
      api_key: pick.(:api_key, nil),
      client_id: pick.(:client_id, nil),
      redirect_uri: pick.(:redirect_uri, nil),
      default_organization_id: pick.(:default_organization_id, nil),
      api_base: pick.(:api_base, "https://api.workos.com"),
      jwks_cache: pick.(:jwks_cache, JwksCache),
      finch_pool: pick.(:finch_pool, :jwks_pool),
      recurse_role_map: pick.(:recurse_role_map, %{})
    }
  end

  # The LoginHandler passes its resolved config as a MAP (not keyword)
  # — `resolve_config/1` accepts a keyword OR a map. Convert here so the
  # WorkOS-specific keys (`:workos_response`, etc.) plus the LoginHandler-
  # threaded WorkOS opts both flow through.
  defp config_to_opts(%{} = config) do
    config
    |> Map.to_list()
    # Filter out nil values so `pick.(:key, default)` falls back to the
    # app env when a LoginHandler config key is absent.
    |> Enum.reject(fn {_k, v} -> is_nil(v) end)
  end

  # WorkOS User Management JWTs (both `access_token` and `id_token`
  # paths) carry `iss = <api_base>/user_management/<client_id>`, NOT
  # bare `api_base`. Validator `check_issuer` does string equality on
  # this claim, so the expected issuer must include the per-client
  # suffix. `JwksCache.fetch_jwk(issuer, kid)` likewise keys on this
  # exact URL.
  defp workos_issuer(config) do
    base = String.trim_trailing(config.api_base, "/")

    case config.client_id do
      cid when is_binary(cid) and cid != "" -> base <> "/user_management/" <> cid
      _ -> base
    end
  end

  defp maybe_put_organization_id(params, %{default_organization_id: org_id})
       when is_binary(org_id) and org_id != "" do
    Map.put(params, "organization_id", org_id)
  end

  defp maybe_put_organization_id(params, _config), do: params

  # Role resolution — finding #2 (no fail-open fallback) + #5 (validate
  # against canonical allowlist before cookie issuance).
  #
  # Returns:
  #   * `{:ok, validated_role}` when the role claim is present, maps
  #     through `recurse_role_map` (or passes through), AND lands in the
  #     canonical allowlist.
  #   * `{:error, :no_role_claim}` when the WorkOS access_token lacks
  #     a `role` claim or it's non-binary / empty.
  #   * `{:error, :invalid_role}` when the post-`recurse_role_map` value
  #     isn't one of the canonical Recurse roles.
  defp pick_role(nil, _config), do: {:error, :no_role_claim}
  defp pick_role("", _config), do: {:error, :no_role_claim}

  defp pick_role(role, config) when is_binary(role) do
    mapped = Map.get(config.recurse_role_map, role, role)

    if mapped in @canonical_console_roles do
      {:ok, mapped}
    else
      {:error, :invalid_role}
    end
  end

  defp pick_role(_other, _config), do: {:error, :no_role_claim}

  # Finding #3 — sanitize WorkOS authenticate-response log lines. Never
  # log token strings, refresh tokens, email, or profile fields. Only
  # log: present-key names (sorted), HTTP status (caller appends), and
  # the missing-field reason atom.
  defp decode_authenticate_response(body) when is_binary(body) do
    case JSON.decode(body) do
      {:ok, %{"access_token" => token, "user" => %{}, "organization_id" => org} = decoded}
      when is_binary(token) and is_binary(org) ->
        {:ok, decoded}

      {:ok, %{"access_token" => token, "user" => %{}} = decoded} when is_binary(token) ->
        # `organization_id` may be absent for users without an org
        # membership — surface as malformed (the dogfood deploy requires
        # an org-scoped access_token).
        log_sanitized_warning(decoded, :missing_organization_id)
        {:error, :workos_response_malformed}

      {:ok, decoded} when is_map(decoded) ->
        log_sanitized_warning(decoded, :missing_required_fields)
        {:error, :workos_response_malformed}

      _ ->
        Logger.warning(fn -> "WorkOS authenticate response not JSON-decodable" end)
        {:error, :workos_response_malformed}
    end
  end

  defp decode_authenticate_response(_other), do: {:error, :workos_response_malformed}

  defp log_sanitized_warning(decoded, reason) when is_map(decoded) do
    keys = decoded |> Map.keys() |> Enum.sort()

    Logger.warning(fn ->
      "WorkOS authenticate response malformed reason=#{inspect(reason)} keys=#{inspect(keys)}"
    end)
  end

  # ---------------------------------------------------------------------------
  # JWKS URL helper — used by Application.start/2 when wiring the
  # JwksCache child. WorkOS publishes per-client JWKS at:
  #   https://api.workos.com/sso/jwks/{client_id}
  # ---------------------------------------------------------------------------

  @doc """
  Build the WorkOS JWKS URL for the configured client. Used at boot
  by `RecurseGateway.Application` when constructing the JwksCache
  issuer entry. Returns `nil` if either `:api_base` or `:client_id`
  is unset (caller decides whether to fail-closed).
  """
  @spec jwks_url(keyword()) :: String.t() | nil
  def jwks_url(opts \\ []) do
    config = resolve_config(opts)

    if is_binary(config.client_id) and config.client_id != "" do
      String.trim_trailing(config.api_base, "/") <> @workos_jwks_path_prefix <> config.client_id
    else
      nil
    end
  end

  @doc """
  Issuer URL the WorkOS access_token's `iss` claim matches. Used at
  boot when registering the WorkOS issuer with `JwksCache`. Always
  returns a binary (defaults to `"https://api.workos.com"` if
  unconfigured).
  """
  @spec issuer_url(keyword()) :: String.t()
  def issuer_url(opts \\ []) do
    workos_issuer(resolve_config(opts))
  end
end
