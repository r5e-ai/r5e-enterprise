defmodule Recurse.Gateway.Admin.BrowserAuth.LoginHandler do
  @moduledoc """
  `GET /admin/login/start` + `GET /admin/login/callback` for the browser
  OIDC sign-in flow (F004 T036 — `contracts/browser_oidc_flow.md`
  Steps 2 + 4).

  ## Iron Law check (`elixir:phoenix-thinking`)

  Pure module-Plug (`@behaviour Plug`). No GenServer. Iron Law:

    1. Mutable state across calls? No — every call is a function of
       `(conn, opts)` plus reads/writes through `NonceStore` (Postgres)
       and an HTTP client (Finch).
    2. Concurrent execution? No — runs on the Bandit-spawned per-request
       process.
    3. Fault isolation? No — failures fall through to error responses.

  All three NO → plain `Plug` callbacks dispatched on `conn.path_info`.

  ## Responsibilities

  ### `GET /admin/login/start?return_to=<path>`

    1. Validate `return_to` is a Gateway-relative path (`/...`, NOT
       `//...`). Reject with 400 + `:ui_login` `outcome: "invalid_return_to"`.
    2. Generate `state` (32 random bytes, base64url) and `code_verifier`
       (64 random bytes, base64url — within RFC 7636's 43..128 range).
    3. Compute `code_challenge = base64url(sha256(code_verifier))`.
    4. INSERT row via `NonceStore.insert_nonce/3`.
    5. 302 to the IdP authorize URL with `state` + `code_challenge` +
       `redirect_uri` pointing at the Gateway's `/admin/login/callback`.

  ### `GET /admin/login/callback?state=<state>&code=<code>`

    1. `NonceStore.consume_nonce/1` (SELECT FOR UPDATE; single-use).
       Failures map to per-`outcome`-discriminated `:ui_login` receipts:
       `state_invalid`, `state_already_used`, `state_expired`.
    2. Exchange `code` at the IdP token endpoint with `code_verifier`.
       Failures → 502 + `:ui_login` `outcome: "idp_unreachable"` /
       `"idp_code_exchange_failed"`.
    3. Validate the returned `id_token` (signature against IdP JWKS;
       `aud`/`iss`/`exp`/`nbf`). Failure → 401 + `outcome: "id_token_invalid"`.
    4. Run the existing F002 RFC 8693 token-exchange path (broker
       in-VM dispatch; module pluggable via `:token_exchange_module`
       opt for tests). Failure → 403 + `outcome: "jwt_mint_failed"`.
    5. Build the cookie payload via `BrowserSessionPlug.encrypt_payload/2`,
       set on the Gateway origin with `Path=/`, `Max-Age=28800`.
    6. Emit `:ui_login` `outcome: "success"` and 302 to the validated
       `return_to` path.

  ## Per-failure-path receipt discriminators

  Per `browser_oidc_flow.md` Step 4 + §"Error states", the `outcome`
  field on every `:ui_login` receipt is the audit-distinguishable
  reason for the sign-in result. The seven failure-path discriminators
  wired here are:

    * `state_invalid` — no row
    * `state_already_used` — row but `used_at IS NOT NULL`
    * `state_expired` — row but `expires_at <= now()`
    * `idp_unreachable` / `idp_code_exchange_failed` — IdP HTTP failure
    * `id_token_invalid` — signature / claim check fail
    * `jwt_mint_failed` — RFC 8693 step fails (no role)

  Plus `success` for the happy path = 7 discriminators total + the
  pre-NonceStore `invalid_return_to` for malformed start requests.

  ## Configuration

  `:idp` keyword (or `Application.get_env(:recurse_gateway, :browser_idp)`):

    * `:authorize_url` — IdP's `/authorize` endpoint
    * `:token_url` — IdP's `/token` endpoint
    * `:client_id` — broker client_id registered with the IdP
    * `:redirect_uri` — Gateway-side `/admin/login/callback` URL
    * `:scope` — defaults to `"openid profile email groups"`
    * `:tenant_id` — current tenant (Phase-1 single-tenant)
    * `:finch_pool` — atom name of a Finch pool (defaults `:jwks_pool`)

  `:token_exchange_module` opt (default `Recurse.Gateway.Admin.BrowserAuth.LoginHandler.DefaultTokenExchange`)
  is the seam used by tests to inject a Mox / stub broker call without
  spinning up the real `RecurseBroker.Endpoint`.

  ## Cross-references

    * `specs/004-audit-console/contracts/browser_oidc_flow.md` Steps 2 + 4
    * `apps/recurse_gateway/lib/recurse_gateway/admin/browser_auth/nonce_store.ex`
    * `apps/recurse_gateway/lib/recurse_gateway/admin/browser_session_plug.ex`
    * `apps/recurse_broker/lib/recurse_broker/token_exchange.ex` (the F002 broker)
  """

  @behaviour Plug

  alias Plug.Conn
  alias Recurse.Gateway.Admin.BrowserAuth.NonceStore
  alias Recurse.Gateway.Admin.BrowserAuth.UiReceipts
  alias Recurse.Gateway.Admin.BrowserSessionPlug
  alias Recurse.Gateway.Identity.JwksCache
  alias Recurse.Gateway.Identity.JwtValidator
  alias Recurse.Shared.BrowserSessionId

  require Logger

  @default_scope "openid profile email groups"
  @absolute_max_age_seconds 28_800

  # RFC 8693 form constants for the broker `/token/exchange` POST. Kept
  # local to this module — the broker has its own copies (for inbound
  # validation) but we resist coupling the two via a shared header
  # module per Constitution Principle V (Provider Neutrality).
  @grant_type_token_exchange "urn:ietf:params:oauth:grant-type:token-exchange"
  @subject_token_type_id_token "urn:ietf:params:oauth:token-type:id_token"
  @requested_token_type_jwt "urn:ietf:params:oauth:token-type:jwt"

  # ---------------------------------------------------------------------------
  # Plug interface
  # ---------------------------------------------------------------------------

  @impl Plug
  def init(opts), do: opts

  @impl Plug
  def call(%Conn{method: "GET", path_info: ["admin", "login", "start"]} = conn, opts) do
    handle_start(conn, opts)
  end

  def call(%Conn{method: "GET", path_info: ["admin", "login", "callback"]} = conn, opts) do
    handle_callback(conn, opts)
  end

  def call(%Conn{} = conn, _opts) do
    Conn.send_resp(conn, 404, "")
  end

  # ---------------------------------------------------------------------------
  # /admin/login/start
  # ---------------------------------------------------------------------------

  defp handle_start(conn, opts) do
    config = resolve_config(opts)
    fetched = Conn.fetch_query_params(conn)
    return_to = Map.get(fetched.query_params, "return_to", "/admin/dashboard")

    case validate_return_to(return_to) do
      :ok ->
        build_and_redirect_to_idp(fetched, return_to, config)

      :error ->
        emit_login(config, %{outcome: "invalid_return_to"})
        send_error(fetched, 400, "invalid_return_to")
    end
  end

  # Finding #7 — every `:ui_login` predicate carries `auth_provider` so
  # forensic queries can scope by IdP if one is later compromised.
  defp emit_login(config, meta) do
    UiReceipts.emit(:ui_login, Map.put(meta, :auth_provider, config.auth_provider))
  end

  defp validate_return_to(path) when is_binary(path) do
    cond do
      String.starts_with?(path, "//") -> :error
      String.starts_with?(path, "/") -> :ok
      true -> :error
    end
  end

  defp validate_return_to(_), do: :error

  defp build_and_redirect_to_idp(conn, return_to, config) do
    state = random_url_token(32)
    code_verifier = random_url_token(64)
    code_challenge = pkce_challenge(code_verifier)

    case NonceStore.insert_nonce(state, code_verifier, %{
           return_to: absolutize_return_to(return_to, config),
           tenant_id: config.tenant_id
         }) do
      {:ok, _row} ->
        url = build_authorize_url(state, code_challenge, config)

        conn
        |> Conn.put_resp_header("location", url)
        |> Conn.send_resp(302, "")

      {:error, changeset} ->
        Logger.error(fn ->
          "login start nonce insert failed: #{inspect(changeset.errors)}"
        end)

        send_error(conn, 500, "internal_error")
    end
  end

  # The schema's `return_to` field requires `^https?://` format; we sanitize
  # the incoming Gateway-relative path against the Gateway origin to satisfy
  # the schema. `gateway.example.com` is replaced by the deployed origin in
  # config — defaults to a localhost dev URL.
  defp absolutize_return_to(path, config) do
    config.gateway_origin <> path
  end

  defp build_authorize_url(state, code_challenge, config) do
    base_query = %{
      "response_type" => "code",
      "client_id" => config.client_id,
      "redirect_uri" => config.redirect_uri,
      "state" => state,
      "code_challenge" => code_challenge,
      "code_challenge_method" => "S256"
    }

    # `:scope` is omitted from the WorkOS AuthKit authorize URL — WorkOS
    # derives scopes from the OIDC client's configured product set. For
    # generic OIDC IdPs (Okta, Auth0, Keycloak), `:scope` MUST be on the
    # query string. We emit it conditionally — empty string or `nil`
    # both suppress.
    query_with_scope =
      if is_binary(config.scope) and config.scope != "" do
        Map.put(base_query, "scope", config.scope)
      else
        base_query
      end

    # `:authorize_extra_params` lets per-provider seams thread additional
    # query params without needing a new top-level config key. WorkOS
    # uses this for `provider=authkit` + `organization_id`.
    extras = config.authorize_extra_params || %{}
    query = Map.merge(query_with_scope, extras)

    config.authorize_url <> "?" <> URI.encode_query(query)
  end

  # ---------------------------------------------------------------------------
  # /admin/login/callback
  # ---------------------------------------------------------------------------

  defp handle_callback(conn, opts) do
    config = resolve_config(opts)
    fetched = Conn.fetch_query_params(conn)
    state = Map.get(fetched.query_params, "state")
    code = Map.get(fetched.query_params, "code")

    cond do
      not is_binary(state) or state == "" ->
        emit_login(config, %{outcome: "state_invalid"})
        send_error(fetched, 400, "state_invalid")

      not is_binary(code) or code == "" ->
        emit_login(config, %{outcome: "state_invalid"})
        send_error(fetched, 400, "missing_code")

      true ->
        do_callback(fetched, state, code, config)
    end
  end

  defp do_callback(conn, state, code, config) do
    with {:ok, nonce} <- consume_with_audit(state, config),
         {:ok, id_token, config} <- exchange_code(code, nonce, config),
         {:ok, id_claims} <- validate_id_token(id_token, config),
         {:ok, success} <- token_exchange(id_token, id_claims, config) do
      finalize_success(conn, success, nonce, config)
    else
      {:error, {:halt, status, code_str}} ->
        send_error(conn, status, code_str)
    end
  end

  defp consume_with_audit(state, config) do
    case NonceStore.consume_nonce(state) do
      {:ok, nonce} ->
        {:ok, nonce}

      {:error, reason} ->
        # `:state_invalid | :state_already_used | :state_expired`
        emit_login(config, %{outcome: Atom.to_string(reason)})
        {:error, {:halt, http_for_consume_error(reason), Atom.to_string(reason)}}
    end
  end

  defp http_for_consume_error(_), do: 400

  # `exchange_code/3` returns `{:ok, subject_token, updated_config}` so
  # custom `:code_exchanger` callbacks (e.g. WorkOS) can attach
  # provider-specific extras (a full WorkOS authenticate response, etc.)
  # to the config map for the downstream `:token_exchange` step. The
  # default OIDC path returns the original config unchanged.
  defp exchange_code(code, nonce, config) do
    case config.code_exchanger.(code, nonce.code_verifier, config) do
      {:ok, subject_token, %{} = extras} when is_binary(subject_token) ->
        {:ok, subject_token, Map.merge(config, extras)}

      {:ok, subject_token} when is_binary(subject_token) ->
        # Backwards-compat path for callbacks that don't return extras.
        {:ok, subject_token, config}

      {:error, :idp_unreachable} ->
        emit_login(config, %{outcome: "idp_unreachable"})
        {:error, {:halt, 502, "idp_unreachable"}}

      {:error, :workos_unreachable} ->
        emit_login(config, %{outcome: "idp_unreachable"})
        {:error, {:halt, 502, "idp_unreachable"}}

      {:error, _other} ->
        emit_login(config, %{outcome: "idp_code_exchange_failed"})
        {:error, {:halt, 502, "idp_code_exchange_failed"}}
    end
  end

  @doc """
  Default `:code_exchanger` — the generic RFC 6749 §4.1.3 + RFC 7636
  PKCE auth-code → id_token POST. Returns `{:ok, id_token, %{}}` on
  success (no provider extras), `{:error, atom}` on failure.

  Preserved as a public function so:
    1. Tests can call it directly (`oidc_login_flow_contract_test.exs`
       relied on the in-line behaviour pre-T-WORKOS).
    2. Adapters that want to wrap-not-replace the OIDC flow (e.g.
       Okta, Auth0) can `default_code_exchanger/3` then transform the
       returned id_token themselves.
  """
  @spec default_code_exchanger(String.t(), String.t(), map()) ::
          {:ok, String.t(), map()} | {:error, :idp_unreachable | :idp_code_exchange_failed}
  def default_code_exchanger(code, code_verifier, config) do
    body =
      URI.encode_query(%{
        "grant_type" => "authorization_code",
        "code" => code,
        "redirect_uri" => config.redirect_uri,
        "client_id" => config.client_id,
        "code_verifier" => code_verifier
      })

    headers = [
      {"content-type", "application/x-www-form-urlencoded"},
      {"accept", "application/json"}
    ]

    request = Finch.build(:post, config.idp_token_url, headers, body)

    case Finch.request(request, config.finch_pool, receive_timeout: 5_000) do
      {:ok, %Finch.Response{status: 200, body: resp_body}} ->
        case JSON.decode(resp_body) do
          {:ok, %{"id_token" => id_token}} when is_binary(id_token) ->
            {:ok, id_token, %{}}

          _ ->
            {:error, :idp_code_exchange_failed}
        end

      {:ok, %Finch.Response{status: status}} ->
        Logger.warning(fn ->
          "IdP token endpoint returned non-200 status=#{status}"
        end)

        {:error, :idp_code_exchange_failed}

      {:error, reason} ->
        Logger.warning(fn ->
          "IdP token endpoint unreachable: #{inspect(reason)}"
        end)

        {:error, :idp_unreachable}
    end
  end

  defp validate_id_token(id_token, config) do
    case config.id_token_validator.(id_token, config) do
      {:ok, claims} ->
        {:ok, claims}

      {:error, reason} ->
        # Log the validator's reason atom (e.g. :invalid_issuer,
        # :invalid_audience, :unknown_kid, :token_expired) so deploy
        # debugging doesn't require source-level instrumentation. The
        # outward-facing receipt + body still use the opaque
        # `id_token_invalid` to avoid leaking validator details to the
        # browser.
        Logger.warning(fn -> "id_token_invalid validator reason=#{inspect(reason)}" end)
        emit_login(config, %{outcome: "id_token_invalid"})
        {:error, {:halt, 401, "id_token_invalid"}}
    end
  end

  # `token_exchange/3` accepts both the broker-mediated 3-key shape
  # (`%{jwt, principal_subject, browser_session_id}`) AND the WorkOS-
  # extended 5-key shape (adds `recurse_role` + `tenant_id` so the
  # cookie payload can carry the principal directly without a downstream
  # broker JWT round-trip). The shape with extra fields rides through
  # `finalize_success/3` into the cookie and on into the
  # `:browser_session` assign.
  defp token_exchange(id_token, id_claims, config) do
    case config.token_exchange.(id_token, id_claims, config) do
      {:ok, %{jwt: jwt, principal_subject: subj, browser_session_id: bsid} = success}
      when is_binary(jwt) and is_binary(subj) and is_binary(bsid) ->
        {:ok, success}

      {:error, :no_role_claim} ->
        # Finding #2 — WorkOS access_token had no `role` claim. The
        # auditor's WorkOS organization membership wasn't seeded with
        # a role. Distinct outcome so operators can tell this apart
        # from a generic mint failure.
        emit_login(config, %{outcome: "no_role_claim"})
        {:error, {:halt, 403, "no_role_claim"}}

      {:error, :invalid_role} ->
        # Finding #5 — role validated against canonical Recurse-role
        # allowlist (`tenant_auditor` | `platform_operator`) and
        # rejected. Distinct outcome.
        emit_login(config, %{outcome: "invalid_role"})
        {:error, {:halt, 403, "invalid_role"}}

      {:error, reason} ->
        emit_login(config, %{outcome: "jwt_mint_failed"})

        Logger.warning(fn ->
          "RFC 8693 token exchange failed: #{inspect(reason)}"
        end)

        {:error, {:halt, 403, "jwt_mint_failed"}}
    end
  end

  defp finalize_success(conn, success, nonce, config) do
    %{jwt: jwt, principal_subject: principal_subject, browser_session_id: browser_session_id} =
      success

    now = System.system_time(:second)

    # Tenant id resolution: WorkOS exchange callbacks supply the
    # tenant_id directly (organization_id from the WorkOS authenticate
    # response). Broker-mediated callbacks omit it; we fall back to the
    # deployment-configured tenant_id (Phase-1 single-tenant default).
    tenant_id = Map.get(success, :tenant_id) || config.tenant_id

    base_payload = %{
      jwt: jwt,
      issued_at: now,
      last_activity_at: now,
      browser_session_id: browser_session_id,
      tenant_id: tenant_id
    }

    payload =
      base_payload
      |> maybe_put_payload_field(:principal_subject, principal_subject)
      |> maybe_put_payload_field(:recurse_role, Map.get(success, :recurse_role))

    cookie = BrowserSessionPlug.encrypt_payload(payload)

    emit_login(config, %{
      outcome: "success",
      principal_subject: principal_subject,
      browser_session_id: browser_session_id,
      tenant_id: tenant_id
    })

    return_to = de_absolutize(nonce.return_to, config)

    conn
    |> Conn.put_resp_cookie(
      BrowserSessionPlug.cookie_name(),
      cookie,
      BrowserSessionPlug.cookie_opts(max_age: @absolute_max_age_seconds)
    )
    |> Conn.put_resp_header("location", return_to)
    |> Conn.send_resp(302, "")
  end

  defp maybe_put_payload_field(payload, _key, nil), do: payload
  defp maybe_put_payload_field(payload, key, value), do: Map.put(payload, key, value)

  defp de_absolutize(absolute_url, config) do
    case String.split(absolute_url, config.gateway_origin, parts: 2) do
      [_, path] when path != "" -> path
      _ -> "/admin/dashboard"
    end
  end

  # ---------------------------------------------------------------------------
  # Error short-circuit handling — `do_callback` returns `{:error, {:halt, ...}}`
  # tuples; collapse them to a real HTTP response.
  # ---------------------------------------------------------------------------

  defp send_error(conn, status, code) do
    body = JSON.encode!(%{"error" => code})

    conn
    |> Conn.put_resp_content_type("application/json")
    |> Conn.send_resp(status, body)
  end

  # ---------------------------------------------------------------------------
  # PKCE helpers
  # ---------------------------------------------------------------------------

  defp random_url_token(byte_count) do
    byte_count
    |> :crypto.strong_rand_bytes()
    |> Base.url_encode64(padding: false)
  end

  defp pkce_challenge(code_verifier) do
    :sha256
    |> :crypto.hash(code_verifier)
    |> Base.url_encode64(padding: false)
  end

  # ---------------------------------------------------------------------------
  # Config resolution
  # ---------------------------------------------------------------------------

  defp resolve_config(opts) do
    env = Application.get_env(:recurse_gateway, :browser_idp, [])

    default_gateway_origin =
      Application.get_env(:recurse_gateway, :public_hostname, "http://127.0.0.1:4000")

    pick = fn key, default -> opts[key] || Keyword.get(env, key, default) end

    # Finding #7 — `auth_provider` for `:ui_login` predicate. Forensic
    # queries can scope blast radius if a specific IdP is later
    # compromised. Resolved from `:browser_oidc_idp.provider` env (set
    # by `config/runtime.exs` from `BROWSER_OIDC_PROVIDER`). Caller can
    # override per-request via `opts[:auth_provider]` for tests.
    auth_provider =
      opts[:auth_provider] ||
        Application.get_env(:recurse_gateway, :browser_oidc_idp, [])
        |> Keyword.get(:provider, "broker")

    %{
      authorize_url: pick.(:authorize_url, nil),
      idp_token_url: pick.(:idp_token_url, nil),
      client_id: pick.(:client_id, nil),
      redirect_uri: pick.(:redirect_uri, nil),
      scope: pick.(:scope, @default_scope),
      tenant_id: pick.(:tenant_id, "default"),
      gateway_origin: pick.(:gateway_origin, default_gateway_origin),
      finch_pool: pick.(:finch_pool, :jwks_pool),
      auth_provider: auth_provider,
      # ---- id_token validation (default callbacks below) ----
      # `:idp_issuer_url`  — the customer IdP's `iss` (string-equality on the
      #   `id_token`'s `iss` claim AND the JwksCache lookup key).
      # `:idp_audience`    — the OIDC client_id (string-equality on `aud`).
      # `:jwks_cache`      — the JwksCache GenServer reference. Defaults to
      #   the module-registered name `Recurse.Gateway.Identity.JwksCache`.
      idp_issuer_url: pick.(:idp_issuer_url, nil),
      idp_audience: pick.(:idp_audience, nil) || pick.(:client_id, nil),
      jwks_cache: pick.(:jwks_cache, JwksCache),
      # ---- broker exchange (default callback below) ----
      # In production the broker is a separate container (`recurse-broker`
      # on port 4001 per `docker-compose.yaml`), so the exchange is an
      # HTTP POST against `:broker_token_exchange_url`. Tests OPT into
      # in-VM dispatch by passing `:broker_endpoint` (a `Plug` module)
      # which is invoked via `Plug.Test.conn/3` instead of Finch.
      broker_token_exchange_url: pick.(:broker_token_exchange_url, nil),
      broker_audience: pick.(:broker_audience, nil),
      broker_endpoint: pick.(:broker_endpoint, nil),
      broker_endpoint_opts: pick.(:broker_endpoint_opts, []),
      # ---- pluggable callback seams ----
      # `:code_exchanger` performs the OAuth `code → subject_token` POST.
      # Default = the generic OIDC `id_token` flow (`default_code_exchanger/3`).
      # WorkOS / other AuthKit-shape providers override with their own
      # 2xx-JSON-shape exchanger (`Workos.default_code_exchanger/3`).
      code_exchanger: pick.(:code_exchanger, &__MODULE__.default_code_exchanger/3),
      # `:authorize_extra_params` is merged into the authorize URL query
      # string AFTER the standard PKCE keys. Used by provider seams to
      # thread provider-specific params (e.g. WorkOS `provider=authkit`
      # + `organization_id`) without adding a new config key per provider.
      authorize_extra_params: pick.(:authorize_extra_params, %{}),
      id_token_validator: pick.(:id_token_validator, &__MODULE__.default_id_token_validator/2),
      token_exchange: pick.(:token_exchange, &__MODULE__.default_token_exchange/3)
    }
  end

  @doc """
  Default `id_token` validator — production wiring.

  Resolves the customer IdP's signing key via the Gateway's
  `Recurse.Gateway.Identity.JwksCache` (kid-miss triggers a coalesced
  refresh per Surface P), then runs the standard
  `Recurse.Gateway.Identity.JwtValidator` pipeline:

    1. Alg allowlist (`RS256 | ES256 | EdDSA`) — `alg: none` rejected
       BEFORE any crypto.
    2. JWKS `kid` resolution against the cache (issuer-scoped lookup).
    3. Signature verification via JOSE strict mode.
    4. Claim checks: `exp` / `nbf` / `iat` with 60s skew, `aud` ==
       `config.idp_audience`, `iss` == `config.idp_issuer_url`.

  Returns `{:ok, claims}` on success (claims map carries `sub`, `aud`,
  `iss`, plus any IdP-issued extras like `groups`, `name`, `email`),
  `{:error, reason_atom}` on failure. The reason atom is one of the
  `JwtValidator` enumeration (e.g. `:unknown_kid`, `:invalid_signature`,
  `:token_expired`, `:invalid_audience`, `:invalid_issuer`,
  `:forbidden_alg`, `:malformed_claims`).

  Tests bypass this default by passing `:id_token_validator` in opts
  with a stub fn (see `oidc_login_flow_contract_test.exs`).
  """
  @spec default_id_token_validator(String.t(), map()) ::
          {:ok, map()} | {:error, term()}
  def default_id_token_validator(id_token, config) when is_binary(id_token) do
    cond do
      is_nil(config[:idp_issuer_url]) ->
        Logger.error(fn -> "OIDC validator misconfigured: :idp_issuer_url unset" end)
        {:error, :idp_issuer_url_unset}

      is_nil(config[:idp_audience]) ->
        Logger.error(fn -> "OIDC validator misconfigured: :idp_audience / :client_id unset" end)
        {:error, :idp_audience_unset}

      true ->
        validator_opts = %{
          audience: config.idp_audience,
          issuer: config.idp_issuer_url,
          known_kids: {:cache, config.jwks_cache}
        }

        JwtValidator.validate(id_token, validator_opts)
    end
  end

  def default_id_token_validator(_id_token, _config), do: {:error, :malformed_id_token}

  @doc """
  Default RFC 8693 token-exchange — production wiring.

  Hands the IdP-issued `id_token` to the Standalone Identity Broker's
  `POST /token/exchange` endpoint per `contracts/recurse_broker_api.md`
  + RFC 8693 §2.1, then unpacks the `access_token` (the broker-minted
  X-Observed-Identity JWT) into the cookie payload shape that
  `BrowserSessionPlug` consumes.

  ## Dispatch path

  Production deployments run the broker as a SEPARATE container
  (see `docker-compose.yaml` `recurse-broker` service on port 4001),
  so the default path is an **HTTP POST** via the `:jwks_pool` Finch
  pool against `config.broker_token_exchange_url` (e.g.
  `http://recurse-broker:4001/token/exchange`).

  Tests OPT into **in-VM dispatch** by passing `:broker_endpoint` in
  the LoginHandler opts — a `Plug` module (typically
  `RecurseBroker.Endpoint`) that we invoke via `Plug.Test.conn/3` to
  drive the same call without binding a port. This is the same in-VM
  shortcut used by `apps/recurse_gateway/test/integration/us1_with_real_broker_test.exs`.

  ## Returned cookie payload shape

      {:ok, %{
        jwt: <broker-minted X-Observed-Identity JWT>,
        principal_subject: <id_claims["sub"]>,
        browser_session_id: <fresh browser session id>
      }}

  `principal_subject` is the IdP `sub` (audit-meaningful display in
  `:ui_login` receipts); the minted JWT carries its OWN `principal`
  custom claim that downstream code extracts via `JwtValidator`.
  `browser_session_id` is generated here so each successful login
  yields a fresh session id per F004 audit-correlation conventions.

  Returns `{:ok, payload}` on success, `{:error, reason}` on failure.
  Reasons: `:broker_url_unset`, `:broker_audience_unset`,
  `:broker_unreachable`, `{:broker_status, status}`,
  `{:broker_body_invalid, raw}`, or any `Finch.Error` term.
  """
  @spec default_token_exchange(String.t(), map(), map()) ::
          {:ok, %{jwt: String.t(), principal_subject: String.t(), browser_session_id: String.t()}}
          | {:error, term()}
  def default_token_exchange(id_token, id_claims, config)
      when is_binary(id_token) and is_map(id_claims) and is_map(config) do
    with {:ok, broker_audience} <- require_broker_audience(config),
         form_body <- build_exchange_form(id_token, broker_audience),
         {:ok, status, resp_body} <- dispatch_exchange(form_body, config),
         :ok <- check_status(status),
         {:ok, %{"access_token" => jwt}} <- decode_access_token(resp_body) do
      principal_subject = Map.get(id_claims, "sub", "unknown")

      {:ok,
       %{
         jwt: jwt,
         principal_subject: principal_subject,
         browser_session_id: BrowserSessionId.generate()
       }}
    end
  end

  defp require_broker_audience(%{broker_audience: aud}) when is_binary(aud) and aud != "" do
    {:ok, aud}
  end

  defp require_broker_audience(_) do
    Logger.error(fn -> "broker token-exchange misconfigured: :broker_audience unset" end)
    {:error, :broker_audience_unset}
  end

  defp build_exchange_form(id_token, broker_audience) do
    URI.encode_query(%{
      "grant_type" => @grant_type_token_exchange,
      "subject_token" => id_token,
      "subject_token_type" => @subject_token_type_id_token,
      "requested_token_type" => @requested_token_type_jwt,
      "audience" => broker_audience
    })
  end

  # In-VM dispatch path (test seam): if `:broker_endpoint` is a Plug
  # module, we drive it through Plug.Test rather than the Finch pool.
  # This mirrors the F002 us1_with_real_broker_test pattern (T089).
  defp dispatch_exchange(form_body, %{broker_endpoint: endpoint, broker_endpoint_opts: opts})
       when is_atom(endpoint) and not is_nil(endpoint) do
    conn =
      :post
      |> Plug.Test.conn("/token/exchange", form_body)
      |> Plug.Conn.put_req_header("content-type", "application/x-www-form-urlencoded")
      |> endpoint.call(opts)

    {:ok, conn.status, conn.resp_body}
  rescue
    e ->
      Logger.error(fn ->
        "broker in-VM dispatch raised: #{Exception.message(e)}"
      end)

      {:error, {:broker_unreachable, Exception.message(e)}}
  end

  # Production HTTP path — POSTs against the broker container.
  defp dispatch_exchange(form_body, %{broker_token_exchange_url: url, finch_pool: pool})
       when is_binary(url) and url != "" do
    headers = [
      {"content-type", "application/x-www-form-urlencoded"},
      {"accept", "application/json"}
    ]

    request = Finch.build(:post, url, headers, form_body)

    case Finch.request(request, pool, receive_timeout: 5_000) do
      {:ok, %Finch.Response{status: status, body: body}} ->
        {:ok, status, body}

      {:error, reason} ->
        Logger.warning(fn ->
          "broker token-exchange HTTP failed: #{inspect(reason)}"
        end)

        {:error, {:broker_unreachable, reason}}
    end
  end

  defp dispatch_exchange(_form_body, _config) do
    Logger.error(fn ->
      "broker token-exchange misconfigured: neither :broker_token_exchange_url nor :broker_endpoint set"
    end)

    {:error, :broker_url_unset}
  end

  defp check_status(200), do: :ok

  defp check_status(status) when is_integer(status) do
    {:error, {:broker_status, status}}
  end

  defp decode_access_token(body) when is_binary(body) do
    case JSON.decode(body) do
      {:ok, %{"access_token" => jwt} = decoded} when is_binary(jwt) and jwt != "" ->
        {:ok, decoded}

      _ ->
        {:error, {:broker_body_invalid, body}}
    end
  end

  defp decode_access_token(other), do: {:error, {:broker_body_invalid, other}}
end
