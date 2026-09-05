defmodule Recurse.Gateway.Admin.BrowserSessionPlug do
  @moduledoc """
  Reads, validates, and (on mutating requests) rotates the `r5e_session`
  browser cookie envelope per `contracts/browser_oidc_flow.md` Step 6
  (F004 T034).

  ## Why this plug

  F002 ships JWT auth for direct API callers (`Authorization: Bearer
  <jwt>`). F004 adds a browser shell: humans sign in via Okta and the
  SPA carries an encrypted Session Cookie. This plug is the bridge
  between the cookie and F002's JWT-validating downstream:

    1. Decrypt + verify the cookie via `Plug.Crypto.MessageEncryptor`.
    2. Two-layer expiration: cookie envelope (8h absolute, 60min idle)
       AND embedded JWT `exp` claim. Both must pass.
    3. Lift `payload.jwt` into `Authorization: Bearer <jwt>` so F002's
       `JwtValidator` runs unchanged downstream.
    4. **Mutation-only rotation** (per research D6 Option B): on
       POST/PATCH/PUT/DELETE write a fresh cookie with bumped
       `issued_at` + `last_activity_at`; on GET/HEAD/OPTIONS leave the
       cookie untouched. This trades a slightly larger replay window
       (until the next user mutation) for tab-restore reliability —
       see contract Step 6 for the rationale.
    5. Emit a distinct `:ui_session` `event` subtype on every failure
       (`absolute_timeout` / `idle_timeout` / `jwt_expired_refresh_failed`
       / `cookie_tampered`) so auditors can filter the audit log per
       FR-003.

  ## Iron Law check (`elixir:phoenix-thinking`, `elixir:elixir-thinking`)

  Pure plug. No process. Iron Law:

    1. Mutable state across calls? No — every call is a pure function
       of `(conn, opts)` plus the read of `:persistent_term`-backed
       config (key set, cookie name, TTLs).
    2. Concurrent execution? No — runs on the Bandit-spawned per-request
       process.
    3. Fault isolation? No — failures fall through to a 401/302
       response; we do not crash the request process.

  All three NO → plain `Plug` callbacks.

  Phoenix-thinking note: the `BrowserSessionPlug` does NOT use
  `Plug.Session` because we want explicit control over the envelope
  payload, the rotation policy (mutation-only — `Plug.Session` rotates
  on every write), and the per-failure receipt-emission discriminators.
  `Plug.Crypto.MessageEncryptor` gives us the same crypto primitive
  `Plug.Session` uses internally.

  ## Cookie shape

  Encrypted payload (sealed via `MessageEncryptor.encrypt/3`):

      %{
        jwt: <minted_X-Observed-Identity_jwt>,
        issued_at: <unix_seconds>,
        last_activity_at: <unix_seconds>,
        browser_session_id: <uuid_v4>
      }

  Serialization is `:erlang.term_to_binary/1` (with `[:safe]` on decode
  to defend against atom/term injection from a forged ciphertext) inside
  the encryption envelope.

  ## Configuration

  Reads via `Application.get_env(:recurse_gateway, :browser_session, [])`:

    * `:cookie_name` — defaults to `"r5e_session"`.
    * `:secret_key_base` — primary 32-byte key for encrypt + decrypt.
      MUST be set in non-test envs (no insecure default).
    * `:secondary_keys` — list of rotated-out keys still accepted for
      decrypt. Empty by default.
    * `:absolute_timeout_seconds` — default 28_800 (8h, per Q1).
    * `:idle_timeout_seconds` — default 3_600 (60min idle, per D6).
    * `:secure_cookie?` — default `true`. Override to `false` in tier
      configs running plain HTTP locally.
    * `:absent_cookie_redirect` — default `:auto`. `:auto` = 302 for
      HTML routes, 401 JSON for `/v1/*` API routes. `:always_401` /
      `:always_302` available for tests.

  ## Plug pipeline ordering

  Stitched into the router by Wave 3 (out of scope for this task). The
  plug MUST run BEFORE `JwtValidator` so `Authorization` is populated;
  the validator then runs over the lifted bearer.

  ## Cross-references

    * `specs/004-audit-console/contracts/browser_oidc_flow.md` Step 6 + Sign-out
    * `specs/004-audit-console/research.md` D6 (cookie envelope, mutation-only rotation)
    * `apps/recurse_gateway/lib/recurse_gateway/identity/jwt_validator.ex` (downstream)
    * `apps/recurse_gateway/lib/recurse_gateway/admin/browser_auth/ui_receipts.ex` (receipt seam)
  """

  @behaviour Plug

  alias Plug.Conn
  alias Plug.Crypto.MessageEncryptor
  alias Recurse.Gateway.Admin.BrowserAuth.UiReceipts
  alias Recurse.Gateway.AuditPlane.ErrorEnvelope

  require Logger

  @default_cookie_name "r5e_session"
  @default_absolute_timeout_seconds 28_800
  @default_idle_timeout_seconds 3_600
  @mutation_methods ~w(POST PATCH PUT DELETE)
  @authorization_header "authorization"

  # ---------------------------------------------------------------------------
  # Plug interface
  # ---------------------------------------------------------------------------

  @impl Plug
  def init(opts), do: opts

  @impl Plug
  def call(%Conn{} = conn, opts) do
    config = load_config(opts)
    cookie_name = config.cookie_name
    fetched = Conn.fetch_cookies(conn)

    case Map.get(fetched.req_cookies, cookie_name) do
      nil ->
        handle_absent_cookie(fetched, config)

      cookie ->
        handle_present_cookie(fetched, cookie, config, opts)
    end
  end

  # ---------------------------------------------------------------------------
  # Public helpers — reused by LoginHandler / LogoutHandler / property tests.
  # ---------------------------------------------------------------------------

  @doc """
  Encrypt a session payload into the cookie ciphertext.

  Used by `LoginHandler` after successful token-exchange and by the
  internal rotation path on mutating requests. Tests use the same
  function to mint cookies for fixtures.
  """
  @spec encrypt_payload(map(), keyword()) :: binary()
  def encrypt_payload(payload, opts \\ []) when is_map(payload) do
    config = load_config(opts)
    do_encrypt(payload, primary_secret_pair(config))
  end

  @doc """
  Decrypt + decode a cookie ciphertext using the configured key set
  (primary + secondary). Returns `{:ok, payload_map}` or
  `{:error, :cookie_tampered}` if no key in the set decrypts cleanly
  (or the decrypted bytes don't deserialize to a map).
  """
  @spec decrypt_cookie(binary(), keyword()) ::
          {:ok, map()} | {:error, :cookie_tampered}
  def decrypt_cookie(cookie, opts \\ []) when is_binary(cookie) do
    config = load_config(opts)

    config
    |> all_secret_pairs()
    |> Enum.reduce_while({:error, :cookie_tampered}, fn pair, _acc ->
      case do_decrypt(cookie, pair) do
        {:ok, payload} -> {:halt, {:ok, payload}}
        :error -> {:cont, {:error, :cookie_tampered}}
      end
    end)
  end

  @doc """
  Build the `Set-Cookie` attributes string used by every cookie write
  in F004 (login set, mutation-only rotation, logout clear). Centralized
  so the attributes match between set and clear (browser will not delete
  a cookie unless attributes match).

  Returns a map suitable for `Plug.Conn.put_resp_cookie/4`'s opts
  keyword (extra fields like `:max_age` are caller-supplied).
  """
  @spec cookie_opts(keyword()) :: keyword()
  def cookie_opts(extra \\ []) do
    env = Application.get_env(:recurse_gateway, :browser_session, [])
    secure? = Keyword.get(extra, :secure?, Keyword.get(env, :secure_cookie?, true))

    base = [
      http_only: true,
      secure: secure?,
      same_site: "Lax",
      path: "/"
    ]

    Keyword.merge(base, Keyword.delete(extra, :secure?))
  end

  @doc """
  Cookie name accessor — used by handlers + tests so they don't
  hard-code `"r5e_session"`. Resolved without requiring a secret
  (some callers — e.g. logout / clear-cookie writers — only need the
  name; demanding `:secret_key_base` here would force tests to wire it
  for read-only call sites).
  """
  @spec cookie_name(keyword()) :: String.t()
  def cookie_name(opts \\ []) do
    env = Application.get_env(:recurse_gateway, :browser_session, [])
    opts[:cookie_name] || Keyword.get(env, :cookie_name, @default_cookie_name)
  end

  @doc """
  HTTP methods that trigger cookie rotation per D6 Option B (mutation-
  only). Exposed for tests to assert the rotation surface.
  """
  @spec mutation_methods() :: [String.t()]
  def mutation_methods, do: @mutation_methods

  # ---------------------------------------------------------------------------
  # Private — per-request flow
  # ---------------------------------------------------------------------------

  defp handle_absent_cookie(conn, config) do
    case redirect_strategy(conn, config) do
      :api_401 ->
        send_session_missing_401(conn)

      :html_302 ->
        redirect_to_login(conn)
    end
  end

  defp handle_present_cookie(conn, cookie, config, opts) do
    with {:ok, payload} <- decrypt_cookie(cookie, opts),
         :ok <- check_envelope_expiration(payload, config),
         :ok <- check_jwt_exp(payload),
         conn1 <- lift_jwt_to_authorization(conn, payload),
         conn2 <- maybe_rotate_cookie(conn1, payload, config) do
      conn2
    else
      {:error, :cookie_tampered} ->
        UiReceipts.emit(:ui_session, %{event: "cookie_tampered"})

        conn
        |> drop_cookie(config)
        |> reject_per_route(config, :cookie_invalid)

      {:error, :absolute_timeout, payload} ->
        emit_session_failure(payload, "absolute_timeout")

        conn
        |> drop_cookie(config)
        |> reject_per_route(config, :absolute_timeout)

      {:error, :idle_timeout, payload} ->
        emit_session_failure(payload, "idle_timeout")

        conn
        |> drop_cookie(config)
        |> reject_per_route(config, :idle_timeout)

      {:error, :jwt_expired, payload} ->
        # Wave 2A: silent JWT refresh path (broker re-issue) lands later;
        # for now, an expired JWT inside the cookie means session expired.
        # The contract's "jwt_expired_refresh_failed" subtype is the
        # appropriate audit event because the refresh attempt's outcome
        # (no refresh attempted yet → counts as failed) is the user-visible
        # observable.
        emit_session_failure(payload, "jwt_expired_refresh_failed")

        conn
        |> drop_cookie(config)
        |> reject_per_route(config, :jwt_expired)
    end
  end

  # ---------------------------------------------------------------------------
  # Cookie crypto — encrypt / decrypt with [:safe] term decoding.
  # ---------------------------------------------------------------------------

  defp do_encrypt(payload, {secret, sign_secret}) do
    bytes = :erlang.term_to_binary(payload)
    MessageEncryptor.encrypt(bytes, secret, sign_secret)
  end

  defp do_decrypt(cookie, {secret, sign_secret}) do
    case MessageEncryptor.decrypt(cookie, secret, sign_secret) do
      {:ok, bytes} -> safe_term_decode(bytes)
      :error -> :error
    end
  end

  # `[:safe]` prevents atom-injection / term-injection from forged ciphertexts.
  # Wrapped in try/rescue because `binary_to_term/2` raises ArgumentError on
  # malformed binaries.
  defp safe_term_decode(bytes) do
    case :erlang.binary_to_term(bytes, [:safe]) do
      payload when is_map(payload) -> {:ok, payload}
      _ -> :error
    end
  rescue
    _ -> :error
  end

  # ---------------------------------------------------------------------------
  # Two-layer expiration
  # ---------------------------------------------------------------------------

  defp check_envelope_expiration(payload, config) do
    now = System.system_time(:second)
    issued_at = Map.get(payload, :issued_at) || 0
    last_activity_at = Map.get(payload, :last_activity_at) || issued_at

    cond do
      now - issued_at > config.absolute_timeout_seconds ->
        {:error, :absolute_timeout, payload}

      now - last_activity_at > config.idle_timeout_seconds ->
        {:error, :idle_timeout, payload}

      true ->
        :ok
    end
  end

  defp check_jwt_exp(payload) do
    payload
    |> Map.get(:jwt)
    |> classify_jwt(payload)
  end

  defp classify_jwt(jwt, payload) when is_binary(jwt) do
    case peek_jwt_exp(jwt) do
      {:ok, exp} -> if exp > System.system_time(:second), do: :ok, else: {:error, :jwt_expired, payload}
      :error -> {:error, :jwt_expired, payload}
    end
  end

  defp classify_jwt(_other, _payload), do: {:error, :cookie_tampered}

  # Decode the JWT payload segment WITHOUT verifying the signature — we
  # only need `exp` to gate the request. Downstream `JwtValidator` does
  # the strict-mode signature verification.
  defp peek_jwt_exp(jwt) do
    with [_h, payload_b64, _s] <- String.split(jwt, "."),
         {:ok, payload_bytes} <- Base.url_decode64(payload_b64, padding: false),
         {:ok, %{"exp" => exp}} when is_integer(exp) <- JSON.decode(payload_bytes) do
      {:ok, exp}
    else
      _ -> :error
    end
  end

  # ---------------------------------------------------------------------------
  # JWT lift — populate Authorization for downstream JwtValidator.
  # ---------------------------------------------------------------------------

  defp lift_jwt_to_authorization(conn, %{jwt: jwt} = payload) when is_binary(jwt) do
    # F004 T077-adjacent: stamp a `:browser_session` assign so downstream
    # handlers (e.g., ExportHandler emitting `:ui_evidence_export` overlays)
    # can discriminate browser-flow callers from API-bearer callers without
    # re-decoding the cookie. The assign value carries the minimum
    # auditor-meaningful fields (`browser_session_id`, `tenant_id` if
    # present); the JWT itself stays in the lifted Authorization header.
    #
    # WorkOS-shaped cookies (dogfood deploy scaffolding) ALSO carry
    # `principal_subject` + `recurse_role` directly in the payload so
    # `AuthMeHandler` can render `/v1/auth/me` without a downstream
    # JwtValidator round trip (the WorkOS access_token uses a different
    # claim shape than the broker-minted X-Observed-Identity JWT). When
    # absent (broker-mediated path), the AuthMeHandler falls back to
    # decoding the JWT's `principal` custom claim.
    # Read timeouts directly from app env (no secret required for
    # read-only timeout introspection); falls back to the same defaults
    # `load_config/1` uses.
    env = Application.get_env(:recurse_gateway, :browser_session, [])
    absolute_timeout = Keyword.get(env, :absolute_timeout_seconds, @default_absolute_timeout_seconds)
    idle_timeout = Keyword.get(env, :idle_timeout_seconds, @default_idle_timeout_seconds)

    issued_at = Map.get(payload, :issued_at) || System.system_time(:second)
    last_activity_at = Map.get(payload, :last_activity_at) || issued_at

    session_assign =
      %{
        browser_session_id: Map.get(payload, :browser_session_id),
        tenant_id: Map.get(payload, :tenant_id),
        issued_at: issued_at,
        session_expires_at: iso8601_after(issued_at, absolute_timeout),
        session_idle_timeout_at: iso8601_after(last_activity_at, idle_timeout)
      }
      |> maybe_put_assign(:principal_subject, Map.get(payload, :principal_subject))
      |> maybe_put_assign(:recurse_role, Map.get(payload, :recurse_role))

    conn
    |> Conn.put_req_header(@authorization_header, "Bearer " <> jwt)
    |> Conn.assign(:browser_session, session_assign)
  end

  defp maybe_put_assign(map, _key, nil), do: map
  defp maybe_put_assign(map, key, value), do: Map.put(map, key, value)

  defp iso8601_after(unix_seconds, offset_seconds) do
    (unix_seconds + offset_seconds)
    |> DateTime.from_unix!()
    |> DateTime.to_iso8601()
  end

  # ---------------------------------------------------------------------------
  # Mutation-only rotation (D6 Option B)
  # ---------------------------------------------------------------------------

  defp maybe_rotate_cookie(conn, payload, config) do
    if conn.method in @mutation_methods do
      now = System.system_time(:second)
      # Preserve `issued_at` so the FR-002 8h absolute timeout actually
      # bounds the session. Resetting `issued_at` on rotation would
      # convert the absolute ceiling into a sliding window, allowing
      # indefinite extension via continuous mutation activity.
      # GAN-review fix (PR-readiness blocker #2, 2026-04-25): only
      # `last_activity_at` advances on rotation; `issued_at` is set
      # exactly once at login.
      rotated = %{payload | last_activity_at: now}
      cookie = do_encrypt(rotated, primary_secret_pair(config))

      # max_age advances the cookie expiry to the absolute-timeout
      # remainder, NOT the full window — the browser will drop the
      # cookie at issued_at + absolute_timeout_seconds regardless of
      # how many rotations land before then.
      remaining = max(0, payload.issued_at + config.absolute_timeout_seconds - now)

      Conn.put_resp_cookie(conn, config.cookie_name, cookie,
        cookie_opts(max_age: remaining)
      )
    else
      conn
    end
  end

  # ---------------------------------------------------------------------------
  # Receipt emission helpers
  # ---------------------------------------------------------------------------

  defp emit_session_failure(payload, event) do
    UiReceipts.emit(:ui_session, %{
      event: event,
      browser_session_id: Map.get(payload, :browser_session_id),
      tenant_id: Map.get(payload, :tenant_id)
    })
  end

  # ---------------------------------------------------------------------------
  # Response helpers
  # ---------------------------------------------------------------------------

  defp drop_cookie(conn, config) do
    Conn.put_resp_cookie(conn, config.cookie_name, "",
      cookie_opts(max_age: 0)
    )
  end

  defp reject_per_route(conn, config, cause) do
    case redirect_strategy(conn, config) do
      :api_401 ->
        send_unauthorized(conn, cause)

      :html_302 ->
        redirect_to_login(conn)
    end
  end

  defp redirect_strategy(conn, config) do
    case config.absent_cookie_redirect do
      :always_401 ->
        :api_401

      :always_302 ->
        :html_302

      :auto ->
        if String.starts_with?(conn.request_path, "/v1/") do
          :api_401
        else
          :html_302
        end
    end
  end

  # Map a session-failure cause atom to the canonical Audit Plane error
  # envelope shape via `ErrorEnvelope.send_unauthorized/4` (closes LB-1 from
  # the issue-#29 audit-pass survey: this site previously emitted a flat
  # `{"error_code": ...}` shape that the SPA's `ApiError` parser at
  # `ui/src/lib/api.ts:19-43` could not consume, causing every cookie-401 to
  # render "HTTP 401" inline). Cause atoms preserve the semantic distinctions
  # the prior shape carried:
  #
  #   * `:cookie_missing`     → `ERR_SESSION_MISSING`
  #   * `:cookie_invalid`     → `ERR_SESSION_INVALID`
  #   * `:absolute_timeout`   → `ERR_SESSION_EXPIRED_ABSOLUTE`
  #   * `:idle_timeout`       → `ERR_SESSION_EXPIRED_IDLE`
  #   * `:jwt_expired`        → `ERR_SESSION_JWT_EXPIRED`
  defp send_unauthorized(conn, cause) do
    {code, description} = unauthorized_envelope_for(cause)

    conn
    |> ErrorEnvelope.send_unauthorized(code, description, [])
    |> Conn.halt()
  end

  defp unauthorized_envelope_for(:cookie_missing),
    do:
      {"ERR_SESSION_MISSING",
       "No active browser session. Sign in via /admin/login/start."}

  defp unauthorized_envelope_for(:cookie_invalid),
    do:
      {"ERR_SESSION_INVALID",
       "Browser session cookie is invalid or tampered. Sign in again."}

  defp unauthorized_envelope_for(:absolute_timeout),
    do:
      {"ERR_SESSION_EXPIRED_ABSOLUTE",
       "Browser session reached its absolute timeout. Sign in again."}

  defp unauthorized_envelope_for(:idle_timeout),
    do:
      {"ERR_SESSION_EXPIRED_IDLE",
       "Browser session expired due to inactivity. Sign in again."}

  defp unauthorized_envelope_for(:jwt_expired),
    do:
      {"ERR_SESSION_JWT_EXPIRED",
       "Browser session's underlying credential expired. Sign in again."}

  defp send_session_missing_401(conn) do
    send_unauthorized(conn, :cookie_missing)
  end

  defp redirect_to_login(conn) do
    return_to = URI.encode_www_form(conn.request_path)

    conn
    |> Conn.put_resp_header("location", "/admin/login/start?return_to=#{return_to}")
    |> Conn.send_resp(302, "")
    |> Conn.halt()
  end

  # ---------------------------------------------------------------------------
  # Config resolution — Application env merged with caller overrides.
  # ---------------------------------------------------------------------------

  defp load_config(opts) do
    env = Application.get_env(:recurse_gateway, :browser_session, [])

    %{
      cookie_name:
        opts[:cookie_name] || Keyword.get(env, :cookie_name, @default_cookie_name),
      secret_key_base:
        opts[:secret_key_base] || Keyword.get(env, :secret_key_base) ||
          raise_missing_secret(),
      secondary_keys:
        opts[:secondary_keys] || Keyword.get(env, :secondary_keys, []),
      absolute_timeout_seconds:
        opts[:absolute_timeout_seconds] ||
          Keyword.get(env, :absolute_timeout_seconds, @default_absolute_timeout_seconds),
      idle_timeout_seconds:
        opts[:idle_timeout_seconds] ||
          Keyword.get(env, :idle_timeout_seconds, @default_idle_timeout_seconds),
      secure_cookie?:
        Keyword.get(opts, :secure_cookie?, Keyword.get(env, :secure_cookie?, true)),
      absent_cookie_redirect:
        opts[:absent_cookie_redirect] ||
          Keyword.get(env, :absent_cookie_redirect, :auto)
    }
  end

  defp raise_missing_secret do
    raise """
    BrowserSessionPlug requires `:secret_key_base` in
    config :recurse_gateway, :browser_session, secret_key_base: <32-byte binary>

    See specs/004-audit-console/contracts/browser_oidc_flow.md Step 5 + Key rotation.
    """
  end

  # `MessageEncryptor.encrypt/3` takes (payload, secret, sign_secret). We
  # derive both from the same key_base via SHA-256 split — this matches
  # the pattern `Plug.Session.COOKIE` uses internally and gives us a
  # deterministic mapping from a single configured key to the two crypto
  # inputs MessageEncryptor wants.
  defp primary_secret_pair(config) do
    derive_pair(config.secret_key_base)
  end

  defp all_secret_pairs(config) do
    [config.secret_key_base | config.secondary_keys]
    |> Enum.map(&derive_pair/1)
  end

  defp derive_pair(key_base) when is_binary(key_base) do
    # 32-byte SHA-256 of `key_base <> "enc"` for confidentiality;
    # `key_base <> "sign"` for authentication. Two independent derived
    # secrets per Plug.Crypto convention.
    secret = :crypto.hash(:sha256, key_base <> "enc")
    sign_secret = :crypto.hash(:sha256, key_base <> "sign")
    {secret, sign_secret}
  end
end
