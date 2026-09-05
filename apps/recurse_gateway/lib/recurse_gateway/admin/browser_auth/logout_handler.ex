defmodule Recurse.Gateway.Admin.BrowserAuth.LogoutHandler do
  @moduledoc """
  `POST /admin/logout` for the browser sign-in flow (F004 T037 —
  `contracts/browser_oidc_flow.md` §"Sign-out").

  ## Iron Law check (`elixir:phoenix-thinking`)

  Pure module-Plug. No GenServer. Iron Law:

    1. Mutable state across calls? No — every call is a function of
       `(conn, opts)` plus a Postgres write through the JTI deny-list.
    2. Concurrent execution? No — runs on the Bandit-spawned per-request
       process.
    3. Fault isolation? No — failures fall through to a 200 (idempotent)
       so a misbehaving deny-list write doesn't trap a user with a
       still-valid cookie.

  All three NO → plain `Plug` callbacks.

  ## Idempotent semantics

  The contract specifies "if no cookie present, treat as already-logged-
  out and return 200." This is critical because the SPA may issue a
  logout after a tab-switch where the cookie expired naturally — we do
  NOT want to surface a 401 there.

  ## Flow

    1. Read the `r5e_session` cookie. Absent → 200, `redirect_to: "/admin/login?logged_out=1"`.
    2. Decrypt cookie via `BrowserSessionPlug.decrypt_cookie/2`.
       Tampered → still 200 (idempotent), but emit a `:ui_session`
       `event: "logout"` with no principal.
    3. Extract JWT, decode the `jti` claim (no signature verify; we
       trust the encrypted envelope). Add JTI to the broker's deny-list
       via `:jti_deny_list_writer` opt (default Mox-friendly seam; the
       real impl lands in Wave 3+ once the broker exposes a deny-list
       module).
    4. Emit `:ui_session` `event: "logout"` with `principal_subject`,
       `browser_session_id`, `tenant_id`.
    5. Clear the cookie at the Gateway origin (matches set attributes
       so the browser actually drops it).
    6. Return 200 + `{redirect_to: "/admin/login?logged_out=1"}`.

  ## CSRF defense

  `SameSite=Lax` blocks cross-origin POSTs structurally. An additional
  `X-Recurse-CSRF` token (echoed from `/v1/auth/me`) defends against
  same-origin XSS-injected POSTs. The CSRF check itself is handled by
  the router pipeline (out of scope for this handler) — by the time
  this handler runs, the CSRF token has already been validated.

  ## Cross-references

    * `specs/004-audit-console/contracts/browser_oidc_flow.md` §"Sign-out"
    * `apps/recurse_gateway/lib/recurse_gateway/admin/browser_session_plug.ex`
    * `apps/recurse_gateway/lib/recurse_gateway/admin/browser_auth/ui_receipts.ex`
  """

  @behaviour Plug

  alias Plug.Conn
  alias Recurse.Gateway.Admin.BrowserAuth.UiReceipts
  alias Recurse.Gateway.Admin.BrowserSessionPlug

  require Logger

  @impl Plug
  def init(opts), do: opts

  @impl Plug
  def call(%Conn{method: "POST"} = conn, opts) do
    fetched = Conn.fetch_cookies(conn)
    cookie_name = BrowserSessionPlug.cookie_name()

    case Map.get(fetched.req_cookies, cookie_name) do
      nil ->
        # Idempotent: no cookie → already logged out.
        respond_logged_out(fetched)

      cookie ->
        do_logout(fetched, cookie, opts)
    end
  end

  def call(%Conn{} = conn, _opts) do
    Conn.send_resp(conn, 405, "")
  end

  # ---------------------------------------------------------------------------
  # Logout flow
  # ---------------------------------------------------------------------------

  defp do_logout(conn, cookie, opts) do
    case BrowserSessionPlug.decrypt_cookie(cookie) do
      {:ok, payload} ->
        # Best-effort JTI deny-list write. Failure is logged but does
        # not block the logout response — the cookie is dropped client-
        # side regardless, and the JWT's `exp` is short-TTL by design.
        _ = add_jti_to_deny_list(payload, opts)

        UiReceipts.emit(:ui_session, %{
          event: "logout",
          principal_subject: principal_subject_from(payload),
          browser_session_id: Map.get(payload, :browser_session_id),
          tenant_id: Map.get(payload, :tenant_id)
        })

        respond_logged_out(conn)

      {:error, :cookie_tampered} ->
        # Tampered cookies are STILL idempotent for logout — we can't
        # extract a principal but we still drop the cookie + return 200.
        # Audit emits a `cookie_tampered` event so the operator sees it.
        UiReceipts.emit(:ui_session, %{event: "cookie_tampered"})
        respond_logged_out(conn)
    end
  end

  defp principal_subject_from(payload) do
    case payload do
      %{principal_subject: subj} when is_binary(subj) -> subj
      _ -> peek_jwt_subject(Map.get(payload, :jwt))
    end
  end

  defp peek_jwt_subject(jwt) when is_binary(jwt) do
    with [_h, payload_b64, _s] <- String.split(jwt, "."),
         {:ok, bytes} <- Base.url_decode64(payload_b64, padding: false),
         {:ok, %{"sub" => sub}} when is_binary(sub) <- JSON.decode(bytes) do
      sub
    else
      _ -> nil
    end
  end

  defp peek_jwt_subject(_), do: nil

  defp peek_jwt_jti_and_exp(jwt) when is_binary(jwt) do
    with [_h, payload_b64, _s] <- String.split(jwt, "."),
         {:ok, bytes} <- Base.url_decode64(payload_b64, padding: false),
         {:ok, %{"jti" => jti, "exp" => exp}} when is_binary(jti) and is_integer(exp) <-
           JSON.decode(bytes) do
      {:ok, jti, exp}
    else
      _ -> :error
    end
  end

  defp peek_jwt_jti_and_exp(_), do: :error

  defp add_jti_to_deny_list(payload, opts) do
    writer =
      Keyword.get(opts, :jti_deny_list_writer) ||
        Application.get_env(:recurse_gateway, :jti_deny_list_writer, &__MODULE__.default_jti_writer/2)

    case peek_jwt_jti_and_exp(Map.get(payload, :jwt)) do
      {:ok, jti, exp} ->
        ttl_seconds = max(exp - System.system_time(:second), 1)
        try_writer(writer, jti, ttl_seconds)

      :error ->
        :ok
    end
  end

  defp try_writer(writer, jti, ttl_seconds) when is_function(writer, 2) do
    writer.(jti, ttl_seconds)
  rescue
    error ->
      Logger.warning(fn ->
        "JTI deny-list writer raised: #{inspect(error)} jti=#{jti}"
      end)

      :error
  end

  @doc """
  Default JTI deny-list writer. The Wave 2A scope does not yet wire the
  broker's deny-list module — Wave 3+ replaces this default with a call
  into the F002 broker's `JwtJtiCache.insert/2`. Until then we log at
  `:info` so audits can correlate logout-time JTI invalidation with the
  receipt emission.
  """
  @spec default_jti_writer(String.t(), pos_integer()) :: :ok
  def default_jti_writer(jti, ttl_seconds) do
    Logger.info(fn ->
      "logout JTI deny-list (no-op pending Wave 3+ broker wiring): jti=#{jti} ttl=#{ttl_seconds}s"
    end)

    :ok
  end

  # ---------------------------------------------------------------------------
  # Response
  # ---------------------------------------------------------------------------

  defp respond_logged_out(conn) do
    body = JSON.encode!(%{"redirect_to" => "/admin/login?logged_out=1"})

    conn
    |> Conn.put_resp_cookie(BrowserSessionPlug.cookie_name(), "",
      BrowserSessionPlug.cookie_opts(max_age: 0)
    )
    |> Conn.put_resp_content_type("application/json")
    |> Conn.send_resp(200, body)
  end
end
