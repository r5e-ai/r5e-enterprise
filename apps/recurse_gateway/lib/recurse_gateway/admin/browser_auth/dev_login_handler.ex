defmodule Recurse.Gateway.Admin.BrowserAuth.DevLoginHandler do
  @moduledoc """
  DEV-ONLY `POST /admin/test/login` — mints a browser-session cookie
  server-side, skipping the IdP round-trip entirely.

  This is the endpoint the F004 Playwright suite has assumed since T005
  (`ui/src/tests/e2e/*.spec.ts` `loginAs/2` helper: "hit /admin/test/login
  that the Gateway exposes when MIX_ENV=test") but which never landed in
  lib. It exists for two callers only:

    * Playwright e2e (`loginAs/2`) — CI + local `pnpm test:e2e`.
    * Local demo/dev flows (see `scripts/fable_demo/README.md`) —
      replaces the manual iex `mint_cookie` dance.

  ## Gating

  `Application.get_env(:recurse_gateway, :dev_login_enabled?, false)` is
  read at request time. It is `false` in `config/config.exs`, `true` in
  `config/dev.exs`, and — since spec 012 (Compose quickstart) —
  `config/runtime.exs` applies the `R5E_DEV_LOGIN_ENABLED` env var when it
  is set, so a prod release can opt in for a local, IdP-less stack. An
  unset env var in a prod release leaves it off. Because the handler reads
  the Application env per request (not a module attribute), the runtime
  value is the only switch; there is no compile-time bypass.

  Security posture: this endpoint mints a `platform_operator` cookie for
  any caller who can reach it. It exists for `http://localhost` only; the
  quickstart's `.env.example` and security notes say so.

  ## Request shape

      POST /admin/test/login
      {"principal_subject": "alice@corp.dev", "recurse_role": "tenant_auditor",
       "tenant_id": "01TEN..."}   // role + tenant optional

  Defaults: role `platform_operator`, tenant from `R5E_TENANT_ID` or
  `"01TEN_FABLE_DEMO_LOCAL"`. Response: 200 + Set-Cookie (r5e_session)
  + JSON echo of the identity minted. Uses the SAME primitives as the
  production login path — `JwtMinter` with the collapsed-broker ES256
  PEM (`:internal_jwt` config) and `BrowserSessionPlug.encrypt_payload/1`
  — so everything downstream (JwtValidator, Cedar gate, UiReceipts)
  treats the session identically to a real login.
  """

  alias Plug.Conn
  alias Recurse.Gateway.Admin.BrowserSessionPlug
  alias Recurse.Shared.Identity.JwtMinter

  @default_role "platform_operator"
  @allowed_roles ~w(platform_operator tenant_auditor caller)

  @spec handle(Plug.Conn.t()) :: Plug.Conn.t()
  def handle(%Conn{} = conn) do
    if Application.get_env(:recurse_gateway, :dev_login_enabled?, false) do
      do_handle(conn)
    else
      # Identical body to the router's catch-all so the endpoint is
      # indistinguishable from a nonexistent route when disabled.
      conn
      |> Conn.put_resp_content_type("application/json")
      |> Conn.send_resp(404, ~s({"error":"not_found"}))
    end
  end

  defp do_handle(conn) do
    params = if is_map(conn.body_params), do: conn.body_params, else: %{}

    subject = Map.get(params, "principal_subject", "dev-operator@local.dev")
    role = Map.get(params, "recurse_role", @default_role)

    tenant_id =
      Map.get(params, "tenant_id") ||
        System.get_env("R5E_TENANT_ID") ||
        "01TEN_FABLE_DEMO_LOCAL"

    with :ok <- validate_role(role),
         {:ok, jwt} <- mint_jwt(subject, role, tenant_id) do
      now = System.system_time(:second)

      payload = %{
        jwt: jwt,
        issued_at: now,
        last_activity_at: now,
        browser_session_id: Base.encode16(:crypto.strong_rand_bytes(16), case: :lower),
        principal_subject: subject,
        recurse_role: role,
        tenant_id: tenant_id
      }

      cookie = BrowserSessionPlug.encrypt_payload(payload)

      conn
      |> Conn.put_resp_cookie(
        BrowserSessionPlug.cookie_name(),
        cookie,
        BrowserSessionPlug.cookie_opts()
      )
      |> Conn.put_resp_content_type("application/json")
      |> Conn.send_resp(
        200,
        JSON.encode!(%{
          "dev_login" => true,
          "principal_subject" => subject,
          "recurse_role" => role,
          "tenant_id" => tenant_id
        })
      )
    else
      {:error, code, message} ->
        conn
        |> Conn.put_resp_content_type("application/json")
        |> Conn.send_resp(code, JSON.encode!(%{"error" => message}))
    end
  end

  defp validate_role(role) when role in @allowed_roles, do: :ok

  defp validate_role(role),
    do:
      {:error, 400,
       "recurse_role must be one of #{Enum.join(@allowed_roles, ", ")}; got #{inspect(role)}"}

  defp mint_jwt(subject, role, tenant_id) do
    cfg = Application.get_env(:recurse_gateway, :internal_jwt, [])
    path = Keyword.get(cfg, :signing_key_path)
    audience = Keyword.get(cfg, :audience)
    issuer = Keyword.get(cfg, :issuer)

    cond do
      is_nil(path) or not File.regular?(path) ->
        {:error, 503,
         "dev login unavailable: :internal_jwt.signing_key_path missing or unreadable " <>
           "(set BROKER_JWT_SIGNING_KEY_PATH; generate via scripts/gen-broker-key.sh)"}

      is_nil(audience) or is_nil(issuer) ->
        {:error, 503, "dev login unavailable: :internal_jwt audience/issuer unset"}

      true ->
        jwk = JOSE.JWK.from_pem_file(path)
        kid = path |> Path.basename() |> Path.rootname()

        principal = %{
          "kind" => "obo_human",
          "issuer" => "recurse://dev-login",
          "subject" => subject,
          "display_name" => subject,
          "groups" => [],
          "recurse_role" => role,
          "tenant_id" => tenant_id
        }

        case JwtMinter.mint(
               subject: subject,
               issuer: issuer,
               audience: audience,
               principal: principal,
               jwk: jwk,
               kid: kid,
               ttl_seconds: 28_800
             ) do
          {:ok, jwt} -> {:ok, jwt}
          {:error, reason} -> {:error, 500, "jwt mint failed: #{inspect(reason)}"}
        end
    end
  end
end
