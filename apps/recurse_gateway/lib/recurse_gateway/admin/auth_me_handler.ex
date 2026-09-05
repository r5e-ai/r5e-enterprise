defmodule Recurse.Gateway.Admin.AuthMeHandler do
  @moduledoc """
  `GET /v1/auth/me` (F004 T054).

  Lightweight endpoint that returns the authenticated request's
  principal info derived from the BrowserSessionPlug-lifted session.
  Does NOT expose the JWT itself or any cookie content. Used by the
  SPA's `useAuth` hook to render user-info UI (avatar letter, role
  pill, sign-out button) without re-decoding the cookie client-side.

  ## Response shape (per `contracts/audit_api_extensions.md`
  \u00a7"Auth introspection")

      {
        "principal_subject": "alice@corp",
        "recurse_role": "tenant_auditor",
        "tenant_id": "01HQZN5K7J8M9N0P1Q2R3S4T5V",
        "browser_session_id": "01J9X4...",
        "session_expires_at": "2026-04-25T00:32:18Z",
        "session_idle_timeout_at": "2026-04-24T17:32:18Z"
      }

  ## NO Cedar gate. NO receipt.

  Reading your own identity is not a governance-class action — see
  `contracts/cedar_entity_schema_extensions.md` "Implicit-self
  actions" for the rationale. The browser session itself is already
  attested at `:ui_login` time when the cookie was minted, and the
  SPA fires this endpoint on every boot; emitting a receipt per call
  would drown the audit log in self-referential noise without
  governance value.

  This is the ONLY F004 endpoint that does not emit a receipt per
  call. Every other endpoint in `audit_api_extensions.md` is gated
  by a named Cedar action and emits at least one attested
  `event_kind`.

  ## Iron Law check (`elixir:phoenix-thinking`)

    1. Mutable state across calls? No — pure function of conn assigns.
    2. Concurrent execution? No — runs on the request process.
    3. Fault isolation? No — missing assigns return 401, not crash.

  All three NO → plain function. No GenServer.

  ## Auth contract

  `BrowserSessionPlug` (T034, owned by Wave 2A) MUST run upstream of
  this handler and assign a `:browser_session` map to the conn. The
  expected map shape:

      %{
        principal_subject: binary(),
        recurse_role: "tenant_auditor" | "platform_operator",
        tenant_id: binary(),
        browser_session_id: binary(),
        session_expires_at: DateTime.t(),
        session_idle_timeout_at: DateTime.t()
      }

  If the assign is absent the handler responds 401 with the F001
  error envelope. The SPA's `useAuth` hook treats 401 as a signal to
  redirect to `/admin/login/start` per
  `contracts/frontend_architecture.md` \u00a7"Auth state model".

  ## Cross-references

    * `specs/004-audit-console/contracts/audit_api_extensions.md`
      \u00a7"Auth introspection"
    * `specs/004-audit-console/contracts/cedar_entity_schema_extensions.md`
      \u00a7"Implicit-self actions"
    * `specs/004-audit-console/contracts/frontend_architecture.md`
      \u00a7"Auth state model"
    * `apps/recurse_gateway/priv/schemas/auth_me.json` (response
      schema; flat snake_case shape)
  """

  alias Recurse.Gateway.AuditPlane.ErrorEnvelope

  @doc """
  Plug-shaped entry point. Reads `conn.assigns[:browser_session]`
  (lifted by BrowserSessionPlug upstream), encodes the F004
  auth_me schema response, and returns 200. Returns 401 with the
  F001 error envelope when the assign is missing.

  Broker-path tolerance (finding #8): when `:browser_session` is
  present but `:principal_subject` / `:recurse_role` are absent —
  i.e. the broker-mediated path where the principal lives in the
  lifted JWT's `principal` custom claim, NOT in the cookie payload —
  we decode the bearer JWT (already lifted into the
  `Authorization` header by BrowserSessionPlug) and fall back to
  reading the principal from there.
  """
  @spec handle(Plug.Conn.t()) :: Plug.Conn.t()
  def handle(%Plug.Conn{} = conn) do
    case fetch_session_from_assigns(conn) do
      {:ok, session} ->
        body = JSON.encode!(render(conn, session))

        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.send_resp(200, body)

      :error ->
        send_unauthorized(conn)
    end
  end

  # ---------------------------------------------------------------------------
  # Private — assigns extraction
  # ---------------------------------------------------------------------------

  defp fetch_session_from_assigns(%Plug.Conn{assigns: assigns}) do
    case Map.fetch(assigns, :browser_session) do
      {:ok, %{} = session} -> {:ok, session}
      _ -> :error
    end
  end

  # Build the flat snake_case response per the contract. The
  # underlying conn.assigns map carries atom-keyed fields (lifted by
  # BrowserSessionPlug); we map them to the wire schema's string
  # keys here so the wire format is the SOLE source of truth.
  #
  # `principal_subject` + `recurse_role` may be supplied directly by
  # BrowserSessionPlug (WorkOS dogfood path — extracted from the
  # cookie payload at login). On the broker-mediated path the values
  # live in the lifted JWT's `principal` custom claim — finding #8
  # fix: peek into the bearer JWT from the Authorization header
  # (already lifted by BrowserSessionPlug upstream).
  defp render(conn, session) do
    fallback = read_principal_from_bearer(conn)

    %{
      "principal_subject" =>
        Map.get(session, :principal_subject) || Map.get(fallback, :principal_subject) || "",
      "recurse_role" =>
        Map.get(session, :recurse_role) || Map.get(fallback, :recurse_role) || "",
      "tenant_id" => Map.fetch!(session, :tenant_id),
      "browser_session_id" => Map.fetch!(session, :browser_session_id),
      "session_expires_at" => to_iso8601(Map.fetch!(session, :session_expires_at)),
      "session_idle_timeout_at" => to_iso8601(Map.fetch!(session, :session_idle_timeout_at))
    }
  end

  # Best-effort: peek the bearer JWT's `principal` claim WITHOUT
  # signature verification. The cookie envelope is already verified
  # upstream by `BrowserSessionPlug` (HMAC-encrypted Plug.Crypto), and
  # the F002 `JwtValidator` runs on the same JWT for every other
  # request that hits `/v1/*` — so the peek-only read here is safe
  # for rendering display fields (we don't grant any privilege based
  # on the unverified read; Cedar gates use the validated context).
  defp read_principal_from_bearer(%Plug.Conn{} = conn) do
    case Plug.Conn.get_req_header(conn, "authorization") do
      ["Bearer " <> jwt | _] -> peek_principal(jwt)
      ["bearer " <> jwt | _] -> peek_principal(jwt)
      _ -> %{}
    end
  end

  defp peek_principal(jwt) when is_binary(jwt) do
    with [_h, payload_b64, _s] <- String.split(jwt, "."),
         {:ok, bytes} <- Base.url_decode64(payload_b64, padding: false),
         {:ok, %{"principal" => principal}} when is_map(principal) <- JSON.decode(bytes) do
      %{
        principal_subject: Map.get(principal, "subject"),
        recurse_role: Map.get(principal, "recurse_role")
      }
    else
      _ -> %{}
    end
  end

  defp peek_principal(_), do: %{}

  defp to_iso8601(%DateTime{} = dt), do: DateTime.to_iso8601(dt)
  # BrowserSessionPlug may pass an already-formatted ISO 8601 string
  # (e.g., when the session payload was deserialized from the
  # encrypted cookie). Pass-through; trust the upstream plug to
  # deliver a valid RFC 3339 instant per `audit_me.json` schema.
  defp to_iso8601(value) when is_binary(value), do: value

  # ---------------------------------------------------------------------------
  # F001 error envelope — uniform 4xx shape across the audit API.
  # ---------------------------------------------------------------------------

  defp send_unauthorized(conn) do
    ErrorEnvelope.send_unauthorized(
      conn,
      "ERR_SESSION_MISSING",
      "No active browser session. Sign in via /admin/login/start.",
      correlation_id: correlation_id_or_new(conn)
    )
  end

  # Prefer the request-supplied `x-correlation-id` (when the SPA threads one
  # through) over the canonical envelope fallback. The canonical envelope's
  # default reads the response-side `x-recurse-correlation-id` header which
  # is only stamped by `IdentityContextBuilder` AFTER successful auth — at
  # this 401 site the auth context never resolved, so we fall back to the
  # request-side header (or a stable sentinel).
  defp correlation_id_or_new(conn) do
    case Plug.Conn.get_req_header(conn, "x-correlation-id") do
      [id | _] when is_binary(id) and id != "" -> id
      _ -> "no-correlation-id"
    end
  end
end
