defmodule Recurse.Gateway.Admin.BrowserSessionPipe do
  @moduledoc """
  Cookie-only auth dispatch for F004 admin-plane routes (every route
  the SPA hits that ISN'T also exposed to F002 bearer callers — i.e.,
  `/admin/*`, `/v1/auth/me`, `/v1/policy/*`, `/v1/chat/*`,
  `/v1/audit/receipts/:run_id`, `/v1/audit/sessions/:session_id`,
  `/v1/audit/receipts/:run_id/verify`).

  ## Why this module exists (Issue #29 / Constitution Principle VII)

  Before this landed, 15 routes in `router.ex` (lines 337-660)
  inlined the same six-line pattern:

      conn
      |> Recurse.Gateway.Admin.BrowserSessionPlug.call(
        Recurse.Gateway.Admin.BrowserSessionPlug.init([])
      )
      |> case do
        %Plug.Conn{halted: true} = halted -> halted
        conn_with_session -> Handler.handle(conn_with_session)
      end

  That's ~6 lines × 15 routes = ~90 lines of duplication. Per
  Constitution Principle VII, the second consumer was where this
  should have been extracted; we're 15 consumers late.

  This module retires the inline pattern. The s2 survey filed it
  as #29b for a follow-up MR; the architectural model folded it
  back in (AD-2 user vote: "yeah, that seems like exactly what we
  should") because separating dual-auth (3 routes) from cookie-only
  (15 routes) extraction would be the same Principle-VII
  violation at the same level of abstraction.

  ## Behavior

  Identical to the inline pattern: run `BrowserSessionPlug.call/2`
  to lift the cookie envelope into an `Authorization: Bearer
  <jwt>` header, then either return the halted conn (401) or
  invoke `handler_fn.(conn)`.

  Cookie-only routes do NOT accept bearer-only callers. F002 SIEM
  forwarders + `recurse-verify` CLI use the dual-auth routes
  (`/v1/audit/receipts`, `/v1/audit/payload`,
  `/v1/audit/export`) routed via
  `Recurse.Gateway.Auth.CookieOrBearerPlug`.

  ## Iron Law

  Pure module. No process. Identical control flow to the inline
  pattern, single source.
  """

  alias Plug.Conn
  alias Recurse.Gateway.Admin.BrowserSessionPlug

  @typedoc """
  Handler function — takes a `Plug.Conn` with the cookie-derived
  `Authorization: Bearer <jwt>` header populated, returns the
  responded conn.
  """
  @type handler_fn :: (Conn.t() -> Conn.t())

  @doc """
  Run `BrowserSessionPlug` to lift the cookie envelope, then
  dispatch to `handler_fn` if not halted.
  """
  @spec dispatch(Conn.t(), handler_fn()) :: Conn.t()
  def dispatch(%Conn{} = conn, handler_fn) when is_function(handler_fn, 1) do
    conn
    |> BrowserSessionPlug.call(BrowserSessionPlug.init([]))
    |> case do
      %Conn{halted: true} = halted -> halted
      conn_with_session -> handler_fn.(conn_with_session)
    end
  end
end
