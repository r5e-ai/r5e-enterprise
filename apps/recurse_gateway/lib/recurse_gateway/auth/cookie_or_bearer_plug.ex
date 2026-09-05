defmodule Recurse.Gateway.Auth.CookieOrBearerPlug do
  @moduledoc """
  Auth dispatch for routes that accept BOTH the F002 bearer-shape
  (`Authorization: Bearer <jwt>`, used by SIEM forwarders, the
  `recurse-verify` OSS CLI, and future RFC-8693 token-exchange
  agents) AND the F004 cookie-shape (used by the Audit Console
  SPA).

  ## Why this module exists (Issue #29 / Constitution Principle VII)

  Before this landed, `router.ex:818-831` had a private
  `cookie_or_bearer_then/2` helper that wrapped each F002-reuse
  route. Easy to forget when adding or retrofitting routes —
  exactly the bug shape that produced MR !19 (receipts list
  missed) and MR !25 (payload + export missed). A real module + a
  property test enumerating `Router.__routes__/0` (P-1) catches
  the next "forgot to wrap" miss in CI.

  ## Behavior

    * `Authorization` header present → invoke `handler_fn.(conn)`
      directly. The downstream handler's `Authz.gate` runs the JWT
      validator (F002 bearer path; SIEM/CLI callers).

    * Header absent → run `BrowserSessionPlug.call/2`. It either
      lifts the cookie envelope into an `Authorization: Bearer
      <jwt>` header (and `handler_fn.(conn)` runs), or halts the
      conn with a 401.

    * Both absent → `BrowserSessionPlug` halts with 401 (now via
      the canonical `ErrorEnvelope` flat shape per issue #29's
      LB-1 fix; previously a divergent `{"error_code": "..."}`
      envelope the SPA's `ApiError` parser couldn't read).

  Both paths converge on the same conn shape so handlers stay
  auth-mode-agnostic.

  ## Why not a Plug behaviour

  A Plug behaviour's `call/2` returns a conn for the next plug in
  the pipeline. Here the "next step" is a per-route handler that
  needs to be late-bound by the route definition, not declared at
  Plug.init time. A plain `dispatch/2` function captures that
  shape directly. If a future caller needs the plug-pipeline form,
  add a `behaviour Plug` interface that takes `[handler: fn]`
  opts; today there are no such callers.

  ## Iron Law

  Pure module. No process. Pattern-matches on `conn` headers and
  routes to one of two paths.
  """

  alias Plug.Conn
  alias Recurse.Gateway.Admin.BrowserSessionPlug

  @typedoc """
  A handler function: takes a `Plug.Conn` (with `Authorization`
  header populated, regardless of which path got us there) and
  returns the responded `Plug.Conn`.
  """
  @type handler_fn :: (Conn.t() -> Conn.t())

  @doc """
  Dispatch a request to `handler_fn` after ensuring it has an
  `Authorization` header (either bearer-passed-through or
  cookie-lifted-to-bearer). Returns the responded conn.

  Halted-on-401 conns from `BrowserSessionPlug` are passed back
  unchanged — the caller's response pipeline sees the halt.
  """
  @spec dispatch(Conn.t(), handler_fn()) :: Conn.t()
  def dispatch(%Conn{} = conn, handler_fn) when is_function(handler_fn, 1) do
    if has_authorization_header?(conn) do
      handler_fn.(conn)
    else
      conn
      |> BrowserSessionPlug.call(BrowserSessionPlug.init([]))
      |> case do
        %Conn{halted: true} = halted -> halted
        conn_with_session -> handler_fn.(conn_with_session)
      end
    end
  end

  defp has_authorization_header?(%Conn{} = conn) do
    case Conn.get_req_header(conn, "authorization") do
      [_ | _] -> true
      [] -> false
    end
  end
end
