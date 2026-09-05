defmodule Recurse.Gateway.Auth.RouteMacros do
  @moduledoc """
  Compact macros wrapping `Plug.Router`'s `get`/`post`/`put`/`delete`/`patch`
  with the auth dispatch from `Recurse.Gateway.Auth.CookieOrBearerPlug`
  (dual-auth) or `Recurse.Gateway.Admin.BrowserSessionPipe` (cookie-only).

  ## Why macros (issue #29 / GAN-review iteration)

  The architectural model AD originally chose `dispatch/2` function calls
  over macros at expected route counts (3 dual-auth + 15 cookie-only =
  18 sites). After the m4 migration subagent surfaced 9 more cookie-only
  routes than the model anticipated, the call-site count hit 27 with
  ~5 lines per call — ~108 lines of mechanical redundancy. Macros
  collapse each site to a single `<scheme>_<method> <path>, <handler>`
  line and retain compile-time enforcement that every dual-auth or
  cookie-only route uses the correct dispatch (you can't accidentally
  forget the wrap — the macro IS the wrap).

  ## Usage

      use Plug.Router
      import Recurse.Gateway.Auth.RouteMacros

      dual_auth_get "/v1/audit/receipts",
        &Recurse.Gateway.AuditPlane.ReceiptsHandler.handle/1

      dual_auth_post "/v1/audit/export",
        &Recurse.Gateway.AuditPlane.ExportHandler.handle/1

      cookie_only_get "/v1/auth/me",
        &Recurse.Gateway.Admin.AuthMeHandler.handle/1

      cookie_only_post "/v1/policy/drafts",
        &Recurse.Gateway.Admin.PolicyDraftsHandler.create/1

  The handler value can be any 1-arity function expression — an
  `&Mod.fn/1` capture, a `&Mod.fn(&1, [])` partial, or a
  `fn conn -> ... end` lambda. The macro evaluates it at request time,
  so closures that pre-pipe the conn (e.g., `apply_security_headers`)
  work naturally.

  ## Iron Law (`elixir:elixir-thinking`)

  Pure compile-time expansion. No process. No runtime state. Each
  invocation expands to the same `Plug.Router` route definition the
  hand-written `dispatch/2` call site produced — semantically
  identical, just terser. The dispatch modules
  (`CookieOrBearerPlug`, `BrowserSessionPipe`) own the runtime auth
  control flow; this module only inlines the call.
  """

  @doc "Dual-auth (cookie-or-bearer) `GET` route."
  defmacro dual_auth_get(path, handler_fn) do
    quote do
      get unquote(path) do
        Recurse.Gateway.Auth.CookieOrBearerPlug.dispatch(var!(conn), unquote(handler_fn))
      end
    end
  end

  @doc "Dual-auth (cookie-or-bearer) `POST` route."
  defmacro dual_auth_post(path, handler_fn) do
    quote do
      post unquote(path) do
        Recurse.Gateway.Auth.CookieOrBearerPlug.dispatch(var!(conn), unquote(handler_fn))
      end
    end
  end

  @doc "Dual-auth (cookie-or-bearer) `PUT` route."
  defmacro dual_auth_put(path, handler_fn) do
    quote do
      put unquote(path) do
        Recurse.Gateway.Auth.CookieOrBearerPlug.dispatch(var!(conn), unquote(handler_fn))
      end
    end
  end

  @doc "Dual-auth (cookie-or-bearer) `DELETE` route."
  defmacro dual_auth_delete(path, handler_fn) do
    quote do
      delete unquote(path) do
        Recurse.Gateway.Auth.CookieOrBearerPlug.dispatch(var!(conn), unquote(handler_fn))
      end
    end
  end

  @doc "Dual-auth (cookie-or-bearer) `PATCH` route."
  defmacro dual_auth_patch(path, handler_fn) do
    quote do
      patch unquote(path) do
        Recurse.Gateway.Auth.CookieOrBearerPlug.dispatch(var!(conn), unquote(handler_fn))
      end
    end
  end

  @doc "Cookie-only (BrowserSessionPlug) `GET` route."
  defmacro cookie_only_get(path, handler_fn) do
    quote do
      get unquote(path) do
        Recurse.Gateway.Admin.BrowserSessionPipe.dispatch(var!(conn), unquote(handler_fn))
      end
    end
  end

  @doc "Cookie-only (BrowserSessionPlug) `POST` route."
  defmacro cookie_only_post(path, handler_fn) do
    quote do
      post unquote(path) do
        Recurse.Gateway.Admin.BrowserSessionPipe.dispatch(var!(conn), unquote(handler_fn))
      end
    end
  end

  @doc "Cookie-only (BrowserSessionPlug) `PUT` route."
  defmacro cookie_only_put(path, handler_fn) do
    quote do
      put unquote(path) do
        Recurse.Gateway.Admin.BrowserSessionPipe.dispatch(var!(conn), unquote(handler_fn))
      end
    end
  end

  @doc "Cookie-only (BrowserSessionPlug) `DELETE` route."
  defmacro cookie_only_delete(path, handler_fn) do
    quote do
      delete unquote(path) do
        Recurse.Gateway.Admin.BrowserSessionPipe.dispatch(var!(conn), unquote(handler_fn))
      end
    end
  end

  @doc "Cookie-only (BrowserSessionPlug) `PATCH` route."
  defmacro cookie_only_patch(path, handler_fn) do
    quote do
      patch unquote(path) do
        Recurse.Gateway.Admin.BrowserSessionPipe.dispatch(var!(conn), unquote(handler_fn))
      end
    end
  end
end
