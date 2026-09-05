defmodule Recurse.Gateway.Router.AdminRootRedirectTest do
  @moduledoc """
  Spec 012 S6c — `/admin` and `/admin/` redirect to `/admin/dashboard`.

  Before this route existed the bare prefix fell through to the SPA
  static fallback, which served `index.html`; react-router has no route
  at the basename root and rendered a blank "No routes matched" page.
  The route sits before the `forward "/admin"` in the router, so the
  redirect happens without loading the SPA.
  """

  use ExUnit.Case, async: true

  alias Recurse.Gateway.Router

  @opts Router.init([])

  for path <- ["/admin", "/admin/"] do
    test "GET #{path} redirects to /admin/dashboard" do
      conn =
        :get
        |> Plug.Test.conn(unquote(path))
        |> Router.call(@opts)

      assert conn.status == 302
      assert Plug.Conn.get_resp_header(conn, "location") == ["/admin/dashboard"]
    end
  end
end
