defmodule Recurse.Gateway.Admin.BrowserAuth.DevLoginHandlerTest do
  @moduledoc """
  Gating test for `POST /admin/test/login` (spec 012 S1): the handler
  reads `:dev_login_enabled?` from the Application env at request time —
  which is what lets `config/runtime.exs` drive it from
  `R5E_DEV_LOGIN_ENABLED` in a prod release — and answers 404 (identical
  to an unknown route) when it is off.
  """

  use ExUnit.Case, async: false

  import Plug.Conn, only: [get_resp_header: 2]
  import Plug.Test

  alias Recurse.Gateway.Admin.BrowserAuth.DevLoginHandler

  setup do
    previous = Application.get_env(:recurse_gateway, :dev_login_enabled?)

    on_exit(fn ->
      case previous do
        nil -> Application.delete_env(:recurse_gateway, :dev_login_enabled?)
        v -> Application.put_env(:recurse_gateway, :dev_login_enabled?, v)
      end
    end)

    :ok
  end

  test "404s when :dev_login_enabled? is false (release default)" do
    Application.put_env(:recurse_gateway, :dev_login_enabled?, false)
    conn = DevLoginHandler.handle(login_conn())
    assert conn.status == 404
    assert conn.resp_body == ~s({"error":"not_found"})
  end

  test "mints a cookie when enabled at runtime and the broker key is configured" do
    Application.put_env(:recurse_gateway, :dev_login_enabled?, true)
    conn = DevLoginHandler.handle(login_conn())

    # Either the collapsed-broker PEM is configured (200 + cookie) or it is
    # not (503 with the actionable message). Both prove the switch opened;
    # a 404 would mean the gate did not.
    assert conn.status in [200, 503]

    if conn.status == 200 do
      assert %{"dev_login" => true, "principal_subject" => "local-dev@r5e"} =
               JSON.decode!(conn.resp_body)

      assert [cookie] = get_resp_header(conn, "set-cookie")
      assert cookie =~ "r5e_session="
    else
      assert JSON.decode!(conn.resp_body)["error"] =~ "BROKER_JWT_SIGNING_KEY_PATH"
    end
  end

  defp login_conn do
    conn(:post, "/admin/test/login", %{"principal_subject" => "local-dev@r5e"})
  end
end
