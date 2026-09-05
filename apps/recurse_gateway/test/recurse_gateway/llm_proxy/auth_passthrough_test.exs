defmodule Recurse.Gateway.LlmProxy.AuthPassthroughTest do
  use ExUnit.Case, async: false

  alias Recurse.Gateway.LlmProxy.AuthPassthrough
  alias Recurse.Gateway.Test.MockHttpUpstream

  test "oversized authentication request is rejected before opening an upstream connection" do
    conn = Plug.Test.conn(:post, "/oauth/token", String.duplicate("x", 10_000_001))

    assert %{status: 413} =
             AuthPassthrough.proxy(conn,
               upstream_host: "127.0.0.1",
               upstream_port: 1,
               upstream_scheme: :http,
               tenant_id: "test"
             )
  end

  test "bounded authentication request preserves the body and upstream response" do
    {:ok, upstream} = MockHttpUpstream.start()
    on_exit(fn -> MockHttpUpstream.stop(upstream) end)
    body = "grant_type=refresh_token&refresh_token=test-placeholder"

    MockHttpUpstream.expect(upstream, fn conn ->
      assert {:ok, ^body, conn} = Plug.Conn.read_body(conn)
      Plug.Conn.send_resp(conn, 200, ~s({"access_token":"test-placeholder"}))
    end)

    assert %{status: 200, resp_body: response} =
             AuthPassthrough.proxy(Plug.Test.conn(:post, "/oauth/token", body),
               upstream_host: "127.0.0.1",
               upstream_port: upstream.port,
               upstream_scheme: :http,
               tenant_id: "test"
             )

    assert response == ~s({"access_token":"test-placeholder"})
  end
end
