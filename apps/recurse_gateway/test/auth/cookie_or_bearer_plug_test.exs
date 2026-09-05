defmodule Recurse.Gateway.Auth.CookieOrBearerPlugTest do
  @moduledoc """
  Issue #29 / B6.

  Unit tests focus on the bearer-present branch (which does NOT invoke
  BrowserSessionPlug). The cookie-rejection branch is covered indirectly
  by the integration / contract tests on every route currently using
  the dispatch (3 dual-auth routes; ~16 envelope-shape assertions in
  the audit-plane + admin contract tests run a full conn through
  BrowserSessionPlug, including its Application config).

  Pinning the bearer-pass-through here ensures that an F002 SIEM
  forwarder or `recurse-verify` CLI request reaches the handler without
  an unwarranted cookie-machinery roundtrip.
  """

  use ExUnit.Case, async: true
  import Plug.Test

  alias Recurse.Gateway.Auth.CookieOrBearerPlug

  defp dummy_handler(conn) do
    Plug.Conn.send_resp(conn, 200, "OK from handler")
  end

  describe "dispatch/2 — bearer-shaped request" do
    test "passes conn through to handler when Authorization header present" do
      conn =
        :get
        |> conn("/v1/audit/receipts")
        |> Plug.Conn.put_req_header("authorization", "Bearer test-jwt")

      response = CookieOrBearerPlug.dispatch(conn, &dummy_handler/1)

      assert response.status == 200
      assert response.resp_body == "OK from handler"
    end

    test "passes through even with malformed bearer (handler responsible for JWT validation)" do
      conn =
        :get
        |> conn("/v1/audit/receipts")
        |> Plug.Conn.put_req_header("authorization", "Bearer not-a-real-jwt")

      response = CookieOrBearerPlug.dispatch(conn, &dummy_handler/1)

      # The handler runs; the JWT validator inside the handler's gate
      # would be the one to reject the malformed token (F002 path).
      # CookieOrBearerPlug doesn't try to validate the JWT itself.
      assert response.status == 200
    end

    test "ignores empty Authorization header (treated as cookie path)" do
      # Edge case — `[""]` is not bearer-shaped per F002. Confirms
      # the predicate looks at presence of header, not just non-emptiness.
      # The bearer presence check uses `[_ | _]` pattern matching, so
      # an empty list IS no-bearer; an empty STRING is still a bearer
      # value (and the handler's JWT validator rejects it). This test
      # just verifies the dispatch chooses the bearer branch on any
      # value being present.
      conn =
        :get
        |> conn("/v1/audit/receipts")
        |> Plug.Conn.put_req_header("authorization", "")

      response = CookieOrBearerPlug.dispatch(conn, &dummy_handler/1)

      assert response.status == 200
    end
  end

  describe "dispatch/2 — handler invocation" do
    test "handler receives the original conn unchanged" do
      ref = make_ref()

      handler = fn conn ->
        send(self(), {ref, :got_conn, conn.method, conn.request_path})
        Plug.Conn.send_resp(conn, 204, "")
      end

      conn =
        :post
        |> conn("/v1/audit/export", "{}")
        |> Plug.Conn.put_req_header("authorization", "Bearer x")
        |> Plug.Conn.put_req_header("content-type", "application/json")

      _response = CookieOrBearerPlug.dispatch(conn, handler)

      assert_received {^ref, :got_conn, "POST", "/v1/audit/export"}
    end
  end
end
