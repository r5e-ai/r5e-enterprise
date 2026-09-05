defmodule Recurse.Gateway.Admin.BrowserSessionPipeTest do
  @moduledoc """
  Issue #29 / B7.

  Two layers of contract:

    1. **Function-shape** — `dispatch/2` is exported with arity 2 and
       raises `FunctionClauseError` on a non-function handler arg.

    2. **Behavioral** — when the upstream `BrowserSessionPlug` halts the
       conn (no cookie → canonical flat 401 envelope on `/v1/...`
       paths), the dispatch returns the halted conn AND the handler is
       NOT invoked. Distinguishes from `CookieOrBearerPlug` semantics:
       a bare `Authorization: Bearer …` header alone is rejected — this
       module is for the cookie-only consumer set.

  ## `async: true` + `setup_all` configures `:browser_session`

  `BrowserSessionPlug.call/2` calls `load_config/1` unconditionally,
  which raises if `:secret_key_base` is unset. We populate
  `Application.env(:recurse_gateway, :browser_session, …)` once via
  `setup_all` (with restore on exit) and stay `async: true`. Our
  behavioral assertions only hit the **absent-cookie** branch — the
  decrypt path is never invoked, so concurrent tests racing on the
  same key are not a correctness hazard for this module's tests
  (mirrors the rationale used in
  `apps/recurse_gateway/test/integration/f004_phase2_attestation_wiring_test.exs`).
  """

  use ExUnit.Case, async: true
  import Plug.Test

  alias Recurse.Gateway.Admin.BrowserSessionPipe

  setup_all do
    prior = Application.get_env(:recurse_gateway, :browser_session)

    Application.put_env(:recurse_gateway, :browser_session,
      cookie_name: "r5e_session",
      secret_key_base: :crypto.strong_rand_bytes(32),
      secure_cookie?: false,
      absent_cookie_redirect: :auto
    )

    on_exit(fn ->
      if prior do
        Application.put_env(:recurse_gateway, :browser_session, prior)
      else
        Application.delete_env(:recurse_gateway, :browser_session)
      end
    end)

    :ok
  end

  defp dummy_handler(conn) do
    Plug.Conn.send_resp(conn, 200, "OK from handler")
  end

  describe "dispatch/2 — function shape" do
    test "is exported with arity 2" do
      Code.ensure_loaded(BrowserSessionPipe)
      assert function_exported?(BrowserSessionPipe, :dispatch, 2)
    end

    test "raises on non-function handler arg" do
      conn = conn(:get, "/v1/policy/drafts")

      assert_raise FunctionClauseError, fn ->
        BrowserSessionPipe.dispatch(conn, :not_a_function)
      end
    end
  end

  describe "dispatch/2 — behavioral contract (absent-cookie 401)" do
    test "no cookie + no auth header → halts 401 with canonical flat envelope" do
      conn = conn(:get, "/v1/policy/drafts")
      response = BrowserSessionPipe.dispatch(conn, &dummy_handler/1)

      assert response.halted
      assert response.status == 401
      assert {:ok, %{"error" => "ERR_SESSION_MISSING"}} = JSON.decode(response.resp_body)
    end

    test "halted by BrowserSessionPlug → handler is NOT called" do
      ref = make_ref()
      parent = self()

      handler = fn conn ->
        send(parent, {ref, :handler_ran})
        Plug.Conn.send_resp(conn, 200, "OK")
      end

      conn(:get, "/v1/policy/drafts")
      |> BrowserSessionPipe.dispatch(handler)

      refute_received {^ref, :handler_ran}
    end

    test "bearer header alone is rejected (cookie-only contract)" do
      conn =
        :get
        |> conn("/v1/policy/drafts")
        |> Plug.Conn.put_req_header("authorization", "Bearer test-jwt")

      response = BrowserSessionPipe.dispatch(conn, &dummy_handler/1)

      # BrowserSessionPipe is for cookie-ONLY routes. Even with a bearer
      # header present, no cookie → halt 401. Bearer-callers must route
      # through CookieOrBearerPlug for routes that accept both.
      assert response.halted
      assert response.status == 401
    end
  end
end
