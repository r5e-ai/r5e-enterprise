defmodule Recurse.Gateway.Admin.BrowserAuth.OidcLoginFlowContractTest do
  @moduledoc """
  Contract test for `GET /admin/login/start` + `GET /admin/login/callback`
  per `contracts/browser_oidc_flow.md` Steps 2 + 4 (F004 T033).

  Asserts the externally-observable contract:

    * `/admin/login/start` validates `return_to`, INSERTs an
      `oidc_login_nonces` row, and 302s to the IdP authorize URL with
      `state` + `code_challenge` + `code_challenge_method=S256`.
    * `/admin/login/callback` consumes the row via `SELECT FOR UPDATE`
      single-use semantics; replay returns 400 + `outcome:
      "state_already_used"`; expired row returns 400 + `state_expired`;
      missing row returns 400 + `state_invalid`.
    * Per-failure-path `:ui_login` `outcome` field assertions captured
      via `:telemetry.attach/4` against `UiReceipts`'s telemetry seam.
    * Set-Cookie attributes on success: `HttpOnly`, `Secure`,
      `SameSite=Lax`, `Path=/`, `Max-Age=28800`.

  ## Test architecture

  Uses the `MockHttpUpstream` (F002 T054 helper) to stand in as the
  IdP token endpoint; injects stubbed `:id_token_validator` +
  `:token_exchange` callbacks via opts so we don't boot the real
  RecurseBroker for every callback test (Mox-style isolation per
  `elixir:phoenix-thinking`).

  ## Cross-references

    * `specs/004-audit-console/contracts/browser_oidc_flow.md` Steps 2 + 4
    * `apps/recurse_gateway/lib/recurse_gateway/admin/browser_auth/login_handler.ex`
    * `apps/recurse_gateway/lib/recurse_gateway/admin/browser_auth/nonce_store.ex`
    * `apps/recurse_gateway/test/support/mock_http_upstream.ex`
  """
  use ExUnit.Case, async: false

  alias Ecto.Adapters.SQL.Sandbox
  alias Recurse.Gateway.Admin.BrowserAuth.LoginHandler
  alias Recurse.Gateway.Admin.BrowserAuth.NonceStore
  alias Recurse.Gateway.Admin.BrowserAuth.Schemas.OidcLoginNonce
  alias Recurse.Gateway.Admin.BrowserAuth.UiReceipts
  alias Recurse.Gateway.Test.MockHttpUpstream
  alias Recurse.Providers.Repo

  @tenant_id "tenant-test-1"
  @gateway_origin "https://gateway.test"
  @authorize_url "https://idp.test/authorize"
  @client_id "broker-client"
  @redirect_uri "https://gateway.test/admin/login/callback"

  setup do
    :ok = Sandbox.checkout(Repo)
    Sandbox.mode(Repo, {:shared, self()})

    # BrowserSessionPlug.encrypt_payload/2 (called by the success path's
    # finalize_success) reads the secret from app env when no opts are
    # threaded through. Seed a stable secret for the suite.
    prior_browser_session = Application.get_env(:recurse_gateway, :browser_session)

    Application.put_env(:recurse_gateway, :browser_session,
      secret_key_base: :crypto.strong_rand_bytes(32),
      secure_cookie?: true
    )

    on_exit(fn ->
      if prior_browser_session do
        Application.put_env(:recurse_gateway, :browser_session, prior_browser_session)
      else
        Application.delete_env(:recurse_gateway, :browser_session)
      end
    end)

    {:ok, upstream} = MockHttpUpstream.start()
    on_exit(fn -> MockHttpUpstream.stop(upstream) end)

    # Capture telemetry from `UiReceipts.emit/2` so per-failure-path
    # `outcome` discriminators can be asserted directly without booting
    # the real ledger commit pipeline (deferred to Wave 3+).
    handler_id = "oidc-flow-test-#{System.unique_integer([:positive])}"
    test_pid = self()

    :ok =
      :telemetry.attach(
        handler_id,
        UiReceipts.telemetry_event(),
        fn _event, measurements, metadata, _ ->
          send(test_pid, {:ui_receipt, measurements, metadata})
        end,
        nil
      )

    on_exit(fn -> :telemetry.detach(handler_id) end)

    base_opts = [
      authorize_url: @authorize_url,
      idp_token_url: MockHttpUpstream.url(upstream) <> "/token",
      client_id: @client_id,
      redirect_uri: @redirect_uri,
      tenant_id: @tenant_id,
      gateway_origin: @gateway_origin,
      finch_pool: :openai_pool,
      id_token_validator: fn _token, _config -> {:ok, %{"sub" => "alice@corp"}} end,
      token_exchange: fn _id_token, _claims, _config ->
        {:ok,
         %{
           jwt: "minted.jwt.token",
           principal_subject: "alice@corp",
           browser_session_id: "bsid-#{System.unique_integer([:positive])}"
         }}
      end
    ]

    %{upstream: upstream, base_opts: base_opts}
  end

  # ---------------------------------------------------------------------------
  # /admin/login/start
  # ---------------------------------------------------------------------------

  describe "GET /admin/login/start" do
    test "INSERTs nonce row + 302s to IdP authorize URL with PKCE state", %{base_opts: opts} do
      conn = build_conn("GET", "/admin/login/start", "return_to=/admin/dashboard")
      out = LoginHandler.call(conn, opts)

      assert out.status == 302
      [{"location", location}] = filter_headers(out.resp_headers, "location")
      assert String.starts_with?(location, @authorize_url)

      query =
        location
        |> String.split("?", parts: 2)
        |> List.last()
        |> URI.decode_query()

      assert query["client_id"] == @client_id
      assert query["redirect_uri"] == @redirect_uri
      assert query["code_challenge_method"] == "S256"
      assert is_binary(query["state"]) and byte_size(query["state"]) >= 32
      assert is_binary(query["code_challenge"]) and byte_size(query["code_challenge"]) >= 32

      # Row was actually persisted with the `state` we redirected on.
      assert %OidcLoginNonce{} = Repo.get_by(OidcLoginNonce, state: query["state"])
    end

    test "rejects path-relative return_to that begins with `//`", %{base_opts: opts} do
      conn = build_conn("GET", "/admin/login/start", "return_to=//evil.example/admin")
      out = LoginHandler.call(conn, opts)
      assert out.status == 400
      assert_received {:ui_receipt, _, %{event_kind: :ui_login, outcome: "invalid_return_to"}}
    end

    test "rejects return_to without leading slash", %{base_opts: opts} do
      conn = build_conn("GET", "/admin/login/start", "return_to=admin/dashboard")
      out = LoginHandler.call(conn, opts)
      assert out.status == 400
      assert_received {:ui_receipt, _, %{event_kind: :ui_login, outcome: "invalid_return_to"}}
    end
  end

  # ---------------------------------------------------------------------------
  # /admin/login/callback (single-use, TTL, per-failure outcomes)
  # ---------------------------------------------------------------------------

  describe "GET /admin/login/callback" do
    test "happy path: consumes nonce + sets r5e_session cookie + 302s to return_to",
         %{upstream: upstream, base_opts: opts} do
      {state, _row} = seed_nonce()

      MockHttpUpstream.expect(upstream, fn conn ->
        body = JSON.encode!(%{"id_token" => "synthetic.id.token"})

        conn
        |> Plug.Conn.put_resp_header("content-type", "application/json")
        |> Plug.Conn.send_resp(200, body)
      end)

      callback_conn =
        build_conn("GET", "/admin/login/callback", "state=#{state}&code=AUTHCODE")

      out = LoginHandler.call(callback_conn, opts)
      assert out.status == 302

      assert_received {:ui_receipt, _, %{event_kind: :ui_login, outcome: "success"}}

      # Nonce was consumed (used_at set).
      consumed = Repo.get_by!(OidcLoginNonce, state: state)
      refute is_nil(consumed.used_at)

      # Cookie attributes per Step 5.
      assert {_name,
              %{http_only: true, secure: true, same_site: "Lax", path: "/", max_age: 28_800}} =
               Enum.find(out.resp_cookies, fn {name, _} -> name == "r5e_session" end)
    end

    test "replay (state_already_used) returns 400 + outcome=state_already_used",
         %{base_opts: opts} do
      {state, _row} = seed_nonce()
      {:ok, _consumed} = NonceStore.consume_nonce(state)

      conn = build_conn("GET", "/admin/login/callback", "state=#{state}&code=AUTHCODE")
      out = LoginHandler.call(conn, opts)
      assert out.status == 400
      assert_received {:ui_receipt, _, %{event_kind: :ui_login, outcome: "state_already_used"}}
    end

    test "expired (state_expired) returns 400 + outcome=state_expired", %{base_opts: opts} do
      {state, _row} = seed_nonce(ttl_seconds: -1)

      conn = build_conn("GET", "/admin/login/callback", "state=#{state}&code=AUTHCODE")
      out = LoginHandler.call(conn, opts)
      assert out.status == 400
      assert_received {:ui_receipt, _, %{event_kind: :ui_login, outcome: "state_expired"}}
    end

    test "unknown state returns 400 + outcome=state_invalid", %{base_opts: opts} do
      conn =
        build_conn("GET", "/admin/login/callback", "state=" <> random_state() <> "&code=X")

      out = LoginHandler.call(conn, opts)
      assert out.status == 400
      assert_received {:ui_receipt, _, %{event_kind: :ui_login, outcome: "state_invalid"}}
    end

    test "IdP token endpoint returning non-200 → 502 + idp_code_exchange_failed",
         %{upstream: upstream, base_opts: opts} do
      {state, _row} = seed_nonce()

      MockHttpUpstream.expect(upstream, fn conn ->
        Plug.Conn.send_resp(conn, 500, "boom")
      end)

      conn = build_conn("GET", "/admin/login/callback", "state=#{state}&code=AUTHCODE")
      out = LoginHandler.call(conn, opts)
      assert out.status == 502

      assert_received {:ui_receipt, _,
                       %{event_kind: :ui_login, outcome: "idp_code_exchange_failed"}}
    end

    test "id_token validation failure → 401 + id_token_invalid",
         %{upstream: upstream, base_opts: opts} do
      {state, _row} = seed_nonce()

      MockHttpUpstream.expect(upstream, fn conn ->
        body = JSON.encode!(%{"id_token" => "synthetic.id.token"})

        conn
        |> Plug.Conn.put_resp_header("content-type", "application/json")
        |> Plug.Conn.send_resp(200, body)
      end)

      bad_opts =
        Keyword.put(opts, :id_token_validator, fn _, _ ->
          {:error, :invalid_signature}
        end)

      conn = build_conn("GET", "/admin/login/callback", "state=#{state}&code=AUTHCODE")
      out = LoginHandler.call(conn, bad_opts)
      assert out.status == 401
      assert_received {:ui_receipt, _, %{event_kind: :ui_login, outcome: "id_token_invalid"}}
    end

    test "RFC 8693 token-exchange failure → 403 + jwt_mint_failed",
         %{upstream: upstream, base_opts: opts} do
      {state, _row} = seed_nonce()

      MockHttpUpstream.expect(upstream, fn conn ->
        body = JSON.encode!(%{"id_token" => "synthetic.id.token"})

        conn
        |> Plug.Conn.put_resp_header("content-type", "application/json")
        |> Plug.Conn.send_resp(200, body)
      end)

      bad_opts =
        Keyword.put(opts, :token_exchange, fn _, _, _ ->
          {:error, :no_role_match_no_default}
        end)

      conn = build_conn("GET", "/admin/login/callback", "state=#{state}&code=AUTHCODE")
      out = LoginHandler.call(conn, bad_opts)
      assert out.status == 403
      assert_received {:ui_receipt, _, %{event_kind: :ui_login, outcome: "jwt_mint_failed"}}
    end
  end

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  defp seed_nonce(seed_opts \\ []) do
    state = random_state()
    code_verifier = random_state(64)
    ttl = Keyword.get(seed_opts, :ttl_seconds, 600)

    {:ok, row} =
      NonceStore.insert_nonce(state, code_verifier, %{
        return_to: @gateway_origin <> "/admin/dashboard",
        tenant_id: @tenant_id,
        ttl_seconds: ttl
      })

    {state, row}
  end

  defp random_state(byte_count \\ 32) do
    byte_count
    |> :crypto.strong_rand_bytes()
    |> Base.url_encode64(padding: false)
  end

  defp build_conn(method, path, query_string) do
    full_path = if query_string in [nil, ""], do: path, else: path <> "?" <> query_string

    Plug.Test.conn(method, full_path)
    # Plug.Test.conn/3 sets path_info via the URL parser; the LoginHandler
    # dispatches on `path_info` so we just rely on Plug's parser.
  end

  defp filter_headers(headers, name) do
    Enum.filter(headers, fn {k, _v} -> k == name end)
  end
end
