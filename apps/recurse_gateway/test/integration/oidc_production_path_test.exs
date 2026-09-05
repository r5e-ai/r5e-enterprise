defmodule RecurseGateway.Integration.OidcProductionPathTest do
  @moduledoc """
  Integration test for the F004 OIDC production wiring (PR-readiness
  blocker #3 — `LoginHandler.default_id_token_validator/2` and
  `LoginHandler.default_token_exchange/3`).

  Proves the **full production path**:

    1. `GET /admin/login/start?return_to=/admin/dashboard` validates
       `return_to`, INSERTs an `oidc_login_nonces` row, and 302s to the
       (mock) IdP authorize URL with PKCE state + code_challenge.
    2. The auditor "logs in at the IdP" — we synthesize the IdP's
       authorize-then-callback redirect by reading the `state` from the
       302's `Location` query string, then calling
       `GET /admin/login/callback?state=<state>&code=AUTHCODE`.
    3. The callback POSTs the auth code to the IdP token endpoint
       (MockHttpUpstream stubs the IdP) and gets back a real
       `MockOidcIssuer`-signed `id_token` (ES256 + JWKS-discoverable).
    4. **`default_id_token_validator/2` runs for real**:
       - Hits the Gateway's `JwksCache` to resolve the IdP's signing
         key by `kid` (cache cold → coalesced refresh against a
         plug-stubbed Req fetcher serving the MockOidcIssuer's JWKS).
       - Validates signature + `aud`/`iss`/`exp`/`nbf`/`iat` via
         `JwtValidator.validate/2` with 60s skew.
    5. **`default_token_exchange/3` runs for real**:
       - Drives the IdP-issued `id_token` through the in-VM
         `RecurseBroker.Endpoint` `POST /token/exchange` (RFC 8693)
         via the `:broker_endpoint` test seam (the production path
         POSTs over Finch — same form body, same response shape;
         the in-VM seam saves a port-binding round trip).
       - Unpacks the broker's `access_token` (the X-Observed-Identity
         JWT signed by `RecurseBroker.JWT.KeyRing`) into the cookie
         payload.
    6. The auditor lands at `/admin/dashboard` with a sealed
       `r5e_session` cookie. The cookie's encrypted payload decrypts
       to `%{jwt: <broker_jwt>, ...}` and the broker JWT validates
       against the broker's published JWKS via `JwtValidator`.

  This is the test that PROVES "an auditor can sign in" — the bug it
  guards against (both default callbacks returning `:not_implemented`)
  silently rendered every login attempt a 401/403 in any environment
  that didn't override the callbacks via opts.

  ## `async: false`

  Per the same reasoning as `us1_with_real_broker_test.exs`:
  Bandit/Cowboy ports for MockHttpUpstream + MockOidcIssuer plug
  stubs, broker-side `Application.put_env` mutation, and module-
  registered GenServers (`JwksCache`, `KeyRing`, `DiscoveryCache`).
  Decisively serial.

  ## Cross-references

    * `apps/recurse_gateway/lib/recurse_gateway/admin/browser_auth/login_handler.ex`
      (`default_id_token_validator/2`, `default_token_exchange/3`)
    * `apps/recurse_gateway/lib/recurse_gateway/identity/jwks_cache.ex`
    * `apps/recurse_gateway/lib/recurse_gateway/identity/jwt_validator.ex`
    * `apps/recurse_broker/lib/recurse_broker/token_exchange.ex`
    * `apps/recurse_gateway/test/integration/us1_with_real_broker_test.exs`
      (sibling F002 broker test — same MockOidcIssuer + KeyRing pattern)
    * `specs/004-audit-console/contracts/browser_oidc_flow.md` Steps 2–6
  """
  use ExUnit.Case, async: false

  @moduletag :integration

  alias Ecto.Adapters.SQL.Sandbox
  alias Recurse.Gateway.Admin.BrowserAuth.LoginHandler
  alias Recurse.Gateway.Admin.BrowserSessionPlug
  alias Recurse.Gateway.Identity.JwksCache
  alias Recurse.Gateway.Identity.JwtValidator
  alias Recurse.Gateway.Test.MockHttpUpstream
  alias Recurse.Providers.Repo
  alias RecurseBroker.Endpoint, as: BrokerEndpoint
  alias RecurseBroker.OIDC.DiscoveryCache
  alias RecurseBroker.Test.MockOidcIssuer
  alias RecurseBroker.Test.SupervisorHelper

  @tenant_id "tenant-oidc-prod-test"
  @gateway_origin "https://gateway.test"
  @authorize_url "https://idp.test/authorize"
  @oidc_client_id "broker-client-prod-test"
  @broker_audience "recurse-gateway-test"
  @broker_issuer "https://broker.recurse.test"
  @interactive_aud @broker_audience <> "-interactive"

  @broker_endpoint_opts BrokerEndpoint.init([])

  # Role mapping that maps the IdP "auditors" group → the `tenant_auditor`
  # Recurse role. Full audit-console RBAC.
  @mapping %{
    group_to_recurse_role: %{
      "cn=recurse-auditors,ou=groups,dc=corp,dc=example" => "tenant_auditor"
    },
    default_recurse_role: "tenant_auditor",
    role_privilege_order: ["platform_operator", "tenant_auditor", "caller"]
  }

  setup do
    # -- DB ---------------------------------------------------------------
    :ok = Sandbox.checkout(Repo)
    Sandbox.mode(Repo, {:shared, self()})

    # -- BrowserSessionPlug cookie key ------------------------------------
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

    # -- Mock IdP — signs id_tokens; also exposes JWKS via plug stub ------
    mock_issuer = MockOidcIssuer.new()
    jwks_plug = MockOidcIssuer.jwks_plug_fn(mock_issuer)

    # -- Broker side: KeyRing (mints X-Observed-Identity JWT) +
    #    DiscoveryCache (validates IdP id_token via its JWKS) ------------
    # Same pattern as `us1_with_real_broker_test.exs`: the umbrella test
    # boot starts these under module-registered names; restart with our
    # ephemeral keypair + plug-stubbed Req for IdP discovery.
    SupervisorHelper.stop_auto_started(RecurseBroker.OIDC.DiscoveryCache)
    SupervisorHelper.stop_auto_started(RecurseBroker.JWT.KeyRing)

    start_supervised!({RecurseBroker.JWT.KeyRing, generate_ephemeral?: true})
    start_supervised!({DiscoveryCache, req_opts: [plug: jwks_plug]})

    previous_broker_env = swap_broker_env(mock_issuer.issuer)
    on_exit(fn -> restore_broker_env(previous_broker_env) end)

    # -- Gateway side: JwksCache pointed at the same MockOidcIssuer JWKS
    #    via plug-stubbed Req. We start under the default module name so
    #    `default_id_token_validator/2` resolves the cache via
    #    `JwksCache.fetch_jwk/2` (arity-2 form uses module-registered name).
    # Stop any existing default-named cache first (umbrella test boot may
    # have started one).
    case Process.whereis(JwksCache) do
      nil -> :ok
      pid -> Process.exit(pid, :shutdown)
    end

    # The JwksCache uses Task.Supervisor.async_nolink/2 — give it a
    # supervisor scoped to this test.
    {:ok, task_sup} = start_supervised(Task.Supervisor)

    # Issuer URL used by the JwksCache must match the `iss` claim in the
    # MockOidcIssuer-minted id_token (`mock_issuer.issuer`). The
    # `jwks_url` is hit via the plug-stubbed Req — the path doesn't
    # matter as the plug serves any GET — so we use a synthetic URL.
    {:ok, _cache_pid} =
      start_supervised(
        {JwksCache,
         issuers: [
           %{
             issuer_url: mock_issuer.issuer,
             jwks_url: mock_issuer.issuer <> "/jwks",
             ttl_seconds: 300
           }
         ],
         finch_pool: :jwks_pool,
         task_supervisor: task_sup,
         req_opts: [plug: jwks_plug],
         name: JwksCache}
      )

    # -- IdP token endpoint stub (Bandit on a random port) ----------------
    # The auth-code → id_token POST in `LoginHandler.exchange_code/3`
    # uses the real `:jwks_pool` Finch pool, so we need a real bound port.
    {:ok, idp_token_endpoint} = MockHttpUpstream.start()
    on_exit(fn -> MockHttpUpstream.stop(idp_token_endpoint) end)

    %{mock_issuer: mock_issuer, idp_token_endpoint: idp_token_endpoint}
  end

  describe "production OIDC happy path (no callback overrides)" do
    test "auditor signs in end-to-end through the real defaults", %{
      mock_issuer: mock_issuer,
      idp_token_endpoint: idp_token_endpoint
    } do
      # ----- LoginHandler opts WITHOUT id_token_validator / token_exchange
      # We thread the broker_endpoint test seam (in-VM dispatch instead
      # of real HTTP to localhost:4001), but otherwise let the production
      # defaults resolve.
      opts = [
        authorize_url: @authorize_url,
        idp_token_url: MockHttpUpstream.url(idp_token_endpoint) <> "/token",
        client_id: @oidc_client_id,
        redirect_uri: @gateway_origin <> "/admin/login/callback",
        tenant_id: @tenant_id,
        gateway_origin: @gateway_origin,
        finch_pool: :jwks_pool,
        # ---- production-default validator wiring ----
        idp_issuer_url: mock_issuer.issuer,
        idp_audience: @interactive_aud,
        jwks_cache: JwksCache,
        # ---- production-default broker exchange wiring (in-VM seam) ----
        broker_audience: @broker_audience,
        broker_endpoint: BrokerEndpoint,
        broker_endpoint_opts: @broker_endpoint_opts
      ]

      # ----- Step 1: /admin/login/start mints state + 302s to IdP -------
      start_conn = build_conn("GET", "/admin/login/start", "return_to=/admin/dashboard")
      start_out = LoginHandler.call(start_conn, opts)

      assert start_out.status == 302

      [{"location", location}] = filter_headers(start_out.resp_headers, "location")
      assert String.starts_with?(location, @authorize_url)

      query =
        location
        |> String.split("?", parts: 2)
        |> List.last()
        |> URI.decode_query()

      state = Map.fetch!(query, "state")
      assert byte_size(state) >= 32

      # ----- Step 2: stub the IdP's token endpoint to return the
      # MockOidcIssuer-minted id_token --------------------------------
      id_token =
        MockOidcIssuer.mint_id_token(mock_issuer, %{
          "sub" => "auth0|alice-prod-path",
          "aud" => @interactive_aud,
          "groups" => ["cn=recurse-auditors,ou=groups,dc=corp,dc=example"]
        })

      MockHttpUpstream.expect(idp_token_endpoint, fn conn ->
        # Production token-endpoint contract per RFC 6749 §4.1.3:
        # POST application/x-www-form-urlencoded with the auth-code +
        # PKCE verifier. Verify the body shape minimally (the stricter
        # contract is in oidc_login_flow_contract_test.exs).
        assert conn.method == "POST"
        assert conn.request_path == "/token"

        body = JSON.encode!(%{"id_token" => id_token})

        conn
        |> Plug.Conn.put_resp_header("content-type", "application/json")
        |> Plug.Conn.send_resp(200, body)
      end)

      # ----- Step 3: /admin/login/callback drives the full default path
      callback_conn =
        build_conn("GET", "/admin/login/callback", "state=#{state}&code=AUTHCODE")

      out = LoginHandler.call(callback_conn, opts)

      # The production path MUST reach the success branch — NOT the
      # `{:error, :not_implemented}` short-circuit that the bug
      # produced. Status 401 (id_token_invalid) or 403 (jwt_mint_failed)
      # would mean the defaults are still broken.
      assert out.status == 302,
             "OIDC callback failed (status=#{out.status}, body=#{inspect(out.resp_body)})"

      [{"location", redirect_to}] = filter_headers(out.resp_headers, "location")
      assert redirect_to == "/admin/dashboard"

      # ----- Step 4: cookie was set + payload contains a real broker JWT
      {_name, cookie_attrs} =
        Enum.find(out.resp_cookies, fn {name, _} -> name == "r5e_session" end) ||
          flunk("r5e_session cookie not set on success: #{inspect(out.resp_cookies)}")

      assert cookie_attrs.http_only == true
      assert cookie_attrs.secure == true
      assert cookie_attrs.same_site == "Lax"
      assert cookie_attrs.path == "/"
      assert cookie_attrs.max_age == 28_800

      # ----- Step 5: decrypt the cookie + validate the broker JWT
      payload = decrypt_session_cookie(cookie_attrs.value)

      assert is_binary(payload[:jwt]) and payload[:jwt] != "",
             "cookie payload missing :jwt — saw #{inspect(payload)}"

      assert is_binary(payload[:browser_session_id]) and
               payload[:browser_session_id] != ""

      assert payload[:tenant_id] == @tenant_id

      # The broker JWT MUST validate against the broker's published JWKS.
      # Pull the active broker keys (sibling test pattern T089).
      {:ok, broker_keys} = RecurseBroker.JWT.KeyRing.all_active_keys()

      known_kids =
        Enum.map(broker_keys, fn {kid, jwk} ->
          {_, fields} = jwk |> JOSE.JWK.to_public() |> JOSE.JWK.to_map()
          {kid, Map.put(fields, "kid", kid)}
        end)

      assert {:ok, broker_claims} =
               JwtValidator.validate(payload[:jwt], %{
                 audience: @broker_audience,
                 issuer: @broker_issuer,
                 known_kids: known_kids
               })

      # Sanity-check the principal claim shape (proves the IdP →
      # broker → cookie chain carried the auditor's identity end-to-end).
      principal = broker_claims["principal"]
      assert is_map(principal)
      assert principal["kind"] == "obo_human"
      assert principal["issuer"] == mock_issuer.issuer
      assert principal["subject"] == "auth0|alice-prod-path"
      assert principal["recurse_role"] == "tenant_auditor"
    end

    test "default_id_token_validator/2 unset config → fails closed (not :not_implemented)" do
      # Explicitly proves the regression guard: a deployment that forgets
      # to wire `:idp_issuer_url` MUST fail closed rather than silently
      # accept any id_token.
      assert {:error, :idp_issuer_url_unset} =
               LoginHandler.default_id_token_validator("any.token.here", %{
                 idp_audience: "x",
                 jwks_cache: JwksCache
               })

      assert {:error, :idp_audience_unset} =
               LoginHandler.default_id_token_validator("any.token.here", %{
                 idp_issuer_url: "https://idp.test",
                 jwks_cache: JwksCache
               })
    end

    test "default_token_exchange/3 unset config → fails closed (not :not_implemented)" do
      # `:broker_audience` unset → no exchange even attempted.
      assert {:error, :broker_audience_unset} =
               LoginHandler.default_token_exchange(
                 "synthetic.id.token",
                 %{"sub" => "auth0|alice"},
                 %{}
               )

      # `:broker_audience` set but neither `:broker_endpoint` nor
      # `:broker_token_exchange_url` → no dispatch path available.
      assert {:error, :broker_url_unset} =
               LoginHandler.default_token_exchange(
                 "synthetic.id.token",
                 %{"sub" => "auth0|alice"},
                 %{broker_audience: @broker_audience}
               )
    end
  end

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  defp build_conn(method, path, query_string) do
    full_path = if query_string in [nil, ""], do: path, else: path <> "?" <> query_string
    Plug.Test.conn(method, full_path)
  end

  defp filter_headers(headers, name) do
    Enum.filter(headers, fn {k, _v} -> k == name end)
  end

  # Decrypt via the same public helper LoginHandler / BrowserSessionPlug
  # use under the hood. Returns the raw payload map (atoms keys per
  # `LoginHandler.finalize_success/6`).
  defp decrypt_session_cookie(cookie_value) do
    case BrowserSessionPlug.decrypt_cookie(cookie_value) do
      {:ok, payload} -> payload
      {:error, :cookie_tampered} -> flunk("cookie ciphertext failed to decrypt")
    end
  end

  # ---------------------------------------------------------------------------
  # Broker env swap helpers (lifted verbatim from us1_with_real_broker_test.exs).
  # ---------------------------------------------------------------------------

  defp swap_broker_env(issuer_url) do
    previous = %{
      expected_audience: Application.get_env(:recurse_broker, :expected_audience),
      broker_issuer: Application.get_env(:recurse_broker, :broker_issuer),
      role_mapping: Application.get_env(:recurse_broker, :role_mapping),
      oidc_validator_opts: Application.get_env(:recurse_broker, :oidc_validator_opts)
    }

    Application.put_env(:recurse_broker, :expected_audience, @broker_audience)
    Application.put_env(:recurse_broker, :broker_issuer, @broker_issuer)
    Application.put_env(:recurse_broker, :role_mapping, @mapping)

    Application.put_env(:recurse_broker, :oidc_validator_opts,
      alg_allowlist: [:rs256, :es256, :eddsa],
      issuer: issuer_url,
      audience: @interactive_aud
    )

    previous
  end

  defp restore_broker_env(previous) do
    for {k, v} <- previous do
      case v do
        nil -> Application.delete_env(:recurse_broker, k)
        val -> Application.put_env(:recurse_broker, k, val)
      end
    end

    :ok
  end
end
