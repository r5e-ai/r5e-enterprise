defmodule RecurseGateway.Integration.WorkosLoginPathTest do
  @moduledoc """
  End-to-end integration test for the WorkOS AuthKit dogfood-deploy
  sign-in flow (`feat/dogfood-deploy-scaffolding`).

  Proves the full WorkOS path bypasses the broker:

    1. `GET /admin/login/start?return_to=/admin/dashboard` validates
       `return_to`, INSERTs an `oidc_login_nonces` row, and 302s to
       `https://api.workos.com/user_management/authorize?provider=authkit&...`
       with PKCE state + code_challenge + organization_id.
    2. Callback `GET /admin/login/callback?state=<state>&code=<code>`
       drives `BrowserAuth.Workos.default_code_exchanger/3` which
       POSTs JSON to the (mock) WorkOS authenticate endpoint and gets
       back `{user, organization_id, access_token}`. The access_token
       is signed by a `MockOidcIssuer` keypair whose JWKS is served by
       a Req-style `:plug` callback feeding the Gateway's `JwksCache`.
    3. `BrowserAuth.Workos.default_validator/2` resolves the access
       token's `kid` against the JwksCache and runs `JwtValidator` for
       signature + standard claims (`aud == client_id`, `iss == api_base`).
    4. `BrowserAuth.Workos.default_exchange/3` materializes the cookie
       payload directly from the WorkOS user/org fields + the validated
       access_token claims (no broker round-trip).
    5. `r5e_session` cookie is set on the conn; decrypted payload
       carries `principal_subject == workos_user.id`,
       `tenant_id == workos_response.organization_id`,
       `recurse_role == "platform_operator"` (read from the WorkOS
       access_token's `role` claim per
       https://workos.com/docs/user-management/sessions/access-tokens).
    6. A follow-up `GET /v1/auth/me` with the cookie returns the
       principal correctly mapped — the assert anchors that
       BrowserSessionPlug → AuthMeHandler renders the WorkOS-shaped
       payload without a downstream JWT-principal-claim lookup.

  ## What this test does NOT exercise

    * The boot-time JwksCache supervision (covered indirectly — we
      start a JwksCache under the default module name in `setup`).
    * The router's tier-config-driven opts selection
      (`Router.login_handler_opts/0`) — exercised by booting the full
      router elsewhere; here we call `LoginHandler.call/2` directly
      with the WorkOS opts to keep the test from binding a port.
    * Real network calls to `api.workos.com` — the WorkOS JSON API
      is mocked via `MockHttpUpstream` (Bandit on a random port);
      the JWKS endpoint is mocked via `MockOidcIssuer.jwks_plug_fn/1`
      threaded through `JwksCache`'s `req_opts: [plug: ...]` DI seam.

  ## `async: false`

  MockHttpUpstream binds a port; `JwksCache` is started under its
  module-registered name; the `:browser_session` app env is mutated.
  Decisively serial.

  ## Cross-references

    * `apps/recurse_gateway/lib/recurse_gateway/admin/browser_auth/workos.ex`
    * `apps/recurse_gateway/lib/recurse_gateway/admin/browser_auth/login_handler.ex`
      (`:code_exchanger` seam)
    * `apps/recurse_gateway/lib/recurse_gateway/admin/browser_session_plug.ex`
      (lifts `principal_subject` + `recurse_role` from cookie payload)
    * `apps/recurse_gateway/lib/recurse_gateway/admin/auth_me_handler.ex`
      (renders the assigns into the `auth_me` JSON shape)
  """

  use ExUnit.Case, async: false

  setup_all do
    Recurse.Gateway.Test.KernelFixture.boot()
  end

  @moduletag :integration

  alias Ecto.Adapters.SQL.Sandbox
  alias Recurse.Gateway.Admin.AuthMeHandler
  alias Recurse.Gateway.Admin.BrowserAuth.LoginHandler
  alias Recurse.Gateway.Admin.BrowserAuth.UiReceipts
  alias Recurse.Gateway.Admin.BrowserAuth.Workos
  alias Recurse.Gateway.Admin.BrowserSessionPlug
  alias Recurse.Gateway.AuditPlane.Authz
  alias Recurse.Gateway.Identity.JwksCache
  alias Recurse.Gateway.Policy.BundleLoader
  alias Recurse.Gateway.ProviderRegistry
  alias Recurse.Gateway.Test.MockHttpUpstream
  alias Recurse.Providers.Impls.PostgresMerkleLedger
  alias Recurse.Providers.Repo
  alias RecurseBroker.Test.MockOidcIssuer

  @tenant_id_default "tenant-workos-dogfood"
  @gateway_origin "https://gateway.dogfood.test"
  @workos_client_id "client_dogfood_test"
  @workos_api_key "sk_test_dogfood_secret"
  @workos_redirect_uri "https://gateway.dogfood.test/admin/login/callback"
  @workos_default_org_id "org_01KQ5T2EH9NP3AWE54AB2APWNH"
  @workos_user_id "user_01KQ5VCDXS5J0DASQCZ4F5G5QT"

  # Recurse-internal JWT (broker-shape) audience + issuer that the
  # WorkOS adapter mints and `JwtValidator` accepts. Distinct from the
  # WorkOS issuer/audience (which are about the WorkOS access_token).
  @internal_jwt_audience "recurse-gateway-test"
  @internal_jwt_issuer "https://gateway.dogfood.test/internal"

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

    # -- WorkOS app env (used by Workos adapter's resolve_config/1) -------
    prior_workos = Application.get_env(:recurse_gateway, :workos)
    # Use a synthetic api_base. WorkOS User Management tokens carry
    # iss=<api_base>/user_management/<client_id>, so the access-token
    # fixtures below mint that per-client issuer shape.
    mock_issuer = MockOidcIssuer.new()

    Application.put_env(:recurse_gateway, :workos,
      api_key: @workos_api_key,
      client_id: @workos_client_id,
      redirect_uri: @workos_redirect_uri,
      default_organization_id: @workos_default_org_id,
      api_base: mock_issuer.issuer
    )

    on_exit(fn ->
      if prior_workos do
        Application.put_env(:recurse_gateway, :workos, prior_workos)
      else
        Application.delete_env(:recurse_gateway, :workos)
      end
    end)

    # -- JwksCache pointing at MockOidcIssuer's plug-stubbed JWKS ---------
    case Process.whereis(JwksCache) do
      nil -> :ok
      pid -> Process.exit(pid, :shutdown)
    end

    {:ok, task_sup} = start_supervised(Task.Supervisor)

    jwks_plug = MockOidcIssuer.jwks_plug_fn(mock_issuer)

    {:ok, _cache_pid} =
      start_supervised(
        {JwksCache,
         issuers: [
           %{
             issuer_url: mock_issuer.issuer,
             jwks_url: mock_issuer.issuer <> "/sso/jwks/" <> @workos_client_id,
             ttl_seconds: 300
           },
           %{
             issuer_url: workos_issuer(mock_issuer),
             jwks_url: mock_issuer.issuer <> "/sso/jwks/" <> @workos_client_id,
             ttl_seconds: 300
           }
         ],
         finch_pool: :jwks_pool,
         task_supervisor: task_sup,
         req_opts: [plug: jwks_plug],
         name: JwksCache}
      )

    # -- Mock WorkOS authenticate endpoint (Bandit on a random port) ------
    {:ok, workos_endpoint} = MockHttpUpstream.start()
    on_exit(fn -> MockHttpUpstream.stop(workos_endpoint) end)

    # -- Internal JWT signing key (gateway-side broker-shape mint) -------
    # The dogfood deploy mints a broker-shaped JWT in-process so Cedar-
    # gated F004 endpoints work post-WorkOS-login. Generate a fresh
    # ES256 keypair, write the private PEM to a tmp file (the WorkOS
    # adapter's `load_signing_key/1` reads PEM-on-disk), and register
    # the public JWK with `:jwt_validator_opts` so downstream
    # `JwtValidator.validate/2` accepts the minted token.
    {internal_jwt_path, internal_kid, internal_public_jwk} = mint_internal_signing_key()

    prior_internal_jwt = Application.get_env(:recurse_gateway, :internal_jwt)

    Application.put_env(:recurse_gateway, :internal_jwt,
      signing_key_path: internal_jwt_path,
      audience: @internal_jwt_audience,
      issuer: @internal_jwt_issuer,
      ttl_seconds: 900
    )

    on_exit(fn ->
      if prior_internal_jwt do
        Application.put_env(:recurse_gateway, :internal_jwt, prior_internal_jwt)
      else
        Application.delete_env(:recurse_gateway, :internal_jwt)
      end

      File.rm(internal_jwt_path)
    end)

    %{
      mock_issuer: mock_issuer,
      workos_endpoint: workos_endpoint,
      internal_kid: internal_kid,
      internal_public_jwk: internal_public_jwk
    }
  end

  describe "WorkOS happy path" do
    test "auditor signs in end-to-end via WorkOS (no broker)", %{
      mock_issuer: mock_issuer,
      workos_endpoint: workos_endpoint
    } do
      # ----- Build LoginHandler opts in the WorkOS shape -----------------
      # api_base is the mock_issuer's issuer; Workos.verify_access_token/2
      # expects the derived per-client User Management issuer. The
      # authenticate endpoint URL points at the MockHttpUpstream port.
      opts = [
        authorize_url: mock_issuer.issuer <> "/user_management/authorize",
        idp_token_url: MockHttpUpstream.url(workos_endpoint) <> "/user_management/authenticate",
        client_id: @workos_client_id,
        redirect_uri: @workos_redirect_uri,
        scope: "",
        tenant_id: @tenant_id_default,
        gateway_origin: @gateway_origin,
        finch_pool: :jwks_pool,
        authorize_extra_params: %{
          "provider" => "authkit",
          "organization_id" => @workos_default_org_id
        },
        # WorkOS-specific seam callbacks. The adapter reads its own
        # config (api_key, client_id, etc.) from app env via
        # `resolve_config/1` — we override only what the LoginHandler
        # itself needs to dispatch (URLs).
        code_exchanger: fn code, code_verifier, _config ->
          # The WorkOS adapter's `default_code_exchanger/3` reads
          # `api_base` from app env. For this test we want the POST to
          # land on `MockHttpUpstream` (random port) rather than
          # `mock_issuer.issuer` (which has no listener). Call the
          # `exchange_code/3` helper directly with the upstream URL as
          # `:api_base` and adapt its return tuple to the LoginHandler
          # `code_exchanger` contract.
          case Workos.exchange_code(code, code_verifier,
                 api_key: @workos_api_key,
                 client_id: @workos_client_id,
                 redirect_uri: @workos_redirect_uri,
                 api_base: MockHttpUpstream.url(workos_endpoint),
                 finch_pool: :jwks_pool
               ) do
            {:ok, %{"access_token" => access_token} = resp} ->
              {:ok, access_token, %{workos_response: resp}}

            {:error, reason} ->
              {:error, reason}
          end
        end,
        id_token_validator: &Workos.default_validator/2,
        token_exchange: &Workos.default_exchange/3
      ]

      # ----- Step 1: /admin/login/start mints state + 302s to WorkOS ----
      start_conn = build_conn("GET", "/admin/login/start", "return_to=/admin/dashboard")
      start_out = LoginHandler.call(start_conn, opts)

      assert start_out.status == 302

      [{"location", location}] = filter_headers(start_out.resp_headers, "location")
      assert String.starts_with?(location, mock_issuer.issuer <> "/user_management/authorize")

      query =
        location
        |> String.split("?", parts: 2)
        |> List.last()
        |> URI.decode_query()

      assert query["client_id"] == @workos_client_id
      assert query["redirect_uri"] == @workos_redirect_uri
      assert query["response_type"] == "code"
      assert query["provider"] == "authkit"
      assert query["organization_id"] == @workos_default_org_id
      assert query["code_challenge_method"] == "S256"
      state = Map.fetch!(query, "state")
      assert byte_size(state) >= 32
      assert is_binary(query["code_challenge"])

      # ----- Step 2: stub WorkOS authenticate endpoint --------------------
      # WorkOS access_tokens carry `role` for org-scoped users. We mint
      # one with `role: "platform_operator"` so AuthMeHandler renders
      # that role downstream.
      access_token =
        mint_workos_access_token(mock_issuer, %{
          "sub" => @workos_user_id,
          "aud" => @workos_client_id,
          "org_id" => @workos_default_org_id,
          "role" => "platform_operator"
        })

      MockHttpUpstream.expect(workos_endpoint, fn conn ->
        # WorkOS authenticate endpoint contract: JSON POST.
        assert conn.method == "POST"
        assert conn.request_path == "/user_management/authenticate"

        body =
          JSON.encode!(%{
            "user" => %{
              "id" => @workos_user_id,
              "email" => "operator@example.com",
              "first_name" => "Thomas",
              "last_name" => "Jones"
            },
            "organization_id" => @workos_default_org_id,
            "access_token" => access_token,
            "refresh_token" => "rt_dogfood_test_refresh",
            "authentication_method" => "Password"
          })

        conn
        |> Plug.Conn.put_resp_header("content-type", "application/json")
        |> Plug.Conn.send_resp(200, body)
      end)

      # ----- Step 3: /admin/login/callback drives the WorkOS adapter ----
      callback_conn =
        build_conn("GET", "/admin/login/callback", "state=#{state}&code=AUTHCODE")

      out = LoginHandler.call(callback_conn, opts)

      # The WorkOS path MUST reach success — NOT 401 (validator failed)
      # or 403 (adapter mis-mapped the response).
      assert out.status == 302,
             "WorkOS callback failed (status=#{out.status}, body=#{inspect(out.resp_body)})"

      [{"location", redirect_to}] = filter_headers(out.resp_headers, "location")
      assert redirect_to == "/admin/dashboard"

      # ----- Step 4: cookie was set + payload is WorkOS-shaped ----------
      {_name, cookie_attrs} =
        Enum.find(out.resp_cookies, fn {name, _} -> name == "r5e_session" end) ||
          flunk("r5e_session cookie not set on success: #{inspect(out.resp_cookies)}")

      assert cookie_attrs.http_only == true
      assert cookie_attrs.secure == true
      assert cookie_attrs.same_site == "Lax"
      assert cookie_attrs.path == "/"
      assert cookie_attrs.max_age == 28_800

      payload = decrypt_session_cookie(cookie_attrs.value)

      # The cookie's `jwt` is the gateway-minted, broker-shaped internal
      # JWT (NOT the WorkOS access_token directly — finding #1 fix).
      # The WorkOS access_token only carries `sub/aud/org_id/role`, but
      # `IdentityContextBuilder` requires a `principal` custom claim
      # for downstream Cedar gates.
      refute payload[:jwt] == access_token,
             "cookie carries WorkOS access_token raw — should be the broker-shaped internal JWT"

      assert is_binary(payload[:jwt])

      # WorkOS-shape principal lifted from the authenticate response:
      assert payload[:principal_subject] == @workos_user_id
      assert payload[:tenant_id] == @workos_default_org_id
      assert payload[:recurse_role] == "platform_operator"
      assert is_binary(payload[:browser_session_id]) and payload[:browser_session_id] != ""

      # ----- Step 5: GET /v1/auth/me returns the principal --------------
      # The BrowserSessionPlug lifts the cookie payload into
      # conn.assigns[:browser_session] with `principal_subject` /
      # `recurse_role` filled in (WorkOS path); AuthMeHandler renders
      # the assigns to the auth_me JSON shape.
      auth_me_conn =
        build_conn("GET", "/v1/auth/me", "")
        |> Plug.Test.put_req_cookie("r5e_session", cookie_attrs.value)

      session_conn =
        BrowserSessionPlug.call(
          auth_me_conn,
          BrowserSessionPlug.init([])
        )

      refute session_conn.halted, "BrowserSessionPlug halted on a freshly-issued WorkOS cookie"

      auth_me_out = AuthMeHandler.handle(session_conn)
      assert auth_me_out.status == 200

      auth_me_body = JSON.decode!(auth_me_out.resp_body)
      assert auth_me_body["principal_subject"] == @workos_user_id
      assert auth_me_body["tenant_id"] == @workos_default_org_id
      assert auth_me_body["recurse_role"] == "platform_operator"
      assert is_binary(auth_me_body["browser_session_id"])
      assert is_binary(auth_me_body["session_expires_at"])
      assert is_binary(auth_me_body["session_idle_timeout_at"])
    end
  end

  describe "WorkOS misconfiguration fails closed" do
    test "Workos.default_validator/2 with no client_id returns :workos_client_id_unset" do
      # Reset app env to simulate an unconfigured deploy.
      Application.put_env(:recurse_gateway, :workos,
        api_base: "https://api.workos.com"
        # no :client_id
      )

      assert {:error, :workos_client_id_unset} =
               Workos.default_validator("any.token.here", %{})
    end

    test "Workos.default_exchange/3 with no workos_response returns :workos_response_unset" do
      assert {:error, :workos_response_unset} =
               Workos.default_exchange("token", %{}, %{})
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

  defp decrypt_session_cookie(cookie_value) do
    case BrowserSessionPlug.decrypt_cookie(cookie_value) do
      {:ok, payload} -> payload
      {:error, :cookie_tampered} -> flunk("cookie ciphertext failed to decrypt")
    end
  end

  defp mint_workos_access_token(mock_issuer, claims) do
    MockOidcIssuer.mint_id_token(mock_issuer, claims, iss_override: workos_issuer(mock_issuer))
  end

  defp workos_issuer(mock_issuer) do
    String.trim_trailing(mock_issuer.issuer, "/") <> "/user_management/" <> @workos_client_id
  end

  # Generate a fresh ES256 keypair, write the private PEM to a tmp file
  # (the WorkOS adapter's `load_signing_key/1` reads PEM-on-disk), and
  # return the public JWK shape `JwtValidator` needs in `:known_kids`.
  defp mint_internal_signing_key do
    jwk = JOSE.JWK.generate_key({:ec, "P-256"})

    kid_seed = "internal-test-#{System.unique_integer([:positive])}"
    path = Path.join(System.tmp_dir!(), "#{kid_seed}.pem")

    {_, pem} = JOSE.JWK.to_pem(jwk)
    File.write!(path, pem)

    public_jwk =
      jwk
      |> JOSE.JWK.to_public()
      |> JOSE.JWK.to_map()
      |> elem(1)
      |> Map.put("kid", kid_seed)
      |> Map.put("use", "sig")
      |> Map.put("alg", "ES256")

    {path, kid_seed, public_jwk}
  end

  # Build the WorkOS LoginHandler opts shared by happy-path + new tests.
  # The `code_exchanger` is wrapped to point at the test MockHttpUpstream
  # rather than `api.workos.com`.
  defp workos_opts(workos_endpoint, mock_issuer) do
    [
      authorize_url: mock_issuer.issuer <> "/user_management/authorize",
      idp_token_url: MockHttpUpstream.url(workos_endpoint) <> "/user_management/authenticate",
      client_id: @workos_client_id,
      redirect_uri: @workos_redirect_uri,
      scope: "",
      tenant_id: @tenant_id_default,
      gateway_origin: @gateway_origin,
      finch_pool: :jwks_pool,
      auth_provider: "workos",
      authorize_extra_params: %{
        "provider" => "authkit",
        "organization_id" => @workos_default_org_id
      },
      code_exchanger: fn code, code_verifier, _config ->
        case Workos.exchange_code(code, code_verifier,
               api_key: @workos_api_key,
               client_id: @workos_client_id,
               redirect_uri: @workos_redirect_uri,
               api_base: MockHttpUpstream.url(workos_endpoint),
               finch_pool: :jwks_pool
             ) do
          {:ok, %{"access_token" => access_token} = resp} ->
            {:ok, access_token, %{workos_response: resp}}

          {:error, reason} ->
            {:error, reason}
        end
      end,
      id_token_validator: &Workos.default_validator/2,
      token_exchange: &Workos.default_exchange/3
    ]
  end

  # ---------------------------------------------------------------------------
  # GAN-fix tests (T-A through T-E from /tmp/r5e-gan-dogfood-deploy)
  # ---------------------------------------------------------------------------

  describe "GAN-fix #1 — post-login Cedar-gated endpoint reachability (T-A)" do
    test "after WorkOS sign-in, a Cedar-gated F004 audit endpoint is reachable", %{
      mock_issuer: mock_issuer,
      workos_endpoint: workos_endpoint,
      internal_public_jwk: internal_public_jwk
    } do
      # Install the providers + bundle + JwtValidator opts so Authz.gate/4
      # has everything it needs to evaluate Cedar against the
      # internal-JWT's principal.
      install_audit_plane_fixtures(internal_public_jwk)

      opts = workos_opts(workos_endpoint, mock_issuer)

      access_token =
        mint_workos_access_token(mock_issuer, %{
          "sub" => @workos_user_id,
          "aud" => @workos_client_id,
          "org_id" => @workos_default_org_id,
          "role" => "platform_operator"
        })

      stub_workos_authenticate(workos_endpoint, access_token)

      cookie_value = drive_login_callback(opts)

      # ----- Now hit a Cedar-gated audit endpoint with the cookie -----
      # `Authz.gate/4` extracts `Authorization: Bearer <jwt>` (lifted
      # from the cookie by BrowserSessionPlug), runs JwtValidator,
      # builds the IdentityContext, and evaluates Cedar. Pre-fix this
      # would have returned `{:error, :auth_failed, :malformed_principal}`
      # because the WorkOS access_token has no `principal` claim. With
      # the fix the cookie carries a broker-shaped internal JWT.
      gated_conn =
        Plug.Test.conn("GET", "/v1/audit/sessions/some-session-id")
        |> Plug.Test.put_req_cookie("r5e_session", cookie_value)
        |> BrowserSessionPlug.call(BrowserSessionPlug.init([]))

      refute gated_conn.halted, "BrowserSessionPlug should pass through the freshly-issued cookie"

      resource = %{
        type: "Recurse::Resource::ConsoleSurface",
        id: "session_timeline",
        attrs: %{"endpoint" => "/v1/audit/sessions/some-session-id"}
      }

      result = Authz.gate(gated_conn, "Recurse::Action::\"DashboardQuery\"", resource)

      # The load-bearing assertion: the gate did NOT fail with
      # `:malformed_principal` (the bug finding #1 guards against). It
      # should authenticate successfully + permit (platform_operator
      # has DashboardQuery in the policy bundle).
      assert {:ok, _conn, _ctx, _bundle_ref} = result
    end
  end

  describe "GAN-fix #2 — missing role claim fails closed (T-B)" do
    test "WorkOS access_token without `role` claim → outcome=no_role_claim, no cookie", %{
      mock_issuer: mock_issuer,
      workos_endpoint: workos_endpoint
    } do
      opts = workos_opts(workos_endpoint, mock_issuer)
      attach_ui_login_telemetry()

      # Mint an access_token WITHOUT a `role` claim — pre-fix this
      # silently fell through to `tenant_auditor`. Post-fix it MUST
      # fail with `outcome: "no_role_claim"`.
      access_token =
        mint_workos_access_token(mock_issuer, %{
          "sub" => @workos_user_id,
          "aud" => @workos_client_id,
          "org_id" => @workos_default_org_id
          # no "role" key
        })

      stub_workos_authenticate(workos_endpoint, access_token)

      out = drive_login_callback_raw(opts)

      assert out.status == 403
      assert JSON.decode!(out.resp_body) == %{"error" => "no_role_claim"}

      # No cookie set on failure.
      refute Enum.any?(out.resp_cookies, fn {name, _} -> name == "r5e_session" end)

      # `:ui_login` predicate carries the `no_role_claim` outcome AND
      # auth_provider="workos" (finding #7).
      assert_receive {:ui_login_emitted, meta}, 1_000
      assert meta.outcome == "no_role_claim"
      assert meta.auth_provider == "workos"
    end
  end

  describe "GAN-fix #5 — invalid role rejected before cookie issuance (T-C)" do
    test "WorkOS access_token with non-canonical role → outcome=invalid_role", %{
      mock_issuer: mock_issuer,
      workos_endpoint: workos_endpoint
    } do
      opts = workos_opts(workos_endpoint, mock_issuer)
      attach_ui_login_telemetry()

      # `superadmin` is not in the canonical Recurse-role allowlist.
      access_token =
        mint_workos_access_token(mock_issuer, %{
          "sub" => @workos_user_id,
          "aud" => @workos_client_id,
          "org_id" => @workos_default_org_id,
          "role" => "superadmin"
        })

      stub_workos_authenticate(workos_endpoint, access_token)

      out = drive_login_callback_raw(opts)

      assert out.status == 403
      assert JSON.decode!(out.resp_body) == %{"error" => "invalid_role"}

      refute Enum.any?(out.resp_cookies, fn {name, _} -> name == "r5e_session" end)

      assert_receive {:ui_login_emitted, meta}, 1_000
      assert meta.outcome == "invalid_role"
      assert meta.auth_provider == "workos"
    end
  end

  describe "GAN-fix #3 — WorkOS HTTP failure does not leak tokens (T-D)" do
    test "WorkOS authenticate returns 500 → outcome=idp_code_exchange_failed; no token in logs",
         %{
           mock_issuer: mock_issuer,
           workos_endpoint: workos_endpoint
         } do
      opts = workos_opts(workos_endpoint, mock_issuer)
      attach_ui_login_telemetry()

      # MockHttpUpstream returns 500 with a plausibly-shaped JSON body.
      # The sanitized log path MUST NOT log the body's contents — only
      # status + present-key names.
      MockHttpUpstream.expect(workos_endpoint, fn conn ->
        body =
          JSON.encode!(%{
            "error" => "internal_server_error",
            # Even if WorkOS leaked a token in an error body, we MUST
            # NOT log it.
            "access_token" => "eyJhbGciOiJSUzI1NiJ9.MUST_NOT_APPEAR_IN_LOGS.x"
          })

        conn
        |> Plug.Conn.put_resp_header("content-type", "application/json")
        |> Plug.Conn.send_resp(500, body)
      end)

      log =
        ExUnit.CaptureLog.capture_log(fn ->
          out = drive_login_callback_raw(opts)
          # Status will be 502 (idp_code_exchange_failed maps to 502).
          assert out.status == 502
          refute Enum.any?(out.resp_cookies, fn {name, _} -> name == "r5e_session" end)
        end)

      # Sanitized log assertion — sentinel substring NEVER appears.
      refute log =~ "MUST_NOT_APPEAR_IN_LOGS",
             "log line leaked WorkOS response body content: #{log}"

      assert_receive {:ui_login_emitted, %{outcome: outcome, auth_provider: "workos"}}, 1_000
      assert outcome in ["idp_code_exchange_failed", "idp_unreachable"]
    end
  end

  describe "GAN-fix #6 — boot-time WorkOS env-var validation (T-E)" do
    test "validate_browser_oidc_provider!/0 raises when provider=workos AND WORKOS_CLIENT_ID is unset" do
      # Save + simulate a misconfigured deploy: audit_console enabled,
      # provider=workos, but WORKOS_CLIENT_ID unset.
      prior_audit_console = Application.get_env(:recurse_gateway, :audit_console_enabled?)
      prior_idp = Application.get_env(:recurse_gateway, :browser_oidc_idp)
      prior_workos = Application.get_env(:recurse_gateway, :workos)

      try do
        Application.put_env(:recurse_gateway, :audit_console_enabled?, true)
        Application.put_env(:recurse_gateway, :browser_oidc_idp, provider: "workos")
        Application.put_env(:recurse_gateway, :workos, api_key: nil, client_id: nil)

        assert_raise RuntimeError,
                     ~r/WORKOS_CLIENT_ID|WORKOS_API_KEY|client_id|api_key/,
                     fn ->
                       RecurseGateway.Application.validate_browser_oidc_provider!()
                     end
      after
        restore(:audit_console_enabled?, prior_audit_console)
        restore(:browser_oidc_idp, prior_idp)
        restore(:workos, prior_workos)
      end
    end

    test "validate_browser_oidc_provider!/0 raises on unknown provider value" do
      prior_audit_console = Application.get_env(:recurse_gateway, :audit_console_enabled?)
      prior_idp = Application.get_env(:recurse_gateway, :browser_oidc_idp)

      try do
        Application.put_env(:recurse_gateway, :audit_console_enabled?, true)
        Application.put_env(:recurse_gateway, :browser_oidc_idp, provider: "worksos")

        assert_raise RuntimeError, ~r/unknown browser-OIDC provider|worksos/, fn ->
          RecurseGateway.Application.validate_browser_oidc_provider!()
        end
      after
        restore(:audit_console_enabled?, prior_audit_console)
        restore(:browser_oidc_idp, prior_idp)
      end
    end

    test "validate_browser_oidc_provider!/0 is no-op when audit_console disabled" do
      prior_audit_console = Application.get_env(:recurse_gateway, :audit_console_enabled?)

      try do
        Application.put_env(:recurse_gateway, :audit_console_enabled?, false)
        # Even with provider=workos AND no WORKOS env vars, this should
        # NOT raise — non-console deployments don't care.
        assert :ok == RecurseGateway.Application.validate_browser_oidc_provider!()
      after
        restore(:audit_console_enabled?, prior_audit_console)
      end
    end
  end

  describe "GAN-fix #4 — internal JWT TTL bound" do
    test "minted internal JWT carries TTL ≤ 15 minutes from issue", %{
      mock_issuer: mock_issuer,
      workos_endpoint: workos_endpoint
    } do
      opts = workos_opts(workos_endpoint, mock_issuer)

      access_token =
        mint_workos_access_token(mock_issuer, %{
          "sub" => @workos_user_id,
          "aud" => @workos_client_id,
          "org_id" => @workos_default_org_id,
          "role" => "tenant_auditor"
        })

      stub_workos_authenticate(workos_endpoint, access_token)
      now = System.system_time(:second)
      cookie_value = drive_login_callback(opts)

      payload = decrypt_session_cookie(cookie_value)

      [_, payload_b64, _] = String.split(payload[:jwt], ".")
      {:ok, jwt_payload_bytes} = Base.url_decode64(payload_b64, padding: false)
      {:ok, jwt_claims} = JSON.decode(jwt_payload_bytes)

      exp = jwt_claims["exp"]
      iat = jwt_claims["iat"]

      # TTL is 15 minutes (900s). Validate as a tight bound — finding
      # #4 documents this as the WorkOS-path replay-window cap.
      assert exp - iat == 900
      # iat is roughly "now" (allow 5s slop for test clock).
      assert_in_delta iat, now, 5
    end
  end

  describe "GAN round-2 #1 — TTL clamp" do
    # Round-2 finding: a misconfigured `INTERNAL_JWT_TTL_SECONDS` (or
    # `:internal_jwt, :ttl_seconds` app env) could silently widen the
    # WorkOS-path replay window past the 15-min documented bound.
    # The clamp lives in `Workos.parse_ttl/1` and raises on out-of-range.

    test "ttl_seconds=901 (1s past max) raises ArgumentError" do
      assert_raise ArgumentError, ~r/ttl_seconds out of bounds.*901/, fn ->
        Recurse.Gateway.Admin.BrowserAuth.Workos.parse_ttl(901)
      end
    end

    test "ttl_seconds=59 (1s below min) raises ArgumentError" do
      assert_raise ArgumentError, ~r/ttl_seconds out of bounds.*59/, fn ->
        Recurse.Gateway.Admin.BrowserAuth.Workos.parse_ttl(59)
      end
    end

    test "ttl_seconds=non-integer (e.g., binary) raises ArgumentError" do
      assert_raise ArgumentError, ~r/ttl_seconds out of bounds/, fn ->
        Recurse.Gateway.Admin.BrowserAuth.Workos.parse_ttl("900")
      end
    end

    test "ttl_seconds boundary values accepted" do
      assert 60 == Recurse.Gateway.Admin.BrowserAuth.Workos.parse_ttl(60)
      assert 900 == Recurse.Gateway.Admin.BrowserAuth.Workos.parse_ttl(900)
      assert 600 == Recurse.Gateway.Admin.BrowserAuth.Workos.parse_ttl(600)
    end
  end

  describe "GAN round-2 #2 — principal.issuer provenance (customer IdP, not internal)" do
    # Round-2 finding: principal.issuer was recording `cfg.issuer` (the
    # internal Recurse JWT issuer that wraps the WorkOS assertion) — but
    # receipts/audit need the IdP that ASSERTED the identity. WorkOS
    # adapter now derives it from the verified access_token's `iss`.
    # Cedar doesn't key on `principal.issuer` so this is a
    # forensic-correctness fix, not an authz one.

    test "internal JWT principal claim records WorkOS as issuer, not internal Recurse JWT issuer",
         %{
           mock_issuer: mock_issuer,
           workos_endpoint: workos_endpoint
         } do
      opts = workos_opts(workos_endpoint, mock_issuer)

      access_token =
        mint_workos_access_token(mock_issuer, %{
          "sub" => @workos_user_id,
          "aud" => @workos_client_id,
          "org_id" => @workos_default_org_id,
          "role" => "platform_operator"
        })

      stub_workos_authenticate(workos_endpoint, access_token)
      cookie_value = drive_login_callback(opts)
      payload = decrypt_session_cookie(cookie_value)

      [_, payload_b64, _] = String.split(payload[:jwt], ".")
      {:ok, jwt_payload_bytes} = Base.url_decode64(payload_b64, padding: false)
      {:ok, jwt_claims} = JSON.decode(jwt_payload_bytes)

      # The JWT envelope's `iss` is still the internal Recurse issuer
      # (the broker-shaped wrapper signed it). That's correct.
      assert jwt_claims["iss"] == @internal_jwt_issuer

      # But the principal CLAIM's issuer is DERIVED from the verified
      # access_token's `iss` claim — which in this test is the mock
      # WorkOS User Management issuer URL. NOT the hardcoded
      # `https://api.workos.com` constant; NOT the internal Recurse JWT
      # issuer.
      #
      # This mirrors broker precedent (RecurseBroker.TokenExchange uses
      # claims["iss"] from upstream tokens) and is regional-endpoint-safe
      # (works for `api.workos.eu` etc. without code changes).
      principal = jwt_claims["principal"]
      assert is_map(principal)

      assert principal["issuer"] == workos_issuer(mock_issuer),
             "principal.issuer must be the verified access_token's iss claim (#{workos_issuer(mock_issuer)}), got: #{inspect(principal["issuer"])}"

      # Sanity: the principal still carries the right shape for Cedar.
      assert principal["kind"] == "obo_human"
      assert principal["subject"] == @workos_user_id
      assert principal["tenant_id"] == @workos_default_org_id
      assert principal["recurse_role"] == "platform_operator"
    end
  end

  describe "GAN round-2 #3 — internal_jwt boot validation" do
    # Round-2 finding: `validate_workos_required_env!` only checked
    # WorkOS env, not the broker-signing-key the WorkOS adapter needs
    # to mint. Now `validate_internal_jwt_required_env!` covers that.

    test "missing :internal_jwt.signing_key_path raises at boot" do
      prior_audit = Application.get_env(:recurse_gateway, :audit_console_enabled?)
      prior_idp = Application.get_env(:recurse_gateway, :browser_oidc_idp)
      prior_workos = Application.get_env(:recurse_gateway, :workos)
      prior_internal = Application.get_env(:recurse_gateway, :internal_jwt)

      try do
        Application.put_env(:recurse_gateway, :audit_console_enabled?, true)
        Application.put_env(:recurse_gateway, :browser_oidc_idp, provider: "workos")

        Application.put_env(:recurse_gateway, :workos,
          client_id: "client_test",
          api_key: "sk_test"
        )

        Application.put_env(:recurse_gateway, :internal_jwt,
          signing_key_path: nil,
          audience: "x"
        )

        assert_raise RuntimeError, ~r/signing_key_path.*unset/i, fn ->
          RecurseGateway.Application.validate_browser_oidc_provider!()
        end
      after
        restore(:audit_console_enabled?, prior_audit)
        restore(:browser_oidc_idp, prior_idp)
        restore(:workos, prior_workos)
        restore(:internal_jwt, prior_internal)
      end
    end

    test "missing :internal_jwt.audience raises at boot" do
      prior_audit = Application.get_env(:recurse_gateway, :audit_console_enabled?)
      prior_idp = Application.get_env(:recurse_gateway, :browser_oidc_idp)
      prior_workos = Application.get_env(:recurse_gateway, :workos)
      prior_internal = Application.get_env(:recurse_gateway, :internal_jwt)

      # Use a real tempfile so signing_key_path passes the readable-regular-file
      # check, which lets us isolate the audience validator's behavior.
      tmp_pem =
        Path.join(
          System.tmp_dir!(),
          "audit-console-test-#{System.unique_integer([:positive])}.pem"
        )

      File.write!(
        tmp_pem,
        "-----BEGIN FAKE TEST KEY-----\nplaceholder\n-----END FAKE TEST KEY-----\n"
      )

      try do
        Application.put_env(:recurse_gateway, :audit_console_enabled?, true)
        Application.put_env(:recurse_gateway, :browser_oidc_idp, provider: "workos")

        Application.put_env(:recurse_gateway, :workos,
          client_id: "client_test",
          api_key: "sk_test"
        )

        Application.put_env(:recurse_gateway, :internal_jwt,
          signing_key_path: tmp_pem,
          audience: nil
        )

        assert_raise RuntimeError, ~r/audience.*unset/i, fn ->
          RecurseGateway.Application.validate_browser_oidc_provider!()
        end
      after
        File.rm(tmp_pem)
        restore(:audit_console_enabled?, prior_audit)
        restore(:browser_oidc_idp, prior_idp)
        restore(:workos, prior_workos)
        restore(:internal_jwt, prior_internal)
      end
    end
  end

  # ---------------------------------------------------------------------------
  # Test-helpers for the new gated-endpoint test
  # ---------------------------------------------------------------------------

  defp install_audit_plane_fixtures(internal_public_jwk) do
    bundle_path = write_bundle()

    entity_schema_path =
      Path.join([
        Application.app_dir(:recurse_gateway, "priv"),
        "cedar",
        "schema.cedarschema.json"
      ])

    {:ok, _} =
      start_supervised(
        Supervisor.child_spec(
          {BundleLoader,
           bundle_path: bundle_path,
           entity_schema_path: entity_schema_path,
           trap_sighup: false,
           name: nil},
          id: make_ref()
        )
      )

    ProviderRegistry.install_raw!(%{
      llm: {Recurse.Gateway.Test.StubLLM, %{}},
      ledger: {PostgresMerkleLedger, %{repo: Repo, pubsub: Recurse.PubSub, config: %{}}},
      storage: {Recurse.Gateway.Test.StubStorage, %{}},
      secrets: {Recurse.Gateway.Test.StubSecretsProvider, %{}},
      tenant_id: @tenant_id_default,
      signer: "observed://gateway/workos-test"
    })

    on_exit(fn -> ProviderRegistry.uninstall() end)

    prior_validator_opts = Application.get_env(:recurse_gateway, :jwt_validator_opts)

    Application.put_env(:recurse_gateway, :jwt_validator_opts,
      audience: @internal_jwt_audience,
      issuer: @internal_jwt_issuer,
      known_kids: [{internal_public_jwk["kid"], internal_public_jwk}]
    )

    on_exit(fn ->
      if prior_validator_opts do
        Application.put_env(:recurse_gateway, :jwt_validator_opts, prior_validator_opts)
      else
        Application.delete_env(:recurse_gateway, :jwt_validator_opts)
      end
    end)
  end

  defp write_bundle do
    source =
      Path.join([
        Application.app_dir(:recurse_gateway, "priv"),
        "reference_policies",
        "platform_roles.cedar"
      ])
      |> File.read!()

    path = Path.join(System.tmp_dir!(), "workos_bundle_#{System.unique_integer()}.cedar")
    File.write!(path, source)
    on_exit(fn -> File.rm(path) end)
    path
  end

  defp drive_login_callback(opts) do
    out = drive_login_callback_raw(opts)

    assert out.status == 302,
           "WorkOS callback failed (status=#{out.status}, body=#{inspect(out.resp_body)})"

    {_name, cookie_attrs} =
      Enum.find(out.resp_cookies, fn {name, _} -> name == "r5e_session" end) ||
        flunk("r5e_session cookie not set on success: #{inspect(out.resp_cookies)}")

    cookie_attrs.value
  end

  # Drive `/admin/login/start` → `/admin/login/callback` and return the
  # raw responded conn (so failure-path tests can assert status / body /
  # absence of cookie).
  defp drive_login_callback_raw(opts) do
    start_conn = build_conn("GET", "/admin/login/start", "return_to=/admin/dashboard")
    start_out = LoginHandler.call(start_conn, opts)
    assert start_out.status == 302

    [{"location", location}] = filter_headers(start_out.resp_headers, "location")

    state =
      location
      |> String.split("?", parts: 2)
      |> List.last()
      |> URI.decode_query()
      |> Map.fetch!("state")

    callback_conn = build_conn("GET", "/admin/login/callback", "state=#{state}&code=AUTHCODE")
    LoginHandler.call(callback_conn, opts)
  end

  defp stub_workos_authenticate(workos_endpoint, access_token) do
    MockHttpUpstream.expect(workos_endpoint, fn conn ->
      body =
        JSON.encode!(%{
          "user" => %{
            "id" => @workos_user_id,
            "email" => "operator@example.com",
            "first_name" => "Thomas",
            "last_name" => "Jones"
          },
          "organization_id" => @workos_default_org_id,
          "access_token" => access_token,
          "refresh_token" => "rt_dogfood_test_refresh",
          "authentication_method" => "Password"
        })

      conn
      |> Plug.Conn.put_resp_header("content-type", "application/json")
      |> Plug.Conn.send_resp(200, body)
    end)
  end

  defp attach_ui_login_telemetry do
    test_pid = self()
    handler_id = "workos-ui-login-#{System.unique_integer()}"

    :telemetry.attach(
      handler_id,
      UiReceipts.telemetry_event(),
      fn _event, _measurements, meta, _config ->
        if meta[:event_kind] == :ui_login do
          send(test_pid, {:ui_login_emitted, meta})
        end
      end,
      nil
    )

    on_exit(fn -> :telemetry.detach(handler_id) end)
  end

  defp restore(key, nil), do: Application.delete_env(:recurse_gateway, key)
  defp restore(key, value), do: Application.put_env(:recurse_gateway, key, value)
end
