defmodule RecurseBroker.EndpointContractTest do
  @moduledoc """
  Endpoint contract tests (F002 T081).

  Straight ExUnit contract test — no property generation. Covers every
  endpoint documented in `contracts/recurse_broker_api.md` against
  `RecurseBroker.Endpoint.call/2` via `Plug.Test`. Drives the plug directly
  rather than booting a Bandit port so each test runs in-process with no
  socket orchestration.

  ## Endpoints covered

    * `GET /healthz`
    * `GET /oidc/jwks`
    * `POST /token/exchange` — twelve scenarios per the contract:
        1. Happy path (200 + all RFC 8693 fields).
        2. Wrong grant_type → 400 `unsupported_grant_type`.
        3. Missing subject_token → 400 `invalid_request`.
        4. Unknown subject_token_type → 400 `invalid_subject_token_type`.
        5. Audience mismatch → 400 `invalid_request` (description ~= "audience").
        6. Subject_token signature invalid → 401 `invalid_subject_token`.
        7. Subject_token expired → 401 `invalid_subject_token`.
        8. No role match + no default → 403 `unauthorized_client`.
        9. JWKS fetch failure → 503 `temporarily_unavailable`.
    * `GET /unknown/path` → 404 (catch-all).

  ## `async: false` — documented seams

  This test:

    * Mutates `Application.put_env(:recurse_broker, ...)` for every
      scenario's role-mapping / issuer / audience config.
    * Starts `RecurseBroker.JWT.KeyRing` and `RecurseBroker.OIDC.DiscoveryCache`
      GenServers under their module-registered names.

  Either of those alone would require serial execution; together they
  make `async: false` unambiguous. `on_exit` restores app env.

  ## Cross-references

    * `specs/002-standalone-gateway-vertical-slice/contracts/recurse_broker_api.md`
    * `specs/002-standalone-gateway-vertical-slice/tasks.md` T081
    * `apps/recurse_broker/lib/recurse_broker/endpoint.ex`
  """

  use ExUnit.Case, async: false

  alias RecurseBroker.Endpoint
  alias RecurseBroker.OIDC.DiscoveryCache
  alias RecurseBroker.Test.MockOidcIssuer
  alias RecurseBroker.Test.SupervisorHelper

  @broker_audience "recurse-gateway-test"
  @broker_issuer "https://broker.recurse.test"
  @interactive_aud @broker_audience <> "-interactive"

  @endpoint_opts Endpoint.init([])

  @mapping_with_all_three_roles %{
    group_to_recurse_role: %{
      "cn=recurse-operators,ou=groups,dc=corp,dc=example" => "platform_operator",
      "cn=recurse-auditors,ou=groups,dc=corp,dc=example" => "tenant_auditor",
      "cn=recurse-users,ou=groups,dc=corp,dc=example" => "caller"
    },
    default_recurse_role: "caller",
    role_privilege_order: ["platform_operator", "tenant_auditor", "caller"]
  }

  # No default → "no role match" path reaches :no_role_match_no_default.
  @mapping_no_default %{
    group_to_recurse_role: %{
      "cn=recurse-operators,ou=groups,dc=corp,dc=example" => "platform_operator"
    },
    default_recurse_role: nil,
    role_privilege_order: ["platform_operator", "tenant_auditor", "caller"]
  }

  setup do
    mock_issuer = MockOidcIssuer.new()

    # `RecurseBroker.Application` auto-starts KeyRing + DiscoveryCache
    # under their module-registered names (see
    # `lib/recurse_broker/application.ex`). We can't call
    # `start_supervised!` on the SAME registered names — that raises
    # `:already_started`. Instead we stop the auto-started processes
    # first, then re-start under the ExUnit supervisor with our test
    # configuration (Req `plug:` DI, ephemeral keypair).
    :ok = SupervisorHelper.stop_auto_started(RecurseBroker.OIDC.DiscoveryCache)
    :ok = SupervisorHelper.stop_auto_started(RecurseBroker.JWT.KeyRing)

    start_supervised!({RecurseBroker.JWT.KeyRing, generate_ephemeral?: true})

    jwks_plug = MockOidcIssuer.jwks_plug_fn(mock_issuer)
    start_supervised!({DiscoveryCache, req_opts: [plug: jwks_plug]})

    previous_env = swap_broker_env(@mapping_with_all_three_roles, mock_issuer.issuer)
    on_exit(fn -> restore_broker_env(previous_env) end)

    %{mock_issuer: mock_issuer}
  end

  # ---------------------------------------------------------------------------
  # GET /healthz
  # ---------------------------------------------------------------------------

  describe "GET /healthz" do
    test "returns 200 with status + version fields" do
      conn =
        :get
        |> Plug.Test.conn("/healthz")
        |> Endpoint.call(@endpoint_opts)

      assert conn.status == 200
      decoded = JSON.decode!(conn.resp_body)
      assert decoded["status"] == "ok"
      assert is_binary(decoded["version"])
    end
  end

  # ---------------------------------------------------------------------------
  # GET /oidc/jwks
  # ---------------------------------------------------------------------------

  describe "GET /oidc/jwks" do
    test "returns 200 with at least one ES256 signing key" do
      conn =
        :get
        |> Plug.Test.conn("/oidc/jwks")
        |> Endpoint.call(@endpoint_opts)

      assert conn.status == 200

      %{"keys" => keys} = JSON.decode!(conn.resp_body)
      assert is_list(keys) and keys != []

      Enum.each(keys, fn key ->
        assert is_binary(key["kid"])
        assert key["kty"] == "EC"
        assert key["alg"] == "ES256"
        assert key["use"] == "sig"
      end)
    end
  end

  # ---------------------------------------------------------------------------
  # POST /token/exchange
  # ---------------------------------------------------------------------------

  describe "POST /token/exchange — happy path" do
    test "valid id_token + audience match → 200 RFC-8693 body",
         %{mock_issuer: mock_issuer} do
      id_token =
        MockOidcIssuer.mint_id_token(mock_issuer, %{
          "sub" => "auth0|alice",
          "aud" => @interactive_aud,
          "groups" => ["cn=recurse-operators,ou=groups,dc=corp,dc=example"]
        })

      conn = exchange(id_token, @broker_audience)

      assert conn.status == 200

      decoded = JSON.decode!(conn.resp_body)
      assert is_binary(decoded["access_token"])
      assert decoded["issued_token_type"] == "urn:ietf:params:oauth:token-type:jwt"
      assert decoded["token_type"] == "Bearer"
      assert decoded["expires_in"] == 900
    end
  end

  describe "POST /token/exchange — RFC-6749 error responses" do
    test "wrong grant_type → 400 unsupported_grant_type", %{mock_issuer: mock_issuer} do
      id_token = valid_id_token(mock_issuer)

      conn =
        exchange_with_form(%{
          "grant_type" => "client_credentials",
          "subject_token" => id_token,
          "subject_token_type" => "urn:ietf:params:oauth:token-type:id_token",
          "audience" => @broker_audience
        })

      assert conn.status == 400
      assert %{"error" => "unsupported_grant_type"} = JSON.decode!(conn.resp_body)
    end

    test "missing subject_token → 400 invalid_request" do
      conn =
        exchange_with_form(%{
          "grant_type" => "urn:ietf:params:oauth:grant-type:token-exchange",
          "subject_token_type" => "urn:ietf:params:oauth:token-type:id_token",
          "audience" => @broker_audience
        })

      assert conn.status == 400
      decoded = JSON.decode!(conn.resp_body)
      assert decoded["error"] == "invalid_request"
    end

    test "unknown subject_token_type → 400 invalid_subject_token_type",
         %{mock_issuer: mock_issuer} do
      id_token = valid_id_token(mock_issuer)

      conn =
        exchange_with_form(%{
          "grant_type" => "urn:ietf:params:oauth:grant-type:token-exchange",
          "subject_token" => id_token,
          "subject_token_type" => "urn:ietf:params:oauth:token-type:access_token",
          "audience" => @broker_audience
        })

      assert conn.status == 400
      assert %{"error" => "invalid_subject_token_type"} = JSON.decode!(conn.resp_body)
    end

    test "audience mismatch → 400 invalid_request (description mentions 'audience')",
         %{mock_issuer: mock_issuer} do
      id_token = valid_id_token(mock_issuer)

      conn = exchange(id_token, "some-other-audience")

      assert conn.status == 400
      decoded = JSON.decode!(conn.resp_body)
      assert decoded["error"] == "invalid_request"
      assert is_binary(decoded["error_description"])
      assert decoded["error_description"] =~ ~r/audience/i
    end

    test "subject_token signature invalid → 401 invalid_subject_token",
         %{mock_issuer: mock_issuer} do
      # Mint a token under an UNRELATED issuer so its signature won't
      # verify against the mock issuer's JWKS advertised in setup.
      alien_issuer = MockOidcIssuer.new(issuer: mock_issuer.issuer, kid: mock_issuer.kid)

      # Force the kid to collide with the mock issuer's kid so the
      # broker looks up the *mock* issuer's key from its JWKS — but
      # the signature was made with the *alien* issuer's private key,
      # so verification fails.
      alien_token =
        MockOidcIssuer.mint_id_token(alien_issuer, %{
          "sub" => "auth0|alice",
          "aud" => @interactive_aud
        })

      conn = exchange(alien_token, @broker_audience)

      assert conn.status == 401
      assert %{"error" => "invalid_subject_token"} = JSON.decode!(conn.resp_body)
    end

    test "subject_token expired → 401 invalid_subject_token",
         %{mock_issuer: mock_issuer} do
      past = System.system_time(:second) - 10_000

      expired_token =
        MockOidcIssuer.mint_id_token(mock_issuer, %{
          "sub" => "auth0|alice",
          "aud" => @interactive_aud,
          "iat" => past,
          "nbf" => past,
          "exp" => past + 60
        })

      conn = exchange(expired_token, @broker_audience)

      assert conn.status == 401
      assert %{"error" => "invalid_subject_token"} = JSON.decode!(conn.resp_body)
    end

    test "no role match + no default → 403 unauthorized_client",
         %{mock_issuer: mock_issuer} do
      # Swap the mapping to one with no default so a missing group
      # match rejects rather than falling back.
      previous_env = swap_broker_env(@mapping_no_default, mock_issuer.issuer)
      on_exit(fn -> restore_broker_env(previous_env) end)

      # Caller with no recognized group + no default role.
      id_token =
        MockOidcIssuer.mint_id_token(mock_issuer, %{
          "sub" => "auth0|unknown",
          "aud" => @interactive_aud,
          "groups" => ["cn=random-other-group,ou=groups,dc=corp,dc=example"]
        })

      conn = exchange(id_token, @broker_audience)

      assert conn.status == 403
      assert %{"error" => "unauthorized_client"} = JSON.decode!(conn.resp_body)
    end

    test "JWKS fetch failure → 503 temporarily_unavailable",
         %{mock_issuer: _mock_issuer} do
      # Stop the DiscoveryCache and re-start with a plug that always
      # 500s the JWKS fetch.
      :ok = stop_supervised(DiscoveryCache)

      failing_issuer = MockOidcIssuer.new()

      failing_plug =
        MockOidcIssuer.jwks_plug_fn(failing_issuer,
          response: {:error, 500, ~s|{"error":"upstream_oidc_down"}|}
        )

      start_supervised!({DiscoveryCache, req_opts: [plug: failing_plug]})

      # Re-swap broker env to point at the failing issuer.
      previous_env = swap_broker_env(@mapping_with_all_three_roles, failing_issuer.issuer)
      on_exit(fn -> restore_broker_env(previous_env) end)

      id_token =
        MockOidcIssuer.mint_id_token(failing_issuer, %{
          "sub" => "auth0|alice",
          "aud" => @interactive_aud
        })

      conn = exchange(id_token, @broker_audience)

      assert conn.status == 503
      assert %{"error" => "temporarily_unavailable"} = JSON.decode!(conn.resp_body)
    end
  end

  # ---------------------------------------------------------------------------
  # Unknown path
  # ---------------------------------------------------------------------------

  describe "catch-all" do
    test "GET /unknown/path → 404" do
      conn =
        :get
        |> Plug.Test.conn("/unknown/path")
        |> Endpoint.call(@endpoint_opts)

      assert conn.status == 404
      assert JSON.decode!(conn.resp_body) == %{"error" => "not_found"}
    end
  end

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  defp exchange(id_token, audience) do
    exchange_with_form(%{
      "grant_type" => "urn:ietf:params:oauth:grant-type:token-exchange",
      "subject_token" => id_token,
      "subject_token_type" => "urn:ietf:params:oauth:token-type:id_token",
      "audience" => audience
    })
  end

  defp exchange_with_form(form_map) do
    body = URI.encode_query(form_map)

    :post
    |> Plug.Test.conn("/token/exchange", body)
    |> Plug.Conn.put_req_header("content-type", "application/x-www-form-urlencoded")
    |> Endpoint.call(@endpoint_opts)
  end

  defp valid_id_token(mock_issuer) do
    MockOidcIssuer.mint_id_token(mock_issuer, %{
      "sub" => "auth0|alice",
      "aud" => @interactive_aud,
      "groups" => ["cn=recurse-users,ou=groups,dc=corp,dc=example"]
    })
  end

  defp swap_broker_env(mapping, issuer_url) do
    previous = %{
      expected_audience: Application.get_env(:recurse_broker, :expected_audience),
      broker_issuer: Application.get_env(:recurse_broker, :broker_issuer),
      role_mapping: Application.get_env(:recurse_broker, :role_mapping),
      oidc_validator_opts: Application.get_env(:recurse_broker, :oidc_validator_opts)
    }

    Application.put_env(:recurse_broker, :expected_audience, @broker_audience)
    Application.put_env(:recurse_broker, :broker_issuer, @broker_issuer)
    Application.put_env(:recurse_broker, :role_mapping, mapping)

    # The TokenExchange plug passes `:oidc_validator_opts` directly to
    # `RecurseBroker.OIDC.Validator.validate_id_token/2`. The validator
    # requires `:issuer` (customer-IdP's `iss`) and `:audience`
    # (id_token's `aud`) as keyword options. See
    # `lib/recurse_broker/oidc/validator.ex` for the full opts schema.
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
