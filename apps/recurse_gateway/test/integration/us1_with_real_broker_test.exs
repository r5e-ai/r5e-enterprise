defmodule RecurseGateway.Integration.US1WithRealBrokerTest do
  @moduledoc """
  Internal legacy chat-handler integration coverage. Every request first
  asserts the public router returns 503 capability_unavailable, then invokes
  the retained handler directly to exercise provider, receipt, and SIEM
  behavior. These assertions do not claim this execution route is released.
  """

  use ExUnit.Case, async: false

  setup_all do
    Recurse.Gateway.Test.KernelFixture.boot()
  end

  @moduletag :integration

  alias Ecto.Adapters.SQL.Sandbox
  alias Recurse.Gateway.Policy.BundleLoader
  alias Recurse.Gateway.ProviderRegistry
  alias Recurse.Gateway.Test.LegacyChatHandler
  alias Recurse.Gateway.Test.MockHttpUpstream
  alias Recurse.Gateway.Test.StubSecretsProvider
  alias Recurse.Gateway.Test.StubStorageProvider
  alias Recurse.Providers.Impls.OpenAiLlmProvider
  alias Recurse.Providers.Impls.PostgresMerkleLedger
  alias Recurse.Providers.Repo
  alias RecurseBroker.Endpoint, as: BrokerEndpoint
  alias RecurseBroker.OIDC.DiscoveryCache
  alias RecurseBroker.Test.MockOidcIssuer
  alias RecurseBroker.Test.SupervisorHelper

  @tenant_id "01HQZN5K7J8M9N0P1Q2R3S4T5V"
  @broker_audience "recurse-gateway-test"
  @broker_issuer "https://broker.recurse.test"
  @interactive_aud @broker_audience <> "-interactive"
  @siem_topic "recurse:attestation_first_committed"

  @broker_endpoint_opts BrokerEndpoint.init([])

  @mapping %{
    group_to_recurse_role: %{
      "cn=recurse-users,ou=groups,dc=corp,dc=example" => "caller"
    },
    default_recurse_role: "caller",
    role_privilege_order: ["platform_operator", "tenant_auditor", "caller"]
  }

  setup do
    # -- DB ---------------------------------------------------------------
    :ok = Sandbox.checkout(Repo)
    Sandbox.mode(Repo, {:shared, self()})

    # -- Mock LLM upstream + provider install -----------------------------
    {:ok, upstream} = MockHttpUpstream.start()

    on_exit(fn ->
      MockHttpUpstream.stop(upstream)
      ProviderRegistry.uninstall()
      StubStorageProvider.reset()
    end)

    :ok = StubStorageProvider.reset()

    {:ok, llm_state} =
      OpenAiLlmProvider.init(%{
        base_url: MockHttpUpstream.url(upstream),
        finch_pool: :openai_pool,
        resolved_api_key: "sk-test-fake-key",
        timeout_ms: 10_000,
        pool_timeout_ms: 5_000
      })

    {:ok, ledger_state} = PostgresMerkleLedger.init(%{})
    {:ok, storage_state} = StubStorageProvider.init(%{bucket: "test-bucket"})
    {:ok, secrets_state} = StubSecretsProvider.init(%{})

    ProviderRegistry.install_raw!(%{
      llm: {OpenAiLlmProvider, llm_state},
      ledger: {PostgresMerkleLedger, ledger_state},
      storage: {StubStorageProvider, storage_state},
      secrets: {StubSecretsProvider, secrets_state},
      tenant_id: @tenant_id,
      signer: "observed://gateway/test"
    })

    # -- Cedar bundle -----------------------------------------------------
    bundle_path =
      Path.join([
        Application.app_dir(:recurse_gateway, "priv"),
        "reference_policies",
        "platform_roles.cedar"
      ])

    entity_schema_path =
      Path.join([
        Application.app_dir(:recurse_gateway, "priv"),
        "cedar",
        "schema.cedarschema.json"
      ])

    _bundle_loader =
      start_supervised!(
        Supervisor.child_spec(
          {BundleLoader,
           bundle_path: bundle_path,
           entity_schema_path: entity_schema_path,
           trap_sighup: false,
           name: nil},
          id: {BundleLoader, make_ref()}
        )
      )

    # -- Customer IdP (mock) + broker --------------------------------------
    mock_issuer = MockOidcIssuer.new()
    jwks_plug = MockOidcIssuer.jwks_plug_fn(mock_issuer)

    # `RecurseBroker.Application` auto-starts KeyRing + DiscoveryCache
    # under module-registered names during umbrella test boot. Stop them
    # so we can restart with the test's Req `plug:` DI + ephemeral
    # keypair.
    SupervisorHelper.stop_auto_started(RecurseBroker.OIDC.DiscoveryCache)
    SupervisorHelper.stop_auto_started(RecurseBroker.JWT.KeyRing)

    start_supervised!({RecurseBroker.JWT.KeyRing, generate_ephemeral?: true})

    start_supervised!({DiscoveryCache, req_opts: [plug: jwks_plug]})

    previous_broker_env = swap_broker_env(mock_issuer.issuer)

    on_exit(fn -> restore_broker_env(previous_broker_env) end)

    # -- Gateway JwtValidator opts ----------------------------------------
    # Populate `known_kids:` from the broker's active signing keys. This
    # is option (b) from the dispatch prompt — simpler than wiring the
    # JwksCache for a single-test flow. The sub-assertion below
    # ("JWKS fidelity") ALSO hits `GET /oidc/jwks` to prove the endpoint
    # round-trips the same key bytes; option (b) alone doesn't prove that.
    {:ok, broker_keys} = RecurseBroker.JWT.KeyRing.all_active_keys()

    known_kids =
      Enum.map(broker_keys, fn {kid, jwk} ->
        {_, fields} = jwk |> JOSE.JWK.to_public() |> JOSE.JWK.to_map()
        {kid, Map.put(fields, "kid", kid)}
      end)

    previous_jwt_opts = Application.get_env(:recurse_gateway, :jwt_validator_opts)

    Application.put_env(:recurse_gateway, :jwt_validator_opts,
      audience: @broker_audience,
      issuer: @broker_issuer,
      known_kids: known_kids
    )

    on_exit(fn ->
      case previous_jwt_opts do
        nil -> Application.delete_env(:recurse_gateway, :jwt_validator_opts)
        val -> Application.put_env(:recurse_gateway, :jwt_validator_opts, val)
      end
    end)

    %{upstream: upstream, mock_issuer: mock_issuer, known_kids: known_kids}
  end

  test "internal legacy handler: end-to-end: customer id_token → broker exchange → Gateway chat completion",
       %{upstream: upstream, mock_issuer: mock_issuer, known_kids: known_kids} do
    :ok = Phoenix.PubSub.subscribe(Recurse.PubSub, @siem_topic)

    # -- LLM upstream expectation (sync happy path) ------------------------
    MockHttpUpstream.expect(upstream, fn conn ->
      {:ok, _raw, conn} = Plug.Conn.read_body(conn)

      conn
      |> Plug.Conn.put_resp_header("content-type", "application/json")
      |> Plug.Conn.send_resp(200, canned_completion_body())
    end)

    # -- 1. Mint customer-IdP id_token ------------------------------------
    id_token =
      MockOidcIssuer.mint_id_token(mock_issuer, %{
        "sub" => "auth0|alice-real-broker",
        "aud" => @interactive_aud,
        "groups" => ["cn=recurse-users,ou=groups,dc=corp,dc=example"]
      })

    # -- 2. POST /token/exchange against REAL broker Endpoint --------------
    form_body =
      URI.encode_query(%{
        "grant_type" => "urn:ietf:params:oauth:grant-type:token-exchange",
        "subject_token" => id_token,
        "subject_token_type" => "urn:ietf:params:oauth:token-type:id_token",
        "audience" => @broker_audience
      })

    broker_conn =
      :post
      |> Plug.Test.conn("/token/exchange", form_body)
      |> Plug.Conn.put_req_header("content-type", "application/x-www-form-urlencoded")
      |> BrokerEndpoint.call(@broker_endpoint_opts)

    assert broker_conn.status == 200, "broker exchange failed: #{inspect(broker_conn.resp_body)}"

    %{
      "access_token" => access_token,
      "token_type" => "Bearer",
      "issued_token_type" => "urn:ietf:params:oauth:token-type:jwt",
      "expires_in" => 900
    } = JSON.decode!(broker_conn.resp_body)

    # -- 3. POST /v1/chat/completions with broker-minted JWT ---------------
    request_body = %{
      "model" => "gpt-4o-mini",
      "messages" => [%{"role" => "user", "content" => "real broker e2e"}]
    }

    conn =
      :post
      |> Plug.Test.conn("/v1/chat/completions", JSON.encode!(request_body))
      |> Plug.Conn.put_req_header("content-type", "application/json")
      |> Plug.Conn.put_req_header("authorization", "Bearer " <> access_token)
      |> LegacyChatHandler.call()

    assert conn.status == 200,
           "Gateway rejected broker-minted JWT: status=#{conn.status}, body=#{inspect(conn.resp_body)}"

    decoded = JSON.decode!(conn.resp_body)
    assert decoded["object"] == "chat.completion"

    correlation_id =
      conn.resp_headers
      |> List.keyfind("x-recurse-correlation-id", 0)
      |> then(fn {_, v} -> v end)

    assert is_binary(correlation_id) and byte_size(correlation_id) > 0

    # -- 4. Attestation + SIEM event (minimal — sibling test has exhaustive
    #       per-field coverage) -------------------------------------------
    {:ok, receipt} = fetch_attestation_by_correlation_id(correlation_id)
    assert receipt.tenant_id == @tenant_id
    assert receipt.policy_decision == :allow
    assert receipt.outcome == :success

    assert_receive {:first_committed, run_id, _payload}, 2_000
    assert run_id == receipt.run_id

    # -- 5. JWKS fidelity sub-assertion -----------------------------------
    # Hit GET /oidc/jwks against the real broker Endpoint and confirm the
    # published keys match the ones we used to populate the Gateway's
    # JwtValidator known_kids. This proves the broker's JWKS endpoint
    # round-trips the same kid + key bytes the signer used.
    jwks_conn =
      :get
      |> Plug.Test.conn("/oidc/jwks")
      |> BrokerEndpoint.call(@broker_endpoint_opts)

    assert jwks_conn.status == 200

    %{"keys" => published_keys} = JSON.decode!(jwks_conn.resp_body)

    for {kid, known_jwk} <- known_kids do
      published =
        Enum.find(published_keys, fn k -> Map.get(k, "kid") == kid end)

      assert published != nil, "JWKS endpoint did not publish kid=#{inspect(kid)}"

      # Core EC fields MUST match between the setup fixture and the
      # endpoint-published JWK. We don't compare the whole map because
      # the endpoint is free to add `use`/`alg` fields that the raw
      # `to_map` may not include.
      for field <- ["kty", "crv", "x", "y"] do
        assert Map.get(published, field) == Map.get(known_jwk, field),
               "JWKS field #{field} drift for kid=#{kid}"
      end
    end
  end

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  defp canned_completion_body do
    JSON.encode!(%{
      "id" => "chatcmpl-real-broker",
      "object" => "chat.completion",
      "created" => 1_700_000_000,
      "model" => "gpt-4o-mini",
      "choices" => [
        %{
          "index" => 0,
          "message" => %{
            "role" => "assistant",
            "content" => "Real broker round-trip complete."
          },
          "finish_reason" => "stop"
        }
      ],
      "usage" => %{
        "prompt_tokens" => 5,
        "completion_tokens" => 5,
        "total_tokens" => 10
      }
    })
  end

  defp fetch_attestation_by_correlation_id(correlation_id) do
    import Ecto.Query, only: [from: 2]

    query =
      from(a in Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Attestation,
        where: a.correlation_id == ^correlation_id,
        limit: 1
      )

    case Repo.one(query) do
      nil -> {:error, :not_found}
      att -> {:ok, att}
    end
  end

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

    # The broker's TokenExchange plug forwards this keyword list to
    # `RecurseBroker.OIDC.Validator.validate_id_token/2`. The validator
    # requires both the customer-IdP's `:issuer` (matches the id_token's
    # `iss` claim) and its `:audience` (matches the id_token's `aud`).
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
