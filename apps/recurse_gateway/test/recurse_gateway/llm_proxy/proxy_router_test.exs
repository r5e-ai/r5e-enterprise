defmodule Recurse.Gateway.LlmProxy.ProxyRouterTest do
  @moduledoc """
  Routing-layer tests for `Recurse.Gateway.LlmProxy.ProxyRouter`.

  Spec source: `specs/009-llm-api-proxy/contracts/streaming_proxy.md`
  §"Routing" + tasks.md T027/T028/T032.

  These tests exercise the dispatch decision tree:

    * `auth.openai.com` Host → `AuthPassthrough.proxy/2`
    * Other configured hostname → `StreamingProxy.proxy/2` (HTTPS+SSE)
      OR `WebSocketBridge.upgrade/2` (WS upgrade)
    * Unknown hostname → 502 ERR_NO_UPSTREAM_CONFIG

  We mock `UpstreamResolver` so the router can be exercised without
  touching the real LlmProviderConfig table.

  The actual end-to-end forwarding paths are covered by the
  individual module tests; this file verifies the dispatch rules.
  """

  use ExUnit.Case, async: false

  alias Ecto.Adapters.SQL.Sandbox
  alias Recurse.Gateway.LlmProxy.ProxyRouter
  alias Recurse.Gateway.Policy.Active
  alias Recurse.Gateway.PolicyBundleRef
  alias Recurse.Gateway.Test.{KernelFixture, MockHttpUpstream}
  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Tenant
  alias Recurse.Providers.Repo
  alias Recurse.Providers.Schemas.LlmProviderConfig
  alias Recurse.Shared.Ulid

  setup_all do
    :ok = KernelFixture.boot()
    activate_permit_all()
  end

  defp activate_permit_all do
    source = "permit(principal, action, resource);"
    hash = Recurse.Cedar.canonical_hash(source)

    Active.update(%Active{
      source: :filesystem,
      source_ref: "proxy-router-test",
      loaded_at: DateTime.utc_now(),
      bundle: %PolicyBundleRef{
        bundle_id: Base.encode16(hash, case: :lower),
        canonical_hash: hash,
        loaded_at: DateTime.utc_now(),
        evaluator_handle: source,
        bundle_bytes: source
      }
    })
  end

  setup do
    :ok = Sandbox.checkout(Repo)
    Sandbox.mode(Repo, {:shared, self()})

    keys = [:llm_proxy_default_upstream_host, :llm_proxy_fallback_unknown_hosts]
    prior = Map.new(keys, &{&1, Application.get_env(:recurse_gateway, &1)})
    Enum.each(keys, &Application.delete_env(:recurse_gateway, &1))

    on_exit(fn ->
      Enum.each(prior, fn
        {key, nil} -> Application.delete_env(:recurse_gateway, key)
        {key, value} -> Application.put_env(:recurse_gateway, key, value)
      end)
    end)

    :ok
  end

  defp new_tenant do
    tenant_id = "01TEN_ROUTER_" <> Ulid.generate()

    %Tenant{}
    |> Tenant.changeset(%{
      tenant_id: tenant_id,
      display_name: "ProxyRouterTest tenant",
      tier: :standalone_gateway,
      created_at: DateTime.utc_now()
    })
    |> Repo.insert!()

    tenant_id
  end

  defp insert_config(tenant_id, attrs) do
    base = %{
      tenant_id: tenant_id,
      provider: "anthropic",
      upstream_host: "api.anthropic.com",
      upstream_port: 443,
      transport_modes: ["https-sse"],
      auth_mode: :passthrough,
      api_format: :anthropic_messages,
      enabled: true,
      metadata: %{"scheme" => "https"}
    }

    %LlmProviderConfig{}
    |> LlmProviderConfig.changeset(Map.merge(base, attrs))
    |> Repo.insert!()
  end

  defp set_default(host) do
    Application.put_env(:recurse_gateway, :llm_proxy_default_upstream_host, host)
  end

  describe "/healthz and /readyz" do
    test "GET /healthz returns 200" do
      conn = Plug.Test.conn(:get, "/healthz")
      result = ProxyRouter.call(conn, ProxyRouter.init([]))

      assert result.status == 200
      assert result.resp_body == "ok"
    end

    test "GET /readyz reports mandatory admission and only permits the documented JWKS warmup" do
      conn = Plug.Test.conn(:get, "/readyz")
      result = ProxyRouter.call(conn, ProxyRouter.init([]))

      body = JSON.decode!(result.resp_body)
      assert body["checks"]["admission"] == "ready"
      assert body["checks"]["policy_bundle"] == "ready"
      assert body["checks"]["db_pool"] == "ready"
      assert body["checks"]["llm_pool"] == "ready"

      case result.status do
        200 ->
          assert body["ready"] == true

        503 ->
          assert body["ready"] == false
          assert body["checks"]["jwks_warm"] =~ "pending:"
          assert Enum.count(body["checks"], fn {_name, value} -> value != "ready" end) == 1
      end
    end
  end

  describe "unknown Host header → 502 ERR_NO_UPSTREAM_CONFIG" do
    test "no LlmProviderConfig matches → 502 with structured error body" do
      conn =
        Plug.Test.conn(:post, "/v1/responses", "{}")
        |> Map.put(:host, "unknown.example.com")
        |> Plug.Conn.put_req_header("x-recurse-tenant-id", "01TEN_TEST")

      result = ProxyRouter.call(conn, ProxyRouter.init([]))

      assert result.status == 502
      body = result.resp_body
      assert body =~ "ERR_NO_UPSTREAM_CONFIG"
      assert body =~ "no_config_for_host"
    end
  end

  describe "auth.openai.com special case (T032)" do
    test "passthrough_host?/1 matches auth.openai.com (case-insensitive)" do
      assert Recurse.Gateway.LlmProxy.AuthPassthrough.passthrough_host?("auth.openai.com")
      assert Recurse.Gateway.LlmProxy.AuthPassthrough.passthrough_host?("AUTH.OPENAI.COM")
      refute Recurse.Gateway.LlmProxy.AuthPassthrough.passthrough_host?("api.openai.com")
      refute Recurse.Gateway.LlmProxy.AuthPassthrough.passthrough_host?("chatgpt.com")
      refute Recurse.Gateway.LlmProxy.AuthPassthrough.passthrough_host?(nil)
    end
  end

  describe "WebSocket upgrade detection" do
    # The actual dispatch is tested end-to-end in
    # `web_socket_bridge_test.exs`; here we verify the detection
    # predicate is correct.

    test "Connection: upgrade + Upgrade: websocket → recognized" do
      # The router's `websocket_upgrade?/1` is private; we exercise it
      # indirectly by confirming a 502 (no config for unknown host)
      # path runs even when WS headers present (no dispatch confusion).
      conn =
        Plug.Test.conn(:get, "/")
        |> Map.put(:host, "unknown.example.com")
        |> Plug.Conn.put_req_header("upgrade", "websocket")
        |> Plug.Conn.put_req_header("connection", "upgrade")

      result = ProxyRouter.call(conn, ProxyRouter.init([]))

      # Even with WS headers, if Host doesn't resolve → 502.
      assert result.status == 502
    end
  end

  describe "HEAD/GET /api/hello — Claude Code connectivity probe (spec 012 §9)" do
    test "HEAD answers 200 without auth and without proxying" do
      conn = Plug.Test.conn(:head, "/api/hello") |> Map.put(:host, "localhost")
      result = ProxyRouter.call(conn, ProxyRouter.init([]))

      assert result.status == 200
      assert Plug.Conn.get_resp_header(result, "content-type") |> hd() =~ "application/json"
    end

    test "GET answers 200 {}" do
      conn = Plug.Test.conn(:get, "/api/hello") |> Map.put(:host, "localhost")
      result = ProxyRouter.call(conn, ProxyRouter.init([]))

      assert result.status == 200
      assert result.resp_body == "{}"
    end

    test "a Host with an anthropic_messages row is answered locally too (DNS-override shape)" do
      tenant = new_tenant()
      insert_config(tenant, %{})

      conn =
        Plug.Test.conn(:head, "/api/hello")
        |> Map.put(:host, "api.anthropic.com")
        |> Plug.Conn.put_req_header("x-recurse-tenant-id", tenant)

      result = ProxyRouter.call(conn, ProxyRouter.init([]))
      assert result.status == 200
    end

    test "any other Host is routed like every other path (no row → 502)" do
      tenant = new_tenant()
      insert_config(tenant, %{})
      set_default("api.anthropic.com")

      conn =
        Plug.Test.conn(:get, "/api/hello")
        |> Map.put(:host, "www.example.com")
        |> Plug.Conn.put_req_header("x-recurse-tenant-id", tenant)

      result = ProxyRouter.call(conn, ProxyRouter.init([]))
      assert result.status == 502
      assert %{"error" => %{"code" => "ERR_NO_UPSTREAM_CONFIG"}} = JSON.decode!(result.resp_body)
    end
  end

  describe "self_host?/1" do
    test "loopback, docker host alias, container names and the local hostname" do
      for h <- ~w[localhost 127.0.0.1 127.0.0.2 ::1 0.0.0.0 host.docker.internal recurse-gateway] do
        assert ProxyRouter.self_host?(h), h
      end

      {:ok, hostname} = :inet.gethostname()
      assert ProxyRouter.self_host?(hostname |> List.to_string() |> String.downcase())
    end

    test "upstream names are not self" do
      refute ProxyRouter.self_host?("api.anthropic.com")
      refute ProxyRouter.self_host?("chatgpt.com")
      refute ProxyRouter.self_host?("auth.openai.com")
      refute ProxyRouter.self_host?(nil)
    end
  end

  describe "default_upstream_host/0" do
    test "nil when unset, empty, or none" do
      assert ProxyRouter.default_upstream_host() == nil
      set_default("")
      assert ProxyRouter.default_upstream_host() == nil
      set_default("none")
      assert ProxyRouter.default_upstream_host() == nil
    end

    test "lower-cased when set" do
      set_default("API.Anthropic.com")
      assert ProxyRouter.default_upstream_host() == "api.anthropic.com"
    end
  end

  describe "select_upstream/2 — default-upstream mode (spec 012 D3)" do
    test "gateway-self Host resolves the default upstream row" do
      tenant = new_tenant()
      insert_config(tenant, %{})
      set_default("api.anthropic.com")

      for host <- ~w[localhost 127.0.0.1 host.docker.internal] do
        assert {:ok, %LlmProviderConfig{upstream_host: "api.anthropic.com"}} =
                 ProxyRouter.select_upstream(tenant, host)
      end
    end

    test "a Host with no row is :not_configured — the default is for the gateway's own Host only" do
      tenant = new_tenant()
      insert_config(tenant, %{})
      set_default("api.anthropic.com")

      assert {:error, :not_configured} =
               ProxyRouter.select_upstream(tenant, "unknown.example.com")
    end

    test "R5E_LLM_PROXY_FALLBACK_UNKNOWN_HOSTS=true redirects an unknown Host and warns" do
      tenant = new_tenant()
      insert_config(tenant, %{})
      set_default("api.anthropic.com")
      Application.put_env(:recurse_gateway, :llm_proxy_fallback_unknown_hosts, true)

      log =
        ExUnit.CaptureLog.capture_log(fn ->
          assert {:ok, %LlmProviderConfig{upstream_host: "api.anthropic.com"}} =
                   ProxyRouter.select_upstream(tenant, "unknown.example.com")
        end)

      assert log =~ "[warning]"
      assert log =~ ~s|"unknown.example.com"|
      assert log =~ ~s|"api.anthropic.com"|

      # A disabled row is still an operator decision, never redirected.
      insert_config(tenant, %{
        provider: "openai_api",
        upstream_host: "api.openai.com",
        api_format: :openai_responses,
        auth_mode: :bearer,
        enabled: false
      })

      assert {:error, :not_allowed} = ProxyRouter.select_upstream(tenant, "api.openai.com")
    end

    test "Codex Host-header routing is unchanged: a matching row wins over the default" do
      tenant = new_tenant()
      insert_config(tenant, %{})

      insert_config(tenant, %{
        provider: "openai_chatgpt",
        upstream_host: "chatgpt.com",
        transport_modes: ["wss", "https-sse"],
        auth_mode: :bearer_plus_chatgpt_account_id,
        api_format: :openai_responses
      })

      set_default("api.anthropic.com")

      assert {:ok,
              %LlmProviderConfig{upstream_host: "chatgpt.com", api_format: :openai_responses}} =
               ProxyRouter.select_upstream(tenant, "chatgpt.com")
    end

    test "a disabled row does not fall back to the default (operator decision)" do
      tenant = new_tenant()
      insert_config(tenant, %{})

      insert_config(tenant, %{
        provider: "openai_api",
        upstream_host: "api.openai.com",
        api_format: :openai_responses,
        auth_mode: :bearer,
        enabled: false
      })

      set_default("api.anthropic.com")

      assert {:error, :not_allowed} = ProxyRouter.select_upstream(tenant, "api.openai.com")
    end

    test "default upstream configured but its row missing → :not_configured" do
      tenant = new_tenant()
      set_default("api.anthropic.com")

      assert {:error, :not_configured} = ProxyRouter.select_upstream(tenant, "localhost")

      assert {:error, :not_configured} =
               ProxyRouter.select_upstream(tenant, "unknown.example.com")
    end

    test "no default upstream → plain Host-header routing (pre-S2 behaviour)" do
      tenant = new_tenant()
      insert_config(tenant, %{})

      assert {:error, :not_configured} = ProxyRouter.select_upstream(tenant, "localhost")

      assert {:ok, %LlmProviderConfig{}} =
               ProxyRouter.select_upstream(tenant, "api.anthropic.com")
    end
  end

  describe "dispatch in default-upstream mode — end to end against a mock upstream" do
    setup do
      {:ok, upstream} = MockHttpUpstream.start()
      on_exit(fn -> MockHttpUpstream.stop(upstream) end)
      {:ok, upstream: upstream}
    end

    test "Host: localhost:4443 reaches the default upstream with Host rewritten, path+query preserved, credential verbatim",
         %{upstream: upstream} do
      tenant = new_tenant()

      # The "default upstream" is the mock on 127.0.0.1:<port> over plain
      # http; the routing rule is identical to api.anthropic.com:443.
      insert_config(tenant, %{
        upstream_host: "127.0.0.1",
        upstream_port: upstream.port,
        metadata: %{"scheme" => "http"}
      })

      set_default("127.0.0.1")

      # The upstream handler runs in Cowboy's own process; record what it
      # saw in an Agent the test reads afterwards.
      {:ok, seen} = Agent.start_link(fn -> nil end)

      MockHttpUpstream.expect(upstream, fn conn ->
        Agent.update(seen, fn _ ->
          {conn.method, conn.request_path, conn.query_string, conn.req_headers}
        end)

        conn
        |> Plug.Conn.put_resp_header("content-type", "application/json")
        |> Plug.Conn.put_resp_header("request-id", "req_test_123")
        |> Plug.Conn.send_resp(200, ~s|{"type":"message","content":[]}|)
      end)

      conn =
        Plug.Test.conn(
          :post,
          "/v1/messages?beta=true",
          ~s|{"model":"claude-haiku-4-5","max_tokens":5}|
        )
        |> Map.put(:host, "localhost")
        |> Map.update!(:req_headers, &[{"host", "localhost:4443"} | &1])
        |> Plug.Conn.put_req_header("x-recurse-tenant-id", tenant)
        |> Plug.Conn.put_req_header("content-type", "application/json")
        |> Plug.Conn.put_req_header("authorization", "Bearer sk-ant-oat01-TESTTOKEN")
        |> Plug.Conn.put_req_header("anthropic-beta", "oauth-2025-04-20")
        |> Plug.Conn.put_req_header("anthropic-version", "2023-06-01")
        |> Plug.Conn.put_req_header("accept-encoding", "gzip, br")

      result = ProxyRouter.call(conn, ProxyRouter.init([]))

      assert result.status == 200
      assert {"POST", "/v1/messages", "beta=true", headers} = Agent.get(seen, & &1)

      assert {"host", "127.0.0.1"} in headers
      refute Enum.any?(headers, fn {n, v} -> n == "host" and v =~ "localhost" end)
      assert {"authorization", "Bearer sk-ant-oat01-TESTTOKEN"} in headers
      assert {"anthropic-beta", "oauth-2025-04-20"} in headers
      assert {"anthropic-version", "2023-06-01"} in headers
      refute List.keyfind(headers, "accept-encoding", 0)

      assert {"request-id", "req_test_123"} in result.resp_headers
    end
  end

  describe "LlmProviderConfig struct shape — sanity checks" do
    test "build a representative config without raising" do
      cfg = %LlmProviderConfig{
        tenant_id: "01TEN",
        provider: "openai_chatgpt",
        upstream_host: "chatgpt.com",
        upstream_port: 443,
        transport_modes: ["wss", "https-sse"],
        auth_mode: :bearer_plus_chatgpt_account_id,
        api_format: :openai_responses,
        enabled: true,
        metadata: %{}
      }

      assert cfg.upstream_host == "chatgpt.com"
      assert cfg.api_format == :openai_responses
    end
  end
end
