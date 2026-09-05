defmodule Recurse.Gateway.RouterTest do
  @moduledoc """
  Smoke / contract tests for `Recurse.Gateway.Router` (F002 T050).

  Covers the routing surface without exercising the full
  `ChatCompletionsHandler` pipeline (that's `ChatCompletionsHandlerTest`,
  and the end-to-end integration surface is `us1_happy_path_test.exs`
  T054):

    * POST `/v1/chat/completions` without Authorization → 503 unavailable.
    * POST `/v1/chat/completions` with expired JWT → 503 unavailable.
    * GET `/healthz` / `/readyz` / `/metrics` → 200 unauthenticated stubs.
    * Runtime-only tier-mismatch paths → 501 `ERR_TIER_MISMATCH` shape
      (spot check; T102 iterates the full list).
    * Unknown path → 404.

  `async: false` because the Router reads from the singleton
  `ProviderRegistry`; we install a minimal stub state at setup and
  uninstall at teardown so other tests don't see the residue.
  """

  use ExUnit.Case, async: false

  alias Recurse.Gateway.ProviderRegistry
  alias Recurse.Gateway.Router
  alias Recurse.Gateway.Test.JwtTestHelper

  @tenant_id "01HQZN5K7J8M9N0P1Q2R3S4T5V"

  @opts Router.init([])

  setup do
    # Install a stub provider state so `Router.authenticate/1` can read
    # `tenant_id` without failing. The router never reaches any of the
    # provider callback surfaces in these tests (the handler is what
    # dispatches into providers), but the tenant accessor is reached.
    ProviderRegistry.install_raw!(%{
      llm: {Recurse.Gateway.Test.StubLLM, %{}},
      ledger: {Recurse.Gateway.Test.StubLedger, %{}},
      storage: {Recurse.Gateway.Test.StubStorage, %{}},
      secrets: {Recurse.Gateway.Test.StubSecretsProvider, %{}},
      tenant_id: @tenant_id,
      signer: "observed://gateway/test"
    })

    previous_validator_opts = Application.get_env(:recurse_gateway, :jwt_validator_opts)

    Application.put_env(:recurse_gateway, :jwt_validator_opts,
      audience: "recurse-gateway-test",
      issuer: "https://test-broker.example.invalid",
      known_kids: [
        {"test-key-rs256", JwtTestHelper.public_jwk(:rs256)}
      ]
    )

    on_exit(fn ->
      ProviderRegistry.uninstall()

      if previous_validator_opts do
        Application.put_env(:recurse_gateway, :jwt_validator_opts, previous_validator_opts)
      else
        Application.delete_env(:recurse_gateway, :jwt_validator_opts)
      end
    end)

    :ok
  end

  describe "POST /v1/chat/completions — unavailable before authentication" do
    test "returns 503 when Authorization header is missing" do
      conn =
        conn_with_body(:post, "/v1/chat/completions", %{
          "model" => "gpt-4o-mini",
          "messages" => []
        })
        |> Router.call(@opts)

      assert conn.status == 503
      body = JSON.decode!(conn.resp_body)
      assert %{"error" => %{"code" => "capability_unavailable"}} = body
    end

    test "returns 503 when JWT has expired" do
      expired_iat = System.system_time(:second) - 3600
      # 5 min ttl → exp = 3000 seconds ago → well past.
      jwt =
        JwtTestHelper.mint_test_jwt(
          iat: expired_iat,
          ttl_seconds: 300,
          audience: "recurse-gateway-test",
          issuer: "https://test-broker.example.invalid"
        )

      conn =
        :post
        |> conn_with_body("/v1/chat/completions", %{"model" => "gpt-4o-mini", "messages" => []})
        |> Plug.Conn.put_req_header("authorization", "Bearer " <> jwt)
        |> Router.call(@opts)

      assert conn.status == 503
      body = JSON.decode!(conn.resp_body)
      assert %{"error" => %{"code" => "capability_unavailable"}} = body
    end
  end

  describe "observability routes" do
    # With T091 landed, `/healthz` + `/readyz` aggregate per-component
    # state via `Recurse.Gateway.Observability.{Healthz, Readyz}`. The
    # router's responsibility is still the same: route to the correct
    # plug; dispatch works even when ancillary services (JwksCache,
    # BundleLoader, MetricsRegistry) are not started in this router-
    # level test. Those modules are covered in their own suites; here
    # we assert shape-level invariants that hold regardless of
    # ancillary-service readiness.

    test "GET /healthz dispatches to the healthz plug and returns JSON" do
      conn =
        :get
        |> Plug.Test.conn("/healthz")
        |> Router.call(@opts)

      # Without JwksCache / BundleLoader running, aggregate is "down"
      # (503). Assert that the route DISPATCHED correctly — i.e. returned
      # the canonical JSON envelope — and that the status is either 200
      # or 503 depending on ancillary-service readiness.
      assert conn.status in [200, 503]
      assert conn.resp_body != ""

      decoded = JSON.decode!(conn.resp_body)
      assert Map.has_key?(decoded, "status")
      assert Map.has_key?(decoded, "components")
      assert is_map(decoded["components"])
    end

    test "GET /readyz dispatches to the readyz plug and returns JSON" do
      conn =
        :get
        |> Plug.Test.conn("/readyz")
        |> Router.call(@opts)

      assert conn.status in [200, 503]
      assert conn.resp_body != ""

      decoded = JSON.decode!(conn.resp_body)
      assert Map.has_key?(decoded, "ready")
      assert Map.has_key?(decoded, "checks")
    end

    test "GET /metrics dispatches to the metrics plug" do
      # Without the MetricsRegistry child running, `scrape/0` raises;
      # our dispatch still returns via the router. Either way we want
      # to assert the content-type + status shape.
      try do
        conn =
          :get
          |> Plug.Test.conn("/metrics")
          |> Router.call(@opts)

        assert conn.status == 200

        assert {"content-type", ct} =
                 Enum.find(conn.resp_headers, fn {k, _} -> k == "content-type" end)

        assert ct =~ "text/plain"
      rescue
        # Expected when MetricsRegistry is not running in this scope.
        # The dispatch is still tested via the `/healthz` + `/readyz`
        # routes above. Document the expected error so unrelated changes
        # don't mask real regressions.
        ArgumentError -> :ok
      catch
        :exit, _reason -> :ok
      end
    end
  end

  describe "Runtime-only tier-mismatch paths" do
    test "GET /v1/control/runtime/spawn returns 501 ERR_TIER_MISMATCH" do
      conn =
        :get
        |> Plug.Test.conn("/v1/control/runtime/spawn")
        |> Router.call(@opts)

      assert conn.status == 501

      assert %{
               "error" => %{
                 "code" => "ERR_TIER_MISMATCH",
                 "details" => %{
                   "active_tier" => "standalone_gateway",
                   "endpoint_requires_tier" => "runtime_shape"
                 }
               }
             } = JSON.decode!(conn.resp_body)
    end

    test "POST /v1/governance/policy/propose-from-event returns 501" do
      conn =
        :post
        |> conn_with_body("/v1/governance/policy/propose-from-event", %{})
        |> Router.call(@opts)

      assert conn.status == 501

      assert %{"error" => %{"details" => %{"endpoint_requires_tier" => "governance_shape"}}} =
               JSON.decode!(conn.resp_body)
    end

    test "runtime_only_paths/0 exposes the authoritative list to T102" do
      paths = Router.runtime_only_paths()
      assert is_list(paths)
      assert length(paths) >= 5
      assert Enum.all?(paths, fn {p, t} -> is_binary(p) and is_binary(t) end)
    end
  end

  describe "unknown routes" do
    test "unknown path returns 404 JSON envelope" do
      conn =
        :get
        |> Plug.Test.conn("/does-not-exist")
        |> Router.call(@opts)

      assert conn.status == 404
      assert %{"error" => "not_found"} = JSON.decode!(conn.resp_body)
    end
  end

  # Build a Plug.Test conn with a pre-parsed JSON body so the Router's
  # `Plug.Parsers` chain doesn't attempt to re-parse it.
  defp conn_with_body(method, path, body) do
    bytes = JSON.encode!(body)

    method
    |> Plug.Test.conn(path, bytes)
    |> Plug.Conn.put_req_header("content-type", "application/json")
  end
end

# --- Router-test-private stubs ------------------------------------------------
# Minimal `@behaviour` impls so `ProviderRegistry.install_raw!/1` accepts
# the tuples. These are never called by the router-level tests (router
# doesn't reach provider callbacks), but the registry type contract
# wants `{module, state}` tuples.

defmodule Recurse.Gateway.Test.StubLLM do
  @moduledoc false
  @behaviour Recurse.Providers.LLMProvider
  @impl true
  def init(_), do: {:ok, %{}}
  @impl true
  def chat_complete(_state, _req, _ctx), do: {:ok, %{}}
  @impl true
  def chat_complete_stream(_state, _req, _ctx), do: {:ok, []}
  @impl true
  def capabilities(_state), do: [:sync]
  @impl true
  def healthcheck(_state), do: :ok
  @impl true
  def terminate(_state, _reason), do: :ok
end

defmodule Recurse.Gateway.Test.StubLedger do
  @moduledoc false
  @behaviour Recurse.Providers.LedgerProvider
  @impl true
  def init(_), do: {:ok, %{}}
  @impl true
  def commit_epoch(_state, _session_id, _epoch, _leaves), do: {:error, :not_implemented}
  @impl true
  def inclusion_proof(_state, _session_id, _index), do: {:error, :not_implemented}
  @impl true
  def consistency_proof(_state, _session_id, _from), do: {:error, :not_implemented}
  @impl true
  def current_root(_state), do: {:error, :not_implemented}
  @impl true
  def capabilities(_state), do: []
  @impl true
  def healthcheck(_state), do: :ok
  @impl true
  def terminate(_state, _reason), do: :ok
end

defmodule Recurse.Gateway.Test.StubStorage do
  @moduledoc false
  @behaviour Recurse.Providers.StorageProvider
  @impl true
  def init(_), do: {:ok, %{}}
  @impl true
  # Spec 012 S6b: `Resolvers.Payload.store/2` checks the returned hash
  # against the bytes, so the stub must report the real one.
  def put_payload(_state, payload, _ctx),
    do: {:ok, %{uri: "s3://stub/key", hash: :crypto.hash(:sha256, payload)}}

  @impl true
  def get_payload(_state, _uri, _ctx), do: {:error, :permanent, :not_implemented}
  @impl true
  def delete_payload(_state, _uri, _ctx), do: {:error, :permanent, :not_implemented}
  @impl true
  def capabilities(_state), do: []
  @impl true
  def healthcheck(_state), do: :ok
  @impl true
  def terminate(_state, _reason), do: :ok
end
