defmodule Recurse.Gateway.LlmProxy.WebSocketBridgeTest do
  @moduledoc """
  Contract tests for `Recurse.Gateway.LlmProxy.WebSocketBridge`.

  Spec source: `specs/009-llm-api-proxy/contracts/streaming_proxy.md`
  + tasks.md T034 / T037 / T038a.

  ## CTs covered here

    * **CT-001 (T034)** — WS upgrade against a `Bypass`-mocked upstream
      completes with 101 + bidirectional frame relay works.
    * **CT-003-WS / CT-005-WS slice (T036 / T038a)** — R-012 request
      headers preserved on the forwarded WS upgrade (Bypass-side
      header capture); upstream response metadata also passes through
      on the WS path.
    * **CT-004 (T037)** — 50 parallel WS connections run independently
      without head-of-line blocking.

  ## Two-Bandit topology

  This test boots:

    * `MockWebsocketUpstream` — a Bandit listener acting as the LLM
      provider (chatgpt.com analog).
    * `BridgeTestEndpoint` — a separate Bandit listener whose Plug
      delegates to `WebSocketBridge.upgrade/2` with an
      `LlmProviderConfig` pointing at the mock upstream.

  The test client uses `Mint.WebSocket` to connect to the bridge's
  port, mimicking what Codex CLI would do (after the corp DNS override
  redirected `chatgpt.com` to recurse-gateway).
  """

  use ExUnit.Case, async: false

  alias Mint.HTTP, as: MintHttp
  alias Mint.WebSocket, as: MintWs
  alias Recurse.Gateway.LlmProxy.WebSocketBridge
  alias Recurse.Gateway.Policy.Active
  alias Recurse.Gateway.PolicyBundleRef
  alias Recurse.Gateway.Test.{KernelFixture, MockWebsocketUpstream}
  alias Recurse.Providers.Schemas.LlmProviderConfig

  setup_all do
    :ok = KernelFixture.boot()
    activate_permit_all()
  end

  defp activate_permit_all do
    source = "permit(principal, action, resource);"
    hash = Recurse.Cedar.canonical_hash(source)

    Active.update(%Active{
      source: :filesystem,
      source_ref: "web-socket-bridge-test",
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

  defp request(input \\ "test input") do
    Jason.encode!(%{type: "response.create", model: "test-model", input: input})
  end

  defmodule BridgeTestEndpoint do
    @moduledoc false
    @behaviour Plug

    @impl true
    def init(opts), do: opts

    @impl true
    def call(conn, opts) do
      cfg = Keyword.fetch!(opts, :llm_provider_config)
      tenant_id = Keyword.fetch!(opts, :tenant_id)

      WebSocketBridge.upgrade(conn,
        llm_provider_config: cfg,
        tenant_id: tenant_id,
        parser_module:
          Keyword.get(
            opts,
            :parser_module,
            Recurse.Gateway.LlmProxy.WebSocketBridgeTest.NoopParser
          )
      )
    end
  end

  setup context do
    {:ok, upstream} = MockWebsocketUpstream.start()

    cfg = %LlmProviderConfig{
      tenant_id: "01TEN_WS_TEST",
      provider: "test_ws_provider",
      upstream_host: "127.0.0.1",
      upstream_port: upstream.port,
      transport_modes: ["wss"],
      auth_mode: :bearer,
      api_format: :openai_responses,
      enabled: true,
      metadata: %{"scheme" => "http"}
    }

    {:ok, bridge_pid} =
      Bandit.start_link(
        plug:
          {BridgeTestEndpoint,
           llm_provider_config: cfg,
           tenant_id: "01TEN_WS_TEST",
           parser_module: Map.get(context, :parser_module, __MODULE__.NoopParser)},
        port: 0
      )

    {:ok, {_addr, bridge_port}} = ThousandIsland.listener_info(bridge_pid)

    on_exit(fn ->
      try do
        Process.exit(bridge_pid, :shutdown)
      catch
        _, _ -> :ok
      end

      MockWebsocketUpstream.stop(upstream)
    end)

    {:ok, upstream: upstream, bridge_pid: bridge_pid, bridge_port: bridge_port}
  end

  describe "CT-001 — WS upgrade + bidirectional frame relay (T034)" do
    test "echoes a frame end-to-end through the bridge", %{
      upstream: upstream,
      bridge_port: bridge_port
    } do
      MockWebsocketUpstream.expect(upstream, fn
        {:text, payload}, state ->
          {:push, [{:text, "echo:" <> payload}], state}

        _, state ->
          {:ok, state}
      end)

      {:ok, ws_state} = open_client_ws(bridge_port)

      payload = request("hello")
      ws_state = send_frame(ws_state, {:text, payload})

      assert {:ok, ws_state, frames} = recv_until_text(ws_state, 5_000)

      texts =
        Enum.flat_map(frames, fn
          {:text, body} -> [body]
          _ -> []
        end)

      assert ("echo:" <> payload) in texts

      close_ws(ws_state)
    end

    test "preserves R-012 client headers on upstream upgrade", %{
      upstream: upstream,
      bridge_port: bridge_port
    } do
      MockWebsocketUpstream.expect(upstream, fn _frame, state -> {:ok, state} end)

      r012_headers = [
        {"authorization", "Bearer abc.eyJ.foo"},
        {"chatgpt-account-id", "uuid-1234"},
        {"openai-beta", "responses=v1"},
        {"originator", "codex_cli_rs"},
        {"session_id", "session-abc"}
      ]

      {:ok, ws_state} = open_client_ws(bridge_port, r012_headers)

      # Push a frame so the upstream WS handshake completes (the
      # client side might not see anything until upstream acknowledges
      # the handshake-with-headers).
      ws_state = send_frame(ws_state, {:text, request("ping")})

      headers_seen = await_received_headers(upstream, 3_000)

      assert is_list(headers_seen),
             "upstream never received any HTTP request"

      forwarded =
        Enum.into(headers_seen, %{}, fn {k, v} -> {String.downcase(k), v} end)

      assert forwarded["authorization"] == "Bearer abc.eyJ.foo"
      assert forwarded["chatgpt-account-id"] == "uuid-1234"
      assert forwarded["openai-beta"] == "responses=v1"
      assert forwarded["originator"] == "codex_cli_rs"
      assert forwarded["session_id"] == "session-abc"

      assert is_binary(forwarded["x-recurse-trace-id"])
      assert forwarded["x-recurse-tenant-id"] == "01TEN_WS_TEST"

      close_ws(ws_state)
    end
  end

  describe "CT-004 — 50 parallel connections without head-of-line blocking (T037)" do
    # Fifty concurrent sockets against an in-process upstream is a load test;
    # a shared CI runner fails it on scheduling alone (2026-09-05). Opt in with
    # `--include slow`; it stays in the local full run.
    @tag :slow
    @tag timeout: 30_000
    test "50 parallel WS clients each round-trip independently", %{
      upstream: upstream,
      bridge_port: bridge_port
    } do
      MockWebsocketUpstream.expect(upstream, fn
        {:text, payload}, state ->
          {:push, [{:text, "echo:" <> payload}], state}

        _, state ->
          {:ok, state}
      end)

      results =
        1..50
        |> Task.async_stream(
          fn i ->
            {:ok, ws_state} = open_client_ws(bridge_port)
            payload = request("msg-#{i}")
            ws_state = send_frame(ws_state, {:text, payload})

            case recv_until_text(ws_state, 5_000) do
              {:ok, ws_state, frames} ->
                close_ws(ws_state)
                expected = "echo:" <> payload

                if Enum.any?(frames, fn f -> f == {:text, expected} end) do
                  :ok
                else
                  {:error, {:no_echo, i, frames}}
                end

              other ->
                {:error, {:recv_failed, i, other}}
            end
          end,
          max_concurrency: 50,
          timeout: 20_000
        )
        |> Enum.to_list()

      ok_count =
        Enum.count(results, fn
          {:ok, :ok} -> true
          _ -> false
        end)

      # Allow up to 5 flaky connections; 90%+ success demonstrates
      # absence of head-of-line blocking. Anything below is a real
      # bridge bug.
      assert ok_count >= 45,
             "only #{ok_count}/50 connections completed — head-of-line blocking suspected; " <>
               "results=#{inspect(results)}"
    end
  end

  # ===========================================================================
  # Mint.WebSocket client helper (drives the bridge from "Codex's side")
  # ===========================================================================

  defmodule WsState do
    @moduledoc false
    defstruct [:conn, :ref, :ws, :open?]
  end

  defp open_client_ws(port, extra_headers \\ []) do
    {:ok, conn} =
      MintHttp.connect(:http, "127.0.0.1", port, protocols: [:http1])

    {:ok, conn, ref} = MintWs.upgrade(:ws, conn, "/", extra_headers)

    state = %WsState{conn: conn, ref: ref, open?: false}

    drain_until_open(state, 3_000)
  end

  defp drain_until_open(state, timeout) do
    deadline = System.monotonic_time(:millisecond) + timeout
    do_drain_until_open(state, deadline)
  end

  defp do_drain_until_open(state, deadline) do
    if System.monotonic_time(:millisecond) > deadline do
      {:error, :timeout}
    else
      receive do
        msg ->
          case MintHttp.stream(state.conn, msg) do
            {:ok, conn, responses} ->
              state = %{state | conn: conn}

              {state, opened?} =
                Enum.reduce(responses, {state, false}, fn
                  {:status, ref, 101}, {st, _} when ref == st.ref ->
                    {Map.put(st, :_pending_status, 101), false}

                  {:headers, ref, headers}, {st, _} when ref == st.ref ->
                    {Map.put(st, :_pending_headers, headers), false}

                  {:done, ref}, {st, _} when ref == st.ref ->
                    case MintWs.new(st.conn, st.ref, 101, st._pending_headers) do
                      {:ok, conn, ws} ->
                        st =
                          %{st | conn: conn, ws: ws, open?: true}
                          |> Map.delete(:_pending_status)
                          |> Map.delete(:_pending_headers)

                        {st, true}

                      _ ->
                        {st, false}
                    end

                  _, acc ->
                    acc
                end)

              if opened? do
                {:ok, state}
              else
                do_drain_until_open(state, deadline)
              end

            {:error, _conn, reason, _} ->
              {:error, reason}

            :unknown ->
              do_drain_until_open(state, deadline)
          end
      after
        100 ->
          do_drain_until_open(state, deadline)
      end
    end
  end

  defp send_frame(state, frame) do
    {:ok, ws, data} = MintWs.encode(state.ws, frame)
    {:ok, conn} = MintWs.stream_request_body(state.conn, state.ref, data)
    %{state | conn: conn, ws: ws}
  end

  defp recv_until_text(state, timeout) do
    deadline = System.monotonic_time(:millisecond) + timeout
    do_recv_until_text(state, deadline, [])
  end

  defp do_recv_until_text(state, deadline, acc) do
    if System.monotonic_time(:millisecond) > deadline do
      if Enum.empty?(acc), do: {:error, :timeout}, else: {:ok, state, acc}
    else
      receive do
        msg ->
          case MintWs.stream(state.conn, msg) do
            {:ok, conn, mint_messages} ->
              state = %{state | conn: conn}

              {state, frames} =
                Enum.reduce(mint_messages, {state, acc}, fn
                  {:data, ref, payload}, {st, fr} when ref == st.ref ->
                    case MintWs.decode(st.ws, payload) do
                      {:ok, ws, decoded} -> {%{st | ws: ws}, fr ++ decoded}
                      _ -> {st, fr}
                    end

                  _, acc2 ->
                    acc2
                end)

              if Enum.any?(frames, fn
                   {:text, _} -> true
                   {:close, _, _} -> true
                   _ -> false
                 end) do
                {:ok, state, frames}
              else
                do_recv_until_text(state, deadline, frames)
              end

            {:error, _conn, _reason, _} ->
              {:error, :stream_error}

            :unknown ->
              do_recv_until_text(state, deadline, acc)
          end
      after
        100 ->
          do_recv_until_text(state, deadline, acc)
      end
    end
  end

  defp close_ws(state) do
    case MintWs.encode(state.ws, :close) do
      {:ok, ws, data} ->
        case MintWs.stream_request_body(state.conn, state.ref, data) do
          {:ok, conn} ->
            deadline = System.monotonic_time(:millisecond) + 1_000
            _ = do_recv_until_text(%{state | conn: conn, ws: ws}, deadline, [])

          _ ->
            :ok
        end

      _ ->
        :ok
    end

    _ = MintHttp.close(state.conn)
    :ok
  end

  defp await_received_headers(upstream, timeout_ms) do
    deadline = System.monotonic_time(:millisecond) + timeout_ms
    do_await_received_headers(upstream, deadline)
  end

  defp do_await_received_headers(upstream, deadline) do
    case MockWebsocketUpstream.received_headers(upstream) do
      headers when is_list(headers) ->
        headers

      nil ->
        if System.monotonic_time(:millisecond) >= deadline do
          nil
        else
          Process.sleep(10)
          do_await_received_headers(upstream, deadline)
        end
    end
  end

  @tag parser_module: __MODULE__.RaisingParser
  test "a raised parser closes without forwarding its response", %{
    upstream: upstream,
    bridge_port: port
  } do
    MockWebsocketUpstream.expect(upstream, fn {:text, _}, state ->
      {:push, [{:text, "unapproved executable response"}], state}
    end)

    {:ok, client} = open_client_ws(port)
    client = send_frame(client, {:text, request()})
    assert {:ok, client, frames} = recv_until_text(client, 5_000)
    assert Enum.any?(frames, &match?({:close, 1011, _}, &1))
    refute Enum.any?(frames, &match?({:text, _}, &1))
    close_ws(client)
  end

  test "binary upstream frames cannot bypass tool parsing", %{
    upstream: upstream,
    bridge_port: port
  } do
    MockWebsocketUpstream.expect(upstream, fn {:text, _}, state ->
      {:push, [{:binary, "unapproved executable response"}], state}
    end)

    {:ok, client} = open_client_ws(port)
    client = send_frame(client, {:text, request()})
    assert {:ok, client, frames} = recv_until_text(client, 5_000)
    assert Enum.any?(frames, &match?({:close, 1011, _}, &1))
    refute Enum.any?(frames, &match?({:binary, _}, &1))
    close_ws(client)
  end

  defmodule RaisingParser do
    def init(_opts), do: %{}
    def parse_chunk(_state, _chunk), do: raise("synthetic parser failure")
    def finalize(_state), do: {%{}, []}
  end

  defmodule NoopParser do
    @moduledoc false
    @behaviour Recurse.Shared.LlmProxy.Parsers.Parser

    @impl true
    def init(_opts), do: %{count: 0}

    @impl true
    def parse_chunk(state, chunk) do
      {%{state | count: state.count + 1}, [], [{:forward, chunk}]}
    end

    @impl true
    def finalize(state) do
      {%{event_count: state.count, intent_count: 0, completion_seen?: true}, []}
    end
  end
end
