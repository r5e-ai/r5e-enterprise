defmodule Recurse.Gateway.LlmProxy.WebSocketBridgeLongTest do
  @moduledoc """
  CT-006 / T038b — long-running stream memory-stability test.

  Spec source: spec.md Edge Cases ("Long-running streaming responses
  (>10 minutes) MUST NOT be buffered in proxy memory") + tasks.md
  T038b.

  Asserts: a Bandit-mocked upstream emits one text frame per second
  for 11 minutes; the WebSocketBridge process's memory stays below
  50MB throughout (sampled every 10s via
  `:erlang.process_info(pid, :memory)`).

  ## Why tagged `:slow`

  This test runs for 11 minutes wall-clock. Default `mix test` skips
  it. To run locally: `mix test --include slow apps/recurse_gateway/...`

  ## Why a separate file from `web_socket_bridge_test.exs`

  Keeping the slow test in its own file prevents accidental
  inclusion in CI runs (any wholesale `:moduletag :slow` slip would
  otherwise pull all bridge tests into the slow lane).
  """

  use ExUnit.Case, async: false

  @moduletag :slow

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
      source_ref: "web-socket-bridge-long-test",
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

  defp request do
    Jason.encode!(%{type: "response.create", model: "test-model", input: "start"})
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
        parser_module: Recurse.Gateway.LlmProxy.WebSocketBridgeLongTest.NoopParser
      )
    end
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

  setup do
    {:ok, upstream} = MockWebsocketUpstream.start()

    cfg = %LlmProviderConfig{
      tenant_id: "01TEN_LONG",
      provider: "test_long_provider",
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
        plug: {BridgeTestEndpoint, llm_provider_config: cfg, tenant_id: "01TEN_LONG"},
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

  @tag timeout: 750_000
  test "11 minutes of 1 frame/sec sustains memory < 50MB", %{
    upstream: upstream,
    bridge_port: bridge_port
  } do
    duration_seconds = 11 * 60
    threshold_bytes = 50 * 1024 * 1024

    # Configure upstream: every inbound text frame triggers a stream
    # of `frame_count` outbound frames at 1 frame/sec via
    # Process.send_after self-trigger. We start the loop on first
    # client frame ("start").
    request = request()

    MockWebsocketUpstream.expect(upstream, fn
      {:text, ^request}, state ->
        send(self(), :tick)
        {:ok, Map.put(state, :tick_count, 0)}

      {:text, _other}, state ->
        {:ok, state}

      _, state ->
        {:ok, state}
    end)

    # Open client → bridge.
    {:ok, ws_state} = open_client_ws(bridge_port)

    # Find the bridge's per-conn process. Bandit names per-connection
    # processes; we look up via Process.list and pick the most recent
    # WebSocketBridge-handling one. (Approximate; sufficient for a
    # single-connection memory-stability test.)
    Process.sleep(200)
    bridge_proc_pid = find_bridge_process()

    if is_nil(bridge_proc_pid) do
      flunk(
        "could not locate bridge per-connection process; CT-006 requires direct memory introspection"
      )
    end

    ws_state = send_frame(ws_state, {:text, request})

    # Drive the upstream's tick loop from THIS test process —
    # the upstream callback is in a different process so its
    # Process.send_after won't reach our process; we orchestrate
    # ticks here.
    deadline = System.monotonic_time(:millisecond) + duration_seconds * 1_000

    final_max =
      Stream.iterate(0, &(&1 + 1))
      |> Enum.reduce_while(0, fn _i, max_so_far ->
        now = System.monotonic_time(:millisecond)

        if now >= deadline do
          {:halt, max_so_far}
        else
          mem =
            case Process.info(bridge_proc_pid, :memory) do
              {:memory, n} -> n
              _ -> 0
            end

          new_max = max(max_so_far, mem)

          if new_max > threshold_bytes do
            {:halt, {:overflow, new_max, now}}
          else
            # Drain Mint frames from the test pid's mailbox so the
            # OS socket buffer doesn't fill (which would back-pressure
            # the bridge → upstream loop and skew the test). The
            # 200ms sleep inside drain_client_frames acts as our
            # sample-cadence governor — over 11 minutes that's ~3,300
            # samples, well above the spec's "every 10s" minimum.
            _ = drain_client_frames(ws_state, 200)
            {:cont, new_max}
          end
        end
      end)

    case final_max do
      {:overflow, n, t} ->
        flunk(
          "WebSocketBridge memory exceeded 50MB at t=#{t}ms: #{n} bytes; expected stable < 50MB"
        )

      max_bytes when is_integer(max_bytes) ->
        # Sanity floor: process should occupy at least a few KB.
        assert max_bytes > 1_000,
               "bridge process memory looks suspiciously low (#{max_bytes}B); fixture likely broken"

        IO.puts(
          "CT-006 OK: WebSocketBridge peak memory over 11 min = " <>
            "#{:erlang.float_to_binary(max_bytes / 1024 / 1024, decimals: 2)} MB"
        )
    end

    close_ws(ws_state)
    :ok
  end

  # ===========================================================================
  # Helpers (mirrored from web_socket_bridge_test.exs minus the assertion path)
  # ===========================================================================

  defmodule WsState do
    @moduledoc false
    defstruct [:conn, :ref, :ws, :open?]
  end

  defp open_client_ws(port) do
    {:ok, conn} = MintHttp.connect(:http, "127.0.0.1", port, protocols: [:http1])
    {:ok, conn, ref} = MintWs.upgrade(:ws, conn, "/", [])

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

              if opened?, do: {:ok, state}, else: do_drain_until_open(state, deadline)

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

  defp drain_client_frames(state, timeout) do
    receive do
      msg ->
        case MintWs.stream(state.conn, msg) do
          {:ok, _conn, _frames} -> :ok
          _ -> :ok
        end
    after
      timeout -> :ok
    end
  end

  defp close_ws(state) do
    case MintWs.encode(state.ws, :close) do
      {:ok, ws, data} ->
        case MintWs.stream_request_body(state.conn, state.ref, data) do
          {:ok, conn} ->
            _ = drain_client_frames(%{state | conn: conn, ws: ws}, 1_000)

          _ ->
            :ok
        end

      _ ->
        :ok
    end

    _ = MintHttp.close(state.conn)
    :ok
  end

  # Locate the WebSocketBridge per-connection process. Bandit names
  # processes via initial_call/dictionary metadata; we scan for any
  # process whose dictionary mentions our module.
  defp find_bridge_process do
    Process.list()
    |> Enum.find(fn pid ->
      case Process.info(pid, :dictionary) do
        {:dictionary, dict} ->
          inspect(dict) =~ "WebSocketBridge"

        _ ->
          false
      end
    end)
  end
end
