defmodule Recurse.Gateway.Test.MockWebsocketUpstream do
  @moduledoc """
  Bandit-backed inline mock WebSocket upstream for the LLM-proxy
  WebSocketBridge tests (009 T034 / T037).

  Each test starts its own Bandit listener on a random port. Inbound
  HTTP/1.1 GET requests with `Upgrade: websocket` headers are
  upgraded to a `WebSock`-handler process that the test configures
  per-instance. The handler receives client text frames, runs a
  test-supplied callback, and pushes any returned frames back to the
  client.

  Headers received during the WS upgrade are recorded into a per-
  instance Agent so the test can assert R-012 preservation
  (CT-003-style assertions for the WS path).

  ## Usage

      setup do
        {:ok, upstream} = MockWebsocketUpstream.start()
        on_exit(fn -> MockWebsocketUpstream.stop(upstream) end)
        %{upstream: upstream}
      end

      test "round-trips a frame", %{upstream: upstream} do
        MockWebsocketUpstream.expect(upstream, fn
          {:text, payload}, state -> {:push, [{:text, "echo:" <> payload}], state}
          _, state -> {:ok, state}
        end)
        # ... open WS to MockWebsocketUpstream.url(upstream)
      end

  ## Why a separate fixture from `MockHttpUpstream`

  Plug.Cowboy doesn't ship the `Plug.Conn.upgrade_adapter(:websocket)`
  hook that `WebSockAdapter` requires. Bandit does. We keep the HTTP
  fixture (Plug.Cowboy) for the HTTP/SSE-side tests and add this
  Bandit-specific fixture for the WS-side tests.
  """

  defmodule Plug do
    @moduledoc false
    @behaviour Elixir.Plug

    import Elixir.Plug.Conn

    @impl true
    def init(ref), do: ref

    @impl true
    def call(conn, ref) do
      meta = :persistent_term.get({Recurse.Gateway.Test.MockWebsocketUpstream, ref})

      _ = Agent.update(meta.headers_agent, fn _ -> conn.req_headers end)

      cond do
        conn.request_path == "/__health" ->
          send_resp(conn, 200, "ok")

        websocket_upgrade?(conn) ->
          handler_init = %{ref: ref}

          conn
          |> WebSockAdapter.upgrade(
            Recurse.Gateway.Test.MockWebsocketUpstream.Handler,
            handler_init,
            []
          )

        true ->
          send_resp(conn, 426, "upgrade required")
      end
    end

    defp websocket_upgrade?(conn) do
      conn
      |> get_req_header("upgrade")
      |> List.first()
      |> case do
        nil -> false
        v -> String.downcase(v, :ascii) == "websocket"
      end
    end
  end

  defmodule Handler do
    @moduledoc false
    @behaviour WebSock

    @impl true
    def init(state), do: {:ok, state}

    @impl true
    def handle_in({payload, opcode: opcode}, state) do
      callback =
        :persistent_term.get({Recurse.Gateway.Test.MockWebsocketUpstream, state.ref}).callback_agent
        |> Agent.get(& &1)

      case callback do
        nil ->
          {:ok, state}

        fun when is_function(fun, 2) ->
          fun.({opcode, payload}, state)
      end
    end

    @impl true
    def handle_info(_msg, state), do: {:ok, state}

    @impl true
    def terminate(_reason, _state), do: :ok
  end

  @doc """
  Start a fresh Bandit-backed mock WS upstream on a random port.
  """
  @spec start() :: {:ok, map()} | {:error, term()}
  def start do
    ref = make_ref()
    {:ok, headers_agent} = Agent.start_link(fn -> nil end)
    {:ok, callback_agent} = Agent.start_link(fn -> nil end)

    meta = %{
      ref: ref,
      headers_agent: headers_agent,
      callback_agent: callback_agent
    }

    :persistent_term.put({__MODULE__, ref}, meta)

    case Bandit.start_link(plug: {__MODULE__.Plug, ref}, port: 0) do
      {:ok, pid} ->
        {:ok, {_addr, port}} = ThousandIsland.listener_info(pid)
        {:ok, Map.merge(meta, %{pid: pid, port: port})}

      {:error, reason} ->
        :persistent_term.erase({__MODULE__, ref})
        Agent.stop(headers_agent)
        Agent.stop(callback_agent)
        {:error, reason}
    end
  end

  @doc "Stop a started upstream + clean up."
  @spec stop(map()) :: :ok
  def stop(%{ref: ref, pid: pid, headers_agent: ha, callback_agent: ca}) do
    _ =
      try do
        Process.exit(pid, :shutdown)
      catch
        _, _ -> :ok
      end

    :persistent_term.erase({__MODULE__, ref})

    if Process.alive?(ha), do: Agent.stop(ha)
    if Process.alive?(ca), do: Agent.stop(ca)

    :ok
  end

  @doc "Register the per-frame callback. Overwrites any previous one."
  @spec expect(map(), (term(), term() -> term())) :: :ok
  def expect(%{callback_agent: ca}, fun) when is_function(fun, 2) do
    Agent.update(ca, fn _ -> fun end)
  end

  @doc "The captured request-headers list from the most recent upgrade."
  @spec received_headers(map()) :: [{String.t(), String.t()}] | nil
  def received_headers(%{headers_agent: ha}) do
    Agent.get(ha, & &1)
  end

  @doc "The base URL ws://127.0.0.1:port — caller chooses scheme."
  @spec url(map()) :: String.t()
  def url(%{port: port}), do: "ws://127.0.0.1:#{port}"

  @doc "The host:port suitable for Mint connect."
  @spec endpoint(map()) :: {String.t(), pos_integer()}
  def endpoint(%{port: port}), do: {"127.0.0.1", port}
end
