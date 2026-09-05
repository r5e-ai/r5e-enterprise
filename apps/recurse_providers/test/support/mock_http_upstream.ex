defmodule Recurse.Providers.Support.MockHttpUpstream do
  @moduledoc """
  Bypass-style inline mock HTTP upstream for provider contract tests
  (T029 and later).

  Minimal Plug.Cowboy server on a random port. Each test starts its own
  instance under a unique ref + port so the suite stays `async: true` —
  no global singletons, no port collisions.

  ## Why not the `bypass` Hex package?

  Bypass 2.1 pins `ranch ~> 1.3`; the umbrella's `cowboy 2.14` requires
  `ranch >= 1.8`. We already have `plug_cowboy` transitively, so the
  zero-conflict move is to roll the ~40-LOC equivalent in-tree. Same
  mental model: register a callback per-test that receives a `Plug.Conn`
  and returns a response.

  ## Usage

      setup do
        {:ok, upstream} = MockHttpUpstream.start()
        on_exit(fn -> MockHttpUpstream.stop(upstream) end)
        %{upstream: upstream}
      end

      test "routes request", %{upstream: upstream} do
        MockHttpUpstream.expect(upstream, fn conn ->
          assert conn.method == "POST"
          conn
          |> Plug.Conn.put_resp_header("content-type", "application/json")
          |> Plug.Conn.send_resp(200, ~s|{"ok":true}|)
        end)

        # issue request to MockHttpUpstream.url(upstream)
      end

  Isolation: each upstream owns its own Agent pid; the Dispatcher reads
  the current callback from the Agent via `:persistent_term` keyed by
  ref. No cross-test leakage.
  """

  defmodule Dispatcher do
    @moduledoc false
    @behaviour Plug

    @impl true
    def init(ref), do: ref

    @impl true
    def call(conn, ref) do
      agent = :persistent_term.get({Recurse.Providers.Support.MockHttpUpstream, ref})

      case Agent.get(agent, & &1) do
        nil ->
          Plug.Conn.send_resp(conn, 500, "no expectation registered for ref #{inspect(ref)}")

        fun when is_function(fun, 1) ->
          fun.(conn)
      end
    end
  end

  @doc """
  Start a mock upstream on a random ephemeral port. Returns an opaque
  map the test passes to other helpers. Each call produces an isolated
  server + agent — two tests run in parallel with no cross-talk.
  """
  @spec start() :: {:ok, map()} | {:error, term()}
  def start do
    ref = make_ref()
    {:ok, agent} = Agent.start_link(fn -> nil end)
    :persistent_term.put({__MODULE__, ref}, agent)

    case Plug.Cowboy.http(Dispatcher, ref, port: 0, ref: ref) do
      {:ok, _pid} ->
        port = :ranch.get_port(ref)
        {:ok, %{ref: ref, port: port, agent: agent}}

      {:error, reason} ->
        :persistent_term.erase({__MODULE__, ref})
        Agent.stop(agent)
        {:error, reason}
    end
  end

  @doc """
  Stop the mock upstream + clean up the agent + `:persistent_term`
  entry. Safe to call from `on_exit/1`.
  """
  @spec stop(map()) :: :ok
  def stop(%{ref: ref, agent: agent}) do
    _ = Plug.Cowboy.shutdown(ref)
    :persistent_term.erase({__MODULE__, ref})

    if Process.alive?(agent) do
      Agent.stop(agent)
    end

    :ok
  end

  @doc """
  Register the callback invoked on the next request. Overwrites any
  previously-registered callback.
  """
  @spec expect(map(), (Plug.Conn.t() -> Plug.Conn.t())) :: :ok
  def expect(%{agent: agent}, fun) when is_function(fun, 1) do
    Agent.update(agent, fn _ -> fun end)
  end

  @doc """
  Full base URL (scheme + host + port) of the upstream, suitable for
  passing as an OpenAI-compatible `base_url` config value.
  """
  @spec url(map()) :: String.t()
  def url(%{port: port}), do: "http://127.0.0.1:#{port}"
end
