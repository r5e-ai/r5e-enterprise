defmodule Recurse.Gateway.Test.MockHttpUpstream do
  @moduledoc """
  Bypass-style inline mock HTTP upstream for Gateway integration tests
  (F002 T054).

  Minimal `Plug.Cowboy` server on a random port. Each test starts its own
  instance under a unique ref + port; shutting it down releases the port
  and the backing Agent cleanly.

  ## Why does this module exist in BOTH apps?

  `apps/recurse_providers/test/support/mock_http_upstream.ex` ships the
  same helper scoped to provider contract tests. The copy here is
  deliberate per the F002 tasks.md T054 option-A direction: test modules
  in one umbrella app SHOULD NOT reach into sibling apps' `:test`
  artifacts (doing so breaks `mix test apps/recurse_gateway`-only runs
  + couples compile graphs that should stay loosely coupled). ~50 LOC
  duplication for zero cross-app dep drag.

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

  ## HTTP/2 (spec 012 S2 review)

  `start(scheme: :https)` serves TLS with a throwaway RSA chain from
  `:public_key.pkix_test_data/1` and ALPN `h2` + `http/1.1` (Cowboy's
  default), so a Mint client with `protocols: [:http2, :http1]`
  negotiates HTTP/2 exactly as it does against api.anthropic.com. The
  client must skip verification (`verify: :verify_none`) — the chain is
  generated per VM. `tls_server_opts/0` exposes the same chain for
  hand-rolled `:ssl` listeners.
  """

  defmodule Dispatcher do
    @moduledoc false
    @behaviour Plug

    @impl true
    def init(ref), do: ref

    @impl true
    def call(conn, ref) do
      agent = :persistent_term.get({Recurse.Gateway.Test.MockHttpUpstream, ref})

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
  @spec start(keyword()) :: {:ok, map()} | {:error, term()}
  def start(opts \\ []) do
    ref = make_ref()
    scheme = Keyword.get(opts, :scheme, :http)
    {:ok, agent} = Agent.start_link(fn -> nil end)
    :persistent_term.put({__MODULE__, ref}, agent)

    result =
      case scheme do
        :http -> Plug.Cowboy.http(Dispatcher, ref, port: 0, ref: ref)
        :https -> Plug.Cowboy.https(Dispatcher, ref, [port: 0, ref: ref] ++ tls_server_opts())
      end

    case result do
      {:ok, _pid} ->
        port = :ranch.get_port(ref)
        {:ok, %{ref: ref, port: port, agent: agent, scheme: scheme}}

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
  Spec 012 S4 — register an expectation that serves `sse` as a
  `text/event-stream` response, written in chunks of `chunk_size` bytes
  (so event boundaries fall mid-line / mid-event the way a real
  upstream's TCP segments do). Extra response headers may be given.
  """
  @spec serve_sse(map(), binary(), keyword()) :: :ok
  def serve_sse(upstream, sse, opts \\ []) when is_binary(sse) do
    chunk_size = Keyword.get(opts, :chunk_size, 97)
    headers = Keyword.get(opts, :headers, [])
    status = Keyword.get(opts, :status, 200)

    expect(upstream, fn conn ->
      conn =
        Enum.reduce(headers, conn, fn {k, v}, c -> Plug.Conn.put_resp_header(c, k, v) end)

      conn =
        conn
        |> Plug.Conn.put_resp_content_type("text/event-stream")
        |> Plug.Conn.send_chunked(status)

      sse
      |> chunk_bytes(chunk_size)
      |> Enum.reduce(conn, fn part, c ->
        {:ok, c} = Plug.Conn.chunk(c, part)
        c
      end)
    end)
  end

  defp chunk_bytes("", _size), do: []

  defp chunk_bytes(bytes, size) when byte_size(bytes) <= size, do: [bytes]

  defp chunk_bytes(bytes, size) do
    <<head::binary-size(size), rest::binary>> = bytes
    [head | chunk_bytes(rest, size)]
  end

  @doc """
  Full base URL (scheme + host + port) of the upstream, suitable for
  passing as an OpenAI-compatible `base_url` config value.
  """
  @spec url(map()) :: String.t()
  def url(%{port: port} = upstream),
    do: "#{Map.get(upstream, :scheme, :http)}://127.0.0.1:#{port}"

  @doc """
  `[cert: der, key: {:RSAPrivateKey, der}, cacerts: [der]]` for a
  throwaway server chain, generated once per VM (RSA 2048 — ECDSA test
  chains fail OTP's TLS 1.3 server cert selection). Suitable for
  `Plug.Cowboy.https/3` and `:ssl.listen/2`.
  """
  @spec tls_server_opts() :: keyword()
  def tls_server_opts do
    case :persistent_term.get({__MODULE__, :tls_server_opts}, nil) do
      nil ->
        key = {:rsa, 2048, 65_537}

        %{server_config: server} =
          :public_key.pkix_test_data(%{
            server_chain: %{root: [key: key], intermediates: [], peer: [key: key]},
            client_chain: %{root: [key: key], intermediates: [], peer: [key: key]}
          })

        opts = Keyword.take(server, [:cert, :key, :cacerts])
        :persistent_term.put({__MODULE__, :tls_server_opts}, opts)
        opts

      opts ->
        opts
    end
  end
end
