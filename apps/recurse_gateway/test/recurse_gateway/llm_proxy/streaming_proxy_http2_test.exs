defmodule Recurse.Gateway.LlmProxy.StreamingProxyHttp2Test do
  @moduledoc """
  Spec 012 S2 review — the HTTP/2 request path of `StreamingProxy` against
  an h2 upstream (Cowboy over TLS, ALPN `h2`; the proxy's own
  `protocols: [:http2, :http1]` negotiation, unchanged):

    * a request body larger than the 65,535-byte initial window arrives
      upstream intact (windowed send, WINDOW_UPDATE consumed);
    * an early 4xx that lands while the body is still being sent reaches
      the client with its status and body;
    * an upstream that never sends WINDOW_UPDATE makes the proxy give up
      after `:llm_proxy_window_update_timeout_ms`, answer 503, close the
      upstream socket, and log the request headers only in redacted form;
    * messages that are not the Mint socket's stay in the mailbox.
  """

  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias Recurse.Gateway.LlmProxy.StreamingProxy
  alias Recurse.Gateway.Policy.Active
  alias Recurse.Gateway.PolicyBundleRef
  alias Recurse.Gateway.Test.{KernelFixture, MockHttpUpstream}
  alias Recurse.Providers.Schemas.LlmProviderConfig

  @window 65_535
  @bearer "Bearer sk-ant-oat01-" <> String.duplicate("s", 100)

  setup_all do
    :ok = KernelFixture.boot()
    activate_permit_all()
  end

  setup do
    {:ok, upstream} = MockHttpUpstream.start(scheme: :https)

    prior_tls = Application.get_env(:recurse_gateway, :llm_proxy_outbound_tls_opts)
    prior_timeout = Application.get_env(:recurse_gateway, :llm_proxy_window_update_timeout_ms)
    Application.put_env(:recurse_gateway, :llm_proxy_outbound_tls_opts, verify: :verify_none)

    on_exit(fn ->
      MockHttpUpstream.stop(upstream)
      restore_env(:llm_proxy_outbound_tls_opts, prior_tls)
      restore_env(:llm_proxy_window_update_timeout_ms, prior_timeout)
    end)

    {:ok, upstream: upstream}
  end

  defp restore_env(key, nil), do: Application.delete_env(:recurse_gateway, key)
  defp restore_env(key, value), do: Application.put_env(:recurse_gateway, key, value)

  defp activate_permit_all do
    source = "permit(principal, action, resource);"
    hash = Recurse.Cedar.canonical_hash(source)

    :ok =
      Active.update(%Active{
        source: :filesystem,
        source_ref: "streaming-proxy-http2-test",
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

  defp build_config(port) do
    %LlmProviderConfig{
      tenant_id: "01TEN_H2",
      provider: "test_h2",
      upstream_host: "127.0.0.1",
      upstream_port: port,
      transport_modes: ["https-sse"],
      auth_mode: :bearer,
      api_format: :anthropic_messages,
      enabled: true,
      metadata: %{"scheme" => "https"}
    }
  end

  defp proxy(conn, port) do
    StreamingProxy.proxy(conn, %{llm_provider_config: build_config(port), tenant_id: "01TEN_H2"})
  end

  defp post(body) do
    Plug.Test.conn(:post, "/v1/messages", body)
    |> Plug.Conn.put_req_header("content-type", "application/json")
    |> Plug.Conn.put_req_header("authorization", @bearer)
  end

  defp big_body(bytes) do
    pad = String.duplicate("x", bytes)
    ~s|{"model":"claude-haiku-4-5","max_tokens":5,"pad":"#{pad}"}|
  end

  defp resp_body(%Plug.Conn{adapter: {_, %{chunks: chunks}}}) when is_list(chunks),
    do: IO.iodata_to_binary(chunks)

  defp resp_body(%Plug.Conn{adapter: {_, %{chunks: chunks}}}) when is_binary(chunks), do: chunks
  defp resp_body(%Plug.Conn{resp_body: body}) when is_binary(body), do: body

  defp read_all(conn, acc) do
    case Plug.Conn.read_body(conn) do
      {:ok, chunk, conn} -> {acc <> chunk, conn}
      {:more, chunk, conn} -> read_all(conn, acc <> chunk)
    end
  end

  test "a request body larger than the h2 initial window arrives upstream intact",
       %{upstream: upstream} do
    body = big_body(3 * @window)
    assert byte_size(body) > @window
    test_pid = self()

    MockHttpUpstream.expect(upstream, fn conn ->
      {seen, conn} = read_all(conn, "")

      send(
        test_pid,
        {:upstream_saw, Plug.Conn.get_http_protocol(conn), byte_size(seen),
         :crypto.hash(:sha256, seen), conn.req_headers}
      )

      conn
      |> Plug.Conn.put_resp_header("content-type", "application/json")
      |> Plug.Conn.send_resp(200, ~s|{"type":"message","content":[]}|)
    end)

    result = proxy(post(body), upstream.port)

    assert result.status == 200
    assert resp_body(result) == ~s|{"type":"message","content":[]}|

    expected_size = byte_size(body)
    expected_hash = :crypto.hash(:sha256, body)

    assert_receive {:upstream_saw, :"HTTP/2", ^expected_size, ^expected_hash, headers}, 5_000
    assert {"authorization", @bearer} in headers
  end

  test "an early 4xx that lands mid-send is surfaced with its status and headers", %{
    upstream: upstream
  } do
    body = big_body(3 * @window)
    wire = ~s|{"type":"error","error":{"type":"request_too_large"}}|

    # Reply without reading the body: the response crosses the wire while
    # the proxy is still blocked on the stream window.
    MockHttpUpstream.expect(upstream, fn conn ->
      conn
      |> Plug.Conn.put_resp_header("content-type", "application/json")
      |> Plug.Conn.put_resp_header("request-id", "req_early_413")
      |> Plug.Conn.send_resp(413, wire)
    end)

    result = proxy(post(body), upstream.port)

    # B3 (RC review 2026-09-05): the status code no longer switches the
    # parser off, and this body survives that change. The parser for this
    # format reads whole JSON bodies, it read this one, and it found no
    # executable tool frame in it — so the bytes are classified and
    # forwarded, exactly as they would be at 200. Nothing is appended to a
    # non-SSE body that was released in full; the client sees the
    # provider's own error, its status and its `request-id`.
    assert result.status == 413
    assert {"request-id", "req_early_413"} in result.resp_headers
    assert resp_body(result) == wire
  end

  test "an h2 stream reset before response headers returns 503 and records interruption" do
    before_count = length(R5e.Log.read_events())
    {port, upstream_pid} = start_stalled_h2_upstream(self(), :reset)
    result = proxy(post(big_body(3 * @window)), port)

    assert result.status == 503
    assert %{"error" => %{"code" => "ERR_UPSTREAM_UNAVAILABLE"}} = JSON.decode!(result.resp_body)
    assert_receive {:upstream_closed, ^upstream_pid, _}, 3_000

    assert_new_interruption(before_count)
  end

  test "connection refusal records the admitted opening's interrupted outcome" do
    # Reserve an ephemeral port, then close it: no upstream listener remains.
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    {:ok, {_, port}} = :inet.sockname(listener)
    :ok = :gen_tcp.close(listener)
    before_count = length(R5e.Log.read_events())

    result = proxy(post(big_body(10)), port)

    assert result.status == 503
    assert %{"error" => %{"code" => "ERR_UPSTREAM_UNAVAILABLE"}} = JSON.decode!(result.resp_body)
    assert_new_interruption(before_count)
  end

  test "WINDOW_UPDATE timeout answers 503, closes the upstream socket, logs headers redacted only" do
    Application.put_env(:recurse_gateway, :llm_proxy_window_update_timeout_ms, 300)
    {port, upstream_pid} = start_stalled_h2_upstream(self())
    Logger.put_module_level(StreamingProxy, :debug)
    on_exit(fn -> Logger.delete_module_level(StreamingProxy) end)

    body = big_body(3 * @window)
    before_count = length(R5e.Log.read_events())
    started = System.monotonic_time(:millisecond)

    {result, log} =
      with_log([level: :debug], fn -> proxy(post(body), port) end)

    elapsed = System.monotonic_time(:millisecond) - started

    assert result.status == 503
    assert %{"error" => %{"code" => "ERR_UPSTREAM_UNAVAILABLE"}} = JSON.decode!(result.resp_body)
    assert elapsed < 5_000, "expected the 300 ms window timeout, took #{elapsed} ms"

    # The proxy closed its side: the upstream's blocking recv returns
    # :closed rather than waiting for more DATA frames.
    assert_receive {:upstream_closed, ^upstream_pid, bytes_seen}, 3_000
    assert bytes_seen >= @window

    assert log =~ "window_update_timeout"
    assert log =~ "request headers (redacted)"
    assert log =~ "Bearer s…<redacted len=#{String.length(@bearer)}>"
    refute log =~ @bearer
    assert_new_interruption(before_count)
  end

  test "messages that are not the Mint socket's are left in the mailbox", %{upstream: upstream} do
    test_pid = self()

    MockHttpUpstream.expect(upstream, fn conn ->
      # Mid-stream, from another process — the shape Bandit uses for h2
      # flow control on the request process.
      send(test_pid, {:bandit, {:send_window_update, 4_096}})
      send(test_pid, {:bandit, {:rst_stream, :cancel}})

      conn
      |> Plug.Conn.put_resp_content_type("text/event-stream")
      |> Plug.Conn.send_resp(200, "event: ping\ndata: {\"type\":\"ping\"}\n\n")
    end)

    result = proxy(post(big_body(2 * @window)), upstream.port)

    assert result.status == 200
    assert_received {:bandit, {:send_window_update, 4_096}}
    assert_received {:bandit, {:rst_stream, :cancel}}
  end

  # A TLS listener that completes the h2 handshake (server SETTINGS, ACK of
  # the client's SETTINGS), reads whatever arrives, and never sends a
  # WINDOW_UPDATE. Reports `{:upstream_closed, pid, bytes}` to `owner`
  # when the client closes the connection.
  defp start_stalled_h2_upstream(owner, mode \\ :stall) do
    {:ok, listen} =
      :ssl.listen(
        0,
        MockHttpUpstream.tls_server_opts() ++
          [alpn_preferred_protocols: ["h2"], active: false, mode: :binary, reuseaddr: true]
      )

    {:ok, {_, port}} = :ssl.sockname(listen)

    pid =
      spawn_link(fn ->
        {:ok, transport} = :ssl.transport_accept(listen, 5_000)
        {:ok, socket} = :ssl.handshake(transport, 5_000)
        # Empty server SETTINGS, then an ACK for the client's SETTINGS.
        :ok = :ssl.send(socket, <<0, 0, 0, 4, 0, 0, 0, 0, 0>>)
        :ok = :ssl.send(socket, <<0, 0, 0, 4, 1, 0, 0, 0, 0>>)

        if mode == :reset do
          {:ok, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"} = :ssl.recv(socket, 24, 5_000)
          stream_id = read_request_stream_id(socket)
          # RST_STREAM(PROTOCOL_ERROR), after the client's HEADERS frame.
          :ok = :ssl.send(socket, <<4::24, 3, 0, 0::1, stream_id::31, 1::32>>)
        end

        drain(socket, owner, 0)
      end)

    {port, pid}
  end

  defp read_request_stream_id(socket) do
    {:ok, <<length::24, type, _flags, _reserved::1, stream_id::31>>} = :ssl.recv(socket, 9, 5_000)
    if length > 0, do: {:ok, _payload} = :ssl.recv(socket, length, 5_000)
    if type == 1, do: stream_id, else: read_request_stream_id(socket)
  end

  defp assert_new_interruption(before_count) do
    new_records =
      R5e.Log.read_events()
      |> Enum.drop(before_count)
      |> Enum.map(fn event ->
        {:ok, payload} = R5e.Log.payload(event)
        {event, payload}
      end)

    of_kind = fn kind ->
      Enum.filter(new_records, fn {_, payload} ->
        R5e.Admission.target_path(payload) == "gateway.r5e.io/v1alpha1/" <> kind
      end)
    end

    assert [{opening_event, opening}] = of_kind.("LlmCall")
    assert [{response_event, response}] = of_kind.("LlmResponse")
    assert opening["outcome"] == "admitted"
    assert response["outcome"] == "admitted"
    assert response_event["seq"] > opening_event["seq"]
    assert response["spec"]["llmCall"] == %{"$ref" => "event:" <> opening_event["hash"]}
    assert response["spec"]["outcome"] == "error"
    assert response["spec"]["errorKind"] == "upstream_connection_failed"
    refute Map.has_key?(response["spec"], "completion")
    assert of_kind.("Completion") == []
  end

  defp drain(socket, owner, seen) do
    case :ssl.recv(socket, 0, 10_000) do
      {:ok, data} -> drain(socket, owner, seen + byte_size(data))
      {:error, _closed} -> send(owner, {:upstream_closed, self(), seen})
    end
  end
end
