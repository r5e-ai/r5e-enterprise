defmodule Recurse.Gateway.LlmProxy.TransportRealAdmissionTest do
  use ExUnit.Case, async: false

  alias Mint.HTTP, as: Http
  alias Mint.WebSocket, as: Ws
  alias Recurse.Gateway.Fold.Admission
  alias Recurse.Gateway.LlmProxy.{StreamingProxy, WebSocketBridge}
  alias Recurse.Gateway.Policy.Active
  alias Recurse.Gateway.PolicyBundleRef
  alias Recurse.Gateway.Test.{MockHttpUpstream, MockWebsocketUpstream}
  alias Recurse.Providers.Schemas.LlmProviderConfig

  # These tests exercise actual kernel policy, CAS and admission. The provider
  # endpoint is the only mock; the optional legacy audit registry is absent.
  setup do
    previous = Application.get_all_env(:r5e)
    previous_retention = Application.get_env(:recurse_gateway, :retain_payloads?)
    Application.stop(:recurse_fold)
    Application.stop(:r5e)
    dir = Path.join(System.tmp_dir!(), "r5e-real-transport-#{System.unique_integer([:positive])}")
    Application.put_env(:r5e, :data_dir, dir)
    Application.put_env(:r5e, :start_server, false)
    Application.put_env(:r5e, :seed_kernel_policy, true)
    Application.put_env(:r5e, :policy, Recurse.Fold.Policy.Cedar)
    Application.put_env(:recurse_gateway, :retain_payloads?, false)
    Application.delete_env(:recurse_fold, :engine_build_address)
    {:ok, _} = Application.ensure_all_started(:recurse_fold)
    {:ok, _} = Application.ensure_all_started(:plug_cowboy)
    {:ok, _} = Application.ensure_all_started(:bandit)
    Active.erase()
    :ok = activate("permit(principal, action, resource);")
    assert Admission.ready?()

    on_exit(fn ->
      Application.stop(:recurse_fold)
      Application.stop(:r5e)
      for {key, _} <- Application.get_all_env(:r5e), do: Application.delete_env(:r5e, key)
      for {key, value} <- previous, do: Application.put_env(:r5e, key, value)
      Application.put_env(:recurse_gateway, :retain_payloads?, previous_retention)
      Active.erase()
      File.rm_rf!(dir)
    end)

    :ok
  end

  defp activate(source) do
    hash = Recurse.Cedar.canonical_hash(source)

    Active.update(%Active{
      source: :filesystem,
      source_ref: "real-transport-test",
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

  defp config(port, format \\ :openai_responses) do
    %LlmProviderConfig{
      tenant_id: "real-transport-tenant",
      provider: "test-provider",
      upstream_host: "127.0.0.1",
      upstream_port: port,
      transport_modes: ["https-sse", "wss"],
      auth_mode: :bearer,
      api_format: format,
      enabled: true,
      metadata: %{"scheme" => "http"}
    }
  end

  defp request,
    do: Jason.encode!(%{type: "response.create", model: "test-model", input: "test input"})

  defp event(type, fields), do: Jason.encode!(Map.put(fields, "type", type))

  defp events(call_id \\ "call-1") do
    item = %{
      "type" => "function_call",
      "id" => "item-" <> call_id,
      "call_id" => call_id,
      "name" => "read_file",
      "arguments" => ~s({"path":"/tmp/allowed-evidence"})
    }

    [
      event("response.created", %{
        "response" => %{"id" => "response-" <> call_id, "model" => "test-model"}
      }),
      event("response.output_item.added", %{"item" => Map.put(item, "arguments", "")}),
      event("response.function_call_arguments.done", %{
        "call_id" => call_id,
        "arguments" => item["arguments"]
      }),
      event("response.completed", %{
        "response" => %{
          "id" => "response-" <> call_id,
          "model" => "test-model",
          "output" => [item]
        }
      })
    ]
  end

  defp sse(events), do: Enum.map_join(events, &("data: " <> &1 <> "\n\n"))

  defp http_upstream do
    {:ok, upstream} = MockHttpUpstream.start()
    on_exit(fn -> MockHttpUpstream.stop(upstream) end)
    upstream
  end

  defp http_call(upstream, body \\ request()) do
    StreamingProxy.proxy(Plug.Test.conn(:post, "/v1/responses", body), %{
      llm_provider_config: config(upstream.port),
      tenant_id: "real-transport-tenant"
    })
  end

  defp payloads(kind) do
    for event <- R5e.Log.read_events(),
        {:ok, payload} <- [R5e.Log.payload(event)],
        R5e.Admission.target_path(payload) == "gateway.r5e.io/v1alpha1/" <> kind,
        do: payload
  end

  # Remove only the policy object in this test's fresh CAS after the model
  # request is admitted. The next real kernel workload admission must fail;
  # operational admission can still record the interrupted response.
  defp remove_test_policy_source do
    {:ok, bundle} = Recurse.Fold.Policy.Cedar.active_bundle()
    address = get_in(bundle, ["spec", "sourceRef", "$ref"])
    File.rm!(Path.join(R5e.CAS.root(), R5e.CAS.relative_path(address)))
  end

  test "HTTP tool admission failure interrupts output and preserves its cause" do
    upstream = http_upstream()

    MockHttpUpstream.expect(upstream, fn conn ->
      assert length(payloads("LlmCall")) == 1
      remove_test_policy_source()

      conn
      |> Plug.Conn.put_resp_content_type("text/event-stream")
      |> Plug.Conn.send_resp(200, sse(events()))
    end)

    assert %{status: 200, resp_body: body} = http_call(upstream)
    refute body =~ "function_call"
    refute body =~ "/tmp/allowed-evidence"
    refute body =~ "response.completed"
    assert body =~ "gateway_interrupted"

    assert [%{"policy" => %{"decision" => "error"}}] = payloads("ToolCall")

    assert [%{"spec" => %{"outcome" => "error", "errorKind" => "policy_evaluation_failure"}}] =
             payloads("LlmResponse")
  end

  test "HTTP cannot release a tool when the workload engine build descriptor is unavailable" do
    upstream = http_upstream()

    MockHttpUpstream.expect(upstream, fn conn ->
      Application.delete_env(:recurse_fold, :engine_build_address)

      conn
      |> Plug.Conn.put_resp_content_type("text/event-stream")
      |> Plug.Conn.send_resp(200, sse(events()))
    end)

    assert %{resp_body: body} = http_call(upstream)
    refute body =~ "function_call"
    refute body =~ "response.completed"
    assert body =~ "gateway_interrupted"

    assert [%{"policy" => %{"decision" => "error", "evaluation" => nil, "note" => note}}] =
             payloads("ToolCall")

    assert note =~ "engineBuildUnavailable"
  end

  test "HTTP model denial and unavailable kernel send no request to provider" do
    upstream = http_upstream()
    test_pid = self()

    MockHttpUpstream.expect(upstream, fn conn ->
      send(test_pid, :unexpected_upstream_request)
      Plug.Conn.send_resp(conn, 200, "unexpected")
    end)

    :ok = activate("forbid(principal, action, resource);")
    assert %{status: 503, resp_body: body} = http_call(upstream)
    assert body =~ "admission_failed"
    refute_receive :unexpected_upstream_request, 100
    assert length(payloads("LlmCall")) == 1

    Application.stop(:r5e)
    assert %{status: 503} = http_call(upstream)
    refute_receive :unexpected_upstream_request, 100
  end

  test "HTTP request admission precedes provider receipt and allowed tools retain evidence with retention off" do
    upstream = http_upstream()
    test_pid = self()
    wire = sse(events())

    MockHttpUpstream.expect(upstream, fn conn ->
      {:ok, bytes, conn} = Plug.Conn.read_body(conn)
      send(test_pid, {:provider_observed, bytes, length(payloads("LlmCall"))})

      conn
      |> Plug.Conn.put_resp_content_type("text/event-stream")
      |> Plug.Conn.send_resp(200, wire)
    end)

    assert %{status: 200, resp_body: ^wire} = http_call(upstream)
    assert_receive {:provider_observed, body, 1}
    assert body == request()
    assert length(payloads("ToolCall")) == 1

    assert [%{"spec" => %{"outcome" => "ok", "toolCalls" => [_], "llmCall" => %{"$ref" => _}}}] =
             payloads("LlmResponse")

    assert [%{"spec" => %{"contentRef" => %{"$ref" => address}}}] = payloads("Completion")
    assert {:ok, ^wire} = R5e.CAS.get(address)
  end

  test "HTTP denied tools never reach client, including terminal output repeats" do
    :ok = activate(~s|permit(principal, action == Action::"call_model", resource);|)
    upstream = http_upstream()
    :ok = MockHttpUpstream.serve_sse(upstream, sse(events()), chunk_size: 31)
    assert %{status: 200, resp_body: body} = http_call(upstream)
    refute body =~ "function_call"
    refute body =~ "/tmp/allowed-evidence"
    assert body =~ "response.completed"
    assert length(payloads("ToolCall")) == 1
    assert [%{"spec" => %{"outcome" => "ok", "toolCalls" => [_]}}] = payloads("LlmResponse")
  end

  test "HTTP policy identity comes from admission when the loader projection is absent" do
    expected = Recurse.Cedar.canonical_hash_hex("permit(principal, action, resource);")
    Active.erase()
    upstream = http_upstream()
    wire = sse(events())
    :ok = MockHttpUpstream.serve_sse(upstream, wire)
    assert %{status: 200, resp_body: ^wire} = http_call(upstream)

    assert [call] = payloads("LlmCall")
    assert {:ok, source} = R5e.CAS.get(call["policy"]["source"])
    assert Recurse.Cedar.canonical_hash_hex(source) == expected
    refute Map.has_key?(call["spec"]["gatewayContext"], "cedar_bundle_hash")

    assert [%{"spec" => %{"gatewayContext" => %{"opening_model_policy_hash" => ^expected}}}] =
             payloads("ToolCall")
  end

  test "HTTP malformed JSON and partial tool output are interrupted without executable bytes" do
    upstream = http_upstream()

    for {wire, error_type} <- [
          {"data: {malformed}\n\n", "gateway_upstream_unclassified"},
          {sse(Enum.take(events(), 2)), "gateway_interrupted"}
        ] do
      :ok = MockHttpUpstream.serve_sse(upstream, wire, chunk_size: 17)
      assert %{status: 200, resp_body: body} = http_call(upstream)
      refute body =~ "function_call"
      refute body =~ "response.completed"
      assert body =~ error_type
      assert body =~ Base.encode16(:crypto.hash(:sha256, wire), case: :lower)
    end

    assert payloads("ToolCall") == []
    assert Enum.all?(payloads("LlmResponse"), &(&1["spec"]["outcome"] == "error"))
    assert length(payloads("LlmResponse")) == 2
  end

  defmodule BridgeEndpoint do
    @behaviour Plug
    def init(opts), do: opts

    def call(conn, cfg),
      do: WebSocketBridge.upgrade(conn, llm_provider_config: cfg, tenant_id: cfg.tenant_id)
  end

  defp ws_upstream do
    {:ok, upstream} = MockWebsocketUpstream.start()
    {:ok, bridge} = Bandit.start_link(plug: {BridgeEndpoint, config(upstream.port)}, port: 0)
    {:ok, {_, port}} = ThousandIsland.listener_info(bridge)

    on_exit(fn ->
      monitor = Process.monitor(bridge)
      Process.exit(bridge, :shutdown)

      receive do
        {:DOWN, ^monitor, :process, ^bridge, _} -> :ok
      after
        2_000 -> flunk("bridge supervisor did not stop")
      end

      MockWebsocketUpstream.stop(upstream)
    end)

    {upstream, port}
  end

  test "WS admits independent turns on one socket and suppresses denied terminal repeats" do
    {upstream, port} = ws_upstream()
    test_pid = self()

    MockWebsocketUpstream.expect(upstream, fn {:text, _payload}, state ->
      count = Map.get(state, :count, 0) + 1
      send(test_pid, {:provider_turn, count, length(payloads("LlmCall"))})
      {:push, Enum.map(events("call-#{count}"), &{:text, &1}), Map.put(state, :count, count)}
    end)

    client = open_ws(port)
    client = send_ws(client, request())
    {client, first} = receive_turn(client)
    assert_receive {:provider_turn, 1, 1}
    assert Enum.any?(first, &String.contains?(&1, "/tmp/allowed-evidence"))
    assert length(payloads("LlmResponse")) == 1

    :ok = activate(~s|permit(principal, action == Action::"call_model", resource);|)
    client = send_ws(client, request())
    {client, second} = receive_turn(client)
    assert_receive {:provider_turn, 2, 2}
    refute Enum.any?(second, &String.contains?(&1, "function_call"))
    refute Enum.any?(second, &String.contains?(&1, "/tmp/allowed-evidence"))
    assert length(payloads("LlmCall")) == 2
    assert length(payloads("ToolCall")) == 2
    assert length(payloads("LlmResponse")) == 2
    assert Enum.all?(payloads("LlmResponse"), &(length(&1["spec"]["toolCalls"]) == 1))
    close_ws(client)
  end

  test "WS overlapping requests are closed before a second provider request" do
    {upstream, port} = ws_upstream()
    test_pid = self()

    MockWebsocketUpstream.expect(upstream, fn {:text, _}, state ->
      send(test_pid, :provider_got_request)
      {:ok, state}
    end)

    client = open_ws(port) |> send_ws(request())
    assert_receive :provider_got_request, 3_000
    client = send_ws(client, request())

    {client, frames} =
      receive_until(client, &Enum.any?(&1, fn f -> match?({:close, _, _}, f) end))

    assert Enum.any?(frames, &match?({:close, 1008, _}, &1))
    refute_receive :provider_got_request, 100
    assert length(payloads("LlmCall")) == 1
    close_ws(client)
  end

  test "WS model denial after handshake sends no model frame upstream" do
    {upstream, port} = ws_upstream()
    test_pid = self()

    MockWebsocketUpstream.expect(upstream, fn {:text, _}, state ->
      send(test_pid, :unexpected_model_frame)
      {:ok, state}
    end)

    client = open_ws(port)
    :ok = activate("forbid(principal, action, resource);")
    client = send_ws(client, request())

    {client, frames} =
      receive_until(client, &Enum.any?(&1, fn f -> match?({:close, _, _}, f) end))

    assert Enum.any?(frames, &match?({:close, 1008, _}, &1))
    refute_receive :unexpected_model_frame, 100
    close_ws(client)
  end

  test "WS tool admission failure closes output and preserves its cause" do
    {upstream, port} = ws_upstream()

    MockWebsocketUpstream.expect(upstream, fn {:text, _}, state ->
      assert length(payloads("LlmCall")) == 1
      remove_test_policy_source()
      {:push, Enum.map(events(), &{:text, &1}), state}
    end)

    client = open_ws(port) |> send_ws(request())

    {client, frames} =
      receive_until(client, &Enum.any?(&1, fn f -> match?({:close, _, _}, f) end))

    assert Enum.any?(frames, &match?({:close, 1011, _}, &1))

    refute Enum.any?(frames, fn
             {:text, bytes} ->
               String.contains?(bytes, "function_call") or
                 String.contains?(bytes, "response.completed")

             _ ->
               false
           end)

    close_ws(client)
    assert [%{"policy" => %{"decision" => "error"}}] = payloads("ToolCall")

    assert [%{"spec" => %{"outcome" => "error", "errorKind" => "policy_evaluation_failure"}}] =
             payloads("LlmResponse")
  end

  test "WS malformed and partial provider output closes without releasing executable bytes" do
    {upstream, port} = ws_upstream()

    for replies <- [
          ["{malformed"],
          Enum.take(events(), 2) ++
            [event("response.completed", %{"response" => %{"output" => []}})]
        ] do
      MockWebsocketUpstream.expect(upstream, fn {:text, _}, state ->
        {:push, Enum.map(replies, &{:text, &1}), state}
      end)

      client = open_ws(port) |> send_ws(request())

      {client, frames} =
        receive_until(client, &Enum.any?(&1, fn f -> match?({:close, _, _}, f) end))

      assert Enum.any?(frames, &match?({:close, 1011, _}, &1))

      refute Enum.any?(frames, fn
               {:text, bytes} ->
                 String.contains?(bytes, "function_call") or
                   String.contains?(bytes, "response.completed")

               _ ->
                 false
             end)

      close_ws(client)
    end

    assert payloads("ToolCall") == []
  end

  test "WS readiness fails before upgrade when kernel is unavailable" do
    {_upstream, port} = ws_upstream()
    Application.stop(:r5e)
    {:ok, conn} = Http.connect(:http, "127.0.0.1", port, protocols: [:http1])
    {:ok, conn, ref} = Ws.upgrade(:ws, conn, "/", [])
    socket = Http.get_socket(conn)

    receive do
      {:tcp, ^socket, _} = message ->
        {:ok, conn, responses} = Http.stream(conn, message)
        assert {:status, ref, 503} in responses
        Http.close(conn)
    after
      5_000 -> flunk("unavailable readiness did not reject upgrade")
    end
  end

  defp open_ws(port) do
    {:ok, conn} = Http.connect(:http, "127.0.0.1", port, protocols: [:http1])
    {:ok, conn, ref} = Ws.upgrade(:ws, conn, "/", [])
    await_open(%{conn: conn, ref: ref, ws: nil, headers: [], status: nil})
  end

  defp await_open(state) do
    socket = Http.get_socket(state.conn)

    receive do
      {tag, ^socket, _} = message when tag in [:tcp, :ssl] ->
        {:ok, conn, responses} = Http.stream(state.conn, message)

        state =
          Enum.reduce(responses, %{state | conn: conn}, fn
            {:status, ref, status}, st when ref == st.ref ->
              %{st | status: status}

            {:headers, ref, headers}, st when ref == st.ref ->
              %{st | headers: headers}

            {:done, ref}, st when ref == st.ref ->
              {:ok, conn, ws} = Ws.new(st.conn, st.ref, st.status, st.headers)
              %{st | conn: conn, ws: ws}

            _, st ->
              st
          end)

        if state.ws, do: state, else: await_open(state)
    after
      5_000 -> flunk("WebSocket upgrade timed out")
    end
  end

  defp send_ws(state, payload) do
    {:ok, ws, bytes} = Ws.encode(state.ws, {:text, payload})
    {:ok, conn} = Ws.stream_request_body(state.conn, state.ref, bytes)
    %{state | conn: conn, ws: ws}
  end

  defp receive_turn(state) do
    {state, frames} =
      receive_until(
        state,
        &Enum.any?(&1, fn
          {:text, bytes} ->
            case Jason.decode(bytes) do
              {:ok, %{"type" => "response.completed"}} -> true
              _ -> false
            end

          {:close, _, _} ->
            true

          _ ->
            false
        end)
      )

    refute Enum.any?(frames, &match?({:close, _, _}, &1)), "unexpected close: #{inspect(frames)}"
    {state, for({:text, bytes} <- frames, do: bytes)}
  end

  defp receive_until(state, predicate),
    do: receive_until(state, predicate, [], System.monotonic_time(:millisecond) + 5_000)

  defp receive_until(state, predicate, acc, deadline) do
    if predicate.(acc) do
      {state, acc}
    else
      socket = Http.get_socket(state.conn)
      remaining = max(deadline - System.monotonic_time(:millisecond), 0)

      receive do
        {tag, ^socket, _} = message when tag in [:tcp, :ssl] ->
          {:ok, conn, messages} = Ws.stream(state.conn, message)

          {state, frames} =
            Enum.reduce(messages, {%{state | conn: conn}, []}, fn
              {:data, ref, bytes}, {st, frames} when ref == st.ref ->
                {:ok, ws, decoded} = Ws.decode(st.ws, bytes)
                {%{st | ws: ws}, frames ++ decoded}

              _, acc ->
                acc
            end)

          receive_until(state, predicate, acc ++ frames, deadline)

        {tag, ^socket} when tag in [:tcp_closed, :ssl_closed] ->
          flunk("socket closed without requested protocol outcome: #{inspect(acc)}")
      after
        remaining -> flunk("timed out waiting for protocol outcome: #{inspect(acc)}")
      end
    end
  end

  defp close_ws(state) do
    {:ok, _ws, bytes} = Ws.encode(state.ws, :close)
    _ = Ws.stream_request_body(state.conn, state.ref, bytes)
    _ = Http.close(state.conn)
    :ok
  end
end
