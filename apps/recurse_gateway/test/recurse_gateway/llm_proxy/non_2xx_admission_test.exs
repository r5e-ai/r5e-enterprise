defmodule Recurse.Gateway.LlmProxy.Non2xxAdmissionTest do
  @moduledoc """
  B3 (RC review 2026-09-05): **the upstream's status code does not decide
  whether the gateway enforces.**

  These are reviewer 1's probes, kept. On the release candidate they
  demonstrated the defect: `send_response_head/2` set `parser_bypass?` on
  any status ≥ 400 and every later byte went straight to the client, so a
  429 or a 500 carrying a `function_call` frame reached the client
  byte-for-byte with **zero** `ToolCall` admissions. R4 enumerates the
  ways a stream may not become a raw forward; "the upstream said 429" was
  not on the list, which is exactly what made it reachable.

  The rule now is one rule for every status:

    * the parser runs, and a tool intent it finds is admitted through the
      kernel before its bytes are released — whatever the status was;
    * a body the parser cannot classify is **withheld**, and the client
      gets a gateway error envelope carrying the upstream's status and the
      sha256 of the bytes this gateway received;
    * the status line and the forwarded headers are still the upstream's,
      so a client backing off on `429` + `Retry-After` still can.

  Everything here runs against a real kernel: real admission, real CAS,
  real Cedar. The provider endpoint is the only mock.
  """
  use ExUnit.Case, async: false

  alias Recurse.Gateway.Fold.Admission
  alias Recurse.Gateway.LlmProxy.StreamingProxy
  alias Recurse.Gateway.Policy.Active
  alias Recurse.Gateway.PolicyBundleRef
  alias Recurse.Gateway.Test.MockHttpUpstream
  alias Recurse.Providers.Schemas.LlmProviderConfig

  setup do
    previous = Application.get_all_env(:r5e)
    previous_retention = Application.get_env(:recurse_gateway, :retain_payloads?)
    Application.stop(:recurse_fold)
    Application.stop(:r5e)
    dir = Path.join(System.tmp_dir!(), "r5e-non2xx-#{System.unique_integer([:positive])}")
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
      source_ref: "non-2xx-test",
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

  defp config(port) do
    %LlmProviderConfig{
      tenant_id: "non2xx-tenant",
      provider: "test-provider",
      upstream_host: "127.0.0.1",
      upstream_port: port,
      transport_modes: ["https-sse"],
      auth_mode: :bearer,
      api_format: :openai_responses,
      enabled: true,
      metadata: %{"scheme" => "http"}
    }
  end

  defp request,
    do: Jason.encode!(%{type: "response.create", model: "test-model", input: "test input"})

  defp event(type, fields), do: Jason.encode!(Map.put(fields, "type", type))

  defp tool_stream(call_id \\ "call-1") do
    item = %{
      "type" => "function_call",
      "id" => "item-" <> call_id,
      "call_id" => call_id,
      "name" => "read_file",
      "arguments" => ~s({"path":"/etc/shadow"})
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
    |> Enum.map_join(&("data: " <> &1 <> "\n\n"))
  end

  defp http_upstream do
    {:ok, upstream} = MockHttpUpstream.start()
    on_exit(fn -> MockHttpUpstream.stop(upstream) end)
    upstream
  end

  defp answer(upstream, status, content_type, body) do
    MockHttpUpstream.expect(upstream, fn conn ->
      conn
      |> Plug.Conn.put_resp_content_type(content_type)
      |> Plug.Conn.send_resp(status, body)
    end)
  end

  defp http_call(upstream) do
    StreamingProxy.proxy(Plug.Test.conn(:post, "/v1/responses", request()), %{
      llm_provider_config: config(upstream.port),
      tenant_id: "non2xx-tenant"
    })
  end

  defp payloads(kind) do
    for event <- R5e.Log.read_events(),
        {:ok, payload} <- [R5e.Log.payload(event)],
        R5e.Admission.target_path(payload) == "gateway.r5e.io/v1alpha1/" <> kind,
        do: payload
  end

  describe "a tool frame in a non-2xx body is admitted like any other" do
    test "429 with a function_call produces a ToolCall admission" do
      upstream = http_upstream()
      wire = tool_stream()
      answer(upstream, 429, "text/event-stream", wire)

      assert %{status: 429, resp_body: body} = http_call(upstream)

      # The tool went through the kernel. That is the whole finding: on the
      # release candidate this list was empty.
      assert length(payloads("ToolCall")) == 1
      assert length(payloads("LlmCall")) == 1

      # The permit policy allowed it, so the bytes are released — but only
      # after the admission that made them releasable.
      assert body =~ "function_call"
    end

    test "500 with a function_call produces a ToolCall admission" do
      upstream = http_upstream()
      answer(upstream, 500, "text/event-stream", tool_stream("call-500"))

      assert %{status: 500} = http_call(upstream)
      assert length(payloads("ToolCall")) == 1
    end

    test "control: the same body at 200 behaves identically" do
      upstream = http_upstream()
      answer(upstream, 200, "text/event-stream", tool_stream())

      assert %{status: 200} = http_call(upstream)
      assert length(payloads("ToolCall")) == 1
    end
  end

  describe "a non-2xx body the parser cannot classify is withheld" do
    test "the client gets an envelope naming the status and the bytes, not the bytes" do
      upstream = http_upstream()
      wire = ~s|{"error":{"type":"rate_limit_error","message":"slow down"}}|
      answer(upstream, 429, "application/json", wire)

      assert %{status: 429, resp_body: body} = http_call(upstream)

      refute body =~ "rate_limit_error"
      refute body =~ "slow down"
      assert body =~ "gateway_upstream_unclassified"
      assert body =~ ~s("upstream_status":429)
      assert body =~ Base.encode16(:crypto.hash(:sha256, wire), case: :lower)
    end

    test "the LlmResponse records the suppression and the status" do
      upstream = http_upstream()
      answer(upstream, 503, "application/json", ~s|{"error":"upstream is down"}|)

      assert %{status: 503} = http_call(upstream)

      assert [response] = payloads("LlmResponse")
      assert response["spec"]["outcome"] == "error"
      assert response["spec"]["upstreamStatus"] == 503
      assert response["spec"]["errorKind"] == "parser_failure"
      assert response["spec"]["responseWithheld"] == true
      assert response["spec"]["toolCalls"] == []
    end

    test "an incomplete Anthropic JSON error body reports withholding after EOF" do
      upstream = http_upstream()
      wire = "{"
      answer(upstream, 429, "application/json", wire)

      assert %{status: 429, resp_body: body} =
               StreamingProxy.proxy(Plug.Test.conn(:post, "/v1/messages", request()), %{
                 llm_provider_config: %{config(upstream.port) | api_format: :anthropic_messages},
                 tenant_id: "non2xx-tenant"
               })

      assert %{"error" => error} = Jason.decode!(body)
      assert error["type"] == "gateway_upstream_unclassified"
      assert error["upstream_status"] == 429
      assert error["response_sha256"] == Base.encode16(:crypto.hash(:sha256, wire), case: :lower)
      refute body == wire
      assert payloads("ToolCall") == []
      assert [response] = payloads("LlmResponse")
      assert response["spec"]["errorKind"] == "parser_failure"
      assert response["spec"]["responseWithheld"] == true
    end

    test "an unrecognized SSE error frame reports the suppressed body and its hash" do
      upstream = http_upstream()

      wire =
        "data: " <> event("unrecognized.provider.error", %{"secret" => "withhold-me"}) <> "\n\n"

      answer(upstream, 429, "text/event-stream", wire)

      assert %{status: 429, resp_body: body} = http_call(upstream)
      refute body =~ "withhold-me"
      refute body =~ "unrecognized.provider.error"
      assert body =~ "gateway_upstream_unclassified"
      assert body =~ ~s("upstream_status":429)
      assert body =~ Base.encode16(:crypto.hash(:sha256, wire), case: :lower)
      assert payloads("ToolCall") == []
      assert [response] = payloads("LlmResponse")
      assert response["spec"]["errorKind"] == "parser_failure"
      assert response["spec"]["responseWithheld"] == true
    end

    test "a released SSE prefix remains an interruption, not full-body withholding" do
      upstream = http_upstream()

      prefix =
        "data: " <> event("response.created", %{"response" => %{"id" => "prefix"}}) <> "\n\n"

      invalid =
        "data: " <> event("unrecognized.provider.error", %{"secret" => "withhold-me"}) <> "\n\n"

      wire = prefix <> invalid

      MockHttpUpstream.expect(upstream, fn conn ->
        conn =
          conn
          |> Plug.Conn.put_resp_content_type("text/event-stream")
          |> Plug.Conn.send_chunked(429)

        {:ok, conn} = Plug.Conn.chunk(conn, prefix)
        Process.sleep(100)
        {:ok, conn} = Plug.Conn.chunk(conn, invalid)
        conn
      end)

      assert %{status: 429, resp_body: body} = http_call(upstream)
      assert body =~ "response.created"
      refute body =~ "withhold-me"
      assert body =~ "gateway_interrupted"
      refute body =~ "gateway_upstream_unclassified"
      assert body =~ ~s("upstream_status":429)
      assert body =~ Base.encode16(:crypto.hash(:sha256, wire), case: :lower)
      assert payloads("ToolCall") == []
      assert [response] = payloads("LlmResponse")
      assert response["spec"]["errorKind"] == "parser_failure"
      refute response["spec"]["responseWithheld"] == true
    end

    test "a 2xx body the parser cannot classify is withheld the same way" do
      # Not a regression of B3 — the pre-existing rule for an unreadable
      # 200, asserted here because B3 made the two paths one path.
      upstream = http_upstream()
      answer(upstream, 200, "application/json", ~s|{"output":[{"type":"function_call"}]}|)

      assert %{status: 200, resp_body: body} = http_call(upstream)

      refute body =~ "function_call"
      assert payloads("ToolCall") == []
      assert [response] = payloads("LlmResponse")
      assert response["spec"]["responseWithheld"] == true
    end
  end
end
