defmodule Recurse.Gateway.LlmProxy.StreamingProxyFailureModesTest do
  @moduledoc """
  Failure-mode contract tests for `Recurse.Gateway.LlmProxy.StreamingProxy`
  (T033).

  Spec source:
  `specs/009-llm-api-proxy/contracts/streaming_proxy.md` §"Failure modes"
  + spec.md FR-016.

  | Failure | Behavior |
  |---|---|
  | Upstream connection fails | 503 to client |
  | Upstream 401 | status and headers forwarded; an unclassifiable body is withheld |
  | Upstream 429 | same, Retry-After preserved |
  | Parser failure mid-stream | fail-CLOSED, suppress undecidable and later chunks |
  | Cedar eval failure | fail-CLOSED (Sub-3.4 hook; not exercised here) |

  B3 (RC review 2026-09-05) changed the first two rows. A non-2xx status
  used to switch the proxy into raw forwarding, and a 429 body carrying a
  `function_call` frame reached the client byte-for-byte with no ToolCall
  admission — an upstream-chosen integer decided whether to enforce at
  all. The status and every forwarded header still reach the client
  unmodified, so a client still sees `429` and its `Retry-After`; the
  **body** now follows the same rule as any other: parsed and gated when
  the parser can read it, withheld with a gateway error envelope when it
  cannot.

  Workload and tool decisions run against the active kernel-governed Cedar
  bundle. These tests activate an explicit permit policy and then exercise
  transport failures around that admission boundary.
  """

  use ExUnit.Case, async: false

  alias Recurse.Gateway.LlmProxy.StreamingProxy
  alias Recurse.Gateway.Policy.Active
  alias Recurse.Gateway.PolicyBundleRef
  alias Recurse.Gateway.Test.{KernelFixture, MockHttpUpstream}
  alias Recurse.Providers.Schemas.LlmProviderConfig

  setup_all do
    :ok = KernelFixture.boot()
    activate_permit_all()
  end

  setup do
    {:ok, upstream} = MockHttpUpstream.start()
    on_exit(fn -> MockHttpUpstream.stop(upstream) end)
    {:ok, upstream: upstream}
  end

  defp build_config(upstream) do
    %LlmProviderConfig{
      tenant_id: "01TEN_FAIL",
      provider: "test_fail_provider",
      upstream_host: "127.0.0.1",
      upstream_port: upstream.port,
      transport_modes: ["https-sse"],
      auth_mode: :bearer,
      api_format: :openai_responses,
      enabled: true,
      metadata: %{"scheme" => "http"}
    }
  end

  defp build_conn(method, path, body, headers \\ []) do
    Plug.Test.conn(method, path, body)
    |> Map.update!(:req_headers, &(&1 ++ headers))
  end

  defp request_body, do: ~s({"model":"test-model"})

  defp activate_permit_all do
    source = "permit(principal, action, resource);"
    hash = Recurse.Cedar.canonical_hash(source)

    Active.update(%Active{
      source: :filesystem,
      source_ref: "streaming-proxy-failure-modes-test",
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

  defp sent_resp_body(%Plug.Conn{resp_body: body}) when is_binary(body), do: body

  defp sent_resp_body(%Plug.Conn{adapter: {Plug.Adapters.Test.Conn, %{chunks: chunks}}})
       when is_list(chunks) do
    IO.iodata_to_binary(chunks)
  end

  defp sent_resp_body(%Plug.Conn{adapter: {_, %{chunks: chunks}}}) when is_binary(chunks) do
    chunks
  end

  defp sent_resp_body(_), do: ""

  describe "upstream connection failures → 503" do
    test "connect-refused returns 503 with structured error", %{upstream: _upstream} do
      cfg = %LlmProviderConfig{
        tenant_id: "01TEN_FAIL",
        provider: "test",
        upstream_host: "127.0.0.1",
        upstream_port: 1,
        transport_modes: ["https-sse"],
        auth_mode: :bearer,
        api_format: :openai_responses,
        enabled: true,
        metadata: %{"scheme" => "http"}
      }

      conn = build_conn(:post, "/v1/responses", request_body())

      result =
        StreamingProxy.proxy(conn, %{
          llm_provider_config: cfg,
          tenant_id: "01TEN_FAIL",
          parser_module: Recurse.Gateway.LlmProxy.StreamingProxyFailureModesTest.NoopParser
        })

      assert result.status == 503
      body = sent_resp_body(result)
      assert body =~ "ERR_UPSTREAM_UNAVAILABLE"
      assert body =~ "upstream_connection_failed"
    end
  end

  describe "upstream 401 / 429 — status forwarded, unclassifiable body withheld (B3)" do
    test "401 keeps its status and withholds a body the parser cannot read", %{
      upstream: upstream
    } do
      MockHttpUpstream.expect(upstream, fn conn ->
        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.send_resp(401, ~s|{"error":"invalid_token"}|)
      end)

      conn = build_conn(:post, "/v1/responses", request_body())
      cfg = build_config(upstream)

      result =
        StreamingProxy.proxy(conn, %{
          llm_provider_config: cfg,
          tenant_id: "01TEN_FAIL",
          parser_module: Recurse.Gateway.LlmProxy.StreamingProxyFailureModesTest.NoopParser
        })

      assert result.status == 401

      body = sent_resp_body(result)
      refute body =~ "invalid_token"
      assert body =~ "gateway_upstream_unclassified"
      assert body =~ ~s("upstream_status":401)
    end

    test "429 keeps Retry-After and names the withheld body's hash", %{upstream: upstream} do
      wire = ~s|{"error":"rate_limit"}|

      MockHttpUpstream.expect(upstream, fn conn ->
        conn
        |> Plug.Conn.put_resp_header("retry-after", "120")
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.send_resp(429, wire)
      end)

      conn = build_conn(:post, "/v1/responses", request_body())
      cfg = build_config(upstream)

      result =
        StreamingProxy.proxy(conn, %{
          llm_provider_config: cfg,
          tenant_id: "01TEN_FAIL",
          parser_module: Recurse.Gateway.LlmProxy.StreamingProxyFailureModesTest.NoopParser
        })

      assert result.status == 429

      headers =
        Enum.into(result.resp_headers, %{}, fn {k, v} -> {String.downcase(k), v} end)

      # The client can still back off: the status and the header are the
      # upstream's own. What it does not get is bytes nothing classified.
      assert headers["retry-after"] == "120"

      body = sent_resp_body(result)
      refute body =~ "rate_limit"
      assert body =~ ~s("upstream_status":429)

      # The envelope names the bytes it withheld, so an auditor can line
      # the receipt up against the wire.
      assert body =~ Base.encode16(:crypto.hash(:sha256, wire), case: :lower)
    end
  end

  describe "parser failure mid-stream → fail-CLOSED" do
    test "parser raise suppresses the undecidable chunk and all later chunks", %{
      upstream: upstream
    } do
      MockHttpUpstream.expect(upstream, fn conn ->
        conn =
          conn
          |> Plug.Conn.put_resp_content_type("text/event-stream")
          |> Plug.Conn.send_chunked(200)

        # Three chunks; the parser will raise on the second.
        Enum.reduce(["data: chunk-1\n\n", "data: chunk-2\n\n", "data: chunk-3\n\n"], conn, fn p,
                                                                                              c ->
          {:ok, c} = Plug.Conn.chunk(c, p)
          c
        end)
      end)

      conn = build_conn(:post, "/v1/responses", request_body())
      cfg = build_config(upstream)

      result =
        StreamingProxy.proxy(conn, %{
          llm_provider_config: cfg,
          tenant_id: "01TEN_FAIL",
          parser_module: Recurse.Gateway.LlmProxy.StreamingProxyFailureModesTest.RaisingParser
        })

      assert result.status == 200

      body = sent_resp_body(result)

      # Approved bytes remain visible; undecidable and subsequent bytes do not.
      assert body =~ "chunk-1"
      refute body =~ "chunk-2"
      refute body =~ "chunk-3"

      # Spec 012 S4 review — after the raise the parser is never called
      # again (the proxy runs in this process, so the parser's
      # notifications land in our mailbox).
      assert_received {:parse_chunk_called, 1}
      assert_received {:parse_chunk_called, 2}
      refute_received {:parse_chunk_called, 3}
    end
  end

  test "unsupported successful JSON cannot release tool output", %{upstream: upstream} do
    MockHttpUpstream.expect(upstream, fn conn ->
      conn
      |> Plug.Conn.put_resp_content_type("application/json")
      |> Plug.Conn.send_resp(200, ~s({"output":[{"type":"function_call","name":"Bash"}]}))
    end)

    result =
      StreamingProxy.proxy(build_conn(:post, "/v1/responses", request_body()), %{
        llm_provider_config: build_config(upstream),
        tenant_id: "01TEN_FAIL",
        parser_module: __MODULE__.NoopParser
      })

    refute sent_resp_body(result) =~ "function_call"
  end

  test "unmatched admission marker suppresses its chunk and EOF tail", %{upstream: upstream} do
    MockHttpUpstream.expect(upstream, fn conn ->
      conn
      |> Plug.Conn.put_resp_content_type("text/event-stream")
      |> Plug.Conn.send_resp(200, "unapproved tool bytes")
    end)

    result =
      StreamingProxy.proxy(build_conn(:post, "/v1/responses", request_body()), %{
        llm_provider_config: build_config(upstream),
        tenant_id: "01TEN_FAIL",
        parser_module: __MODULE__.MissingIntentParser
      })

    body = sent_resp_body(result)
    assert body =~ "gateway_interrupted"
    refute body =~ "unapproved"
  end

  test "EOF cannot forward an intent that was never evaluated", %{upstream: upstream} do
    MockHttpUpstream.expect(upstream, fn conn ->
      conn
      |> Plug.Conn.put_resp_content_type("text/event-stream")
      |> Plug.Conn.send_resp(200, "held tool")
    end)

    result =
      StreamingProxy.proxy(build_conn(:post, "/v1/responses", request_body()), %{
        llm_provider_config: build_config(upstream),
        tenant_id: "01TEN_FAIL",
        parser_module: __MODULE__.FinalIntentParser
      })

    body = sent_resp_body(result)
    assert body =~ "gateway_interrupted"
    refute body =~ "unapproved"
    refute body =~ "held tool"
  end

  defmodule MissingIntentParser do
    def init(_opts), do: %{}

    def parse_chunk(state, chunk),
      do: {state, [], [{:cedar_eval, "missing"}, {:forward, chunk}]}

    def finalize(_state), do: {%{}, [{:forward, "unapproved EOF tool"}]}
  end

  defmodule FinalIntentParser do
    def init(_opts), do: %{}
    def parse_chunk(state, _chunk), do: {state, [], []}

    def finalize(_state),
      do: {%{}, [{:forward, "unapproved EOF tool"}, {:cedar_eval, "missing"}]}
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

  defmodule RaisingParser do
    @moduledoc false
    @behaviour Recurse.Shared.LlmProxy.Parsers.Parser

    @impl true
    def init(_opts), do: %{count: 0}

    @impl true
    def parse_chunk(state, chunk) do
      new_count = state.count + 1
      send(self(), {:parse_chunk_called, new_count})

      if new_count >= 2 do
        # Per Invariant I-001 parsers MUST NOT raise; we deliberately
        # violate to verify the proxy's fail-CLOSED handling.
        raise "synthetic parser bug — should be caught by proxy"
      end

      {%{state | count: new_count}, [], [{:forward, chunk}]}
    end

    @impl true
    def finalize(state) do
      {%{event_count: state.count, intent_count: 0}, []}
    end
  end
end
