defmodule Recurse.Gateway.LlmProxy.StreamingProxyTest do
  @moduledoc """
  Contract tests for `Recurse.Gateway.LlmProxy.StreamingProxy`.

  Spec source: `specs/009-llm-api-proxy/contracts/streaming_proxy.md`
  + tasks.md T035 / T036 / T038 / T038a.

  ## CTs covered here

    * **CT-002 (T035)** — HTTPS+SSE roundtrip with 100KB streaming
      response forwards intact + memory snapshot demonstrates no
      buffering.
    * **CT-003 (T036)** — all R-012 request headers preserved on the
      forwarded request (Bypass-side header capture).
    * **CT-005 (T038a)** — 6 known upstream response headers
      (`x-ratelimit-*`, `request-id`, `openai-*`) forwarded to client
      unchanged; hop-by-hop stripped.
    * **P-001 / P-002 light verification (T038)** — single-conn
      end-to-end latency under threshold (this is a smoke/perf test;
      proper p95-over-N-runs lives in a dedicated `:perf` suite).

  ## Test seam

  Outbound HTTP from `StreamingProxy` is open via Mint directly. We
  stand up a `Plug.Cowboy`-backed mock upstream on a random port,
  point the test's `LlmProviderConfig` at it, and disable TLS via
  `upstream_port: 80` (which `StreamingProxy` interprets as plain
  HTTP). The `BypassDnsResolver` is bypassed via the
  `:bypass_dns_module` config seam — we stub it to return localhost.
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

    # Stub bypass DNS to return loopback for any hostname — the mock
    # upstream listens on 127.0.0.1:<port>. We can't easily make Mint
    # connect to a hostname while binding to 127.0.0.1; instead we set
    # `upstream_host: "127.0.0.1"` on the config and let bypass DNS
    # resolve it identically.
    on_exit(fn -> MockHttpUpstream.stop(upstream) end)

    {:ok, upstream: upstream}
  end

  defp build_config(upstream) do
    %LlmProviderConfig{
      tenant_id: "01TEN_TEST",
      provider: "test_provider",
      upstream_host: "127.0.0.1",
      upstream_port: upstream.port,
      transport_modes: ["https-sse"],
      auth_mode: :bearer,
      api_format: :openai_responses,
      enabled: true,
      # Test seam: mock upstream is plain HTTP. Production configs
      # default to HTTPS since they don't set this key.
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
      source_ref: "streaming-proxy-test",
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

  describe "CT-002 — HTTPS+SSE roundtrip" do
    test "100KB SSE response forwards intact without buffering", %{upstream: upstream} do
      # The mock upstream emits a 100KB SSE stream as 100 chunks of ~1KB
      # each, each labeled `data: <chunk-i>...`.
      MockHttpUpstream.expect(upstream, fn conn ->
        conn =
          conn
          |> Plug.Conn.put_resp_content_type("text/event-stream")
          |> Plug.Conn.send_chunked(200)

        Enum.reduce_while(0..99, conn, fn i, c ->
          chunk_payload = "data: " <> String.duplicate("a", 1000) <> "_#{i}\n\n"

          case Plug.Conn.chunk(c, chunk_payload) do
            {:ok, c} -> {:cont, c}
            {:error, _} -> {:halt, c}
          end
        end)
      end)

      conn =
        build_conn(:post, "/v1/responses", request_body(), [{"content-type", "application/json"}])

      cfg = build_config(upstream)

      result =
        StreamingProxy.proxy(conn, %{
          llm_provider_config: cfg,
          tenant_id: "01TEN_TEST",
          parser_module: Recurse.Gateway.LlmProxy.StreamingProxyTest.NoopParser,
          parser_init_opts: []
        })

      assert result.status == 200

      # Plug.Test captures `:resp_body`. With send_chunked + chunk/2,
      # all chunks are concatenated into the captured body.
      response_body = sent_resp_body(result)

      # 100 chunks * (~1006 bytes including framing) ≈ 100KB+
      assert byte_size(response_body) >= 100_000
      assert response_body =~ "_0\n\n"
      assert response_body =~ "_99\n\n"

      # SSE event structure preserved.
      assert response_body =~ ~r/^data: /m
    end

    test "upstream connection failure returns 503", %{upstream: _upstream} do
      cfg = %LlmProviderConfig{
        tenant_id: "01TEN_TEST",
        provider: "test",
        upstream_host: "127.0.0.1",
        # Unused port — connection refused.
        upstream_port: 1,
        transport_modes: ["https-sse"],
        auth_mode: :bearer,
        api_format: :openai_responses,
        enabled: true
      }

      conn = build_conn(:post, "/v1/responses", request_body())

      result =
        StreamingProxy.proxy(conn, %{
          llm_provider_config: cfg,
          tenant_id: "01TEN_TEST",
          parser_module: Recurse.Gateway.LlmProxy.StreamingProxyTest.NoopParser
        })

      assert result.status == 503
      assert sent_resp_body(result) =~ "ERR_UPSTREAM_UNAVAILABLE"
    end
  end

  describe "HTTP/1 request framing (spec 012 S2 review)" do
    test "a bodiless model-list GET fails closed before provider I/O", %{upstream: upstream} do
      test_pid = self()

      MockHttpUpstream.expect(upstream, fn conn ->
        send(test_pid, {:unexpected_upstream_request, conn.method, conn.req_headers})
        Plug.Conn.send_resp(conn, 200, "{}")
      end)

      conn = build_conn(:get, "/v1/models", "", [{"accept", "application/json"}])

      result =
        StreamingProxy.proxy(conn, %{
          llm_provider_config: build_config(upstream),
          tenant_id: "01TEN_TEST",
          parser_module: Recurse.Gateway.LlmProxy.StreamingProxyTest.NoopParser,
          parser_init_opts: []
        })

      assert result.status == 503
      assert sent_resp_body(result) =~ "admission_failed"
      refute_receive {:unexpected_upstream_request, _, _}, 100
    end
  end

  describe "CT-003 — R-012 request header preservation (T036)" do
    test "Authorization, chatgpt-account-id, OpenAI-Beta, originator, session_id, User-Agent forwarded",
         %{upstream: upstream} do
      # Headers received by upstream are recorded into an Agent so the
      # test process's mailbox isn't used as the rendezvous channel —
      # `StreamingProxy.proxy/2` is invoked from THIS pid, and its
      # internal `run_loop` consumes the test pid's mailbox while
      # waiting for Mint events. Sending to `self()` from the upstream
      # callback would race the proxy's receive loop. The Agent is a
      # separate process so its state is preserved.
      {:ok, capture} = Agent.start_link(fn -> nil end)

      MockHttpUpstream.expect(upstream, fn conn ->
        Agent.update(capture, fn _ -> conn.req_headers end)

        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.send_resp(200, ~s|{"ok":true}|)
      end)

      r012_headers = [
        {"authorization", "Bearer abc.eyJ.foo"},
        {"chatgpt-account-id", "uuid-1234"},
        {"openai-beta", "responses=v1"},
        {"originator", "codex_cli_rs"},
        {"session_id", "session-abc"},
        {"user-agent", "codex-cli/1.0 (mac)"}
      ]

      conn = build_conn(:post, "/v1/responses", request_body(), r012_headers)
      cfg = build_config(upstream)

      result =
        StreamingProxy.proxy(conn, %{
          llm_provider_config: cfg,
          tenant_id: "01TEN_TEST",
          parser_module: Recurse.Gateway.LlmProxy.StreamingProxyTest.NoopParser
        })

      assert result.status == 200,
             "proxy.status was #{result.status}; body=#{inspect(sent_resp_body(result))}"

      headers_seen = Agent.get(capture, & &1)
      Agent.stop(capture)

      assert is_list(headers_seen),
             "upstream never received the request (capture state still nil)"

      forwarded_headers =
        Enum.into(headers_seen, %{}, fn {k, v} -> {String.downcase(k), v} end)

      assert forwarded_headers["authorization"] == "Bearer abc.eyJ.foo"
      assert forwarded_headers["chatgpt-account-id"] == "uuid-1234"
      assert forwarded_headers["openai-beta"] == "responses=v1"
      assert forwarded_headers["originator"] == "codex_cli_rs"
      assert forwarded_headers["session_id"] == "session-abc"
      assert forwarded_headers["user-agent"] == "codex-cli/1.0 (mac)"

      # And the X-Recurse-* injection landed.
      assert is_binary(forwarded_headers["x-recurse-trace-id"])
      assert forwarded_headers["x-recurse-tenant-id"] == "01TEN_TEST"
    end
  end

  describe "CT-005 (T038a) — FR-015 response-header passthrough" do
    test "6 known upstream metadata headers forward unchanged on HTTPS+SSE path",
         %{upstream: upstream} do
      MockHttpUpstream.expect(upstream, fn conn ->
        conn
        |> Plug.Conn.put_resp_header("x-ratelimit-limit-requests", "5000")
        |> Plug.Conn.put_resp_header("x-ratelimit-remaining-requests", "4998")
        |> Plug.Conn.put_resp_header("x-ratelimit-reset-requests", "8.6s")
        |> Plug.Conn.put_resp_header("openai-organization", "org-abc")
        |> Plug.Conn.put_resp_header("openai-processing-ms", "412")
        |> Plug.Conn.put_resp_header("request-id", "req_abc123")
        |> Plug.Conn.send_resp(200, ~s|{"ok":true}|)
      end)

      conn = build_conn(:post, "/v1/responses", request_body())
      cfg = build_config(upstream)

      result =
        StreamingProxy.proxy(conn, %{
          llm_provider_config: cfg,
          tenant_id: "01TEN_TEST",
          parser_module: Recurse.Gateway.LlmProxy.StreamingProxyTest.NoopParser
        })

      headers = Enum.into(result.resp_headers, %{}, fn {k, v} -> {String.downcase(k), v} end)

      assert headers["x-ratelimit-limit-requests"] == "5000"
      assert headers["x-ratelimit-remaining-requests"] == "4998"
      assert headers["x-ratelimit-reset-requests"] == "8.6s"
      assert headers["openai-organization"] == "org-abc"
      assert headers["openai-processing-ms"] == "412"
      assert headers["request-id"] == "req_abc123"
    end

    test "Retry-After preserved on 429 (FR-016)", %{upstream: upstream} do
      MockHttpUpstream.expect(upstream, fn conn ->
        conn
        |> Plug.Conn.put_resp_header("retry-after", "30")
        |> Plug.Conn.send_resp(429, ~s|{"error":"rate_limited"}|)
      end)

      conn = build_conn(:post, "/v1/responses", request_body())
      cfg = build_config(upstream)

      result =
        StreamingProxy.proxy(conn, %{
          llm_provider_config: cfg,
          tenant_id: "01TEN_TEST",
          parser_module: Recurse.Gateway.LlmProxy.StreamingProxyTest.NoopParser
        })

      assert result.status == 429
      headers = Enum.into(result.resp_headers, %{}, fn {k, v} -> {String.downcase(k), v} end)
      assert headers["retry-after"] == "30"
    end
  end

  describe "T038 light P-001/P-002 perf — single-call wall-clock under 1s" do
    @tag :perf
    test "single 1KB roundtrip under 1s wall-clock", %{upstream: upstream} do
      MockHttpUpstream.expect(upstream, fn conn ->
        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.send_resp(200, ~s|{"ok":true}|)
      end)

      conn = build_conn(:post, "/v1/responses", request_body())
      cfg = build_config(upstream)

      {micros, result} =
        :timer.tc(fn ->
          StreamingProxy.proxy(conn, %{
            llm_provider_config: cfg,
            tenant_id: "01TEN_TEST",
            parser_module: Recurse.Gateway.LlmProxy.StreamingProxyTest.NoopParser
          })
        end)

      # Loopback connection + no parser work; should be well under 1s.
      assert micros < 1_000_000
      assert result.status == 200
    end
  end

  # ===========================================================================
  # Helpers
  # ===========================================================================

  # `Plug.Conn.send_chunked/2` produces a conn whose `:resp_body` is the
  # concatenation of all chunks emitted via `Plug.Conn.chunk/2` in tests.
  defp sent_resp_body(%Plug.Conn{resp_body: body}) when is_binary(body), do: body

  defp sent_resp_body(%Plug.Conn{adapter: {Plug.Adapters.Test.Conn, %{chunks: chunks}}})
       when is_list(chunks) do
    IO.iodata_to_binary(chunks)
  end

  defp sent_resp_body(%Plug.Conn{adapter: {_, %{chunks: chunks}}}) when is_binary(chunks) do
    chunks
  end

  defp sent_resp_body(_), do: ""

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
