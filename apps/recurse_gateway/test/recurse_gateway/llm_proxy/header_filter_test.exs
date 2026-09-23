defmodule Recurse.Gateway.LlmProxy.HeaderFilterTest do
  @moduledoc """
  Unit tests for `Recurse.Gateway.LlmProxy.HeaderFilter`. Covers the
  request-side strip + inject path (CT-003) and the response-side
  metadata-passthrough path (CT-005 / FR-015).

  Spec source: `specs/009-llm-api-proxy/contracts/streaming_proxy.md`
  §"Header preservation (CRITICAL — R-012)" + research.md R-012.
  """

  use ExUnit.Case, async: true

  alias Recurse.Gateway.LlmProxy.HeaderFilter

  doctest HeaderFilter

  @wire_timeout 10_000

  @meta %{trace_id: "01ARZ_TRACE_ULID", tenant_id: "01TEN_TENANT_ULID"}

  describe "spec 012 S2 — Claude Code / Anthropic headers" do
    # Exactly the request headers Claude Code 2.1.223 sent through the S0
    # spike stub (fixture `single_tool_use_bash.request.headers.txt`),
    # credential redacted. All must reach upstream verbatim; anthropic-beta
    # carries `oauth-2025-04-20`, without which upstream rejects the bearer.
    @claude_code_headers [
      {"accept", "application/json"},
      {"authorization", "Bearer sk-ant-oat01-REDACTED"},
      {"content-type", "application/json"},
      {"user-agent", "claude-cli/2.1.223 (external, claude-desktop, agent-sdk/0.3.255)"},
      {"x-claude-code-session-id", "ecdcbccc-ecb4-40f4-bbb1-db3ad3b16bca"},
      {"x-stainless-arch", "arm64"},
      {"x-stainless-lang", "js"},
      {"x-stainless-os", "MacOS"},
      {"x-stainless-package-version", "0.94.0"},
      {"x-stainless-retry-count", "0"},
      {"x-stainless-runtime", "node"},
      {"x-stainless-runtime-version", "v26.3.0"},
      {"x-stainless-timeout", "900"},
      {"anthropic-beta",
       "oauth-2025-04-20,interleaved-thinking-2025-05-14,thinking-token-count-2026-05-13,context-management-2025-06-27,prompt-caching-scope-2026-01-05,claude-code-20250219,advisor-tool-2026-03-01,extended-cache-ttl-2025-04-11"},
      {"anthropic-dangerous-direct-browser-access", "true"},
      {"anthropic-version", "2023-06-01"},
      {"x-app", "cli"},
      {"connection", "keep-alive"},
      {"host", "127.0.0.1:4443"},
      {"accept-encoding", "gzip, deflate, br, zstd"},
      {"content-length", "155844"}
    ]

    test "every Claude Code header except hop-by-hop, accept-encoding and host is forwarded verbatim" do
      result =
        HeaderFilter.forward_request_headers(@claude_code_headers, @meta,
          upstream_host: "api.anthropic.com"
        )

      expected_verbatim =
        Enum.reject(@claude_code_headers, fn {name, _} ->
          name in ["connection", "host", "accept-encoding"]
        end)

      for header <- expected_verbatim do
        assert header in result, "missing or altered: #{inspect(header)}"
      end

      refute List.keyfind(result, "accept-encoding", 0),
             "accept-encoding must be stripped so upstream answers identity-encoded"

      refute List.keyfind(result, "connection", 0)
    end

    test "x-api-key (API-key auth) is forwarded verbatim" do
      result =
        HeaderFilter.forward_request_headers([{"x-api-key", "sk-ant-api03-REDACTED"}], @meta)

      assert {"x-api-key", "sk-ant-api03-REDACTED"} in result
    end

    test ":upstream_host rewrites the Host header (default-upstream mode, D3)" do
      result =
        HeaderFilter.forward_request_headers(@claude_code_headers, @meta,
          upstream_host: "api.anthropic.com"
        )

      assert [{"host", "api.anthropic.com"}] = Enum.filter(result, fn {n, _} -> n == "host" end)
    end

    test ":upstream_host is a no-op for the DNS-override (Codex) path where Host already is the upstream" do
      headers = [{"host", "chatgpt.com"}, {"authorization", "Bearer x"}]
      result = HeaderFilter.forward_request_headers(headers, @meta, upstream_host: "chatgpt.com")
      assert [{"host", "chatgpt.com"}] = Enum.filter(result, fn {n, _} -> n == "host" end)
    end

    test "without :upstream_host the Host header passes through unchanged (pre-S2 behaviour)" do
      headers = [{"host", "chatgpt.com"}]
      result = HeaderFilter.forward_request_headers(headers, @meta)
      assert {"host", "chatgpt.com"} in result
    end

    test "the R-012 whitelist documents the Anthropic headers" do
      wl = HeaderFilter.r012_whitelist()

      for h <-
            ~w[x-api-key anthropic-version anthropic-beta anthropic-dangerous-direct-browser-access x-app x-claude-code-session-id] do
        assert h in wl
      end
    end

    test "anthropic response headers (rate-limit, request-id, org ids) pass back; content-length is re-framed" do
      # From fixture `single_tool_use_bash.response.headers.txt`.
      headers = [
        {"date", "Wed, 02 Sep 2026 17:42:57 GMT"},
        {"content-type", "text/event-stream; charset=utf-8"},
        {"transfer-encoding", "chunked"},
        {"connection", "keep-alive"},
        {"cache-control", "no-cache"},
        {"anthropic-ratelimit-unified-status", "allowed"},
        {"anthropic-ratelimit-unified-5h-utilization", "0.32"},
        {"anthropic-ratelimit-unified-reset", "1788376800"},
        {"request-id", "req_011Cef2Uocb2tNPgPqmjRKhf"},
        {"anthropic-organization-id", "00000000-0000-0000-0000-000000000000"},
        {"anthropic-workspace-id", "wrkspc_REDACTED"},
        {"content-length", "1234"}
      ]

      result = HeaderFilter.forward_response_headers(headers)

      for name <-
            ~w[content-type cache-control anthropic-ratelimit-unified-status anthropic-ratelimit-unified-5h-utilization anthropic-ratelimit-unified-reset request-id anthropic-organization-id anthropic-workspace-id] do
        assert List.keyfind(result, name, 0), "missing #{name}"
      end

      refute List.keyfind(result, "transfer-encoding", 0)
      refute List.keyfind(result, "connection", 0)
      refute List.keyfind(result, "content-length", 0)
    end
  end

  describe "credential redaction (spec 012 S2: never log the bearer / x-api-key)" do
    test "redact_credential/1 keeps 8 chars + length, matching the spike stub convention" do
      bearer = "Bearer " <> String.duplicate("s", 108)
      assert HeaderFilter.redact_credential(bearer) == "Bearer s…<redacted len=115>"
      refute HeaderFilter.redact_credential(bearer) =~ "ssssssssss"
      assert HeaderFilter.redact_credential("sk-ant-api03-xyz") == "sk-ant-a…<redacted len=16>"
      assert HeaderFilter.redact_credential("abc") == "…<redacted len=3>"
      assert HeaderFilter.redact_credential(nil) == "…<redacted len=0>"
    end

    test "redact_headers/1 redacts only credential headers" do
      headers = [
        {"authorization", "Bearer sk-ant-oat01-SECRETSECRET"},
        {"x-api-key", "sk-ant-api03-SECRETSECRET"},
        {"Proxy-Authorization", "Basic SECRETSECRET"},
        {"anthropic-version", "2023-06-01"}
      ]

      result = HeaderFilter.redact_headers(headers)

      assert {"anthropic-version", "2023-06-01"} in result
      refute inspect(result) =~ "SECRET"
      assert {"authorization", "Bearer s…<redacted len=32>"} in result
      assert HeaderFilter.credential_header?("X-API-Key")
      refute HeaderFilter.credential_header?("anthropic-beta")
    end
  end

  describe "forward_request_headers/3 — R-012 whitelist preservation (CT-003)" do
    test "preserves Authorization header verbatim" do
      headers = [{"authorization", "Bearer abc123.eyJ.foo"}]
      result = HeaderFilter.forward_request_headers(headers, @meta)

      assert {"authorization", "Bearer abc123.eyJ.foo"} in result
    end

    test "preserves chatgpt-account-id header (ChatGPT Enterprise auth)" do
      headers = [{"chatgpt-account-id", "uuid-1234"}]
      result = HeaderFilter.forward_request_headers(headers, @meta)

      assert {"chatgpt-account-id", "uuid-1234"} in result
    end

    test "preserves OpenAI-Beta and originator headers" do
      headers = [
        {"openai-beta", "responses=v1"},
        {"originator", "codex_cli_rs"}
      ]

      result = HeaderFilter.forward_request_headers(headers, @meta)

      assert {"openai-beta", "responses=v1"} in result
      assert {"originator", "codex_cli_rs"} in result
    end

    test "preserves session_id and User-Agent" do
      headers = [
        {"session_id", "abcdef-12345"},
        {"user-agent", "codex-cli/1.2.3 (macOS 14.5)"}
      ]

      result = HeaderFilter.forward_request_headers(headers, @meta)

      assert {"session_id", "abcdef-12345"} in result
      assert {"user-agent", "codex-cli/1.2.3 (macOS 14.5)"} in result
    end

    test "preserves Content-Type and Accept" do
      headers = [
        {"content-type", "application/json"},
        {"accept", "text/event-stream"}
      ]

      result = HeaderFilter.forward_request_headers(headers, @meta)

      assert {"content-type", "application/json"} in result
      assert {"accept", "text/event-stream"} in result
    end

    # DELIBERATE narrowing of the R-012 whitelist (CT-003 originally
    # asserted Accept-Encoding round-trips unchanged).
    #
    # R-012 was written for a transparent relay. This proxy also PARSES
    # the response stream to extract tool-use intents for Cedar, and it
    # cannot parse a gzipped body. Forwarding `accept-encoding: gzip`
    # (which Codex always sends) had upstream compress the SSE stream,
    # so no events matched, no intents were extracted, and every tool
    # call sailed past the policy gate — a silent fail-open of the
    # enforcement the product exists to provide.
    #
    # Transfer bytes are the cheaper thing to give up.
    test "strips Accept-Encoding so upstream replies identity-encoded" do
      headers = [
        {"accept", "text/event-stream"},
        {"accept-encoding", "gzip, deflate, br"}
      ]

      result = HeaderFilter.forward_request_headers(headers, @meta)

      refute Enum.any?(result, fn {k, _v} -> String.downcase(k) == "accept-encoding" end)
      assert {"accept", "text/event-stream"} in result
    end

    test "preserves all Sec-WebSocket-* headers (WS upgrade flow)" do
      headers = [
        {"sec-websocket-key", "x3JJHMbDL1EzLkh9GBhXDw=="},
        {"sec-websocket-version", "13"},
        {"sec-websocket-protocol", "openai.responses.v1"},
        {"sec-websocket-extensions", "permessage-deflate"}
      ]

      result = HeaderFilter.forward_request_headers(headers, @meta, websocket_upgrade?: true)

      assert {"sec-websocket-key", "x3JJHMbDL1EzLkh9GBhXDw=="} in result
      assert {"sec-websocket-version", "13"} in result
      assert {"sec-websocket-protocol", "openai.responses.v1"} in result
      assert {"sec-websocket-extensions", "permessage-deflate"} in result
    end

    test "preserves x-anthropic-* and x-goog-* prefixed headers" do
      headers = [
        {"x-anthropic-version", "2023-06-01"},
        {"x-anthropic-beta", "tools-2024-04-04"},
        {"x-goog-api-key", "ABCDEF"},
        {"x-goog-user-project", "proj-1"}
      ]

      result = HeaderFilter.forward_request_headers(headers, @meta)

      assert {"x-anthropic-version", "2023-06-01"} in result
      assert {"x-anthropic-beta", "tools-2024-04-04"} in result
      assert {"x-goog-api-key", "ABCDEF"} in result
      assert {"x-goog-user-project", "proj-1"} in result
    end

    test "all 6 R-012 named headers preserved through one filter call" do
      headers = [
        {"authorization", "Bearer xyz"},
        {"chatgpt-account-id", "uuid"},
        {"openai-beta", "responses=v1"},
        {"originator", "codex_cli_rs"},
        {"session_id", "sess123"},
        {"user-agent", "codex/1"}
      ]

      result = HeaderFilter.forward_request_headers(headers, @meta)
      result_map = Map.new(result)

      assert result_map["authorization"] == "Bearer xyz"
      assert result_map["chatgpt-account-id"] == "uuid"
      assert result_map["openai-beta"] == "responses=v1"
      assert result_map["originator"] == "codex_cli_rs"
      assert result_map["session_id"] == "sess123"
      assert result_map["user-agent"] == "codex/1"
    end
  end

  describe "forward_request_headers/3 — RFC 7230 hop-by-hop strip" do
    test "strips Connection, Keep-Alive, Proxy-* without WS upgrade" do
      headers = [
        {"connection", "keep-alive"},
        {"keep-alive", "timeout=5"},
        {"proxy-authenticate", "Basic"},
        {"proxy-authorization", "Basic abc"},
        {"te", "trailers"},
        {"trailers", "X-Foo"},
        {"transfer-encoding", "chunked"}
      ]

      result = HeaderFilter.forward_request_headers(headers, @meta)
      names = Enum.map(result, &elem(&1, 0))

      refute "connection" in names
      refute "keep-alive" in names
      refute "proxy-authenticate" in names
      refute "proxy-authorization" in names
      refute "te" in names
      refute "trailers" in names
      refute "transfer-encoding" in names
    end

    test "constructs canonical Connection and Upgrade on WS upgrade" do
      headers = [
        {"connection", "upgrade"},
        {"upgrade", "websocket"}
      ]

      result =
        HeaderFilter.forward_request_headers(headers, @meta, websocket_upgrade?: true)

      assert {"connection", "upgrade"} in result
      assert {"upgrade", "websocket"} in result
    end

    test "case-insensitive hop-by-hop matching" do
      headers = [
        {"Connection", "keep-alive"},
        {"TRANSFER-ENCODING", "chunked"}
      ]

      result = HeaderFilter.forward_request_headers(headers, @meta)
      names = Enum.map(result, fn {k, _} -> String.downcase(k, :ascii) end)

      refute "connection" in names
      refute "transfer-encoding" in names
    end
  end

  describe "forward_request_headers/3 — X-Recurse-* injection" do
    test "injects X-Recurse-Trace-Id and X-Recurse-Tenant-Id" do
      headers = [{"authorization", "Bearer abc"}]
      result = HeaderFilter.forward_request_headers(headers, @meta)

      assert {"x-recurse-trace-id", "01ARZ_TRACE_ULID"} in result
      assert {"x-recurse-tenant-id", "01TEN_TENANT_ULID"} in result
    end

    test "overwrites client-supplied X-Recurse-* (spoofing defense)" do
      headers = [
        {"x-recurse-trace-id", "EVIL_CLIENT_ATTEMPT"},
        {"x-recurse-tenant-id", "EVIL_CROSS_TENANT"}
      ]

      result = HeaderFilter.forward_request_headers(headers, @meta)

      # Client values stripped; proxy values appended.
      trace_values =
        result
        |> Enum.filter(fn {k, _} -> k == "x-recurse-trace-id" end)
        |> Enum.map(&elem(&1, 1))

      assert trace_values == ["01ARZ_TRACE_ULID"]

      tenant_values =
        result
        |> Enum.filter(fn {k, _} -> k == "x-recurse-tenant-id" end)
        |> Enum.map(&elem(&1, 1))

      assert tenant_values == ["01TEN_TENANT_ULID"]
    end
  end

  describe "forward_response_headers/1 — FR-015 response metadata passthrough (CT-005)" do
    test "all 6 known upstream metadata headers pass through unchanged" do
      headers = [
        {"x-ratelimit-limit-requests", "5000"},
        {"x-ratelimit-remaining-requests", "4998"},
        {"x-ratelimit-reset-requests", "8.6s"},
        {"openai-organization", "user-abc"},
        {"openai-processing-ms", "412"},
        {"request-id", "req_abc123"}
      ]

      result = HeaderFilter.forward_response_headers(headers)

      assert {"x-ratelimit-limit-requests", "5000"} in result
      assert {"x-ratelimit-remaining-requests", "4998"} in result
      assert {"x-ratelimit-reset-requests", "8.6s"} in result
      assert {"openai-organization", "user-abc"} in result
      assert {"openai-processing-ms", "412"} in result
      assert {"request-id", "req_abc123"} in result
    end

    test "Retry-After preserved (FR-016 rate limit handling)" do
      headers = [{"retry-after", "60"}]
      result = HeaderFilter.forward_response_headers(headers)

      assert {"retry-after", "60"} in result
    end

    test "strips RFC 7230 hop-by-hop response headers" do
      headers = [
        {"connection", "close"},
        {"keep-alive", "timeout=5"},
        {"transfer-encoding", "chunked"},
        {"x-ratelimit-limit-requests", "5000"}
      ]

      result = HeaderFilter.forward_response_headers(headers)
      names = Enum.map(result, &elem(&1, 0))

      refute "connection" in names
      refute "keep-alive" in names
      refute "transfer-encoding" in names
      assert "x-ratelimit-limit-requests" in names
    end

    test "strips Upgrade on response side (defensive)" do
      # Response side never carries a real Upgrade header for the data
      # plane — the WS 101 is short-circuited by Mint/WebSockAdapter
      # before the streaming proxy sees response headers. Still, strip
      # it defensively so a misbehaving upstream can't reflect it back.
      headers = [{"upgrade", "h2c"}, {"x-ratelimit-limit-requests", "5"}]
      result = HeaderFilter.forward_response_headers(headers)

      assert "upgrade" not in Enum.map(result, &elem(&1, 0))
      assert {"x-ratelimit-limit-requests", "5"} in result
    end

    test "unknown upstream headers pass through (open response policy)" do
      # FR-015: client behavior MUST be indistinguishable from talking
      # to upstream directly. New upstream headers (e.g. a future
      # `openai-system-fingerprint`) MUST forward without code changes.
      headers = [
        {"openai-system-fingerprint", "fp_abc"},
        {"x-ms-region", "eastus"},
        {"server", "cloudflare"}
      ]

      result = HeaderFilter.forward_response_headers(headers)

      assert {"openai-system-fingerprint", "fp_abc"} in result
      assert {"x-ms-region", "eastus"} in result
      assert {"server", "cloudflare"} in result
    end
  end

  describe "Connection options apply to both hops" do
    test "repeated mixed-case fields and comma OWS strip every nominated occurrence" do
      headers = [
        {"CoNnEcTiOn", " \tX-Hop-Private , UpGrAdE, , x-repeat\t "},
        {"connection", "X-Other, x-recurse-trace-id, X-Recurse-Tenant-Id"},
        {"X-Hop-Private", "private"},
        {"x-repeat", "one"},
        {"X-Repeat", "two"},
        {"x-other", "other"},
        {"Trailer", "X-Checksum"},
        {"Upgrade", "h2c"},
        {"Transfer-Encoding", "chunked"},
        {"content-length", "123"},
        {"x-recurse-trace-id", "spoof"},
        {"X-Recurse-Tenant-Id", "spoof"},
        {"authorization", "Bearer provider"},
        {"request-id", "upstream"},
        {"content-encoding", "gzip"}
      ]

      request = HeaderFilter.forward_request_headers(headers, @meta)
      response = HeaderFilter.forward_response_headers(headers)

      for result <- [request, response],
          name <- ~w(connection x-hop-private x-repeat x-other trailer upgrade transfer-encoding) do
        refute Enum.any?(result, fn {key, _} -> String.downcase(key) == name end)
      end

      assert {"x-recurse-trace-id", @meta.trace_id} in request
      assert {"x-recurse-tenant-id", @meta.tenant_id} in request
      refute inspect(request) =~ "spoof"
      assert {"content-length", "123"} in request
      refute List.keyfind(response, "content-length", 0)

      for result <- [request, response] do
        assert {"authorization", "Bearer provider"} in result
        assert {"request-id", "upstream"} in result
        assert {"content-encoding", "gzip"} in result
      end
    end

    test "nominated normally end-to-end fields are not exempt from hop semantics" do
      headers = [
        {"connection", "AUTHORIZATION, content-type"},
        {"authorization", "provider"},
        {"content-type", "application/json"}
      ]

      for result <- [
            HeaderFilter.forward_request_headers(headers, @meta),
            HeaderFilter.forward_response_headers(headers)
          ] do
        refute List.keyfind(result, "authorization", 0)
        refute List.keyfind(result, "content-type", 0)
      end
    end

    test "WS reconstructs only the required pair and strips client-nominated metadata" do
      headers = [
        {"Connection", "keep-alive, upgrade, x-private"},
        {"connection", "x-other"},
        {"Upgrade", "h2c"},
        {"upgrade", "not-websocket"},
        {"x-private", "secret"},
        {"x-other", "secret"},
        {"authorization", "provider"}
      ]

      result = HeaderFilter.forward_request_headers(headers, @meta, websocket_upgrade?: true)

      assert [{"connection", "upgrade"}] ==
               Enum.filter(result, fn {k, _} -> String.downcase(k) == "connection" end)

      assert [{"upgrade", "websocket"}] ==
               Enum.filter(result, fn {k, _} -> String.downcase(k) == "upgrade" end)

      refute inspect(result) =~ "secret"
      assert {"authorization", "provider"} in result
    end

    test "reserved route tokens never reach request forwarding or diagnostics" do
      token = String.duplicate("secret-token", 4)

      headers = [
        {"X-R5E-Managed-Route", token},
        {"x-r5e-managed-route", token},
        {"authorization", "provider"}
      ]

      for ws <- [false, true] do
        result = HeaderFilter.forward_request_headers(headers, @meta, websocket_upgrade?: ws)
        refute inspect(result) =~ token
        assert {"authorization", "provider"} in result
      end

      assert HeaderFilter.credential_header?("X-R5E-Managed-Route")
      diagnostic = HeaderFilter.redact_headers(headers)
      refute inspect(diagnostic) =~ "secret-t"
      refute Enum.any?(diagnostic, fn {k, _} -> String.downcase(k) == "x-r5e-managed-route" end)
    end
  end

  defmodule FramingFixture do
    def init(opts), do: opts

    def call(conn, _) do
      headers = [
        {"connection", "x-private"},
        {"x-private", "hop-only"},
        {"trailer", "x-checksum"},
        {"content-length", "100"},
        {"request-id", "preserved"}
      ]

      conn =
        Enum.reduce(HeaderFilter.forward_response_headers(headers), conn, fn {k, v}, acc ->
          Plug.Conn.put_resp_header(acc, k, v)
        end)

      {:ok, conn} = conn |> Plug.Conn.send_chunked(200) |> Plug.Conn.chunk("ok")
      conn
    end
  end

  test "actual response framing regenerates chunking without upstream length or nominations" do
    {:ok, _} = Application.ensure_all_started(:bandit)
    server = start_supervised!({Bandit, plug: FramingFixture, port: 0, ip: {127, 0, 0, 1}})
    {:ok, {_, port}} = ThousandIsland.listener_info(server)
    {:ok, socket} = :gen_tcp.connect(~c"localhost", port, [:binary, active: false])
    :ok = :gen_tcp.send(socket, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
    on_exit(fn -> :gen_tcp.close(socket) end)
    bytes = read_to_close(socket, "", wire_deadline())
    assert bytes =~ "transfer-encoding: chunked"
    assert bytes =~ "request-id: preserved"
    refute bytes =~ "content-length:"
    refute bytes =~ "trailer:"
    refute bytes =~ "x-private:"
    assert bytes =~ "2\r\nok\r\n0\r\n\r\n"
  end

  test "Mint regenerates the WS pair on the upstream hop without duplicate options" do
    {:ok, _} = Application.ensure_all_started(:mint_web_socket)
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    on_exit(fn -> :gen_tcp.close(listener) end)
    {:ok, {_, port}} = :inet.sockname(listener)
    parent = self()

    spawn_link(fn ->
      {:ok, socket} = :gen_tcp.accept(listener, @wire_timeout)
      send(parent, {:wire_upgrade, read_headers(socket, "", wire_deadline())})
      :gen_tcp.close(socket)
    end)

    headers =
      HeaderFilter.forward_request_headers(
        [
          {"connection", "upgrade, x-private"},
          {"upgrade", "websocket"},
          {"x-private", "secret"},
          {"authorization", "provider"},
          {"sec-websocket-protocol", "openai.responses.v1"}
        ],
        @meta,
        websocket_upgrade?: true
      )

    # Same final boundary as WebSocketBridge.open_upstream_websocket: Mint owns
    # these handshake fields; the filter's canonical pair is not passed twice.
    headers =
      Enum.reject(headers, fn {k, _} ->
        String.downcase(k) in ~w(sec-websocket-key sec-websocket-version connection upgrade host content-length)
      end)

    {:ok, conn} = Mint.HTTP.connect(:http, "localhost", port, protocols: [:http1], mode: :passive)
    {:ok, conn, _} = Mint.WebSocket.upgrade(:ws, conn, "/responses", headers)
    assert_receive {:wire_upgrade, bytes}, @wire_timeout
    Mint.HTTP.close(conn)
    lines = bytes |> String.downcase() |> String.split("\r\n")
    assert Enum.count(lines, &(&1 == "connection: upgrade")) == 1
    assert Enum.count(lines, &(&1 == "upgrade: websocket")) == 1
    assert "authorization: provider" in lines
    assert "sec-websocket-protocol: openai.responses.v1" in lines
    assert ("x-recurse-trace-id: " <> String.downcase(@meta.trace_id)) in lines
    refute bytes =~ "x-private"
  end

  # Bound the whole exchange while allowing scheduling under the full CI suite.
  # A fresh timeout per fragment could conceal a peer that never finishes.
  defp wire_deadline, do: System.monotonic_time(:millisecond) + @wire_timeout

  defp wire_remaining(deadline) do
    remaining = deadline - System.monotonic_time(:millisecond)
    assert remaining > 0, "HTTP fixture exceeded its wire deadline"
    remaining
  end

  defp read_headers(socket, bytes, deadline) do
    if String.contains?(bytes, "\r\n\r\n") do
      bytes
    else
      {:ok, next} = :gen_tcp.recv(socket, 0, wire_remaining(deadline))
      assert byte_size(bytes) + byte_size(next) < 16_384
      read_headers(socket, bytes <> next, deadline)
    end
  end

  defp read_to_close(socket, bytes, deadline) do
    case :gen_tcp.recv(socket, 0, wire_remaining(deadline)) do
      {:ok, next} ->
        assert byte_size(bytes) + byte_size(next) < 16_384
        read_to_close(socket, bytes <> next, deadline)

      {:error, :closed} ->
        bytes
    end
  end

  describe "introspection helpers" do
    test "hop_by_hop_request/0 returns the canonical strip list" do
      list = HeaderFilter.hop_by_hop_request()

      assert "connection" in list
      assert "keep-alive" in list
      assert "transfer-encoding" in list
      assert "trailer" in list
      assert "trailers" in list
      assert "upgrade" in list
      assert "te" in list
      assert "proxy-authenticate" in list
      assert "proxy-authorization" in list
    end

    test "trace_id_header/0 returns the canonical name" do
      assert HeaderFilter.trace_id_header() == "x-recurse-trace-id"
    end

    test "tenant_id_header/0 returns the canonical name" do
      assert HeaderFilter.tenant_id_header() == "x-recurse-tenant-id"
    end
  end
end
