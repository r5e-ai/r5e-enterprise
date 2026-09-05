defmodule Recurse.Gateway.LlmProxy.StreamingProxyAnthropicTest do
  @moduledoc """
  Spec 012 S2 — the Anthropic Messages shapes Claude Code sends through
  the default-upstream path, exercised end to end against a mock upstream
  with the ProviderRegistry installed so the close-hook attestation
  actually runs:

    * a non-streaming request (`stream` absent, the `side_query` shape)
      passes through byte-for-byte with its `application/json` response
      headers and is attested with `kind = side_query`;
    * a streamed `/v1/messages?beta=true` agent turn is attested with
      `kind = agent_turn`, `upstream_host` / `api_format` from the row,
      and the client's `X-Claude-Code-Session-Id`.

  S4 wired the `AnthropicMessages` parser; the byte-precise enforcement
  and receipt fields are covered in `streaming_proxy_anthropic_s4_test.exs`.
  """

  use ExUnit.Case, async: false

  import Ecto.Query, only: [from: 2]

  alias Recurse.Gateway.LlmProxy.StreamingProxy
  alias Recurse.Gateway.Policy.Active
  alias Recurse.Gateway.PolicyBundleRef
  alias Recurse.Gateway.ProviderRegistry
  alias Recurse.Gateway.Test.{KernelFixture, MockHttpUpstream}
  alias Recurse.Providers.Impls.PostgresMerkleLedger
  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Attestation
  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Tenant
  alias Recurse.Providers.Repo
  alias Recurse.Providers.Schemas.LlmCallRecord
  alias Recurse.Providers.Schemas.LlmProviderConfig

  @tenant_id "01TEN_S2_ANTHROPIC_PROXY"
  @fixtures Path.expand("../../../../recurse_shared/test/fixtures/anthropic_messages", __DIR__)

  setup_all do
    :ok = KernelFixture.boot()
  end

  setup do
    :ok = Ecto.Adapters.SQL.Sandbox.checkout(Repo)
    Ecto.Adapters.SQL.Sandbox.mode(Repo, {:shared, self()})

    Repo.insert!(
      Tenant.changeset(%Tenant{}, %{
        tenant_id: @tenant_id,
        display_name: "S2 anthropic proxy test tenant",
        tier: :standalone_gateway,
        created_at: DateTime.utc_now()
      }),
      on_conflict: :nothing,
      conflict_target: :tenant_id
    )

    ProviderRegistry.install_raw!(%{
      llm: {Recurse.Gateway.Test.StubLLM, %{}},
      ledger: {PostgresMerkleLedger, %{repo: Repo, pubsub: Recurse.PubSub, config: %{}}},
      storage: {Recurse.Gateway.Test.StubStorage, %{}},
      secrets: {Recurse.Gateway.Test.StubSecretsProvider, %{}},
      tenant_id: @tenant_id,
      signer: "observed://gateway/s2-anthropic-test"
    })

    # Model and tool admission both run against the real kernel policy.
    permit_all = "permit(principal, action, resource);"
    canonical_hash = Recurse.Cedar.canonical_hash(permit_all)

    :ok =
      Active.update(%Active{
        source: :filesystem,
        source_ref: "s2-anthropic-test",
        loaded_at: DateTime.utc_now(),
        bundle: %PolicyBundleRef{
          bundle_id: Base.encode16(canonical_hash, case: :lower),
          canonical_hash: canonical_hash,
          loaded_at: DateTime.utc_now(),
          evaluator_handle: permit_all,
          bundle_bytes: permit_all
        }
      })

    {:ok, upstream} = MockHttpUpstream.start()

    on_exit(fn ->
      MockHttpUpstream.stop(upstream)
      ProviderRegistry.uninstall()
    end)

    {:ok, upstream: upstream}
  end

  defp config(upstream) do
    # The seeded anthropic row, pointed at the mock (plain http on loopback).
    %LlmProviderConfig{
      tenant_id: @tenant_id,
      provider: "anthropic",
      upstream_host: "127.0.0.1",
      upstream_port: upstream.port,
      transport_modes: ["https-sse"],
      auth_mode: :passthrough,
      api_format: :anthropic_messages,
      enabled: true,
      metadata: %{"scheme" => "http"}
    }
  end

  defp fixture(name), do: File.read!(Path.join(@fixtures, name))

  defp proxy(conn, upstream) do
    StreamingProxy.proxy(conn, %{llm_provider_config: config(upstream), tenant_id: @tenant_id})
  end

  defp resp_body(%Plug.Conn{adapter: {_, %{chunks: chunks}}}) when is_list(chunks),
    do: IO.iodata_to_binary(chunks)

  defp resp_body(%Plug.Conn{adapter: {_, %{chunks: chunks}}}) when is_binary(chunks), do: chunks
  defp resp_body(%Plug.Conn{resp_body: body}) when is_binary(body), do: body

  defp latest_call_record do
    Repo.one!(
      from(c in LlmCallRecord,
        where: c.tenant_id == @tenant_id,
        order_by: [desc: c.inserted_at],
        limit: 1
      )
    )
  end

  test "non-streaming side query passes through verbatim and is attested as side_query",
       %{upstream: upstream} do
    request = fixture("non_streaming_state_summary.request.json")
    response = fixture("non_streaming_state_summary.response.json")

    # The upstream handler runs in Cowboy's own process; record what it
    # saw in an Agent the test reads afterwards.
    {:ok, seen} = Agent.start_link(fn -> nil end)

    MockHttpUpstream.expect(upstream, fn conn ->
      {:ok, body, conn} = Plug.Conn.read_body(conn)

      Agent.update(seen, fn _ ->
        {conn.request_path, conn.query_string, conn.req_headers, body}
      end)

      conn
      |> Plug.Conn.put_resp_header("content-type", "application/json")
      |> Plug.Conn.put_resp_header("request-id", "req_side_query")
      |> Plug.Conn.put_resp_header("anthropic-ratelimit-unified-status", "allowed")
      |> Plug.Conn.send_resp(200, response)
    end)

    conn =
      Plug.Test.conn(:post, "/v1/messages?beta=true", request)
      |> Map.update!(:req_headers, &[{"host", "localhost:4443"} | &1])
      |> Plug.Conn.put_req_header("content-type", "application/json")
      |> Plug.Conn.put_req_header("authorization", "Bearer sk-ant-oat01-TEST")
      |> Plug.Conn.put_req_header("anthropic-version", "2023-06-01")
      |> Plug.Conn.put_req_header(
        "x-claude-code-session-id",
        "1a229fc9-6eec-4ed7-9341-e80d263fc6a2"
      )
      |> Plug.Conn.put_req_header("accept-encoding", "gzip, deflate, br, zstd")

    result = proxy(conn, upstream)

    assert result.status == 200
    assert resp_body(result) == response
    assert {"content-type", "application/json"} in result.resp_headers
    assert {"request-id", "req_side_query"} in result.resp_headers
    assert {"anthropic-ratelimit-unified-status", "allowed"} in result.resp_headers

    assert {"/v1/messages", "beta=true", headers, ^request} = Agent.get(seen, & &1)
    assert {"host", "127.0.0.1"} in headers
    assert {"authorization", "Bearer sk-ant-oat01-TEST"} in headers
    refute List.keyfind(headers, "accept-encoding", 0)

    record = latest_call_record()
    assert record.upstream_host == "127.0.0.1"
    assert record.api_format == "anthropic_messages"
    assert record.transport == "https-sse"
    assert record.request_path == "/v1/messages?beta=true"
    assert record.upstream_status_code == 200
    assert record.tool_use_intent_count == 0
    assert record.prompt_hash == :crypto.hash(:sha256, request)
    assert record.response_hash == :crypto.hash(:sha256, response)

    att = Repo.get!(Attestation, record.signed_predicate_run_id)
    assert att.event_kind == :llm_call_attested
    assert att.tags["kind"] == "side_query"
    assert att.tags["api_format"] == "anthropic_messages"
    assert att.tags["client_session_id"] == "1a229fc9-6eec-4ed7-9341-e80d263fc6a2"
  end

  test "streamed agent turn is attested as agent_turn with the client session id",
       %{upstream: upstream} do
    request = fixture("single_tool_use_bash.request.json")
    sse = fixture("single_tool_use_bash.sse")

    # Byte-faithful chunking (an event boundary mid-chunk, no bytes
    # added); the split-and-re-append chunker this replaced emitted an
    # extra trailing `\n\n`.
    MockHttpUpstream.serve_sse(upstream, sse)

    conn =
      Plug.Test.conn(:post, "/v1/messages?beta=true", request)
      |> Map.update!(:req_headers, &[{"host", "127.0.0.1:4443"} | &1])
      |> Plug.Conn.put_req_header("content-type", "application/json")
      |> Plug.Conn.put_req_header("authorization", "Bearer sk-ant-oat01-TEST")
      |> Plug.Conn.put_req_header("anthropic-beta", "oauth-2025-04-20,claude-code-20250219")
      |> Plug.Conn.put_req_header(
        "x-claude-code-session-id",
        "ecdcbccc-ecb4-40f4-bbb1-db3ad3b16bca"
      )

    result = proxy(conn, upstream)

    assert result.status == 200
    body = resp_body(result)
    assert body =~ "event: message_start"
    assert body =~ ~s|"name":"Bash"|
    assert body =~ "event: message_stop"

    record = latest_call_record()
    att = Repo.get!(Attestation, record.signed_predicate_run_id)
    assert att.tags["kind"] == "agent_turn"
    assert att.tags["client_session_id"] == "ecdcbccc-ecb4-40f4-bbb1-db3ad3b16bca"
    assert att.tags["upstream_host"] == "127.0.0.1"
    # S4 wired the Anthropic parser: the Bash tool_use is now an intent.
    assert record.tool_use_intent_count == 1
    assert att.tags["parser_module"] == "Recurse.Shared.LlmProxy.Parsers.AnthropicMessages"
  end

  test "session-title request is attested as session_title; session id falls back to metadata.user_id",
       %{upstream: upstream} do
    request = fixture("session_title.request.json")
    sse = fixture("session_title.sse")

    MockHttpUpstream.expect(upstream, fn conn ->
      conn
      |> Plug.Conn.put_resp_content_type("text/event-stream")
      |> Plug.Conn.send_resp(200, sse)
    end)

    # No X-Claude-Code-Session-Id header on purpose.
    conn =
      Plug.Test.conn(:post, "/v1/messages?beta=true", request)
      |> Map.update!(:req_headers, &[{"host", "localhost:4443"} | &1])
      |> Plug.Conn.put_req_header("content-type", "application/json")

    result = proxy(conn, upstream)
    assert result.status == 200

    %{"metadata" => %{"user_id" => user_id}} = JSON.decode!(request)
    %{"session_id" => expected_sid} = JSON.decode!(user_id)

    att = Repo.get!(Attestation, latest_call_record().signed_predicate_run_id)
    assert att.tags["kind"] == "session_title"
    assert att.tags["client_session_id"] == expected_sid
  end

  test "client session id is clamped to 128 bytes before it reaches the receipt",
       %{upstream: upstream} do
    request = fixture("non_streaming_state_summary.request.json")
    response = fixture("non_streaming_state_summary.response.json")

    MockHttpUpstream.expect(upstream, fn conn ->
      conn
      |> Plug.Conn.put_resp_header("content-type", "application/json")
      |> Plug.Conn.send_resp(200, response)
    end)

    conn =
      Plug.Test.conn(:post, "/v1/messages?beta=true", request)
      |> Map.update!(:req_headers, &[{"host", "localhost:4443"} | &1])
      |> Plug.Conn.put_req_header("content-type", "application/json")
      |> Plug.Conn.put_req_header("x-claude-code-session-id", String.duplicate("a", 300))

    assert proxy(conn, upstream).status == 200

    att = Repo.get!(Attestation, latest_call_record().signed_predicate_run_id)
    assert att.tags["client_session_id"] == String.duplicate("a", 128)
  end

  test "the clamp cuts metadata.user_id session ids at a codepoint boundary",
       %{upstream: upstream} do
    response = fixture("non_streaming_state_summary.response.json")

    # 126 ASCII bytes, then a 3-byte codepoint straddling the 128-byte
    # boundary, then more (a header cannot carry non-ASCII, the JSON
    # metadata can).
    oversized = String.duplicate("a", 126) <> "€" <> String.duplicate("b", 400)

    request =
      fixture("non_streaming_state_summary.request.json")
      |> JSON.decode!()
      |> Map.put("metadata", %{"user_id" => JSON.encode!(%{"session_id" => oversized})})
      |> JSON.encode!()

    MockHttpUpstream.expect(upstream, fn conn ->
      conn
      |> Plug.Conn.put_resp_header("content-type", "application/json")
      |> Plug.Conn.send_resp(200, response)
    end)

    conn =
      Plug.Test.conn(:post, "/v1/messages?beta=true", request)
      |> Map.update!(:req_headers, &[{"host", "localhost:4443"} | &1])
      |> Plug.Conn.put_req_header("content-type", "application/json")

    assert proxy(conn, upstream).status == 200

    att = Repo.get!(Attestation, latest_call_record().signed_predicate_run_id)
    assert att.tags["client_session_id"] == String.duplicate("a", 126)
  end
end
