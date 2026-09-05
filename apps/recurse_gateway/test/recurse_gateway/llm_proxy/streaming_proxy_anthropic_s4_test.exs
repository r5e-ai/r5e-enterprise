defmodule Recurse.Gateway.LlmProxy.StreamingProxyAnthropicS4Test do
  @moduledoc """
  Spec 012 S4 — the Anthropic Messages parser + denial injector wired
  into `StreamingProxy`, end to end against a mock upstream that serves
  the S0 fixtures as chunked SSE, with the ProviderRegistry installed so
  the close-hook attestation runs and a real Cedar bundle active so the
  gate decides:

    * allow: bytes out == bytes in, one Bash intent, `parse.events_unhandled = 0`,
      parser identity on the receipt, principal `claude-code:<account_uuid>`;
    * deny: the tool_use frames never reach the client, a `text` block at
      the same index carries the denial, `stop_reason` becomes `end_turn`,
      a `tool_use_denied` receipt links to its parent and carries the
      `toolu_…` id, the parent's intent is `deny`;
    * non-streaming JSON with a denied tool_use is rewritten as JSON;
    * drift: an unknown event type is forwarded, counted on the receipt,
      and lands in the drift store + boot counter.
  """

  use ExUnit.Case, async: false

  import Ecto.Query, only: [from: 2]

  alias Recurse.Gateway.LlmProxy.ParserDrift
  alias Recurse.Gateway.LlmProxy.StreamingProxy
  alias Recurse.Gateway.Policy.Active
  alias Recurse.Gateway.PolicyBundleRef
  alias Recurse.Gateway.ProviderRegistry
  alias Recurse.Gateway.Test.{KernelFixture, MockHttpUpstream}
  alias Recurse.Providers.Impls.PostgresMerkleLedger
  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Attestation
  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Tenant
  alias Recurse.Providers.ParserDrift, as: DriftStore
  alias Recurse.Providers.Repo
  alias Recurse.Providers.Schemas.LlmCallRecord
  alias Recurse.Providers.Schemas.LlmProviderConfig
  alias Recurse.Providers.Schemas.ToolUseIntentRecord

  @tenant_id "01TEN_S4_ANTHROPIC_PROXY"
  @fixtures Path.expand("../../../../recurse_shared/test/fixtures/anthropic_messages", __DIR__)
  @bash_call_id "toolu_01LZV8Ni38xTJKZoqdQM8Pdk"
  @account "00000000-0000-0000-0000-000000000000"

  @bundle """
  permit (principal, action == Action::"call_model", resource);
  permit (principal, action == Action::"invoke_tool", resource);

  forbid (
    principal,
    action == Action::"invoke_tool",
    resource == ToolUse::"Bash"
  ) when {
    context has tool_args && context.tool_args has command &&
    context.tool_args.command like "*rm -rf*"
  };
  """

  setup_all do
    :ok = KernelFixture.boot()
  end

  setup do
    :ok = Ecto.Adapters.SQL.Sandbox.checkout(Repo)
    Ecto.Adapters.SQL.Sandbox.mode(Repo, {:shared, self()})

    Repo.insert!(
      Tenant.changeset(%Tenant{}, %{
        tenant_id: @tenant_id,
        display_name: "S4 anthropic proxy test tenant",
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
      signer: "observed://gateway/s4-anthropic-test"
    })

    canonical_hash = Recurse.Cedar.canonical_hash(@bundle)

    bundle = %PolicyBundleRef{
      bundle_id: Base.encode16(canonical_hash, case: :lower),
      canonical_hash: canonical_hash,
      loaded_at: DateTime.utc_now(),
      evaluator_handle: @bundle,
      bundle_bytes: @bundle
    }

    :ok =
      Active.update(%Active{
        source: :filesystem,
        source_ref: "s4-test",
        loaded_at: DateTime.utc_now(),
        bundle: bundle
      })

    ParserDrift.reset_counter()
    {:ok, upstream} = MockHttpUpstream.start()

    on_exit(fn ->
      MockHttpUpstream.stop(upstream)
      ProviderRegistry.uninstall()
    end)

    {:ok, upstream: upstream, bundle_hash: canonical_hash}
  end

  defp config(upstream) do
    %LlmProviderConfig{
      tenant_id: @tenant_id,
      provider: "anthropic",
      upstream_host: "127.0.0.1",
      upstream_port: upstream.port,
      transport_modes: ["https-sse"],
      auth_mode: :passthrough,
      api_format: :anthropic_messages,
      enabled: true,
      metadata: %{
        "scheme" => "http",
        "appeal_uri" => "https://appeal.example/r5e",
        "appeal_contact" => "#sec-ops"
      }
    }
  end

  defp fixture(name), do: File.read!(Path.join(@fixtures, name))

  defp proxy(conn, upstream) do
    StreamingProxy.proxy(conn, %{llm_provider_config: config(upstream), tenant_id: @tenant_id})
  end

  defp request_conn(body) do
    Plug.Test.conn(:post, "/v1/messages?beta=true", body)
    |> Map.update!(:req_headers, &[{"host", "localhost:4443"} | &1])
    |> Plug.Conn.put_req_header("content-type", "application/json")
    |> Plug.Conn.put_req_header(
      "authorization",
      "Bearer sk-ant-oat01-" <> String.duplicate("x", 100)
    )
    |> Plug.Conn.put_req_header("anthropic-version", "2023-06-01")
    |> Plug.Conn.put_req_header("anthropic-beta", "oauth-2025-04-20,claude-code-20250219")
    |> Plug.Conn.put_req_header(
      "x-claude-code-session-id",
      "ecdcbccc-ecb4-40f4-bbb1-db3ad3b16bca"
    )
  end

  defp resp_body(%Plug.Conn{adapter: {_, %{chunks: chunks}}}) when is_list(chunks),
    do: IO.iodata_to_binary(chunks)

  defp resp_body(%Plug.Conn{adapter: {_, %{chunks: chunks}}}) when is_binary(chunks), do: chunks
  defp resp_body(%Plug.Conn{resp_body: body}) when is_binary(body), do: body

  # Parse an SSE body into decoded event maps (in order).
  defp events(sse) do
    sse
    |> String.split("\n\n", trim: true)
    |> Enum.map(fn block ->
      block
      |> String.split("\n")
      |> Enum.find_value(fn
        "data:" <> rest -> Jason.decode!(String.trim(rest))
        _ -> nil
      end)
    end)
    |> Enum.reject(&is_nil/1)
  end

  defp latest_call_record do
    Repo.one!(
      from(c in LlmCallRecord,
        where: c.tenant_id == @tenant_id,
        order_by: [desc: c.inserted_at],
        limit: 1
      )
    )
  end

  defp intent_rows(record) do
    Repo.all(from(i in ToolUseIntentRecord, where: i.llm_call_record_id == ^record.id))
  end

  # The captured `ls -la` turn with the command rewritten to `rm -rf /tmp/x`
  # across the same two fragments (`": \"l"` + `"s -la\""`).
  defp deny_sse do
    fixture("single_tool_use_bash.sse")
    |> String.replace(~s|"partial_json":": \\"l"|, ~s|"partial_json":": \\"rm -rf /tmp/x"|)
    |> String.replace(~s|"partial_json":"s -la\\""|, ~s|"partial_json":"\\""|)
  end

  test "allow: bytes out equal bytes in; one Bash intent; parser identity + completeness on the receipt",
       %{upstream: upstream, bundle_hash: bundle_hash} do
    request = fixture("single_tool_use_bash.request.json")
    sse = fixture("single_tool_use_bash.sse")
    MockHttpUpstream.serve_sse(upstream, sse, chunk_size: 53)

    result = proxy(request_conn(request), upstream)

    assert result.status == 200
    assert resp_body(result) == sse
    assert {"content-type", "text/event-stream; charset=utf-8"} in result.resp_headers

    record = latest_call_record()
    assert record.tool_use_intent_count == 1
    assert record.tool_use_denied_count == 0
    assert record.decision_summary == "all allow"
    assert record.model == "claude-haiku-4-5-20251001"
    assert record.prompt_token_count == 10
    assert record.completion_token_count == 181
    assert record.reasoning_token_count == 102
    assert record.principal_id == "claude-code:" <> @account
    assert record.principal_kind == "obo_human"
    assert record.cedar_bundle_hash == bundle_hash

    assert [
             %ToolUseIntentRecord{decision: "allow", call_id: @bash_call_id, tool_name: "Bash"} =
               row
           ] =
             intent_rows(record)

    assert row.tool_args_inlined == %{
             "command" => "ls -la",
             "description" => "List files in the current directory"
           }

    att = Repo.get!(Attestation, record.signed_predicate_run_id)
    assert att.event_kind == :llm_call_attested
    assert att.tags["kind"] == "agent_turn"
    assert att.tags["client_session_id"] == "ecdcbccc-ecb4-40f4-bbb1-db3ad3b16bca"
    assert att.tags["parser_module"] == "Recurse.Shared.LlmProxy.Parsers.AnthropicMessages"

    assert att.tags["parser_version"] ==
             Recurse.Shared.LlmProxy.Parsers.AnthropicMessages.version()

    assert att.tags["parser_format"] == "anthropic_messages/2023-06-01"
    assert att.tags["parse_betas_requested"] == ["oauth-2025-04-20", "claude-code-20250219"]
    assert att.tags["parse_status"] == "ok"
    assert att.tags["principal_source"] == "client_metadata"

    assert att.tags["parse_events_total"] == 23
    assert att.tags["parse_events_unhandled"] == 0
    assert att.tags["parse_unhandled_types"] == []
    assert att.tags["tool_use_intent_count"] == 1
    # S5 finding: the receipt names the bundle Cedar evaluated against.
    assert att.policy_canonical_hash == bundle_hash

    assert Repo.aggregate(from(a in Attestation, where: a.event_kind == :tool_use_denied), :count) ==
             0
  end

  test "deny: tool_use frames are replaced by a text block at the same index, stop_reason becomes end_turn, receipts link",
       %{upstream: upstream, bundle_hash: bundle_hash} do
    request = fixture("single_tool_use_bash.request.json")
    sse = deny_sse()
    assert sse =~ "rm -rf /tmp/x"
    MockHttpUpstream.serve_sse(upstream, sse, chunk_size: 61)

    result = proxy(request_conn(request), upstream)
    assert result.status == 200
    body = resp_body(result)

    # The original tool_use never reaches the client; no HTTP error status.
    refute body =~ ~s|"name":"Bash"|
    refute body =~ "input_json_delta"
    refute body =~ ~s|"id":"#{@bash_call_id}"|

    evs = events(body)
    types = Enum.map(evs, & &1["type"])

    assert types == [
             "message_start",
             "content_block_start",
             "ping",
             "content_block_delta",
             "content_block_delta",
             "content_block_delta",
             "content_block_stop",
             "content_block_start",
             "content_block_delta",
             "content_block_stop",
             "message_delta",
             "message_stop"
           ]

    # Every injected frame carries its `event:` line (the SDK dispatches on it).
    assert body =~ "event: content_block_start\ndata: {"
    assert body =~ "event: content_block_delta\ndata: {"

    [thinking_start | _] = Enum.filter(evs, &(&1["type"] == "content_block_start"))
    assert thinking_start["index"] == 0
    assert thinking_start["content_block"]["type"] == "thinking"

    replacement_start = Enum.at(evs, 7)
    assert replacement_start["index"] == 1
    assert replacement_start["content_block"] == %{"type" => "text", "text" => ""}
    refute Map.has_key?(replacement_start["content_block"], "signature")

    replacement_delta = Enum.at(evs, 8)
    assert replacement_delta["index"] == 1
    assert replacement_delta["delta"]["type"] == "text_delta"
    text = replacement_delta["delta"]["text"]
    assert text =~ "Tool call 'Bash' (call_id: #{@bash_call_id}) was blocked by org policy."
    assert text =~ "- Rule: policy2"
    assert text =~ "- Reason: denied_by_admission_policy"
    assert text =~ "- Tenant: #{@tenant_id}"
    assert text =~ "- Principal: claude-code:#{@account} (obo_human)"
    assert text =~ "- To appeal: ping #sec-ops (https://appeal.example/r5e)"
    assert Enum.at(evs, 9) == %{"type" => "content_block_stop", "index" => 1}

    message_delta = Enum.at(evs, 10)
    assert message_delta["delta"]["stop_reason"] == "end_turn"
    assert message_delta["usage"]["output_tokens"] == 181

    # Receipts: parent with a deny intent, child linked to it with the toolu id.
    record = latest_call_record()
    assert record.tool_use_intent_count == 1
    assert record.tool_use_denied_count == 1
    assert record.decision_summary == "all deny"

    assert [
             %ToolUseIntentRecord{
               decision: "deny",
               call_id: @bash_call_id,
               cedar_rule_id: "policy2"
             }
           ] =
             intent_rows(record)

    parent = Repo.get!(Attestation, record.signed_predicate_run_id)
    assert parent.tags["decision_summary"] == "all deny"
    assert parent.tags["parse_events_unhandled"] == 0
    assert parent.policy_canonical_hash == bundle_hash

    assert [denied] = Repo.all(from(a in Attestation, where: a.event_kind == :tool_use_denied))
    assert denied.turn_id == parent.run_id
    assert denied.policy_canonical_hash == bundle_hash
  end

  test "kernel admission failure suppresses tool bytes and terminal success",
       %{upstream: upstream} do
    previous_engine = Application.get_env(:recurse_fold, :engine_build_address)

    on_exit(fn ->
      if is_nil(previous_engine),
        do: Application.delete_env(:recurse_fold, :engine_build_address),
        else: Application.put_env(:recurse_fold, :engine_build_address, previous_engine)
    end)

    request = fixture("single_tool_use_bash.request.json")
    sse = fixture("single_tool_use_bash.sse")

    MockHttpUpstream.expect(upstream, fn conn ->
      # Request admission has already succeeded. Removing the build descriptor
      # now makes the later tool decision unavailable in the real kernel.
      Application.delete_env(:recurse_fold, :engine_build_address)

      conn
      |> Plug.Conn.put_resp_content_type("text/event-stream")
      |> Plug.Conn.send_resp(200, sse)
    end)

    result = proxy(request_conn(request), upstream)
    assert result.status == 200
    body = resp_body(result)

    refute body =~ ~s|"name":"Bash"|
    refute body =~ "input_json_delta"
    refute body =~ ~s|"id":"#{@bash_call_id}"|
    refute body =~ "message_stop"
    assert body =~ "gateway_interrupted"

    # The receipt: the call is marked as a policy evaluation failure and
    # the intent row is a deny under the evaluation-error rule.
    record = latest_call_record()
    assert record.error_kind == "policy_evaluation_failure"
    assert record.tool_use_intent_count == 1
    assert record.tool_use_denied_count == 1

    assert [
             %ToolUseIntentRecord{
               decision: "deny",
               call_id: @bash_call_id,
               cedar_rule_id: nil,
               deny_reason: "policy_evaluation_error"
             }
           ] = intent_rows(record)
  end

  test "parallel: deny the Read (index 1), allow the Bash (index 2) — indices stay contiguous",
       %{upstream: upstream} do
    # Make the Read block deniable by forbidding it in a bundle variant.
    bundle =
      @bundle <>
        ~s|\nforbid (principal, action == Action::"invoke_tool", resource == ToolUse::"Read");\n|

    hash = Recurse.Cedar.canonical_hash(bundle)

    Active.update(%Active{
      source: :filesystem,
      source_ref: "s4-parallel",
      loaded_at: DateTime.utc_now(),
      bundle: %PolicyBundleRef{
        bundle_id: Base.encode16(hash, case: :lower),
        canonical_hash: hash,
        loaded_at: DateTime.utc_now(),
        evaluator_handle: bundle,
        bundle_bytes: bundle
      }
    })

    request = fixture("parallel_tool_use.request.json")
    sse = fixture("parallel_tool_use.sse")
    MockHttpUpstream.serve_sse(upstream, sse, chunk_size: 41)

    result = proxy(request_conn(request), upstream)
    body = resp_body(result)
    evs = events(body)

    refute body =~ ~s|"name":"Read"|
    assert body =~ ~s|"name":"Bash"|

    starts = Enum.filter(evs, &(&1["type"] == "content_block_start"))
    assert Enum.map(starts, & &1["index"]) == [0, 1, 2]
    assert Enum.map(starts, & &1["content_block"]["type"]) == ["thinking", "text", "tool_use"]

    # The allowed Bash block is byte-identical to upstream and comes after the replacement.
    bash_frames = sse |> String.split("\n\n", trim: true) |> Enum.filter(&(&1 =~ ~s|"index":2|))
    assert Enum.all?(bash_frames, &String.contains?(body, &1))
    [before, after_] = String.split(body, ~s|"name":"Bash"|)
    assert before =~ ~s|"text_delta"|
    assert after_ =~ ~s|"stop_reason":"tool_use"|

    record = latest_call_record()
    assert record.decision_summary == "1 allow, 1 deny"

    assert Enum.sort(Enum.map(intent_rows(record), &{&1.tool_name, &1.decision})) == [
             {"Bash", "allow"},
             {"Read", "deny"}
           ]
  end

  test "non-streaming JSON with a denied tool_use is rewritten as JSON (no SSE frames)",
       %{upstream: upstream} do
    request = fixture("non_streaming_state_summary.request.json")

    message = %{
      "id" => "msg_json",
      "type" => "message",
      "role" => "assistant",
      "model" => "claude-haiku-4-5-20251001",
      "content" => [
        %{"type" => "text", "text" => "Cleaning up."},
        %{
          "type" => "tool_use",
          "id" => "toolu_JSON1",
          "name" => "Bash",
          "input" => %{"command" => "rm -rf /tmp/x"}
        }
      ],
      "stop_reason" => "tool_use",
      "usage" => %{"input_tokens" => 3, "output_tokens" => 4}
    }

    MockHttpUpstream.expect(upstream, fn conn ->
      conn
      |> Plug.Conn.put_resp_header("content-type", "application/json")
      |> Plug.Conn.send_resp(200, Jason.encode!(message))
    end)

    result = proxy(request_conn(request), upstream)
    assert result.status == 200
    body = resp_body(result)
    refute body =~ "data: "
    decoded = Jason.decode!(body)

    assert [%{"type" => "text", "text" => "Cleaning up."}, %{"type" => "text", "text" => text}] =
             decoded["content"]

    assert text =~ "Tool call 'Bash' (call_id: toolu_JSON1) was blocked by org policy."
    assert decoded["stop_reason"] == "end_turn"

    record = latest_call_record()
    assert record.tool_use_denied_count == 1
    assert record.completion_token_count == 4
    att = Repo.get!(Attestation, record.signed_predicate_run_id)
    assert att.tags["kind"] == "side_query"
    assert att.tags["parse_events_total"] == 3
  end

  test "non-streaming JSON without tool_use passes through byte-for-byte", %{upstream: upstream} do
    request = fixture("non_streaming_state_summary.request.json")
    response = fixture("non_streaming_state_summary.response.json")

    MockHttpUpstream.expect(upstream, fn conn ->
      conn
      |> Plug.Conn.put_resp_header("content-type", "application/json")
      |> Plug.Conn.send_resp(200, response)
    end)

    result = proxy(request_conn(request), upstream)
    assert resp_body(result) == response
    record = latest_call_record()
    assert record.model == "claude-haiku-4-5-20251001"
    assert record.completion_token_count == 74
    assert record.tool_use_intent_count == 0
  end

  test "drift: an unknown event type is suppressed, counted on the receipt, and stored", %{
    upstream: upstream
  } do
    request = fixture("text_only.request.json")

    sse =
      fixture("text_only.sse")
      |> String.replace(
        "event: message_stop",
        "event: telemetry\ndata: {\"type\":\"telemetry\",\"latency_ms\":1,\"secret\":\"S\"}\n\nevent: message_stop"
      )

    MockHttpUpstream.serve_sse(upstream, sse, chunk_size: 29)

    assert ParserDrift.new_since_boot() == 0
    result = proxy(request_conn(request), upstream)
    refute resp_body(result) =~ "event: telemetry"
    refute resp_body(result) =~ "event: message_stop"
    assert resp_body(result) =~ "PONG"

    record = latest_call_record()
    assert record.error_kind == "parser_failure"
    assert record.tool_use_intent_count == 0
    att = Repo.get!(Attestation, record.signed_predicate_run_id)
    assert att.tags["parse_events_unhandled"] == 1
    assert att.tags["parse_unhandled_types"] == ["event:telemetry"]

    assert [row] = DriftStore.list(@tenant_id)
    assert row.api_format == "anthropic_messages"
    assert row.event_type == "event:telemetry"
    assert row.sample_redacted == "keys=latency_ms,secret,type"
    refute row.sample_redacted =~ "S\""
    assert ParserDrift.new_since_boot() == 1
  end
end
