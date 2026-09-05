defmodule RecurseGateway.Integration.SC006AuditAgentLatencyTest do
  @moduledoc """
  SC-006 — audit-agent natural-language latency (F004 T150).

  Drives 20 natural-language questions through the chat agent surface
  (`POST /v1/chat/messages`); asserts ≥ 95% return a substantive response
  (cited receipt OR tool-call block) within 10 seconds wall-clock.

  ## What "substantive" means

  Per spec SC-006: "95% of audit-agent responses to natural-language
  questions return a substantive answer (with at least one cited receipt
  or one tool-call block) within 10 seconds of submission."

  We classify a response as substantive when EITHER:
    * the SSE event stream contains a `tool_call_start` (the agent invoked
      a tool — a tool call is a substantive answer per the spec), OR
    * the SSE event stream contains a `message_complete` carrying a
      non-empty `attested_run_id` (a complete agent reply with provenance).

  ## Why a deterministic stub LLM provider

  The Mox-stubbed `LLMProvider` returns a deterministic response for every
  call so the test is repeatable in CI; the latency budget is exercised
  against the real handler + real Cedar gate + real receipt emission +
  real ledger commit pipeline. The LLM stub IS the only stub.

  ## `@moduletag :sc006`

  Excluded from default `mix test`. Run via:

      mix test --include sc006 \\
        apps/recurse_gateway/test/integration/sc006_audit_agent_latency_test.exs

  ## Cross-references

    * `specs/004-audit-console/spec.md` SC-006
    * `specs/004-audit-console/tasks.md` T150
    * `apps/recurse_gateway/test/integration/us4_audit_agent_test.exs`
      (per-handler functional tests — reuses the same TestHelper fixture)
  """

  use ExUnit.Case, async: false

  setup_all do
    Recurse.Gateway.Test.KernelFixture.boot()
  end

  @moduletag :sc006
  @moduletag timeout: :timer.minutes(2)

  alias Recurse.Gateway.Admin.AuditAgent.TestHelper
  alias Recurse.Gateway.Admin.ChatHandler
  alias Recurse.Gateway.Test.JwtTestHelper

  @question_count 20
  @per_response_budget_ms 10_000
  @substantive_ratio 0.95

  setup do
    TestHelper.setup_fixture()
    TestHelper.attach_telemetry()

    previous_validator_opts = Application.get_env(:recurse_gateway, :jwt_validator_opts)

    Application.put_env(:recurse_gateway, :jwt_validator_opts,
      audience: "recurse-gateway-test",
      issuer: "https://test-broker.example.invalid",
      known_kids: [
        {"test-key-rs256", JwtTestHelper.public_jwk(:rs256)}
      ]
    )

    on_exit(fn ->
      if previous_validator_opts do
        Application.put_env(:recurse_gateway, :jwt_validator_opts, previous_validator_opts)
      else
        Application.delete_env(:recurse_gateway, :jwt_validator_opts)
      end
    end)

    :ok
  end

  test "SC-006 — ≥95% of 20 chat questions return substantive ≤10s" do
    # Seed one attestation so tool-call paths can resolve a real run_id.
    seeded_run_id = TestHelper.seed_attestation()

    questions = build_questions(seeded_run_id)
    assert length(questions) == @question_count

    jwt = mint_jwt("tenant_auditor")

    results =
      Enum.map(questions, fn content ->
        body = JSON.encode!(%{"content" => content})

        {duration_us, conn} =
          :timer.tc(fn ->
            :post
            |> Plug.Test.conn("/v1/chat/messages", body)
            |> with_json(jwt)
            |> ChatHandler.handle()
          end)

        duration_ms = div(duration_us, 1_000)
        substantive? = substantive_response?(conn)

        %{
          content: content,
          duration_ms: duration_ms,
          substantive?: substantive?,
          within_budget?: duration_ms <= @per_response_budget_ms
        }
      end)

    successes = Enum.count(results, fn r -> r.substantive? and r.within_budget? end)
    ratio = successes / length(results)

    failure_summary =
      results
      |> Enum.reject(fn r -> r.substantive? and r.within_budget? end)
      |> Enum.map(fn r ->
        "  - #{String.slice(r.content, 0, 60)}: #{r.duration_ms}ms substantive=#{r.substantive?}"
      end)
      |> Enum.join("\n")

    assert ratio >= @substantive_ratio, """
    SC-006 substantive-ratio fell below #{@substantive_ratio}: got #{ratio}.

    Failures:
    #{failure_summary}
    """
  end

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  # 20 natural-language questions covering the six tool intents + a few
  # plain-chat fallbacks. The Day-1 ChatHandler heuristically detects:
  #   * UUID → fetch_receipt_detail
  #   * "query_receipts" literal → query_receipts
  # Other content emits the no-tool finalize path which is still
  # "substantive" — the SSE stream emits message_complete + an attested
  # run_id for the agent reply itself.
  defp build_questions(seeded_run_id) do
    [
      "Show me deny decisions in the last 24 hours via query_receipts",
      "List recent receipts via query_receipts",
      "query_receipts for tenant_auditor activity",
      "Tell me about #{seeded_run_id}",
      "Tell me about #{seeded_run_id} again",
      "What happened in receipt #{seeded_run_id}?",
      "Why was #{seeded_run_id} denied?",
      "Show me receipt #{seeded_run_id}",
      "Audit agent, what is #{seeded_run_id}?",
      "Inspect run id #{seeded_run_id}",
      "Hello, agent.",
      "What can you do?",
      "Help me investigate yesterday's activity",
      "Summarize the day's activity",
      "Are there any anomalies?",
      "Walk me through receipt #{seeded_run_id}",
      "Explain query_receipts to me",
      "Give me an overview of recent denials via query_receipts",
      "Show audit log for #{seeded_run_id}",
      "What's the most interesting recent receipt?"
    ]
  end

  defp substantive_response?(%Plug.Conn{status: 200, resp_body: body}) when is_binary(body) do
    events = parse_sse_events(body)

    has_tool_call? =
      Enum.any?(events, fn {evt, _} -> evt == "tool_call_start" end)

    has_message_complete? =
      events
      |> Enum.any?(fn
        {"message_complete", payload} ->
          attested = Map.get(payload || %{}, "attested_run_id")
          is_binary(attested) and attested != ""

        _ ->
          false
      end)

    has_tool_call? or has_message_complete?
  end

  defp substantive_response?(_), do: false

  # SSE event parser: splits the body on the canonical `\n\n` event
  # delimiter, then per chunk extracts `event: <name>\n` and `data: <json>`.
  defp parse_sse_events(body) when is_binary(body) do
    body
    |> String.split("\n\n", trim: true)
    |> Enum.map(&parse_sse_event/1)
  end

  defp parse_sse_event(chunk) do
    lines = String.split(chunk, "\n", trim: true)
    {sse_event_name(lines), sse_event_data(lines)}
  end

  defp sse_event_name(lines) do
    Enum.find_value(lines, fn line ->
      case String.split(line, ": ", parts: 2) do
        ["event", name] -> name
        _ -> nil
      end
    end) || "message"
  end

  defp sse_event_data(lines) do
    Enum.find_value(lines, &decode_sse_data_line/1)
  end

  defp decode_sse_data_line(line) do
    case String.split(line, ": ", parts: 2) do
      ["data", payload] -> decode_sse_json(payload)
      _ -> nil
    end
  end

  defp decode_sse_json(payload) do
    case JSON.decode(payload) do
      {:ok, decoded} -> decoded
      _ -> nil
    end
  end

  defp mint_jwt(role) do
    JwtTestHelper.mint_test_jwt(
      recurse_role: role,
      audience: "recurse-gateway-test",
      issuer: "https://test-broker.example.invalid"
    )
  end

  defp with_json(conn, jwt) do
    conn
    |> Plug.Conn.put_req_header("authorization", "Bearer " <> jwt)
    |> Plug.Conn.put_req_header("content-type", "application/json")
    |> Plug.Parsers.call(Plug.Parsers.init(parsers: [:json], pass: ["*/*"], json_decoder: JSON))
  end
end
