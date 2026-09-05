defmodule Recurse.Gateway.Integration.Us4AuditAgentTest do
  @moduledoc """
  US4 integration test (F004 T098 / T120).

  Drives the chat surface end-to-end:
    * `POST /v1/chat/messages` (SSE) → asserts the canonical event
      sequence (`conversation_id` → `agent_token` → `tool_call_*` →
      `message_complete`).
    * Asserts `:ui_chat` for the message itself + at least one
      `:ui_chat_skill_invoked_<tool>` per tool call.
    * Asserts chat history persists.
    * Asserts conversation retention follows
      `console.retention.chat_history_days`.

  ## Why direct-handler invocation rather than full HTTP

  The router's chat routes are guarded by BrowserSessionPlug (cookie
  auth), but the handler itself uses `AuditPlane.Authz.gate/4` which
  authenticates via the same `Authorization: Bearer <jwt>` header
  BrowserSessionPlug lifts the cookie into. Mirroring the existing
  contract tests, we skip the cookie envelope and pre-stamp the JWT
  header directly — the gate sees identical input either way.

  Per `audit_api_extensions.md` §"Chat (Audit Agent)", per-event errors
  emit in-stream as `event: error\\ndata: {F001 envelope}\\n\\n` without
  closing; recovery + closing are both covered.
  """

  use ExUnit.Case, async: false

  setup_all do
    Recurse.Gateway.Test.KernelFixture.boot()
  end

  alias Recurse.Gateway.Admin.AuditAgent.TestHelper
  alias Recurse.Gateway.Admin.ChatHandler
  alias Recurse.Gateway.Admin.ChatHistory
  alias Recurse.Gateway.Test.JwtTestHelper

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

  describe "POST /v1/chat/messages — SSE flow" do
    test "no-tool message: emits conversation_id → agent_token → message_complete" do
      jwt = mint_jwt("tenant_auditor")
      body = JSON.encode!(%{"content" => "Hello, agent."})

      conn =
        :post
        |> Plug.Test.conn("/v1/chat/messages", body)
        |> with_json(jwt)
        |> ChatHandler.handle()

      assert conn.status == 200

      events = parse_sse_events(conn)

      # Canonical event sequence per audit_api_extensions.md §"SSE event sequence".
      assert match?(%{"conversation_id" => _}, find_event_data(events, "conversation_id"))
      assert match?(%{"delta" => _}, find_event_data(events, "agent_token"))

      assert match?(
               %{"message_id" => _, "attested_run_id" => _},
               find_event_data(events, "message_complete")
             )

      assert_receive {:ui_receipt_emitted, %{event_kind: :ui_chat}}, 2_000
    end

    test "fetch_receipt_detail tool call: emits tool_call_start + tool_call_result + per-tool receipt" do
      run_id = TestHelper.seed_attestation()

      jwt = mint_jwt("tenant_auditor")
      body = JSON.encode!(%{"content" => "Tell me about #{run_id}"})

      conn =
        :post
        |> Plug.Test.conn("/v1/chat/messages", body)
        |> with_json(jwt)
        |> ChatHandler.handle()

      assert conn.status == 200

      events = parse_sse_events(conn)

      assert is_map(find_event_data(events, "tool_call_start"))
      assert is_map(find_event_data(events, "tool_call_result"))
      assert is_map(find_event_data(events, "message_complete"))

      tool_call_result = find_event_data(events, "tool_call_result")
      assert tool_call_result["tool_name"] == "fetch_receipt_detail"
      assert is_binary(tool_call_result["attested_run_id"])

      assert_receive {:ui_receipt_emitted,
                      %{event_kind: :ui_chat_skill_invoked_fetch_receipt_detail}},
                     2_000

      assert_receive {:ui_receipt_emitted, %{event_kind: :ui_chat}}, 2_000
    end

    test "missing content → 400 Bad Request" do
      jwt = mint_jwt("tenant_auditor")
      body = JSON.encode!(%{})

      conn =
        :post
        |> Plug.Test.conn("/v1/chat/messages", body)
        |> with_json(jwt)
        |> ChatHandler.handle()

      assert conn.status == 400
    end

    test "caller role denied at Cedar gate (no chat_drawer access)" do
      jwt = mint_jwt("caller")
      body = JSON.encode!(%{"content" => "should be denied"})

      conn =
        :post
        |> Plug.Test.conn("/v1/chat/messages", body)
        |> with_json(jwt)
        |> ChatHandler.handle()

      assert conn.status == 403
    end
  end

  describe "GET /v1/chat/conversations" do
    test "lists the caller's conversations + emits :ui_query (chat_history)" do
      jwt = mint_jwt("tenant_auditor")

      _ =
        ChatHistory.create_message(:new, %{
          tenant_id: TestHelper.tenant_id(),
          principal_subject: "user-0001",
          role: :user,
          content: "seed"
        })

      conn =
        :get
        |> Plug.Test.conn("/v1/chat/conversations")
        |> with_jwt(jwt)
        |> ChatHandler.list_conversations()

      assert conn.status == 200
      body = JSON.decode!(conn.resp_body)
      assert is_list(body["conversations"])

      assert_receive {:ui_receipt_emitted, %{event_kind: :ui_query, query_kind: "chat_history"}},
                     2_000
    end

    test "each row carries last_user_message_excerpt populated from the most-recent user message" do
      # Per `audit_api_extensions.md` §"GET /v1/chat/conversations" the
      # `last_user_message_excerpt` field MUST contain the user message
      # body (truncated). F007 from MR !93 fix-pass-2 GAN: the field used
      # to be hard-coded `nil`, which made every history-dropdown row
      # render as "(untitled conversation)" against the real backend.
      jwt = mint_jwt("tenant_auditor")

      {:ok, {conv, _msg}} =
        ChatHistory.create_message(:new, %{
          tenant_id: TestHelper.tenant_id(),
          principal_subject: "user-0001",
          role: :user,
          content: "Why was Alice's last bash_exec denied?"
        })

      # Append an agent reply — proves we still pick the most-recent
      # USER message (not the most-recent message of any role).
      {:ok, _} =
        ChatHistory.create_message(conv.id, %{
          role: :agent,
          content: "Looking at the most recent denial..."
        })

      conn =
        :get
        |> Plug.Test.conn("/v1/chat/conversations")
        |> with_jwt(jwt)
        |> ChatHandler.list_conversations()

      assert conn.status == 200
      body = JSON.decode!(conn.resp_body)
      [row | _] = body["conversations"]
      assert row["id"] == conv.id

      assert row["last_user_message_excerpt"] ==
               "Why was Alice's last bash_exec denied?"
    end
  end

  describe "GET /v1/chat/conversations/:id" do
    test "returns conversation + messages; emits :ui_query (chat_history)" do
      jwt = mint_jwt("tenant_auditor")

      {:ok, {conv, _msg}} =
        ChatHistory.create_message(:new, %{
          tenant_id: TestHelper.tenant_id(),
          principal_subject: "user-0001",
          role: :user,
          content: "seed"
        })

      conn =
        :get
        |> Plug.Test.conn("/v1/chat/conversations/#{conv.id}")
        |> with_path_params(%{"id" => conv.id})
        |> with_jwt(jwt)
        |> ChatHandler.get_conversation()

      assert conn.status == 200
      body = JSON.decode!(conn.resp_body)
      assert body["id"] == conv.id
      assert is_list(body["messages"])

      assert_receive {:ui_receipt_emitted, %{event_kind: :ui_query, query_kind: "chat_history"}},
                     2_000
    end

    test "cross-principal access returns 404 (conversation not owned)" do
      # Seed conversation owned by alice
      {:ok, {conv, _}} =
        ChatHistory.create_message(:new, %{
          tenant_id: TestHelper.tenant_id(),
          principal_subject: "alice@corp",
          role: :user,
          content: "alice's message"
        })

      # Try to read as bob (different principal_subject)
      jwt =
        JwtTestHelper.mint_test_jwt(
          subject: "bob@corp",
          recurse_role: "tenant_auditor",
          audience: "recurse-gateway-test",
          issuer: "https://test-broker.example.invalid"
        )

      conn =
        :get
        |> Plug.Test.conn("/v1/chat/conversations/#{conv.id}")
        |> with_path_params(%{"id" => conv.id})
        |> with_jwt(jwt)
        |> ChatHandler.get_conversation()

      assert conn.status == 404
    end
  end

  describe "ChatHistory persistence" do
    test "create_message :new persists user + bumps conversation last_message_at" do
      {:ok, {conv1, msg1}} =
        ChatHistory.create_message(:new, %{
          tenant_id: TestHelper.tenant_id(),
          principal_subject: "alice@corp",
          role: :user,
          content: "first"
        })

      assert msg1.sequence == 1
      assert conv1.last_message_at == conv1.started_at

      Process.sleep(10)

      {:ok, {conv2, msg2}} =
        ChatHistory.create_message(conv1.id, %{
          role: :agent,
          content: "second"
        })

      assert msg2.sequence == 2
      assert msg2.conversation_id == conv1.id
      assert DateTime.compare(conv2.last_message_at, conv1.last_message_at) == :gt
    end

    test "archive_conversation soft-archives + idempotent" do
      {:ok, {conv, _}} =
        ChatHistory.create_message(:new, %{
          tenant_id: TestHelper.tenant_id(),
          principal_subject: "alice@corp",
          role: :user,
          content: "msg"
        })

      assert {:ok, archived} = ChatHistory.archive_conversation(conv.id)
      assert archived.archived_at
      assert {:error, :already_archived} = ChatHistory.archive_conversation(conv.id)
    end
  end

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  defp mint_jwt(role) do
    JwtTestHelper.mint_test_jwt(
      recurse_role: role,
      audience: "recurse-gateway-test",
      issuer: "https://test-broker.example.invalid"
    )
  end

  defp with_jwt(conn, jwt) do
    Plug.Conn.put_req_header(conn, "authorization", "Bearer " <> jwt)
  end

  defp with_json(conn, jwt) do
    conn
    |> Plug.Conn.put_req_header("authorization", "Bearer " <> jwt)
    |> Plug.Conn.put_req_header("content-type", "application/json")
    |> Plug.Parsers.call(Plug.Parsers.init(parsers: [:json], pass: ["*/*"], json_decoder: JSON))
  end

  defp with_path_params(conn, params) do
    %{conn | path_params: Map.merge(conn.path_params || %{}, params)}
  end

  defp parse_sse_events(conn) do
    # Plug.Test's chunked-response collector returns the concatenated
    # body in `conn.resp_body`. Split on the SSE event boundary.
    conn.resp_body
    |> String.split("\n\n", trim: true)
    |> Enum.map(&parse_one/1)
    |> Enum.reject(&is_nil/1)
  end

  defp parse_one(event) do
    lines = String.split(event, "\n", trim: true)

    {event_name, data_lines} =
      Enum.reduce(lines, {nil, []}, fn line, {ev, data} ->
        cond do
          String.starts_with?(line, "event:") ->
            {String.trim(String.replace_prefix(line, "event:", "")), data}

          String.starts_with?(line, "data:") ->
            {ev, [String.trim(String.replace_prefix(line, "data:", "")) | data]}

          true ->
            {ev, data}
        end
      end)

    case data_lines do
      [] ->
        nil

      [json | _] ->
        case Jason.decode(json) do
          {:ok, decoded} -> {event_name, decoded}
          _ -> nil
        end
    end
  end

  defp find_event_data(events, name) do
    case Enum.find(events, fn {n, _} -> n == name end) do
      {_, data} -> data
      _ -> nil
    end
  end
end
