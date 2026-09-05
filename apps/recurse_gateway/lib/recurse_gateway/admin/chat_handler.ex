defmodule Recurse.Gateway.Admin.ChatHandler do
  @moduledoc """
  HTTP handler for the F004 Audit Agent chat surface (T115 / T116).

  Three routes:

    * `POST /v1/chat/messages` (SSE-streamed)
    * `GET /v1/chat/conversations`
    * `GET /v1/chat/conversations/:id`

  All three are cookie-required (BrowserSessionPlug runs upstream in the
  router); each handler embeds its own Cedar gate via
  `AuditPlane.Authz.gate/4` against the per-route action.

  ## SSE event sequence (`POST /v1/chat/messages`)

  Per `audit_api_extensions.md` §"Chat (Audit Agent)":

      event: conversation_id\\ndata: {"conversation_id": "..."}\\n\\n
      event: agent_token\\ndata: {"delta": "..."}\\n\\n
      event: tool_call_start\\ndata: {"tool_name": "...", "args": ..., "attested_run_id": "..."}\\n\\n
      event: tool_call_result\\ndata: {"tool_name": "...", "result": ..., "attested_run_id": "..."}\\n\\n
      event: agent_token\\ndata: {"delta": "..."}\\n\\n
      event: message_complete\\ndata: {"message_id": "...", "attested_run_id": "..."}\\n\\n

  Per-event recoverable errors emit
  `event: error\\ndata: {F001 envelope}\\n\\n` WITHOUT closing the stream.
  Fatal errors send the same shape and then close.

  ## Iron Law check (`elixir:phoenix-thinking`, `elixir:otp-thinking`)

    1. Mutable state across calls? No. Per-request only — the SSE caller
       process owns the conn + its own emit-pipeline state. No GenServer.
    2. Concurrent execution? No — runs synchronously on the Bandit
       request process. Tool calls run inline; the streaming "feel"
       comes from `Plug.Conn.chunk/2` flushing each event as it lands,
       not from concurrent work.
    3. Fault isolation? Per-tool: the Runtime catches tool crashes and
       reports them as in-stream `error` events; the SSE handler itself
       does not trap exits.

  All three NO at the handler-process level → plain Plug functions.

  ## Why SSE rather than WebSocket here

  The chat response is unidirectional (server → client). SSE fits;
  WebSocket would add bidirectional control-frame complexity for zero
  benefit. Live-tail (which needs bidi control) keeps the WebSocket
  path. Documented in `audit_api_extensions.md` §"Chat (Audit Agent)".

  ## Cross-references

    * `specs/004-audit-console/contracts/audit_api_extensions.md` §"Chat (Audit Agent)"
    * `apps/recurse_gateway/lib/recurse_gateway/data_plane/sse_proxy.ex`
      (F002 SSE chunked-response reference pattern)
    * `apps/recurse_gateway/lib/recurse_gateway/admin/audit_agent/runtime.ex`
  """

  alias Recurse.Gateway.Admin.AuditAgent.Runtime
  alias Recurse.Gateway.Admin.BrowserAuth.UiReceipts
  alias Recurse.Gateway.Admin.ChatHistory
  alias Recurse.Gateway.AuditPlane.Authz
  alias Recurse.Shared.IdentityContext

  require Logger

  @action ~s|Recurse::Action::"ChatDrawerQuery"|

  @doc """
  `POST /v1/chat/messages` — SSE-streamed chat endpoint.
  """
  @spec handle(Plug.Conn.t()) :: Plug.Conn.t()
  def handle(%Plug.Conn{} = conn) do
    resource = %{
      type: "Recurse::Resource::ConsoleSurface",
      id: "chat_drawer",
      attrs: %{"endpoint" => "/v1/chat/messages"}
    }

    case Authz.gate(conn, @action, resource) do
      {:ok, conn_after, ctx, _bundle_ref} -> do_handle(conn_after, ctx)
      err -> Authz.dispatch_gate_error(conn, err)
    end
  end

  defp do_handle(conn, %IdentityContext{} = ctx) do
    body = conn.body_params || %{}
    raw_conversation_id = Map.get(body, "conversation_id")
    content = Map.get(body, "content")

    if is_binary(content) and content != "" do
      run_chat(conn, ctx, raw_conversation_id, content)
    else
      Authz.send_bad_request(conn, "field `content` is required and must be a non-empty string")
    end
  end

  # ---------------------------------------------------------------------------
  # SSE pipeline
  # ---------------------------------------------------------------------------

  defp run_chat(conn, ctx, raw_conversation_id, content) do
    conn_chunked =
      conn
      |> Plug.Conn.put_resp_content_type("text/event-stream")
      |> Plug.Conn.put_resp_header("cache-control", "no-cache")
      |> Plug.Conn.send_chunked(200)

    case ensure_conversation(ctx, raw_conversation_id, content) do
      {:ok, conversation, user_message} ->
        conn_chunked
        |> emit_event("conversation_id", %{"conversation_id" => conversation.id})
        |> emit_event("agent_token", %{"delta" => "Processing your request..."})
        |> run_tool_steps(ctx, conversation, user_message, content)
        |> finalize(ctx, conversation)

      {:error, :forbidden} ->
        emit_error_and_close(
          conn_chunked,
          "forbidden",
          "conversation not owned by caller's principal"
        )

      {:error, :conversation_not_found} ->
        emit_error_and_close(conn_chunked, "not_found", "conversation_id not found")

      {:error, reason} ->
        Logger.warning(fn -> "chat ensure_conversation failed: #{inspect(reason)}" end)
        emit_error_and_close(conn_chunked, "internal", "failed to persist message")
    end
  end

  defp ensure_conversation(ctx, nil, content) do
    user_attrs = %{
      tenant_id: ctx.tenant_id,
      principal_subject: principal_subject(ctx),
      role: :user,
      content: content
    }

    case ChatHistory.create_message(:new, user_attrs) do
      {:ok, {conv, msg}} -> {:ok, conv, msg}
      {:error, reason} -> {:error, reason}
    end
  end

  defp ensure_conversation(ctx, conversation_id, content) when is_binary(conversation_id) do
    with {:ok, {conv, _}} <-
           ChatHistory.get_conversation(conversation_id,
             tenant_scope: ctx.tenant_id,
             principal_scope: principal_subject(ctx)
           ),
         {:ok, {conv2, msg}} <-
           ChatHistory.create_message(conv.id, %{
             role: :user,
             content: content
           }) do
      {:ok, conv2, msg}
    else
      {:error, :not_found} -> {:error, :forbidden}
      err -> err
    end
  end

  # Heuristic agent loop: parse the user content for explicit tool intents
  # (e.g. "fetch run_id <UUID>" → fetch_receipt_detail). For the F004 MVP
  # the LLM-driven tool-selection loop is wired in F005; until then this
  # handler dispatches at most ONE tool call inferred from the content,
  # then emits a closing token.
  defp run_tool_steps(conn, ctx, conversation, _user_message, content) do
    case detect_tool_intent(content) do
      {:tool, tool_name, tool_input} ->
        invoke_tool(conn, ctx, conversation, tool_name, tool_input)

      :no_tool ->
        conn
    end
  end

  defp invoke_tool(conn, ctx, conversation, tool_name, tool_input) do
    conn_with_start =
      emit_event(conn, "tool_call_start", %{
        "tool_name" => tool_name,
        "args" => tool_input
      })

    dispatch_ctx = %{
      identity_ctx: ctx,
      tenant_id: ctx.tenant_id,
      conversation_id: conversation.id
    }

    case Runtime.dispatch(tool_name, tool_input, dispatch_ctx) do
      {:ok, output, run_id} ->
        emit_event(conn_with_start, "tool_call_result", %{
          "tool_name" => tool_name,
          "result" => output,
          "attested_run_id" => run_id
        })

      {:error, :forbidden, run_id} ->
        emit_event(conn_with_start, "error", %{
          "error" => "forbidden",
          "error_description" => "tool call denied by policy",
          "attested_run_id" => run_id
        })

      {:error, :rate_limited, retry_after} ->
        emit_event(conn_with_start, "error", %{
          "error" => "rate_limited",
          "retry_after" => retry_after
        })

      {:error, :agent_token_budget_exceeded, run_id} ->
        emit_event(conn_with_start, "error", %{
          "error" => "agent_token_budget_exceeded",
          "attested_run_id" => run_id
        })

      {:error, :upstream_unavailable, run_id} ->
        emit_event(conn_with_start, "error", %{
          "error" => "upstream_unavailable",
          "attested_run_id" => run_id
        })

      {:error, :invalid_input, details} ->
        emit_event(conn_with_start, "error", %{
          "error" => "invalid_input",
          "error_description" => to_string(details)
        })

      {:error, :tool_not_found} ->
        emit_event(conn_with_start, "error", %{
          "error" => "tool_not_found",
          "tool_name" => tool_name
        })

      {:error, :internal, run_id} ->
        emit_event(conn_with_start, "error", %{
          "error" => "internal",
          "attested_run_id" => run_id
        })
    end
  end

  defp finalize(conn, ctx, conversation) do
    emit_chat_receipt(ctx, conversation)

    agent_message_attrs = %{
      role: :agent,
      content: "agent response (Phase-6 stub)"
    }

    {message_id, attested_run_id} =
      case ChatHistory.create_message(conversation.id, agent_message_attrs) do
        {:ok, {_conv, msg}} -> {msg.id, msg.attested_run_id || Ecto.UUID.generate()}
        _ -> {Ecto.UUID.generate(), Ecto.UUID.generate()}
      end

    emit_event(conn, "message_complete", %{
      "message_id" => message_id,
      "attested_run_id" => attested_run_id
    })
  end

  # Detect tool intents from user content. Day-1 simple heuristic:
  #
  #   * Content containing "fetch_receipt_detail <uuid>" → fetch_receipt_detail
  #   * Content containing "query_receipts" → query_receipts (default filters)
  #   * Otherwise: no tool call (handler still emits chat receipt + finalize).
  #
  # The full LLM-driven tool-selection ReAct loop ships in F005.
  defp detect_tool_intent(content) when is_binary(content) do
    cond do
      uuid = extract_uuid(content) ->
        {:tool, "fetch_receipt_detail", %{"run_id" => uuid}}

      String.contains?(content, "query_receipts") ->
        {:tool, "query_receipts", %{}}

      true ->
        :no_tool
    end
  end

  defp extract_uuid(text) do
    case Regex.run(
           ~r/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/i,
           text
         ) do
      [uuid] -> uuid
      _ -> nil
    end
  end

  # ---------------------------------------------------------------------------
  # GET /v1/chat/conversations + /:id
  # ---------------------------------------------------------------------------

  @doc """
  `GET /v1/chat/conversations` — list the caller's conversations.
  """
  @spec list_conversations(Plug.Conn.t()) :: Plug.Conn.t()
  def list_conversations(%Plug.Conn{} = conn) do
    resource = %{
      type: "Recurse::Resource::ConsoleSurface",
      id: "chat_drawer",
      attrs: %{"endpoint" => "/v1/chat/conversations"}
    }

    case Authz.gate(conn, @action, resource) do
      {:ok, conn_after, ctx, _bundle_ref} -> do_list(conn_after, ctx)
      err -> Authz.dispatch_gate_error(conn, err)
    end
  end

  defp do_list(conn, %IdentityContext{} = ctx) do
    convs =
      ChatHistory.list_conversations(%{
        tenant_id: ctx.tenant_id,
        principal_subject: principal_subject(ctx)
      })

    body = %{
      "conversations" =>
        Enum.map(convs, fn {c, excerpt} ->
          %{
            "id" => c.id,
            "started_at" => DateTime.to_iso8601(c.started_at),
            "last_message_at" => DateTime.to_iso8601(c.last_message_at),
            "last_user_message_excerpt" => excerpt
          }
        end),
      "next_cursor" => nil
    }

    emit_query_receipt(ctx, "list")

    conn
    |> Plug.Conn.put_resp_content_type("application/json")
    |> Plug.Conn.send_resp(200, JSON.encode!(body))
  end

  @doc """
  `GET /v1/chat/conversations/:id` — fetch one conversation + its messages.
  """
  @spec get_conversation(Plug.Conn.t()) :: Plug.Conn.t()
  def get_conversation(%Plug.Conn{} = conn) do
    resource = %{
      type: "Recurse::Resource::ConsoleSurface",
      id: "chat_drawer",
      attrs: %{"endpoint" => "/v1/chat/conversations/:id"}
    }

    case Authz.gate(conn, @action, resource) do
      {:ok, conn_after, ctx, _bundle_ref} -> do_get(conn_after, ctx)
      err -> Authz.dispatch_gate_error(conn, err)
    end
  end

  defp do_get(conn, %IdentityContext{} = ctx) do
    conversation_id = conn.path_params["id"]
    conn = Plug.Conn.fetch_query_params(conn)
    include_deleted? = forensic_read_requested?(conn, ctx)

    case ChatHistory.get_conversation(conversation_id,
           tenant_scope: ctx.tenant_id,
           principal_scope: principal_subject(ctx),
           include_deleted: include_deleted?,
           include_archived: include_deleted?
         ) do
      {:ok, {conv, messages}} ->
        body = %{
          "id" => conv.id,
          "started_at" => DateTime.to_iso8601(conv.started_at),
          "messages" =>
            Enum.map(messages, fn m ->
              %{
                "id" => m.id,
                "role" => m.role |> to_string(),
                "content" => m.content,
                "tool_calls" => m.tool_calls,
                "attested_run_id" => m.attested_run_id,
                "sequence" => m.sequence,
                "created_at" => DateTime.to_iso8601(m.inserted_at)
              }
            end)
        }

        emit_query_receipt(ctx, "detail")

        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.send_resp(200, JSON.encode!(body))

      {:error, :not_found} ->
        Authz.send_not_found(conn, "conversation not found")
    end
  end

  # ---------------------------------------------------------------------------
  # SSE helpers
  # ---------------------------------------------------------------------------

  defp emit_event(conn, event_name, data) when is_binary(event_name) and is_map(data) do
    payload = "event: #{event_name}\ndata: #{JSON.encode!(data)}\n\n"

    case Plug.Conn.chunk(conn, payload) do
      {:ok, updated} -> updated
      # On client disconnect we get :closed/:einval; subsequent emits no-op.
      {:error, _reason} -> conn
    end
  end

  defp emit_error_and_close(conn, error_code, description) do
    conn
    |> emit_event("error", %{
      "error" => error_code,
      "error_description" => description
    })
  end

  # ---------------------------------------------------------------------------
  # Receipt emission seam
  # ---------------------------------------------------------------------------

  defp emit_chat_receipt(%IdentityContext{} = ctx, conversation) do
    UiReceipts.emit(:ui_chat, %{
      conversation_id: conversation.id,
      principal_subject: principal_subject(ctx),
      tenant_id: ctx.tenant_id,
      correlation_id: ctx.correlation_id
    })
  end

  defp emit_query_receipt(%IdentityContext{} = ctx, scope) do
    UiReceipts.emit(:ui_query, %{
      query_kind: "chat_history",
      query_scope: scope,
      principal_subject: principal_subject(ctx),
      tenant_id: ctx.tenant_id,
      correlation_id: ctx.correlation_id
    })
  end

  defp principal_subject(%IdentityContext{principal: %{subject: s}}) when is_binary(s), do: s

  defp principal_subject(%IdentityContext{principal: %{account_id: s}}) when is_binary(s),
    do: s

  defp principal_subject(_), do: "unknown"

  # T143 — forensic-read flag (`?include_deleted=true`) is operator-only per
  # `contracts/retention_lifecycle.md` §"Soft-delete column". Auditors get a
  # silent `false` even if they pass the param — we deliberately do NOT
  # 403 since the param is informational; the server simply ignores it.
  defp forensic_read_requested?(conn, %IdentityContext{principal: %{recurse_role: role}}) do
    case {Map.get(conn.query_params, "include_deleted"), role} do
      {"true", "platform_operator"} -> true
      _ -> false
    end
  end

  defp forensic_read_requested?(_conn, _ctx), do: false
end
