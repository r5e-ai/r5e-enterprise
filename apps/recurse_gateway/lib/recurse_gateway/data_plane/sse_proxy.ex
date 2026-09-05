defmodule Recurse.Gateway.DataPlane.SseProxy do
  @moduledoc """
  SSE proxy for `POST /v1/chat/completions` with `stream: true` (F002 T052,
  research D3, FR-004 / FR-006 / FR-018).

  ## Seam

  `SseProxy` does NOT talk to any HTTP client directly. The outbound
  `Req.post/2` with `into: :self` lives entirely in
  `OpenAiLlmProvider.chat_complete_stream/3`; SseProxy receives the
  returned `Enumerable.t()` (a `Req.Response.Async`) and drives the
  enumeration on the Plug caller process. This keeps the Provider
  Interface at the HTTP seam and lets SseProxy stay a pure Plug-layer
  concern.

  ## Iron Law check (`elixir:otp-thinking`)

  Pure module — no GenServer. The Plug-spawned caller process owns the
  socket (downstream), drains the upstream Finch pool via `reduce_while`,
  and does envelope-build + S3 put + ledger commit after stream close —
  all synchronously on the same process. TCP backpressure is the caller's
  natural concurrency model per research D3; inserting a sibling process
  would serialize streams through a mailbox and defeat per-request
  HTTP/2 multiplexing.

  ## Flow

    1. `Plug.Conn.send_chunked/2` switches the downstream conn into chunked
       transfer mode with status 200 + `Content-Type: text/event-stream`.
    2. Call `LLMProvider.chat_complete_stream/3`, which returns an
       `Enumerable.t()` of raw SSE `data: ...\\n\\n`-framed binary chunks.
    3. `Enum.reduce_while/3` — for each chunk:
         - `Plug.Conn.chunk/2` forwards it downstream.
         - accumulate into a list (prepended) for later reassembly.
         - on `{:error, :closed}` / `{:error, :einval}` from `chunk/2`
           the reducer halts with `:cancelled`; `Req.Response.Async`'s
           `cancel_fun` fires on halt and releases the upstream Finch
           slot deterministically.
    4. After the reducer returns, reassemble the chunks into the
       non-streaming `chat.completion` shape per
       `contracts/payload_canonicalization.md` §"Response canonicalization
       — SSE streaming".
    5. Build the envelope with `outcome: :success` (or `:cancelled`),
       S3-put the reassembled payload, ledger-commit. Errors here are
       logged; the downstream conn has already ended from the client's
       perspective.

  ## Cancellation semantics (FR-004 edge case)

  Client-disconnect mid-stream → `Plug.Conn.chunk/2` returns
  `{:error, :closed}`. The reducer halts with `:cancelled`, SseProxy
  still emits an attestation with `outcome: :cancelled` and whatever
  content was reassembled up to the last successfully-forwarded chunk.
  Honest: auditors see a `:cancelled` receipt and know the completion
  was incomplete.

  ## Cross-references

    * `specs/002-standalone-gateway-vertical-slice/tasks.md` T052
    * `specs/002-standalone-gateway-vertical-slice/research.md` D3
    * `specs/002-standalone-gateway-vertical-slice/contracts/payload_canonicalization.md`
    * `apps/recurse_providers/lib/recurse_providers/impls/openai_llm_provider.ex`
    * `apps/recurse_gateway/lib/recurse_gateway/data_plane/chat_completions_handler.ex`
  """

  alias Recurse.Gateway.DataPlane.ChatCompletionsHandler
  alias Recurse.Gateway.ProviderRegistry
  alias Recurse.Shared.IdentityContext

  require Logger

  @type proxy_opts :: %{
          required(:run_id) => String.t(),
          required(:policy_decision) =>
            Recurse.Gateway.Attestation.EnvelopeBuilder.policy_decision(),
          required(:policy_canonical_hash) => <<_::256>>
        }

  @doc """
  Stream a chat completion via the configured LLMProvider and forward
  chunks downstream. Emits a per-turn attestation after stream close.
  """
  @spec proxy(Plug.Conn.t(), IdentityContext.t(), map(), proxy_opts()) ::
          {:ok, Plug.Conn.t()} | {:error, term()}
  def proxy(%Plug.Conn{} = conn, %IdentityContext{} = ctx, request_body, opts)
      when is_map(request_body) and is_map(opts) do
    {llm_mod, llm_state} = ProviderRegistry.llm_provider()

    case llm_mod.chat_complete_stream(llm_state, request_body, ctx) do
      {:ok, stream} ->
        run_proxy(conn, ctx, request_body, stream, opts)

      {:upstream_error, status, body, _headers} when is_integer(status) ->
        send_upstream_error_sync(conn, status, body)

      {:upstream_error, _reason, _body, _headers} ->
        send_upstream_unavailable(conn)

      {:error, reason} ->
        Logger.error(fn -> "chat_complete_stream error: #{inspect(reason)}" end)
        send_upstream_unavailable(conn)
    end
  end

  # ---------------------------------------------------------------------------
  # Core enumeration loop
  # ---------------------------------------------------------------------------

  defp run_proxy(conn, ctx, request_body, stream, opts) do
    conn_chunked =
      conn
      |> Plug.Conn.put_resp_content_type("text/event-stream")
      |> Plug.Conn.put_resp_header("cache-control", "no-cache")
      |> Plug.Conn.send_chunked(200)

    reducer_initial = %{conn: conn_chunked, chunks: []}

    result = Enum.reduce_while(stream, reducer_initial, &forward_chunk/2)

    {final_conn, raw_chunks, outcome} = finalize_reducer_result(result, conn_chunked)
    reassembled = reassemble_chat_completion(raw_chunks, request_body)
    response_bytes = JSON.encode!(reassembled)
    request_bytes = JSON.encode!(request_body)

    _ =
      ChatCompletionsHandler.build_and_commit(
        ctx,
        request_bytes,
        response_bytes,
        Map.fetch!(opts, :policy_decision),
        Map.fetch!(opts, :policy_canonical_hash),
        outcome,
        Map.fetch!(opts, :run_id)
      )

    {:ok, final_conn}
  end

  # Reducer body — one SSE chunk at a time.
  defp forward_chunk(chunk, %{conn: conn, chunks: chunks} = acc) when is_binary(chunk) do
    case Plug.Conn.chunk(conn, chunk) do
      {:ok, updated_conn} ->
        {:cont, %{acc | conn: updated_conn, chunks: [chunk | chunks]}}

      {:error, :closed} ->
        {:halt, {:cancelled, %{acc | chunks: [chunk | chunks]}}}

      {:error, reason} ->
        {:halt, {:chunk_error, reason, %{acc | chunks: [chunk | chunks]}}}
    end
  end

  defp forward_chunk(_non_binary, acc), do: {:cont, acc}

  defp finalize_reducer_result(%{conn: conn, chunks: chunks}, _fallback) do
    {conn, Enum.reverse(chunks), :success}
  end

  defp finalize_reducer_result({:cancelled, %{conn: conn, chunks: chunks}}, _fallback) do
    {conn, Enum.reverse(chunks), :cancelled}
  end

  defp finalize_reducer_result({:chunk_error, reason, %{conn: conn, chunks: chunks}}, _fallback) do
    Logger.warning(fn -> "sse_proxy chunk error: #{inspect(reason)}" end)
    {conn, Enum.reverse(chunks), :cancelled}
  end

  defp finalize_reducer_result(_other, fallback) do
    {fallback, [], :upstream_error}
  end

  # ---------------------------------------------------------------------------
  # Reassembly — contract/payload_canonicalization.md §"SSE streaming"
  # ---------------------------------------------------------------------------

  @doc """
  Reassemble a list of raw SSE chunk binaries into a non-streaming
  `chat.completion` JSON term. Public for testability.

  Each chunk may carry zero or more `data: <json>\\n\\n`-framed events.
  Non-JSON `[DONE]` sentinels are discarded.
  """
  @spec reassemble_chat_completion([binary()], map()) :: map()
  def reassemble_chat_completion(raw_chunks, request_body) do
    events =
      raw_chunks
      |> Enum.flat_map(&parse_sse_events/1)

    initial = %{
      id: nil,
      created: nil,
      model: Map.get(request_body, "model"),
      role: "assistant",
      content: [],
      refusal: [],
      finish_reason: nil,
      usage: nil
    }

    folded = Enum.reduce(events, initial, &merge_event/2)

    content_str =
      folded.content
      |> Enum.reverse()
      |> IO.iodata_to_binary()

    refusal_str =
      case folded.refusal do
        [] -> nil
        list -> list |> Enum.reverse() |> IO.iodata_to_binary()
      end

    %{
      "id" => folded.id || "chatcmpl-reassembled",
      "object" => "chat.completion",
      "created" => folded.created || System.system_time(:second),
      "model" => folded.model,
      "choices" => [
        %{
          "index" => 0,
          "message" => %{
            "role" => folded.role,
            "content" => content_str,
            "refusal" => refusal_str
          },
          "finish_reason" => folded.finish_reason
        }
      ],
      "usage" => folded.usage
    }
  end

  # Parse a single SSE chunk binary into decoded event maps. Returns
  # `[]` on purely-framing chunks (heartbeats, `[DONE]`, malformed).
  defp parse_sse_events(chunk) when is_binary(chunk) do
    chunk
    |> String.split("\n\n", trim: true)
    |> Enum.flat_map(&parse_sse_event/1)
  end

  defp parse_sse_event(event) do
    lines = String.split(event, "\n", trim: true)

    data_payloads =
      for line <- lines,
          String.starts_with?(line, "data:"),
          payload = line |> String.replace_prefix("data:", "") |> String.trim(),
          payload != "",
          payload != "[DONE]",
          do: payload

    Enum.flat_map(data_payloads, fn raw ->
      case Jason.decode(raw) do
        {:ok, %{} = decoded} -> [decoded]
        _ -> []
      end
    end)
  end

  defp merge_event(%{} = event, acc) do
    acc
    |> merge_scalar("id", event, :id)
    |> merge_scalar("created", event, :created)
    |> merge_scalar("model", event, :model)
    |> merge_usage(event)
    |> merge_choices(Map.get(event, "choices", []))
  end

  defp merge_scalar(acc, key, event, acc_key) do
    case Map.get(event, key) do
      nil -> acc
      value -> Map.update(acc, acc_key, value, fn prior -> prior || value end)
    end
  end

  defp merge_usage(acc, %{"usage" => %{} = usage}), do: %{acc | usage: usage}
  defp merge_usage(acc, _), do: acc

  defp merge_choices(acc, choices) when is_list(choices) do
    Enum.reduce(choices, acc, &merge_choice/2)
  end

  defp merge_choice(%{"delta" => %{} = delta} = choice, acc) do
    acc
    |> maybe_update_role(Map.get(delta, "role"))
    |> maybe_append_content(Map.get(delta, "content"))
    |> maybe_append_refusal(Map.get(delta, "refusal"))
    |> maybe_update_finish_reason(Map.get(choice, "finish_reason"))
  end

  defp merge_choice(%{"finish_reason" => reason} = _choice, acc) when not is_nil(reason) do
    maybe_update_finish_reason(acc, reason)
  end

  defp merge_choice(_choice, acc), do: acc

  defp maybe_update_role(acc, nil), do: acc
  defp maybe_update_role(acc, role) when is_binary(role), do: %{acc | role: role}

  defp maybe_append_content(acc, nil), do: acc

  defp maybe_append_content(acc, content) when is_binary(content),
    do: %{acc | content: [content | acc.content]}

  defp maybe_append_refusal(acc, nil), do: acc

  defp maybe_append_refusal(acc, refusal) when is_binary(refusal),
    do: %{acc | refusal: [refusal | acc.refusal]}

  defp maybe_update_finish_reason(acc, nil), do: acc
  defp maybe_update_finish_reason(acc, reason), do: %{acc | finish_reason: reason}

  # ---------------------------------------------------------------------------
  # Error paths — used only when chat_complete_stream refused to open the
  # stream at all. Once a chunked response is underway we can't switch
  # back to a normal error body.
  # ---------------------------------------------------------------------------

  defp send_upstream_error_sync(conn, status, body) do
    body_bytes =
      case body do
        nil -> ~s|{"error":"upstream_error"}|
        b when is_binary(b) -> b
        b when is_map(b) or is_list(b) -> JSON.encode!(b)
        _ -> ~s|{"error":"upstream_error"}|
      end

    conn
    |> Plug.Conn.put_resp_content_type("application/json")
    |> Plug.Conn.send_resp(status, body_bytes)
    |> then(&{:ok, &1})
  end

  defp send_upstream_unavailable(conn) do
    body =
      JSON.encode!(%{
        "error" => %{
          "message" => "Upstream LLM provider unavailable.",
          "type" => "api_error",
          "code" => "upstream_unavailable"
        }
      })

    conn
    |> Plug.Conn.put_resp_content_type("application/json")
    |> Plug.Conn.send_resp(503, body)
    |> then(&{:ok, &1})
  end
end
