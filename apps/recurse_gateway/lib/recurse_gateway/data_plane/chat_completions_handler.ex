defmodule Recurse.Gateway.DataPlane.ChatCompletionsHandler do
  @moduledoc """
  Orchestrator for `POST /v1/chat/completions` (F002 T051, FR-003 / FR-005 /
  FR-016 / FR-029-32).

  ## Flow — sync / non-streaming

    1. Validate request body against the FR-003 scope-cut allowlist
       (reject `tools`, `tool_choice`, `functions`, `function_call`,
       `response_format`, image/audio parts). Rejections return
       OpenAI-shape 400 protocol-native (FR-016c / FR-005).
    2. Capture a per-request Cedar bundle snapshot
       (`Recurse.Gateway.Policy.Active.current/0`) and evaluate. On `:deny`,
       construct a synthetic OpenAI refusal response (FR-016a, single
       canonical channel = `choices[0].message.refusal`), build + commit
       a denial attestation, return HTTP 200.
    3. On `:allow`, call the configured `LLMProvider`. If `stream: true`,
       delegate to `Recurse.Gateway.DataPlane.SseProxy`. Otherwise a sync
       `chat_complete/3`.
    4. On a sync 2xx: JCS-canonicalize the `(request, response)` pair,
       S3-put the combined payload (FR-019/027), build the envelope with
       the returned `payload_uri`, commit via the Ledger provider
       (FR-016). Return the upstream response body verbatim with
       `Content-Type: application/json` (FR-006 header passthrough — no
       headers injected except `x-recurse-correlation-id`, which the
       Router already stamped).
    5. On upstream non-2xx: pass through `status + body + headers`
       (FR-016b), still emit an attestation with
       `outcome: :upstream_error` and `upstream_status_code: <status>`
       so auditors see the failed traversal and can distinguish it
       from policy denials (US6 + FR-005 FR-016b).

  ## Iron Law check (`elixir:otp-thinking`)

  Pure module. No GenServer. Every call runs on the Bandit-spawned
  request process. Provider `{module, state}` tuples are looked up from
  `:persistent_term` via `Recurse.Gateway.ProviderRegistry` — no mailbox
  serialization, no synchronous hop through a sibling process.

  ## Payload canonicalization (FR-018 / contracts/payload_canonicalization.md)

  The Gateway hashes and stores the JCS canonical encoding of
  `{"request": <canonicalized-request-json>, "response":
  <canonicalized-response-json>}`. `EnvelopeBuilder` computes the hash
  internally; this handler duplicates the encoding path once for S3
  storage. The two canonicalizations are deterministic and produce
  identical bytes.

  ## Error routing (FR-016a-f + FR-029-32)

    * `:deny` policy decision → 200 OpenAI refusal shape + committed
      denial attestation.
    * out-of-scope request field → 400 protocol-native validation error.
    * `:missing_authorization` etc. → Router handles before the handler
      runs (FR-016d).
    * upstream 5xx / timeout / connection error → pass-through HTTP
      status with body (`FR-016b`); attestation committed with
      `outcome: :upstream_error`.
    * KMS sign retries exhausted (`{:sign, :retries_exhausted}` in
      builder result) → 503 protocol-native per FR-029; no attestation
      is committed (the aborted call has no receipt).
    * S3 put transient error → today we log + surface 503; the payload
      outbox reconciler lands in T090 (Wave 3G). This interim behavior
      is documented here and in `docs/`. Happy-path hot code is
      unaffected.
    * Ledger commit retry-exhaustion → receipt remains at `:signed`;
      we still return the LLM response to the caller (F001 FR-030 /
      F002 FR-030 outer-container progression is the auditor's
      concern, not the caller's).

  ## Cross-references

    * `specs/002-standalone-gateway-vertical-slice/tasks.md` T051
    * `specs/002-standalone-gateway-vertical-slice/spec.md` FR-003,
      FR-005, FR-016, FR-018, FR-019, FR-027-32
    * `apps/recurse_gateway/lib/recurse_gateway/attestation/envelope_builder.ex`
    * `apps/recurse_providers/lib/recurse_providers/impls/postgres_merkle_ledger.ex`
    * `apps/recurse_providers/lib/recurse_providers/impls/s3_storage_provider.ex`
  """

  alias Recurse.Gateway.Attestation.EnvelopeBuilder
  alias Recurse.Gateway.DataPlane.SseProxy
  alias Recurse.Gateway.Policy.Active
  alias Recurse.Gateway.Policy.Evaluator
  alias Recurse.Gateway.ProviderRegistry
  alias Recurse.Shared.IdentityContext
  alias Recurse.Shared.Jcs

  require Logger

  # Request fields outside the FR-003 scope cut. Presence of any of these
  # at the top level is a protocol-native validation error.
  @out_of_scope_fields ~w(tools tool_choice functions function_call response_format)

  # Whitelisted content-part kinds for `messages[].content` — array-form
  # content may carry text parts only (no image_url / input_audio / etc.).
  @allowed_content_part_types ["text"]

  @doc """
  Entry point. `conn` MUST have `:identity_ctx` assigned (the Router's
  `authenticate/1` does this). Returns the mutated `conn` after a
  response has been sent.
  """
  @spec handle(Plug.Conn.t()) :: Plug.Conn.t()
  def handle(%Plug.Conn{assigns: %{identity_ctx: %IdentityContext{} = ctx}} = conn) do
    with {:ok, request_body} <- read_body(conn),
         :ok <- validate_request(request_body),
         {:ok, %Active{bundle: bundle_ref}} <- Active.current(),
         policy_result <- evaluate_policy(bundle_ref, ctx, request_body),
         {:ok, conn_final} <- dispatch(conn, ctx, request_body, bundle_ref, policy_result) do
      conn_final
    else
      {:error, :invalid_request, details} ->
        send_validation_error(conn, details)

      {:error, :not_loaded} ->
        # Fail-closed per Constitution Principle III. No loader has
        # populated the canonical Active store — the Gateway should
        # not be accepting Data-Plane traffic. Return 503 so the
        # caller retries / operator wakes up.
        send_service_unavailable(conn, "policy bundle not loaded")

      {:error, reason} ->
        Logger.error(fn ->
          "chat_completions_handler unexpected error: #{inspect(reason)}"
        end)

        send_service_unavailable(conn, "internal error")
    end
  end

  # ---------------------------------------------------------------------------
  # Body / validation
  # ---------------------------------------------------------------------------

  defp read_body(%Plug.Conn{body_params: %Plug.Conn.Unfetched{}}) do
    {:error, :invalid_request, "request body not parsed"}
  end

  defp read_body(%Plug.Conn{body_params: body}) when is_map(body), do: {:ok, body}

  defp validate_request(body) when is_map(body) do
    with :ok <- require_field(body, "model"),
         :ok <- require_messages(body),
         :ok <- reject_out_of_scope_fields(body),
         :ok <- validate_message_shapes(Map.get(body, "messages", [])) do
      :ok
    end
  end

  defp validate_request(_), do: {:error, :invalid_request, "body must be a JSON object"}

  defp require_field(body, key) do
    case Map.fetch(body, key) do
      {:ok, value} when is_binary(value) and byte_size(value) > 0 ->
        :ok

      {:ok, _} ->
        {:error, :invalid_request, "`#{key}` must be a non-empty string"}

      :error ->
        {:error, :invalid_request, "`#{key}` is required"}
    end
  end

  defp require_messages(body) do
    case Map.get(body, "messages") do
      list when is_list(list) and list != [] -> :ok
      _ -> {:error, :invalid_request, "`messages` must be a non-empty array"}
    end
  end

  defp reject_out_of_scope_fields(body) do
    case Enum.find(@out_of_scope_fields, fn field -> Map.has_key?(body, field) end) do
      nil ->
        :ok

      field ->
        {:error, :invalid_request, "`#{field}` is not supported in this slice (FR-003 scope-cut)"}
    end
  end

  defp validate_message_shapes(messages) do
    Enum.reduce_while(messages, :ok, fn msg, _acc ->
      case validate_message(msg) do
        :ok -> {:cont, :ok}
        {:error, _, _} = err -> {:halt, err}
      end
    end)
  end

  defp validate_message(%{"role" => role, "content" => content})
       when is_binary(role) and is_binary(content) do
    :ok
  end

  defp validate_message(%{"role" => role, "content" => parts})
       when is_binary(role) and is_list(parts) do
    if Enum.all?(parts, &text_content_part?/1) do
      :ok
    else
      {:error, :invalid_request, "message content parts must be text-only in this slice"}
    end
  end

  defp validate_message(_),
    do:
      {:error, :invalid_request,
       "each message requires `role` + `content` (string or text parts)"}

  defp text_content_part?(%{"type" => type}) when type in @allowed_content_part_types, do: true
  defp text_content_part?(_), do: false

  # ---------------------------------------------------------------------------
  # Policy evaluation
  # ---------------------------------------------------------------------------

  defp evaluate_policy(bundle_ref, ctx, request_body) do
    model = Map.get(request_body, "model", "unknown")

    # Cedar rejects `null` / `nil` context values; filter before building.
    context =
      %{
        "streaming" => truthy?(Map.get(request_body, "stream")),
        "model" => model
      }
      |> maybe_put_string("max_tokens", Map.get(request_body, "max_tokens"))

    request = %{
      action: ~s[Recurse::Action::"ChatCompletion"],
      resource: %{
        type: "Recurse::Resource::LLMEndpoint",
        id: "openai_chat_completions",
        attrs: %{"model" => model, "provider" => "openai"}
      },
      context: context
    }

    Evaluator.evaluate(bundle_ref, ctx, request)
  end

  defp maybe_put_string(map, _key, nil), do: map
  defp maybe_put_string(map, key, value), do: Map.put(map, key, value)

  defp truthy?(true), do: true
  defp truthy?(_), do: false

  # ---------------------------------------------------------------------------
  # Dispatch — route allow/deny, streaming/sync
  # ---------------------------------------------------------------------------

  defp dispatch(conn, ctx, request_body, bundle_ref, {:deny, _matched}) do
    handle_deny(conn, ctx, request_body, bundle_ref)
  end

  defp dispatch(conn, ctx, request_body, bundle_ref, {:allow, _matched}) do
    if truthy?(Map.get(request_body, "stream")) do
      handle_stream(conn, ctx, request_body, bundle_ref)
    else
      handle_sync(conn, ctx, request_body, bundle_ref)
    end
  end

  # --- Deny path ----------------------------------------------------------

  defp handle_deny(conn, ctx, request_body, bundle_ref) do
    run_id = new_run_id()
    policy_hash = bundle_ref.canonical_hash

    refusal_message =
      "Request denied by policy (canonical_hash=#{Base.encode16(policy_hash, case: :lower)})"

    response_body = synthetic_refusal_response(run_id, request_body, refusal_message)
    response_bytes = JSON.encode!(response_body)
    request_bytes = JSON.encode!(request_body)

    case build_and_commit(
           ctx,
           request_bytes,
           response_bytes,
           :deny,
           policy_hash,
           :success,
           run_id
         ) do
      {:ok, _commit_result} ->
        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.send_resp(200, response_bytes)
        |> then(&{:ok, &1})

      {:error, {:sign, _} = reason} ->
        Logger.error(fn -> "denial attestation signing failed: #{inspect(reason)}" end)
        {:ok, send_kms_unavailable(conn)}

      {:error, reason} ->
        Logger.error(fn -> "denial attestation commit failed: #{inspect(reason)}" end)
        # Even when commit fails we return the refusal — the caller has
        # been denied regardless; audit-trail gap is an operator concern.
        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.send_resp(200, response_bytes)
        |> then(&{:ok, &1})
    end
  end

  @doc """
  Build the synthetic OpenAI `chat.completion` body emitted on a policy
  denial (F002 FR-005 / FR-016a).

  Exposed publicly (rather than `defp`) so the Surface S denial-response
  property test at
  `apps/recurse_gateway/test/data_plane/denial_response_property_test.exs`
  can exercise the synthesis directly without booting the Router +
  Ledger. The shape is the single canonical denial channel per
  FR-016a: `choices[0].message.refusal` populated, `content` nil, no
  `tool_calls` field, `finish_reason: "content_filter"`.

  `refusal_message` SHOULD embed the `policy_canonical_hash` (the deny
  branch above formats it as `canonical_hash=<hex>`).
  """
  @doc since: "0.1.0"
  @spec synthetic_refusal_response(String.t(), map(), String.t()) :: map()
  def synthetic_refusal_response(run_id, request_body, refusal_message) do
    model = Map.get(request_body, "model", "unknown")

    %{
      "id" => "chatcmpl-#{run_id}",
      "object" => "chat.completion",
      "created" => System.system_time(:second),
      "model" => model,
      "choices" => [
        %{
          "index" => 0,
          "message" => %{
            "role" => "assistant",
            "content" => nil,
            "refusal" => refusal_message
          },
          "finish_reason" => "content_filter"
        }
      ],
      "usage" => %{
        "prompt_tokens" => 0,
        "completion_tokens" => 0,
        "total_tokens" => 0
      }
    }
  end

  # --- Sync path ----------------------------------------------------------

  defp handle_sync(conn, ctx, request_body, bundle_ref) do
    run_id = new_run_id()
    policy_hash = bundle_ref.canonical_hash
    {llm_mod, llm_state} = ProviderRegistry.llm_provider()

    case llm_mod.chat_complete(llm_state, request_body, ctx) do
      {:ok, response_body} ->
        response_bytes = JSON.encode!(response_body)
        request_bytes = JSON.encode!(request_body)

        _ =
          build_and_commit(
            ctx,
            request_bytes,
            response_bytes,
            :allow,
            policy_hash,
            :success,
            run_id
          )

        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.send_resp(200, response_bytes)
        |> then(&{:ok, &1})

      {:upstream_error, status, body, _headers} when is_integer(status) ->
        body_bytes = upstream_body_bytes(body)

        _ =
          build_and_commit(
            ctx,
            JSON.encode!(request_body),
            body_bytes,
            :allow,
            policy_hash,
            :upstream_error,
            run_id,
            upstream_status_code: status
          )

        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.send_resp(status, body_bytes)
        |> then(&{:ok, &1})

      {:upstream_error, :timeout, _, _} ->
        {:ok, send_upstream_timeout(conn)}

      {:upstream_error, :connection, _reason, _headers} ->
        {:ok, send_upstream_unavailable(conn)}

      {:error, reason} ->
        Logger.error(fn -> "chat_complete error: #{inspect(reason)}" end)
        {:ok, send_upstream_unavailable(conn)}
    end
  end

  defp upstream_body_bytes(nil), do: ~s|{"error":"upstream_error"}|
  defp upstream_body_bytes(body) when is_binary(body), do: body
  defp upstream_body_bytes(body) when is_map(body) or is_list(body), do: JSON.encode!(body)
  defp upstream_body_bytes(_), do: ~s|{"error":"upstream_error"}|

  # --- Streaming path -----------------------------------------------------

  defp handle_stream(conn, ctx, request_body, bundle_ref) do
    run_id = new_run_id()
    policy_hash = bundle_ref.canonical_hash

    SseProxy.proxy(conn, ctx, request_body, %{
      run_id: run_id,
      policy_decision: :allow,
      policy_canonical_hash: policy_hash
    })
  end

  # ---------------------------------------------------------------------------
  # Envelope build + S3 put + ledger commit
  # ---------------------------------------------------------------------------

  @doc """
  Public helper reused by `SseProxy` after stream reassembly. Builds the
  envelope, S3-puts the canonical payload, then commits via the
  configured Ledger provider.

  `opts` accepts:

    * `:upstream_status_code` — integer HTTP status to stamp on the
      outer container when `outcome: :upstream_error`. Only meaningful
      for the upstream-non-2xx path (FR-005 FR-016b, US6). Omitted on
      the success / deny / timeout / connection-error paths.

  Returns `{:ok, commit_result}` on success or `{:error, reason}` on
  any failure step.
  """
  @spec build_and_commit(
          IdentityContext.t(),
          request_bytes :: binary(),
          response_bytes :: binary(),
          Recurse.Gateway.Attestation.EnvelopeBuilder.policy_decision(),
          policy_canonical_hash :: <<_::256>>,
          Recurse.Gateway.Attestation.EnvelopeBuilder.outcome(),
          run_id :: String.t(),
          opts :: keyword()
        ) :: {:ok, map()} | {:error, term()}
  def build_and_commit(
        ctx,
        request_bytes,
        response_bytes,
        decision,
        policy_hash,
        outcome,
        run_id,
        opts \\ []
      ) do
    {secrets_mod, secrets_state} = ProviderRegistry.secrets_provider()
    {storage_mod, storage_state} = ProviderRegistry.storage_provider()
    {ledger_mod, ledger_state} = ProviderRegistry.ledger_provider()

    commit_opts = [
      policy_decision: decision,
      outcome: outcome,
      upstream_status_code: Keyword.get(opts, :upstream_status_code)
    ]

    with {:ok, payload_bytes} <- canonicalize_payload(request_bytes, response_bytes),
         {:ok, %{uri: payload_uri}} <-
           storage_mod.put_payload(storage_state, payload_bytes, ctx),
         {:ok, envelope} <-
           EnvelopeBuilder.build(
             ctx,
             request_bytes,
             response_bytes,
             decision,
             policy_hash,
             outcome,
             run_id: run_id,
             session_id: run_id,
             turn_id: run_id,
             payload_uri: payload_uri,
             secrets_provider: {secrets_mod, secrets_state},
             signer: ProviderRegistry.signer()
           ),
         {:ok, commit_result} <-
           commit_envelope(ledger_mod, ledger_state, envelope, commit_opts) do
      {:ok, commit_result}
    end
  end

  # Compute the same canonical payload bytes that `EnvelopeBuilder` hashes
  # internally. Determinism of JCS guarantees this handler's S3-put bytes
  # match the SHA-256 stamped into `payload_hash`. Mirrors the pipeline in
  # `EnvelopeBuilder.canonicalize_pair/2`.
  defp canonicalize_payload(request_bytes, response_bytes) do
    with {:ok, req_term} <- Jason.decode(request_bytes),
         {:ok, resp_term} <- Jason.decode(response_bytes) do
      combined_term = %{"request" => req_term, "response" => resp_term}
      {:ok, Jcs.encode(combined_term)}
    else
      {:error, reason} -> {:error, {:canonicalize_payload, reason}}
    end
  end

  # Internal run/session/turn IDs are UUIDs because the Postgres-Merkle
  # ledger's `attestations.run_id` / `sessions.session_id` / `attestations.turn_id`
  # columns are `:binary_id` (UUID) per `apps/recurse_providers/priv/repo/
  # migrations/20260423100000_f002_initial_schemas.exs`. Correlation IDs
  # stay ULIDs (the Gateway-observable identifier) — those live on a
  # `:string` column and are resolved by `IdentityContextBuilder`.
  defp new_run_id, do: Ecto.UUID.generate()

  # Two provider entry points: behaviour `commit_epoch/4` (narrow F001) or
  # rich public `commit_attestation/2` (F002). Per the task spec we use
  # the rich one; it accepts the Envelope directly.
  defp commit_envelope(Recurse.Providers.Impls.PostgresMerkleLedger = mod, _state, envelope, opts) do
    mod.commit_attestation(envelope, opts)
  end

  # Fallback for alternate Ledger impls (tests, future providers): call
  # the module's `commit_attestation/2` if exported, else fall back to
  # `commit_epoch/4` shape. Phase-1 only the Postgres impl exists; this
  # keeps the surface forward-compatible without special-casing tests.
  defp commit_envelope(mod, _state, envelope, opts) do
    if function_exported?(mod, :commit_attestation, 2) do
      mod.commit_attestation(envelope, opts)
    else
      {:error, {:ledger_provider_missing_commit_attestation, mod}}
    end
  end

  # ---------------------------------------------------------------------------
  # Error response helpers — OpenAI-shape protocol-native errors.
  # ---------------------------------------------------------------------------

  defp send_validation_error(conn, message) do
    body =
      JSON.encode!(%{
        "error" => %{
          "message" => message,
          "type" => "invalid_request_error",
          "code" => "invalid_request"
        }
      })

    conn
    |> Plug.Conn.put_resp_content_type("application/json")
    |> Plug.Conn.send_resp(400, body)
  end

  defp send_kms_unavailable(conn) do
    body =
      JSON.encode!(%{
        "error" => %{
          "message" => "Signing service unavailable (KMS). Please retry.",
          "type" => "api_error",
          "code" => "signing_unavailable"
        }
      })

    conn
    |> Plug.Conn.put_resp_content_type("application/json")
    |> Plug.Conn.send_resp(503, body)
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
  end

  defp send_upstream_timeout(conn) do
    body =
      JSON.encode!(%{
        "error" => %{
          "message" => "Upstream LLM provider timed out.",
          "type" => "api_error",
          "code" => "upstream_timeout"
        }
      })

    conn
    |> Plug.Conn.put_resp_content_type("application/json")
    |> Plug.Conn.send_resp(504, body)
  end

  defp send_service_unavailable(conn, reason) do
    body =
      JSON.encode!(%{
        "error" => %{
          "message" => "Gateway unavailable: #{reason}.",
          "type" => "api_error",
          "code" => "service_unavailable"
        }
      })

    conn
    |> Plug.Conn.put_resp_content_type("application/json")
    |> Plug.Conn.send_resp(503, body)
  end
end
