defmodule Recurse.Gateway.LlmProxy.StreamingProxy do
  @moduledoc """
  Governed HTTP proxy for supported provider response formats.

  The exact request is retained and admitted through the kernel before an
  upstream connection sends it. Parser-held tool intents are released only
  after their durable ToolCall admission allows them. The proxy does not run
  a separate Cedar decision; a local bundle snapshot supplies context only.

  The response parser fails closed on malformed, unsupported or incomplete
  executable output. Classified non-executable content streams incrementally.
  The chunk containing the provider's terminal event and any final parser
  output are held until Completion/LlmResponse admission succeeds. The outcome
  links the original opening and tool receipts without re-evaluation.

  Evidence capture is mandatory and bounded by the kernel CAS limit. Exceeding
  that bound suppresses subsequent output and records an interrupted response.
  Transport errors, parser errors and completion-recording failures cannot
  release a terminal success marker. Already-delivered admitted output cannot
  be retracted; failures are reported to the client and through telemetry.

  Provider HTTP errors retain their status and body. The optional enterprise
  audit UI remains a projection emitted after the authoritative admission path.
  """

  alias Recurse.Gateway.Fold.Admission
  alias Recurse.Gateway.LlmProxy.AttestationEmitter
  alias Recurse.Gateway.LlmProxy.BodyHasher
  alias Recurse.Gateway.LlmProxy.BypassDnsResolver
  alias Recurse.Gateway.LlmProxy.CedarToolUseGate
  alias Recurse.Gateway.LlmProxy.DenialInjector
  alias Recurse.Gateway.LlmProxy.HeaderFilter
  alias Recurse.Gateway.LlmProxy.ParserDrift
  alias Recurse.Gateway.LlmProxy.PayloadCapture
  alias Recurse.Gateway.LlmProxy.PrincipalExtractor
  alias Recurse.Gateway.LlmProxy.RequestKind
  alias Recurse.Providers.Schemas.LlmProviderConfig

  require Logger

  # The default denial template lives in `DenialInjector.Template.default/0`
  # (shared with `WebSocketBridge`); per-tenant override via
  # `LlmProviderConfig.metadata["denial_template"]`.

  @typedoc """
  Per-request immutable context derived from
  `UpstreamResolver.resolve/2` + the inbound conn.
  """
  @type proxy_opts :: %{
          required(:llm_provider_config) => LlmProviderConfig.t(),
          required(:tenant_id) => String.t(),
          optional(:parser_module) => module(),
          optional(:parser_init_opts) => keyword(),
          optional(:trace_id) => String.t()
        }

  @doc """
  Proxy an HTTPS+SSE request.

  Opens an outbound Mint conn to the resolved upstream (using
  `BypassDnsResolver.resolve/1` so corp-DNS-overridden hostnames
  reach the real provider), forwards the request, then streams the
  response back per-chunk through the chosen parser. Each
  `forward_directive` is emitted via `Plug.Conn.chunk/2` immediately —
  no buffering.

  Returns the (chunk-streamed) `Plug.Conn`.
  """
  @spec proxy(Plug.Conn.t(), proxy_opts()) :: Plug.Conn.t()
  def proxy(%Plug.Conn{} = conn, opts) do
    %LlmProviderConfig{} = cfg = Map.fetch!(opts, :llm_provider_config)
    tenant_id = Map.fetch!(opts, :tenant_id)
    parser_module = Map.get(opts, :parser_module) || parser_for_format(cfg.api_format)

    # Spec 012 S4 — the request's `anthropic-version` / `anthropic-beta`
    # name the wire format the parser is exhaustive for; they ride on the
    # attestation as `parser.format`.
    parser_init_opts =
      Keyword.merge(format_init_opts(conn.req_headers), Map.get(opts, :parser_init_opts, []))

    trace_id = Map.get(opts, :trace_id) || Recurse.Shared.Ulid.generate()

    upstream_host = cfg.upstream_host
    upstream_port = cfg.upstream_port || 443
    scheme = upstream_scheme(cfg)

    with {:ok, body, conn} <- safe_read_body(conn),
         request_params <- parse_request_params(body),
         # Sub-3.7-followon (US1 plumbing) — derive the principal BEFORE the
         # upstream request goes out so it lands on the gate context for
         # every per-intent Cedar evaluation. Decode-without-verify per
         # `PrincipalExtractor.@moduledoc`; spec 012 S4 adds the Claude Code
         # path (opaque OAuth bearer + `metadata.user_id`).
         principal <- principal_or_anonymous(conn.req_headers, request_params),
         gate_context_base <-
           build_gate_context_base(cfg, tenant_id, body, principal),
         {:admission, {:ok, admission}} <-
           {:admission,
            Admission.open(body, gate_context_base, %{
              trace_id: trace_id,
              provider: cfg.provider,
              upstream_host: cfg.upstream_host,
              transport: :https_sse,
              api_format: cfg.api_format,
              request_path: request_path_with_query(conn),
              client_session_id: client_session_id(conn.req_headers, request_params)
            })},
         fwd_headers <-
           HeaderFilter.forward_request_headers(
             conn.req_headers,
             %{trace_id: trace_id, tenant_id: tenant_id},
             # Spec 012 D3 — the inbound Host may be the gateway itself
             # (`localhost:4443`); the upstream must see its own name.
             upstream_host: upstream_host
           ),
         method <- String.upcase(conn.method),
         path <- request_path_with_query(conn),
         # Connect only once the request is read and shaped: every failure
         # after this point carries the live Mint conn in its error tuple
         # and the `else` branch closes it (a 503 must not leak a socket).
         {:ok, mint_conn} <-
           record_setup_failure(admission, fn ->
             open_upstream(scheme, upstream_host, upstream_port)
           end),
         {:ok, mint_conn, request_ref, early_responses} <-
           record_setup_failure(admission, fn ->
             send_request(mint_conn, method, path, fwd_headers, body || "")
           end) do
      parser_state = parser_module.init(parser_init_opts)

      # Sub-3.7-followon — initialise per-direction streaming SHA-256
      # hashers. Request body is read above as one binary (Plug owns
      # the full read); we feed it as a single update. Response body
      # is fed chunk-by-chunk in the receive loop (handle_chunk/2).
      request_body_hasher =
        BodyHasher.init() |> BodyHasher.update(body || "")

      response_body_hasher = BodyHasher.init()

      # Kernel evidence is mandatory; legacy payload-retention preferences
      # cannot disable the observations required by admission.
      request_capture = evidence_capture() |> PayloadCapture.append(body || "")
      response_capture = evidence_capture()

      state = %{
        plug_conn: conn,
        mint_conn: mint_conn,
        request_ref: request_ref,
        parser_module: parser_module,
        parser_state: parser_state,
        parser_failed?: false,
        # Whether the upstream answered `text/event-stream`, set at
        # response-head time. Only the shape of a gateway error envelope
        # depends on it (SSE framing or a bare JSON object); what gets
        # parsed does not.
        response_event_stream?: true,
        # Set at response-head time when the head alone settles that no
        # byte of the body can be classified — so the whole body is
        # withheld, not merely its unreadable remainder. Recorded on the
        # `LlmResponse`.
        body_withheld?: false,
        output_released?: false,
        admission_marker_failed?: false,
        headers_sent?: false,
        upstream_status: nil,
        upstream_response_headers: [],
        gate_context_base: admission.context,
        admission: admission,
        tool_receipts: [],
        admission_index: 0,
        gate_error_kind: nil,
        transport_error: nil,
        deferred_output: [],
        # Sub-3.5 — capture api_format + denial_template at call-open
        # so dispatch_directive can route deny decisions through
        # `DenialInjector.inject_denial/4` without re-loading config
        # mid-stream.
        api_format: cfg.api_format,
        denial_template: resolve_denial_template(cfg),
        # Sub-3.4 changes shape: was `[ToolUseIntent.t()]`; now
        # `[{ToolUseIntent.t(), CedarToolUseGate.decision()}]`. The
        # denial injector (Sub-3.5) + attestation emitter (Sub-3.7)
        # consume the per-intent decision tuple.
        intents_seen: [],
        # Sub-3.7 — captured at proxy-open for the attestation emitter
        # built in `finalize_and_return/1`. `tenant_id` + `cfg` are
        # already on `gate_context_base`; the additional fields are
        # call-stable metadata that the close-hook emit needs without
        # re-traversing config.
        tenant_id: tenant_id,
        llm_provider_config: cfg,
        request_path: path,
        started_at: gate_context_base.started_at,
        # Sub-3.7-followon — per-direction running hashes + the JWT-
        # extracted principal threaded through to attestation emit.
        principal: principal,
        request_body_hasher: request_body_hasher,
        response_body_hasher: response_body_hasher,
        request_capture: request_capture,
        response_capture: response_capture,
        # Captured in the parser's finalize/1 summary at close;
        # populated lazily so the close hook gets the latest values.
        parser_summary: %{},
        # Responses that arrived while the request body was still being
        # streamed (an early 4xx, or a WINDOW_UPDATE bundled with them);
        # replayed into the receive loop before the first socket message.
        early_responses: early_responses,
        # Spec 012 S2 — receipt classification (plan §9 D2) and the
        # client's own session id (`X-Claude-Code-Session-Id`, the same
        # value as `metadata.user_id.session_id`); both ride on the
        # `:llm_call_attested` predicate + receipt tags so the dashboard
        # can group leaves by session and default to `agent_turn`.
        kind: RequestKind.classify(request_params),
        client_session_id: client_session_id(conn.req_headers, request_params),
        # Fallback for `model` when the parser produced no summary (bypass
        # above, or no Cedar bundle so gate_context_base is empty).
        request_model: request_params["model"]
      }

      start_loop(state)
    else
      {:admission, _failure} ->
        send_503(conn, "admission_failed")

      {:error, %Mint.TransportError{reason: reason}} ->
        Logger.warning(fn ->
          "streaming_proxy: upstream connect failed host=#{upstream_host} reason=#{inspect(reason)}"
        end)

        send_503(conn, "upstream_connection_failed")

      {:error, mint_conn, reason} ->
        # Request or body send failed after the connect succeeded
        # (HTTP/2 WINDOW_UPDATE timeout, RST_STREAM, socket error).
        _ = Mint.HTTP.close(mint_conn)

        Logger.warning(fn ->
          "streaming_proxy: request send failed host=#{upstream_host} reason=#{inspect(reason)}"
        end)

        # The only place request headers are ever logged, and only in
        # their redacted shape (`HeaderFilter.redact_headers/1`): the
        # bearer / x-api-key never reaches a log line.
        Logger.debug(fn ->
          "streaming_proxy: request headers (redacted) host=#{upstream_host} " <>
            "headers=#{inspect(HeaderFilter.redact_headers(conn.req_headers))}"
        end)

        send_503(conn, "upstream_connection_failed")

      {:error, reason} ->
        Logger.warning(fn ->
          "streaming_proxy: setup failed host=#{upstream_host} reason=#{inspect(reason)}"
        end)

        send_503(conn, "upstream_connection_failed")
    end
  end

  # Connecting and windowed request sends happen after the opening admission
  # but before response-loop state exists. Preserve that opening on returned
  # errors so its interruption can be admitted without inventing response bytes.
  # The caller still closes any live socket and returns 503 if this write fails.
  defp record_setup_failure(admission, operation) do
    case operation.() do
      error when is_tuple(error) and elem(error, 0) == :error ->
        case Admission.complete(
               admission,
               %{
                 error_kind: "upstream_connection_failed",
                 response_payload: {:error, :response_not_observed},
                 completed_at: DateTime.utc_now()
               },
               []
             ) do
          {:ok, _receipt} ->
            :ok

          failure ->
            Logger.error("streaming_proxy: could not record interrupted upstream setup")

            :telemetry.execute(
              [:recurse, :llm_proxy, :admission, :completion_failed],
              %{count: 1},
              %{reason: failure}
            )
        end

        error

      result ->
        result
    end
  end

  # --------------------------------------------------------------------------
  # Request send — HTTP/1 whole body; HTTP/2 streamed against the window
  # --------------------------------------------------------------------------

  # Returns `{:ok, conn, request_ref, early_responses}` once the request
  # (headers, body, EOF) is on the wire.
  #
  # HTTP/1 hands Mint the body as one binary, exactly as before spec 012
  # S2. (`:stream` + `:eof` would make Mint add `transfer-encoding:
  # chunked` to a bodiless GET, which some upstreams reject.)
  #
  # HTTP/2 (spec 012 S2) streams `min(connection window, stream window)`
  # bytes at a time and, when the window is exhausted, blocks on the
  # socket for the WINDOW_UPDATE; any response frames that arrive
  # meanwhile (an early 4xx) are collected and replayed by `start_loop/1`.
  # A Claude Code agent turn is ~156 KB; the h2 initial window is 65,535
  # bytes and `Mint.HTTP.request/5` with a full body fails with
  # `{:exceeds_window_size, :request, 65535}`. Codex bodies were always
  # smaller, so this never fired before. Mint splits each chunk into
  # `max_frame_size` frames itself.
  @window_update_timeout_ms 30_000

  # The socket-message tags Mint's transports deliver to the owning
  # process; everything else in the mailbox belongs to someone else.
  @socket_tags_with_payload [:tcp, :ssl, :tcp_error, :ssl_error]
  @socket_tags_closed [:tcp_closed, :ssl_closed]

  defp send_request(%Mint.HTTP2{} = conn, method, path, headers, body) do
    # Mint derives :authority from the upstream connection, including a
    # non-default port. A second Host field without that port contradicts
    # :authority and conforming HTTP/2 servers reset the stream (RFC9113 §8.3.1).
    headers = Enum.reject(headers, fn {name, _} -> String.downcase(name, :ascii) == "host" end)

    with {:ok, conn, ref} <- Mint.HTTP.request(conn, method, path, headers, :stream),
         {:ok, conn, early} <- send_windowed(conn, ref, body, []) do
      {:ok, conn, ref, early}
    end
  end

  defp send_request(conn, method, path, headers, body) do
    case Mint.HTTP.request(conn, method, path, headers, body) do
      {:ok, conn, ref} -> {:ok, conn, ref, []}
      {:error, conn, reason} -> {:error, conn, reason}
    end
  end

  defp send_windowed(conn, ref, "", early) do
    case Mint.HTTP.stream_request_body(conn, ref, :eof) do
      {:ok, conn} -> {:ok, conn, early}
      {:error, conn, reason} -> {:error, conn, reason}
    end
  end

  defp send_windowed(conn, ref, body, early) do
    window =
      min(
        Mint.HTTP2.get_window_size(conn, :connection),
        Mint.HTTP2.get_window_size(conn, {:request, ref})
      )

    if window <= 0 do
      await_window_update(conn, ref, body, early)
    else
      size = min(window, byte_size(body))
      <<chunk::binary-size(size), rest::binary>> = body

      case Mint.HTTP.stream_request_body(conn, ref, chunk) do
        {:ok, conn} -> send_windowed(conn, ref, rest, early)
        {:error, conn, reason} -> {:error, conn, reason}
      end
    end
  end

  defp await_window_update(conn, ref, body, early) do
    socket = Mint.HTTP.get_socket(conn)

    receive do
      {tag, ^socket, _} = message when tag in @socket_tags_with_payload ->
        handle_window_message(conn, ref, body, early, message)

      {tag, ^socket} = message when tag in @socket_tags_closed ->
        handle_window_message(conn, ref, body, early, message)
    after
      window_update_timeout_ms() ->
        {:error, conn, :window_update_timeout}
    end
  end

  defp handle_window_message(conn, ref, body, early, message) do
    case Mint.HTTP.stream(conn, message) do
      {:ok, conn, responses} ->
        if Enum.any?(responses, &request_ended?(&1, ref)) do
          # Upstream answered (or reset the stream) before we finished
          # sending: stop sending, let the receive loop render what
          # came back.
          {:ok, conn, early ++ responses}
        else
          send_windowed(conn, ref, body, early ++ responses)
        end

      {:error, conn, reason, _responses} ->
        {:error, conn, reason}

      :unknown ->
        await_window_update(conn, ref, body, early)
    end
  end

  # Test seam only: the default is the production timeout.
  defp window_update_timeout_ms do
    Application.get_env(
      :recurse_gateway,
      :llm_proxy_window_update_timeout_ms,
      @window_update_timeout_ms
    )
  end

  defp request_ended?({:done, ref}, ref), do: true
  defp request_ended?({:error, ref, _}, ref), do: true
  defp request_ended?(_, _), do: false

  # Replay any responses collected during the body send, then enter the
  # socket receive loop.
  defp start_loop(%{early_responses: []} = state), do: run_loop(state)

  defp start_loop(%{early_responses: early} = state) do
    case process_responses(early, %{state | early_responses: []}) do
      {:halt, state} ->
        _ = Mint.HTTP.close(state.mint_conn)
        finalize_and_return(state)

      {:cont, state} ->
        run_loop(state)
    end
  end

  # --------------------------------------------------------------------------
  # Receive loop — per-chunk forward through parser.
  # --------------------------------------------------------------------------

  # Only the Mint socket's own messages are taken out of the mailbox;
  # anything else (Bandit's h2 flow-control notices, a test's
  # `send/2`) is left where it is. See the moduledoc.
  defp run_loop(state) do
    socket = Mint.HTTP.get_socket(state.mint_conn)

    receive do
      {tag, ^socket, _} = message when tag in @socket_tags_with_payload ->
        handle_socket_message(state, message)

      {tag, ^socket} = message when tag in @socket_tags_closed ->
        handle_socket_message(state, message)
    after
      300_000 ->
        # 5-min idle timeout — long-lived streams expected per spec
        # but no-data-for-5-min is a stuck connection.
        _ = Mint.HTTP.close(state.mint_conn)
        finalize_and_return(%{state | transport_error: "upstream_timeout"})
    end
  end

  defp handle_socket_message(state, message) do
    case Mint.HTTP.stream(state.mint_conn, message) do
      {:ok, mint_conn, responses} ->
        state = %{state | mint_conn: mint_conn}

        case process_responses(responses, state) do
          {:halt, state} ->
            _ = Mint.HTTP.close(state.mint_conn)
            finalize_and_return(state)

          {:cont, state} ->
            run_loop(state)
        end

      {:error, mint_conn, _reason, _responses} ->
        state = %{state | mint_conn: mint_conn, transport_error: "upstream_stream_error"}
        _ = Mint.HTTP.close(state.mint_conn)
        finalize_and_return(state)

      :unknown ->
        run_loop(state)
    end
  end

  defp process_responses(responses, state) do
    Enum.reduce_while(responses, {:cont, state}, fn
      {:status, ref, status}, {:cont, st} when ref == st.request_ref ->
        {:cont, {:cont, %{st | upstream_status: status}}}

      {:headers, ref, headers}, {:cont, st} when ref == st.request_ref ->
        st = send_response_head(st, headers)
        {:cont, {:cont, st}}

      {:data, ref, data}, {:cont, st} when ref == st.request_ref ->
        st = handle_chunk(st, data)
        {:cont, {:cont, st}}

      {:done, ref}, {:cont, st} when ref == st.request_ref ->
        {:halt, {:halt, st}}

      {:error, ref, _reason}, {:cont, st} when ref == st.request_ref ->
        {:halt, {:halt, %{st | transport_error: "upstream_stream_error"}}}

      _other, acc ->
        {:cont, acc}
    end)
  end

  # B3 (RC review 2026-09-05): the parser runs whatever the status is.
  # This branch used to set `parser_bypass?` on status >= 400 and write
  # every later byte straight to the client: a 429 or 500 body carrying a
  # `function_call` frame reached the client byte-for-byte with zero
  # `ToolCall` admissions (demonstrated). The gateway was letting an
  # upstream-controlled integer decide whether to enforce at all, which is
  # exactly the class R4 enumerates against. The rule now is the same rule
  # for every status: parse and gate what the parser can classify, and
  # suppress what it cannot — a body nothing could read is not a body
  # anything may forward.
  defp send_response_head(state, headers) do
    fwd_headers = HeaderFilter.forward_response_headers(headers)

    unreadable? = not event_stream?(headers) and not json_capable?(state.parser_module)

    state = %{
      state
      | parser_failed?: state.parser_failed? or unreadable?,
        body_withheld?: unreadable?,
        response_event_stream?: event_stream?(headers),
        upstream_response_headers: headers
    }

    plug_conn =
      Enum.reduce(fwd_headers, state.plug_conn, fn {name, value}, acc ->
        Plug.Conn.put_resp_header(acc, name, value)
      end)

    plug_conn = Plug.Conn.send_chunked(plug_conn, state.upstream_status || 200)

    %{state | plug_conn: plug_conn, headers_sent?: true}
  end

  # `true` when the upstream response is SSE (`text/event-stream`). A
  # missing content-type is treated as SSE so the parser still sees
  # streams from upstreams that omit it (the pre-S2 behaviour).
  defp event_stream?(headers) do
    case Enum.find(headers, fn {name, _} -> String.downcase(name, :ascii) == "content-type" end) do
      {_, value} -> value |> String.downcase(:ascii) |> String.starts_with?("text/event-stream")
      nil -> true
    end
  end

  # Spec 012 S4 — parsers that understand a whole JSON body (Claude Code's
  # non-streaming `side_query`, error bodies) opt out of the bypass.
  defp json_capable?(parser_module) do
    function_exported?(parser_module, :accepts_json_body?, 0) and
      parser_module.accepts_json_body?() == true
  end

  # Spec 012 S4 — request headers that name the wire-format version the
  # parser is exhaustive for (`parser.format` on the attestation).
  defp format_init_opts(headers) do
    Enum.reduce(headers, [], fn {name, value}, acc ->
      case String.downcase(name, :ascii) do
        "anthropic-version" -> Keyword.put(acc, :anthropic_version, value)
        "anthropic-beta" -> Keyword.put(acc, :anthropic_beta, value)
        _ -> acc
      end
    end)
  end

  # A parser failure suppresses the undecidable bytes and the remainder.
  # Already approved bytes remain part of the observed partial response.
  defp handle_chunk(state, data) do
    # Sub-3.7-followon — feed every upstream byte through the response
    # hasher BEFORE we make any forwarding decisions. The hash MUST
    # cover the bytes upstream actually sent (Constitution Principle
    # III), independent of any synthetic-event injection downstream.
    # Synthetic denial events are NOT part of the upstream's response
    # for hash purposes — they're proxy-injected.
    state = %{
      state
      | response_body_hasher: BodyHasher.update(state.response_body_hasher, data),
        response_capture: PayloadCapture.append(state.response_capture, data)
    }

    cond do
      not state.headers_sent? ->
        # Status arrived but headers not yet sent — buffer just
        # enough to call send_chunked. In practice Mint emits
        # status+headers together; this is defensive.
        plug_conn = Plug.Conn.send_chunked(state.plug_conn, state.upstream_status || 200)

        state = %{state | plug_conn: plug_conn, headers_sent?: true}
        handle_chunk_inner(state, data)

      state.response_capture.truncated? ->
        %{state | parser_failed?: true}

      state.parser_failed? ->
        # Unclassified bytes are never forwarded, whatever the status was.
        state

      true ->
        invoke_parser(state, data)
    end
  end

  # The pre-headers branch of handle_chunk/2 needs to recurse without
  # double-hashing the same chunk (the outer call already updated the
  # response hasher). This inner helper bypasses the hash update.
  defp handle_chunk_inner(state, data) do
    cond do
      state.response_capture.truncated? -> %{state | parser_failed?: true}
      state.parser_failed? -> state
      true -> invoke_parser(state, data)
    end
  end

  defp invoke_parser(state, data) do
    case safe_parse_chunk(state, data) do
      {:ok, parser_state, intents, directives} ->
        walk_directives(state, parser_state, intents, directives)

      :failed ->
        # No parser verdict means no executable bytes may be released.
        %{state | parser_failed?: true}
    end
  end

  defp safe_parse_chunk(state, data) do
    {parser_state, intents, directives} =
      state.parser_module.parse_chunk(state.parser_state, data)

    {:ok, parser_state, intents, directives}
  rescue
    e ->
      Logger.warning(fn ->
        "streaming_proxy: parser raised (fail-CLOSED); module=#{inspect(state.parser_module)} " <>
          "error=#{inspect(e)}"
      end)

      :failed
  end

  defp walk_directives(state, parser_state, intents, directives) do
    # Phase 6 byte-precise suppression: the parser emits a
    # `{:cedar_eval, call_id}` marker at the exact stream position
    # where each `ToolUseIntent` fired. We walk directives in order;
    # at the marker we synchronously evaluate Cedar, call
    # `apply_verdict/3` on the parser to drain its held byte buffer,
    # and dispatch the resulting forward/suppress directives INLINE —
    # so the held bytes either reach the client at the right stream
    # position (allow) or NEVER reach the client at all (deny). The
    # synthetic denial events are injected immediately after the
    # suppressed bytes so codex sees a coherent assistant turn.
    intent_by_call_id = Map.new(intents, fn intent -> {intent.call_id, intent} end)

    initial_acc = %{
      plug_conn: state.plug_conn,
      output_released?: state.output_released?,
      admission_marker_failed?: state.admission_marker_failed?,
      deferred_output: state.deferred_output,
      hold_output?: completion_seen?(state.parser_module, parser_state),
      parser_state: parser_state,
      intent_decisions: [],
      tool_receipts: [],
      admission_index: state.admission_index,
      gate_error_kind: nil,
      parser_failed?: false
    }

    final_acc =
      Enum.reduce_while(directives, initial_acc, fn directive, acc ->
        dispatch_directive(directive, acc, state, intent_by_call_id)
      end)

    # A gate error is recorded (first one wins) for the receipt's
    # `error_kind`; the intent itself was already suppressed in
    # `process_cedar_eval/3`, so the stream continues to a clean end.
    %{
      state
      | gate_error_kind: state.gate_error_kind || final_acc.gate_error_kind,
        parser_failed?: state.parser_failed? or final_acc.parser_failed?,
        parser_state: final_acc.parser_state,
        plug_conn: final_acc.plug_conn,
        output_released?: final_acc.output_released?,
        admission_marker_failed?: final_acc.admission_marker_failed?,
        deferred_output: final_acc.deferred_output,
        intents_seen: state.intents_seen ++ final_acc.intent_decisions,
        tool_receipts: state.tool_receipts ++ final_acc.tool_receipts,
        admission_index: final_acc.admission_index
    }
  end

  # Per-directive dispatch, threaded through the per-chunk reduce_while.
  # Returns `{:cont, acc}` to continue or `{:halt, acc}` to short-circuit
  # (fail-CLOSED on Cedar evaluation error).
  defp dispatch_directive({:parser_error, _reason}, acc, _state, _intent_by_call_id),
    do: {:halt, %{acc | parser_failed?: true}}

  defp dispatch_directive({:forward, bytes}, acc, _state, _intent_by_call_id) do
    {:cont, forward_output(acc, bytes)}
  end

  defp dispatch_directive({:suppress, _bytes}, acc, _state, _intent_by_call_id) do
    # Bytes are explicitly dropped from the client stream. This is the
    # path that PREVENTS local execution of denied tool calls — the
    # original function_call frames never reach codex.
    {:cont, acc}
  end

  defp dispatch_directive(:flush_pending, acc, _state, _intent_by_call_id) do
    {:cont, acc}
  end

  defp dispatch_directive({:cedar_eval, call_id}, acc, state, intent_by_call_id) do
    case Map.fetch(intent_by_call_id, call_id) do
      {:ok, intent} ->
        process_cedar_eval(intent, acc, state)

      :error ->
        # This marker identifies an admission gap, not an unclassified body.
        {:halt, %{acc | parser_failed?: true, admission_marker_failed?: true}}
    end
  end

  # Run Cedar evaluation for one intent at the marker position; call
  # apply_verdict on the parser to drain held bytes; dispatch them; then
  # if denied (or undecidable), inject synthetic denial frames.
  defp process_cedar_eval(intent, acc, state) do
    decision = evaluate_intent(state, intent, acc.admission_index)
    acc = %{acc | admission_index: acc.admission_index + 1}

    case decision do
      {:error, reason} ->
        Logger.warning(fn ->
          "streaming_proxy: cedar gate ERROR (fail-CLOSED: held frames suppressed) " <>
            "tool=#{inspect(intent.tool_name)} reason=#{inspect(reason)}"
        end)

        # Admission could not establish a policy decision. Stop this stream;
        # parser_failed? prevents EOF finalization from releasing held bytes.
        # Keep the admission cause distinct from an ordinary policy denial.
        {:halt,
         %{
           acc
           | gate_error_kind: acc.gate_error_kind || reason,
             parser_failed?: true,
             intent_decisions: acc.intent_decisions ++ [{intent, {:error, reason}}]
         }}

      {:ok, {:allow}, receipt} ->
        acc = %{acc | tool_receipts: acc.tool_receipts ++ [receipt]}

        {parser_state, drained} =
          apply_parser_verdict(state.parser_module, acc.parser_state, intent.call_id, :allow, [])

        acc = dispatch_drained(drained, acc)

        {:cont,
         %{
           acc
           | parser_state: parser_state,
             intent_decisions: acc.intent_decisions ++ [{intent, {:allow}}]
         }}

      {:ok, {:deny, deny_payload}, receipt} ->
        acc = %{acc | tool_receipts: acc.tool_receipts ++ [receipt]}

        Logger.warning(fn ->
          "streaming_proxy: cedar gate DENY (Phase 6 byte-suppression) " <>
            "tool=#{inspect(intent.tool_name)} rule=#{inspect(deny_payload.rule_id)}"
        end)

        acc = suppress_and_inject(intent, deny_payload, acc, state)

        {:cont,
         %{acc | intent_decisions: acc.intent_decisions ++ [{intent, {:deny, deny_payload}}]}}
    end
  end

  # Drain the intent's held frames as `:suppress` and inject the denial
  # frames at the parser's placement. Returns `acc` with the updated
  # `plug_conn` + `parser_state`.
  defp suppress_and_inject(intent, deny_payload, acc, state) do
    audit_ctx = audit_context_for_denial(state)

    # Render the denial text once: the parser gets it (JSON mode
    # rewrites the body itself), the synthetic frames carry it, and
    # the receipt's deny_reason stays the Cedar reason.
    denial_text =
      DenialInjector.render_text(
        state.api_format,
        intent,
        deny_payload,
        state.denial_template,
        audit_context: audit_ctx
      )

    {parser_state, drained} =
      apply_parser_verdict(state.parser_module, acc.parser_state, intent.call_id, :deny,
        denial_text: denial_text
      )

    # Spec 012 S4 — the parser may name the suppressed block's index
    # so the replacement block reuses it (`denial_opts/2`).
    denial_opts = parser_denial_opts(state.parser_module, acc.parser_state, intent.call_id)

    frames =
      state.api_format
      |> DenialInjector.inject_denial(
        intent,
        deny_payload,
        state.denial_template,
        [audit_context: audit_ctx, denial_text: denial_text] ++ denial_opts
      )
      |> Enum.map(&DenialInjector.sse_frame(state.api_format, &1))

    # Drained directives are `{:suppress, _}` for the held tool-use
    # frames (they NEVER reach the client), possibly followed by a
    # `:flush_pending` marker at the exact position where the
    # replacement belongs, then any frames the parser queued behind
    # the verdict (`message_delta`, `message_stop`). Parsers that
    # implement `apply_verdict/4` own that placement; legacy
    # `apply_verdict/3` parsers (OpenaiResponses) get the injection
    # appended after the drain, as before.
    {acc, injected?} = dispatch_drained_with_injection(drained, acc, frames)

    acc =
      if injected? or owns_injection_placement?(state.parser_module),
        do: acc,
        else: Enum.reduce(frames, acc, &forward_output(&2, &1))

    %{acc | parser_state: parser_state}
  end

  # A missing policy can never release executable tool bytes.
  defp evaluate_intent(state, intent, index) do
    ctx =
      CedarToolUseGate.gate_context_for_intent(state.gate_context_base, intent)
      |> Map.put(:admission_index, index)
      |> Map.put(:response_so_far_hash, BodyHasher.final(state.response_body_hasher))

    Admission.admit_tool(state.admission, intent, ctx)
  end

  defp dispatch_drained(directives, acc) do
    Enum.reduce(directives, acc, fn
      {:forward, b}, c -> forward_output(c, b)
      {:suppress, _}, c -> c
      _, c -> c
    end)
  end

  # Walk the drained directives; at `:flush_pending` write the synthetic
  # frames. Returns whether an injection point was seen.
  defp dispatch_drained_with_injection(directives, acc, frames) do
    Enum.reduce(directives, {acc, false}, fn
      {:forward, b}, {c, injected?} -> {forward_output(c, b), injected?}
      {:suppress, _}, acc -> acc
      :flush_pending, {c, _} -> {Enum.reduce(frames, c, &forward_output(&2, &1)), true}
      _, acc -> acc
    end)
  end

  defp apply_parser_verdict(parser_module, parser_state, call_id, decision, opts) do
    if function_exported?(parser_module, :apply_verdict, 4) do
      parser_module.apply_verdict(parser_state, call_id, decision, opts)
    else
      parser_module.apply_verdict(parser_state, call_id, decision)
    end
  end

  defp owns_injection_placement?(parser_module),
    do: function_exported?(parser_module, :apply_verdict, 4)

  defp parser_denial_opts(parser_module, parser_state, call_id) do
    if function_exported?(parser_module, :denial_opts, 2) do
      parser_module.denial_opts(parser_state, call_id)
    else
      []
    end
  end

  # Build the audit-context map threaded into the denial injector.
  # Every field is OPTIONAL — the template is no-op-degradant on missing
  # fields. Caller provides what's available at the moment Cedar fired.
  #
  # Per-tenant `appeal_uri` and `appeal_contact` are read from
  # `LlmProviderConfig.metadata` (R5E-104) — same precedent as
  # `denial_template`. When both are nil the default template renders no
  # appeal line at all (`{? ... }` around `{appeal_pointer}`); when either
  # is set, the line renders with whatever fields are present.
  defp audit_context_for_denial(state) do
    base = state.gate_context_base || %{}
    principal = Map.get(base, :principal, %{})
    metadata = (state.llm_provider_config || %{}) |> Map.get(:metadata, %{}) || %{}

    %{
      tenant_id: state.tenant_id,
      principal_id: Map.get(principal, :id),
      principal_kind: principal_kind_to_string(Map.get(principal, :kind)),
      session_id: Map.get(base, :session_id),
      cedar_bundle_hash: Map.get(base, :cedar_bundle_hash),
      appeal_uri: nonempty_string(Map.get(metadata, "appeal_uri")),
      appeal_contact: nonempty_string(Map.get(metadata, "appeal_contact")),
      # R5E-105 follow-on: derived from R5E_CEDAR_BUNDLE_REGISTRY +
      # _REPOSITORY + _REF env vars (smallest of the three follow-ons).
      policy_source_uri: nil
    }
  end

  # Treat empty strings as nil so the template's optional-clause
  # grammar (`{? ... }`) drops the appeal line cleanly when a tenant
  # has the metadata key but with an empty value.
  defp nonempty_string(s) when is_binary(s) and s != "", do: s
  defp nonempty_string(_), do: nil

  # Resolve the denial template: per-tenant override in
  # `LlmProviderConfig.metadata["denial_template"]` if a non-empty
  # string; else the default template.
  defp resolve_denial_template(%LlmProviderConfig{metadata: %{"denial_template" => tmpl}})
       when is_binary(tmpl) and tmpl != "",
       do: tmpl

  defp resolve_denial_template(_cfg), do: DenialInjector.Template.default()

  defp chunk_or_keep(plug_conn, bytes) do
    case Plug.Conn.chunk(plug_conn, bytes) do
      {:ok, plug_conn} -> plug_conn
      {:error, _reason} -> plug_conn
    end
  end

  defp finalize_and_return(state) do
    {summary, final_directives} = finalize_parser(state)

    # Spec 012 S2 — flush whatever the parser was still holding at
    # upstream EOF. An SSE parser buffers bytes until it sees an event
    # boundary (`\n\n`); a NON-streaming response (Claude Code's
    # `side_query`, `stream: false` anywhere) never contains one, so the
    # entire JSON body sat in the parser and was dropped here — the client
    # got a 200 with an empty body. `finalize/1` returns the trailing bytes
    # as forward directives (Parser contract); dispatch them exactly like
    # `apply_verdict/3` output.
    unsafe_final? =
      Map.get(summary, :finalization_failed?, false) or
        Enum.any?(final_directives, fn
          {:parser_error, _} -> true
          {:cedar_eval, _} -> true
          _ -> false
        end)

    admission_marker_failed? =
      state.admission_marker_failed? or
        Enum.any?(final_directives, &match?({:cedar_eval, _}, &1))

    missing_terminal? = summary[:completion_seen?] != true
    state = %{state | parser_failed?: state.parser_failed? or unsafe_final? or missing_terminal?}

    # Media-type support alone cannot tell whether parsing will succeed.
    # Record full withholding after EOF too, but never relabel a released
    # prefix (or an admission failure) as an unclassified whole body.
    state = %{state | body_withheld?: fully_withheld?(state, admission_marker_failed?)}

    state =
      if state.parser_failed?,
        do: state,
        else: flush_final_directives(state, final_directives)

    # Sub-3.7-followon — capture parser summary on state so build_call_state
    # can read model + token counts from it.
    state = %{state | parser_summary: summary}

    # Commit the observed outcome before releasing held terminal output.
    completion =
      Admission.complete(state.admission, build_call_state(state, summary), state.tool_receipts)

    state = release_terminal(state, completion)

    safe_emit_attestation(state, summary)

    # Spec 012 S4 — parser drift is a product surface (plan §10): every
    # type the parser could not classify is upserted into the drift
    # store after the receipt is written. Never raises, never blocks.
    safe_record_drift(state, summary)

    # A reset can arrive before any response head, including while sending
    # a windowed request. Record the interruption above, then return an
    # actual HTTP failure instead of handing the server an unsent connection.
    if state.headers_sent?,
      do: state.plug_conn,
      else: send_503(state.plug_conn, "upstream_connection_failed")
  end

  defp fully_withheld?(state, admission_marker_failed?) do
    state.body_withheld? or
      (state.parser_failed? and not state.output_released? and
         not admission_marker_failed? and state.intents_seen == [] and
         is_nil(state.gate_error_kind) and is_nil(state.transport_error))
  end

  defp finalize_parser(state) do
    if state.parser_failed? do
      {failure_summary(state), []}
    else
      try do
        state.parser_module.finalize(state.parser_state)
      rescue
        _e -> {%{finalization_failed?: true}, []}
      catch
        _, _ -> {%{finalization_failed?: true}, []}
      end
    end
  end

  defp release_terminal(state, completion) do
    case completion do
      {:ok, _receipt}
      when not state.parser_failed? and is_nil(state.transport_error) and
             is_nil(state.gate_error_kind) ->
        conn =
          Enum.reduce(
            Enum.reverse(state.deferred_output),
            state.plug_conn,
            &chunk_or_keep(&2, &1)
          )

        %{state | plug_conn: conn, deferred_output: []}

      failure ->
        if match?({:error, _}, failure) do
          Logger.error("streaming_proxy: completion admission failed #{inspect(failure)}")

          :telemetry.execute(
            [:recurse, :llm_proxy, :admission, :completion_failed],
            %{count: 1},
            %{reason: failure}
          )
        end

        # No terminal success marker is released after an interruption.
        # Prior admitted output cannot be retracted; this reports the gap.
        conn =
          if append_error_envelope?(state),
            do: chunk_or_keep(state.plug_conn, gateway_error_envelope(state)),
            else: state.plug_conn

        %{state | plug_conn: conn, deferred_output: []}
    end
  end

  # What a client is told when the response could not be completed with
  # admitted evidence. Two cases, one shape.
  #
  # B3 (RC review 2026-09-05): when the upstream answered non-2xx and the
  # parser could not classify the body, the bytes are withheld and this
  # envelope carries the two facts the client needs to act and an auditor
  # needs to line the receipt up with the wire — the upstream's status,
  # and the sha256 of the bytes this gateway actually received. The hash
  # is over the upstream's own bytes (`response_body_hasher` is fed before
  # any forwarding decision), so the withheld body remains identifiable
  # against the `LlmResponse` recorded for the same call.
  #
  # The framing follows the response's own content type: SSE when the
  # upstream said `text/event-stream`, a bare JSON object otherwise. The
  # status line and headers were already sent, so the envelope cannot
  # change them; it explains the body that does not follow.
  # An SSE stream takes an `event: error` frame cleanly, and so does a
  # response whose body was withheld in full (there is nothing to corrupt).
  # A non-SSE response that already carried its bytes does not: appending a
  # second JSON object to a JSON body would hand the client something no
  # parser can read. The failure is on the chain either way.
  defp append_error_envelope?(state) do
    state.headers_sent? and (state.response_event_stream? or state.body_withheld?)
  end

  defp gateway_error_envelope(state) do
    status = state.upstream_status || 0

    error =
      if state.body_withheld? do
        %{
          "type" => "gateway_upstream_unclassified",
          "message" =>
            "The upstream answered #{status} with a body this gateway could not classify " <>
              "(#{content_type_or_unknown(state)}). The body was withheld: unclassified " <>
              "bytes carry no admitted tool intent, so they are not released to the client.",
          "upstream_status" => status,
          "response_sha256" =>
            Base.encode16(BodyHasher.final(state.response_body_hasher), case: :lower)
        }
      else
        %{
          "type" => "gateway_interrupted",
          "message" => "Response could not be completed with admitted evidence",
          "upstream_status" => status,
          "response_sha256" =>
            Base.encode16(BodyHasher.final(state.response_body_hasher), case: :lower)
        }
      end

    body = JSON.encode!(%{"type" => "error", "error" => error})

    if state.response_event_stream?,
      do: "event: error\ndata: " <> body <> "\n\n",
      else: body
  end

  defp content_type_or_unknown(state) do
    Enum.find_value(state.upstream_response_headers, "no content-type", fn {name, value} ->
      if String.downcase(name, :ascii) == "content-type", do: value
    end)
  end

  defp failure_summary(state) do
    if function_exported?(state.parser_module, :current_summary, 1),
      do: state.parser_module.current_summary(state.parser_state),
      else: %{}
  rescue
    _ -> %{}
  catch
    _, _ -> %{}
  end

  defp safe_record_drift(state, summary) do
    if Map.get(summary, :events_unhandled, 0) > 0 do
      ParserDrift.record_summary(state.tenant_id, state.api_format, summary)
    end

    :ok
  rescue
    error ->
      Logger.warning(fn -> "streaming_proxy: parser drift record raised #{inspect(error)}" end)
      :ok
  end

  defp flush_final_directives(state, directives) do
    deferred =
      Enum.reduce(directives, state.deferred_output, fn
        {:forward, bytes}, acc -> [bytes | acc]
        _, acc -> acc
      end)

    %{state | deferred_output: deferred}
  end

  defp forward_output(%{hold_output?: true} = acc, bytes),
    do: %{acc | deferred_output: [bytes | acc.deferred_output]}

  defp forward_output(acc, bytes) do
    case Plug.Conn.chunk(acc.plug_conn, bytes) do
      {:ok, conn} ->
        %{
          acc
          | plug_conn: conn,
            output_released?: acc.output_released? or IO.iodata_length(bytes) > 0
        }

      {:error, _reason} ->
        acc
    end
  end

  defp completion_seen?(parser_module, parser_state) do
    function_exported?(parser_module, :current_summary, 1) and
      parser_module.current_summary(parser_state)[:completion_seen?] == true
  end

  # Defensive emitter wrapping. ProviderRegistry may not be installed
  # (unit tests that exercise the proxy without the full provider stack);
  # we treat that case as "no audit substrate available" rather than a
  # request-blocking error. Production deployments always install the
  # registry — Recurse.Gateway.Application boots it before
  # Recurse.Gateway.Endpoint accepts requests.
  defp safe_emit_attestation(state, summary) do
    case maybe_build_call_state(state, summary) do
      {:ok, call_state} ->
        emit_legacy_attestation(call_state)

      :skip ->
        # ProviderRegistry not installed (dev/local-only path). The
        # caller has wired the proxy + Cedar but not the LedgerProvider /
        # SecretsProvider / StorageProvider trio that
        # `AttestationEmitter` needs to sign + persist. Log at info so
        # the live-demo BEAM window surfaces this clearly without
        # spamming production logs (production always installs the
        # registry; this branch never fires).
        Logger.info(fn ->
          "streaming_proxy: ProviderRegistry not installed; skipping attestation emit " <>
            "(set R5E_PROVIDER_LEDGER_IMPL+ for persisted rows)"
        end)

        :telemetry.execute(
          [:recurse, :llm_proxy, :attestation, :emit_skipped],
          %{count: 1},
          %{reason: :provider_registry_not_installed, transport: :https_sse}
        )

        :ok
    end
  rescue
    error ->
      Logger.error(fn ->
        "streaming_proxy: attestation emit raised #{inspect(error)}"
      end)

      :telemetry.execute(
        [:recurse, :llm_proxy, :attestation, :emit_failed],
        %{count: 1},
        %{reason: {:raised, error}, transport: :https_sse}
      )

      :error
  end

  defp emit_legacy_attestation(call_state) do
    case AttestationEmitter.emit_call_attestation(call_state) do
      {:ok, _run_id} ->
        :ok

      {:error, reason} ->
        Logger.error(fn ->
          "streaming_proxy: attestation emit failed reason=#{inspect(reason)}"
        end)

        :telemetry.execute(
          [:recurse, :llm_proxy, :attestation, :emit_failed],
          %{count: 1},
          %{reason: reason, transport: :https_sse}
        )

        :error
    end
  end

  defp maybe_build_call_state(state, summary) do
    case Recurse.Gateway.ProviderRegistry.fetch() do
      {:ok, _registry} -> {:ok, build_call_state(state, summary)}
      {:error, :not_installed} -> :skip
    end
  end

  # Build the `AttestationEmitter.call_state()` payload from the proxy's
  # in-flight state + the parser's finalize summary.
  #
  # Sub-3.7-followon (US1 production-grade plumbing) — every field below
  # carries REAL audit data:
  #
  #   * `principal_id` / `principal_kind` / `chatgpt_account_id` —
  #     extracted from the inbound JWT via `PrincipalExtractor`
  #     (decode-without-verify; upstream does authN). On extract
  #     failure the proxy substitutes `:anonymous` synthetic per
  #     `principal_or_anonymous/1` fail-OPEN posture.
  #   * `model` — the upstream-resolved model identifier from
  #     `response.created.response.model` (parser summary). The
  #     request body's `model` param is NOT authoritative; upstream
  #     may resolve aliases.
  #   * `prompt_hash` / `response_hash` — real SHA-256 over the actual
  #     bytes that crossed the wire, computed by the streaming
  #     `BodyHasher` threaded through the request-read + receive-loop.
  #     Constitution Principle III + IV satisfied: real provenance,
  #     hash-only in predicate.
  #   * Token counts — from `response.completed.response.usage` via
  #     parser summary. nil reasoning_token_count for non-o1/o3 models.
  defp build_call_state(state, summary) do
    cfg = state.llm_provider_config
    principal = state.principal
    completed_at = DateTime.utc_now()
    started_at = state.started_at || completed_at
    latency_ms = DateTime.diff(completed_at, started_at, :millisecond) |> max(0)
    base = state.gate_context_base

    %{
      tenant_id: state.tenant_id,
      principal_id: principal.principal_id,
      principal_kind: principal_kind_to_string(principal.principal_kind),
      session_id: Map.get(base, :session_id, state.tenant_id),
      started_at: started_at,
      completed_at: completed_at,
      model:
        Map.get(summary, :model) || Map.get(base, :model) || Map.get(state, :request_model) ||
          "unknown",
      provider: Map.get(cfg, :provider, "unknown"),
      upstream_host: cfg.upstream_host,
      transport: :https_sse,
      api_format: cfg.api_format,
      request_path: state.request_path,
      prompt_hash: BodyHasher.final(state.request_body_hasher),
      response_hash: BodyHasher.final(state.response_body_hasher),
      # Spec 012 S6b — the bytes behind those hashes, when retained.
      request_payload: PayloadCapture.result(state.request_capture),
      # A pre-head reset observed no model response. Preserve that absence
      # instead of admitting an empty Completion artifact. Once a response
      # starts, retain its observed bytes even when the call ends in error.
      response_payload:
        if(state.headers_sent?,
          do: PayloadCapture.result(state.response_capture),
          else: {:error, :response_not_observed}
        ),
      prompt_token_count: Map.get(summary, :prompt_token_count) || 0,
      completion_token_count: Map.get(summary, :completion_token_count) || 0,
      reasoning_token_count: Map.get(summary, :reasoning_token_count),
      cedar_bundle_hash: Map.get(base, :cedar_bundle_hash),
      admission: state.admission,
      tool_receipts: state.tool_receipts,
      upstream_status_code: state.upstream_status || 0,
      error_kind: error_kind_for(state),
      response_withheld?: state.body_withheld?,
      intents: state.intents_seen,
      latency_ms: latency_ms,
      added_latency_ms: 0,
      chatgpt_account_id: principal.chatgpt_account_id,
      principal_source: Map.get(principal, :principal_source),
      upstream_response_headers: state.upstream_response_headers,
      kind: state.kind,
      client_session_id: state.client_session_id,
      # Spec 012 S4 (plan §11) — which recognizer read the bytes and how
      # much of the stream it did not understand. `parser_failed?` is the
      # failure flag for the emitter to record as `parse.status`.
      parser: AttestationEmitter.parser_identity(state.parser_module, summary, cfg.api_format),
      parse: AttestationEmitter.parse_completeness(summary),
      parser_failed?: state.parser_failed?
    }
  end

  # `X-Claude-Code-Session-Id` header first; the JSON-encoded
  # `metadata.user_id` string (`{"device_id","account_uuid","session_id"}`)
  # second. nil when neither is present (Codex carries `session_id` as a
  # header of its own, which is also honoured).
  #
  # Both are client-controlled; the value lands on the signed predicate
  # and the receipt tags, so it is clamped to
  # `@client_session_id_max_bytes` (a UUID is 36) before it gets there.
  @client_session_id_max_bytes 128

  defp client_session_id(headers, request_params) do
    header =
      Enum.find_value(headers, fn {name, value} ->
        if String.downcase(name, :ascii) in ["x-claude-code-session-id", "session_id"] and
             is_binary(value) and value != "",
           do: value
      end)

    clamp_session_id(header || session_id_from_metadata(request_params))
  end

  defp clamp_session_id(nil), do: nil

  defp clamp_session_id(value) when byte_size(value) <= @client_session_id_max_bytes,
    do: value

  defp clamp_session_id(value) do
    value
    |> binary_part(0, @client_session_id_max_bytes)
    |> trim_to_valid_utf8()
  end

  # A byte clamp can split a multi-byte codepoint; drop trailing bytes
  # until the prefix is valid UTF-8 again (at most three).
  defp trim_to_valid_utf8(""), do: ""

  defp trim_to_valid_utf8(bin) do
    if String.valid?(bin),
      do: bin,
      else: bin |> binary_part(0, byte_size(bin) - 1) |> trim_to_valid_utf8()
  end

  defp session_id_from_metadata(%{"metadata" => %{"user_id" => user_id}})
       when is_binary(user_id) do
    case JSON.decode(user_id) do
      {:ok, %{"session_id" => sid}} when is_binary(sid) and sid != "" -> sid
      _ -> nil
    end
  end

  defp session_id_from_metadata(_), do: nil

  defp principal_kind_to_string(:obo_human), do: "obo_human"
  defp principal_kind_to_string(:service_account), do: "service_account"
  defp principal_kind_to_string(:autonomous), do: "autonomous"
  defp principal_kind_to_string(s) when is_binary(s), do: s
  defp principal_kind_to_string(_), do: "service_account"

  # Sub-3.7-followon — extract the principal from inbound headers,
  # falling back to a synthetic `:anonymous` on any error. The
  # PrincipalExtractor module documents the fail-OPEN rationale: a
  # 401 here would break Codex on every request that doesn't fit our
  # parser; an anonymous audit row is observable + fixable.
  #
  # Spec 012 S4 — Claude Code sends an opaque OAuth bearer (`sk-ant-oat01-…`)
  # and names the account in `metadata.user_id`; `extract_from_request/2`
  # derives `claude-code:<account_uuid>` from it. A bearer that is neither
  # a JWT nor accompanied by that metadata is expected for API keys, so
  # that case logs at debug rather than warning per request.
  defp principal_or_anonymous(headers, request_params) do
    case PrincipalExtractor.extract_from_request(headers, request_params) do
      {:ok, principal} ->
        principal

      {:error, :opaque_bearer} ->
        Logger.debug(fn ->
          "streaming_proxy: opaque bearer without metadata.user_id → using :anonymous synthetic"
        end)

        anonymous_principal()

      {:error, reason} ->
        Logger.warning(fn ->
          "streaming_proxy: principal extract fail-OPEN reason=#{inspect(reason)} " <>
            "→ using :anonymous synthetic"
        end)

        anonymous_principal()
    end
  end

  defp anonymous_principal do
    %{
      principal_id: "anonymous",
      principal_kind: :service_account,
      principal_source: :anonymous,
      chatgpt_account_id: nil,
      claims: %{}
    }
  end

  # Map proxy state into the LlmCallRecord error_kind closed-enum string,
  # per `Recurse.Providers.Schemas.LlmCallRecord.@error_kind_values`.
  # Parser and policy failures are explicit outcomes; upstream failures
  # map from their HTTP status.
  defp error_kind_for(%{transport_error: error}) when is_binary(error),
    do: "upstream_connection_failed"

  defp error_kind_for(%{gate_error_kind: kind}) when not is_nil(kind),
    do: "policy_evaluation_failure"

  defp error_kind_for(%{parser_failed?: true}), do: "parser_failure"

  defp error_kind_for(%{upstream_status: status}) when is_integer(status) and status >= 500,
    do: "upstream_5xx"

  defp error_kind_for(%{upstream_status: status}) when is_integer(status) and status >= 400,
    do: "upstream_4xx"

  defp error_kind_for(_), do: nil

  # --------------------------------------------------------------------------
  # Upstream connection — Mint direct
  # --------------------------------------------------------------------------

  defp open_upstream(scheme, host, port) do
    case BypassDnsResolver.resolve(host) do
      {:ok, [ip | _]} ->
        Mint.HTTP.connect(scheme, ip_to_string(ip), port,
          hostname: host,
          transport_opts: tls_opts(scheme),
          protocols: [:http2, :http1]
        )

      {:ok, []} ->
        {:error, :nxdomain}

      {:error, _} ->
        # Fall back to system DNS so test stubs that don't seed bypass
        # entries still reach localhost mocks.
        Mint.HTTP.connect(scheme, host, port,
          transport_opts: tls_opts(scheme),
          protocols: [:http2, :http1]
        )
    end
  end

  defp tls_opts(:https) do
    Application.get_env(:recurse_gateway, :llm_proxy_outbound_tls_opts,
      verify: :verify_peer,
      cacerts: :public_key.cacerts_get()
    )
  rescue
    _ -> [verify: :verify_peer]
  end

  defp tls_opts(:http), do: []

  defp ip_to_string({a, b, c, d}), do: "#{a}.#{b}.#{c}.#{d}"
  defp ip_to_string(other) when is_binary(other), do: other

  # Scheme is implicit from the LlmProviderConfig metadata. We allow
  # tests + test environments to opt into HTTP via metadata so the
  # mock-upstream test rig (which is HTTP-only) can exercise the proxy
  # without a TLS terminator. Production configs always set scheme=https
  # implicitly via port 443.
  defp upstream_scheme(%LlmProviderConfig{upstream_port: 80}), do: :http
  defp upstream_scheme(%LlmProviderConfig{metadata: %{"scheme" => "http"}}), do: :http
  defp upstream_scheme(%LlmProviderConfig{metadata: %{"scheme" => "https"}}), do: :https
  defp upstream_scheme(_cfg), do: :https

  defp safe_read_body(conn) do
    case Plug.Conn.read_body(conn, length: 50_000_000) do
      {:ok, body, conn} -> {:ok, body, conn}
      {:more, _partial, _conn} -> {:error, :body_too_large}
      {:error, reason} -> {:error, reason}
    end
  end

  # Parser-format → parser-module map. `:openai_responses` is Codex's
  # path (T026); `:anthropic_messages` is Claude Code's (spec 012 S4).
  # Anthropic has no WebSocket transport, so `WebSocketBridge` keeps its
  # OpenAI-only map. Other formats still fall through to OpenaiResponses.
  defp parser_for_format(:openai_responses),
    do: Recurse.Shared.LlmProxy.Parsers.OpenaiResponses

  defp parser_for_format(:anthropic_messages),
    do: Recurse.Shared.LlmProxy.Parsers.AnthropicMessages

  defp parser_for_format(:openai_chat_completions),
    do: Recurse.Shared.LlmProxy.Parsers.OpenaiResponses

  defp parser_for_format(_other),
    do: Recurse.Shared.LlmProxy.Parsers.OpenaiResponses

  defp request_path_with_query(%Plug.Conn{request_path: path, query_string: ""}), do: path

  defp request_path_with_query(%Plug.Conn{request_path: path, query_string: q}),
    do: path <> "?" <> q

  # Sub-3.4 — assemble the per-call gate-context base. Per-intent fields
  # (parallel_tool_call_index) get filled in via
  # `CedarToolUseGate.gate_context_for_intent/2`; everything else is
  # call-stable.
  #
  # Missing local projection does not grant authorization. The mandatory
  # admission path resolves the current admitted policy for every operation.
  #
  # Principal extraction is a Sub-3.7 surface: the proxy doesn't yet
  # have a JWT/SPIFFE identity-context plumb. For Sub-3.4 we synthesize
  # a default-principal from the request headers (HeaderFilter.principal_id_header
  # if present; fallback synthetic) so the gate's principal-keyed cache
  # at least uses a stable per-call identifier. Sub-3.7 will replace
  # this synthesis with the real `Recurse.Shared.Principal` lookup.
  defp build_gate_context_base(%LlmProviderConfig{} = cfg, tenant_id, body, principal) do
    threshold =
      Recurse.Gateway.LlmProxy.CedarToolUseGate.resolve_args_inline_threshold(cfg.metadata)

    base = %{
      # Sub-3.7-followon — real principal from JWT (or :anonymous
      # fallback). The CedarToolUseGate sees the principal_id +
      # claims for any per-intent rule that matches on principal.
      principal: %{
        id: principal.principal_id,
        kind: principal.principal_kind,
        # R1-F4 (RC review 2026-09-05): the provenance the extractor
        # already computed — `:jwt | :client_metadata | :mtls_svid |
        # :anonymous` — travels to admission instead of being dropped for
        # a constant. A rule that wants to refuse an anonymous principal
        # needs to be able to see one.
        source: principal.principal_source,
        chatgpt_account_id: principal.chatgpt_account_id,
        claims: principal.claims
      },
      model: extract_model_from_body(body) || "unknown",
      tenant: tenant_id,
      session_id: tenant_id <> ":" <> Recurse.Shared.Ulid.generate(),
      prompt_hash: :crypto.hash(:sha256, body || ""),
      response_so_far_hash: <<0::256>>,
      cedar_bundle_hash: nil,
      upstream_domain: cfg.upstream_host,
      transport: :https_sse,
      started_at: DateTime.utc_now(),
      args_inline_threshold_bytes: threshold,
      parallel_tool_call_index: nil
    }

    # FR-011 closure — populate estimated completion tokens from the
    # request body's max_tokens param (when present) + body byte size.
    request_params = parse_request_params(body)

    Recurse.Gateway.LlmProxy.CedarToolUseGate.populate_estimated_tokens(base, %{
      prompt_byte_size: byte_size(body || ""),
      request_params: request_params
    })
  end

  defp evidence_capture do
    PayloadCapture.init(
      enabled?: true,
      max_bytes: Application.get_env(:r5e, :cas_max_bytes, 16 * 1024 * 1024)
    )
  end

  defp parse_request_params(nil), do: %{}
  defp parse_request_params(""), do: %{}

  defp parse_request_params(body) when is_binary(body) do
    case JSON.decode(body) do
      {:ok, params} when is_map(params) -> params
      _ -> %{}
    end
  end

  defp extract_model_from_body(body) do
    case parse_request_params(body) do
      %{"model" => model} when is_binary(model) -> model
      _ -> nil
    end
  end

  defp send_503(plug_conn, error_kind) do
    body =
      JSON.encode!(%{
        "error" => %{
          "code" => "ERR_UPSTREAM_UNAVAILABLE",
          "kind" => error_kind,
          "message" =>
            "Upstream unavailable; recurse-gateway could not complete the proxied request."
        }
      })

    plug_conn
    |> Plug.Conn.put_resp_content_type("application/json")
    |> Plug.Conn.send_resp(503, body)
  end
end
