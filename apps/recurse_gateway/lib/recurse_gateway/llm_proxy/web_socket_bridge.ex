defmodule Recurse.Gateway.LlmProxy.WebSocketBridge do
  @moduledoc """
  Governed WebSocket bridge for OpenAI Responses.

  Readiness is required before the upgrade. Each supported `response.create`
  frame obtains its own opening admission before reaching the upstream socket.
  Only one model turn may be active on a socket; overlapping requests and
  unsupported request frames are rejected. A successful terminal response
  resets the per-turn parser, evidence, hashes and admission references for
  the next request.

  Tool bytes remain held until kernel ToolCall admission allows them. The
  parser binds repeated executable output to those exact intents and removes
  denied items from terminal response objects. Completion/LlmResponse must be
  admitted before terminal output is released. Parser, storage and policy
  failures suppress undecidable output and close the connection.

  An early disconnect records an interrupted turn where storage is available;
  an opening without a closing record remains incomplete evidence. Kernel
  evidence capture is bounded and independent of legacy retention preferences.
  Client identity fields are gateway observations, not verified client keys.
  """

  @behaviour WebSock

  alias Mint.HTTP, as: MintHttp
  alias Mint.WebSocket, as: MintWs
  alias Recurse.Gateway.Fold.Admission
  alias Recurse.Gateway.LlmProxy.AttestationEmitter
  alias Recurse.Gateway.LlmProxy.BodyHasher
  alias Recurse.Gateway.LlmProxy.BypassDnsResolver
  alias Recurse.Gateway.LlmProxy.CedarToolUseGate
  alias Recurse.Gateway.LlmProxy.DenialInjector
  alias Recurse.Gateway.LlmProxy.HeaderFilter
  alias Recurse.Gateway.LlmProxy.PayloadCapture
  alias Recurse.Gateway.LlmProxy.PrincipalExtractor
  alias Recurse.Providers.Schemas.LlmProviderConfig

  require Logger

  # The default denial template is `DenialInjector.Template.default/0`
  # (shared with `StreamingProxy`). Per-tenant override via
  # `LlmProviderConfig.metadata["denial_template"]`.

  # ---------------------------------------------------------------------------
  # Plug entry — upgrade gate
  # ---------------------------------------------------------------------------

  @doc """
  Plug entry. Hands the connection to Bandit's WebSocket dispatcher with
  this module as the WebSock handler. The actual upstream WS open
  happens in `init/1` — we keep the upgrade fast (P-001 budget < 50ms
  p95) by deferring upstream-conn establishment to the per-connection
  process.

  Caller is responsible for resolving `LlmProviderConfig` via
  `UpstreamResolver.resolve/2` first; this function takes the resolved
  config in opts.

  ## Required opts

    * `:llm_provider_config` — `%LlmProviderConfig{}`
    * `:tenant_id` — tenant ULID
    * `:parser_module` (optional) — overrides the per-format default
    * `:trace_id` (optional) — overrides the auto-minted trace
  """
  @spec upgrade(Plug.Conn.t(), keyword()) :: Plug.Conn.t()
  def upgrade(%Plug.Conn{} = conn, opts) do
    if Admission.ready?() do
      do_upgrade(conn, opts)
    else
      conn
      |> Plug.Conn.put_resp_content_type("application/json")
      |> Plug.Conn.send_resp(503, Jason.encode!(%{error: "admission_unavailable"}))
    end
  end

  defp do_upgrade(conn, opts) do
    %LlmProviderConfig{} = cfg = Keyword.fetch!(opts, :llm_provider_config)
    tenant_id = Keyword.fetch!(opts, :tenant_id)
    parser_module = Keyword.get(opts, :parser_module) || parser_for_format(cfg.api_format)
    trace_id = Keyword.get(opts, :trace_id) || Recurse.Shared.Ulid.generate()

    # Sub-3.7-followon (US1 plumbing) — extract principal from inbound
    # JWT BEFORE the upgrade so the gate context + every per-intent
    # gate evaluation in the connection's lifetime sees the real
    # principal. Decode-without-verify per PrincipalExtractor module
    # rationale; fail-OPEN to :anonymous on any error.
    principal = principal_or_anonymous(conn.req_headers)

    gate_context_base = build_gate_context_base(cfg, tenant_id, principal)

    initial_state = %{
      llm_provider_config: cfg,
      tenant_id: tenant_id,
      parser_module: parser_module,
      parser_state: nil,
      parser_failed?: false,
      trace_id: trace_id,
      # Sub-3.7 — captured at upgrade-time for the attestation emitter
      # invoked from `terminate/2` per Invariant I-004 (emission is the
      # LAST step before connection close).
      started_at: DateTime.utc_now(),
      attestation_emitted?: false,
      upstream_status: nil,
      # Sub-3.7-followon — real principal from JWT extraction.
      principal: principal,
      # Sub-3.7-followon — per-direction streaming SHA-256 hashers.
      # Fed in `forward_to_upstream/2` (request side) +
      # `parse_text_frame/2` (response side); finalised in
      # `build_call_state/1`.
      request_body_hasher: BodyHasher.init(),
      response_body_hasher: BodyHasher.init(),
      # Buffers are reset to mandatory bounded evidence capture at each turn.
      request_capture: PayloadCapture.init(),
      response_capture: PayloadCapture.init(),
      # Captured from parser's finalize/1 summary at terminate time.
      parser_summary: %{},
      # Sub-3.5 — capture api_format + denial_template at upgrade-start
      # so directive_to_push can route deny decisions through the
      # `DenialInjector` without re-loading config mid-stream.
      api_format: cfg.api_format,
      denial_template: resolve_denial_template(cfg),
      mint_conn: nil,
      mint_ws: nil,
      mint_ref: nil,
      upstream_open?: false,
      # Frames received from the client BEFORE the upstream upgrade
      # completes are buffered here (oldest-first) and flushed on
      # upgrade complete. Codex CLI reliably sends its first request
      # frame within a few ms of receiving the inbound 101, but the
      # outbound upgrade can take longer (TLS + handshake to real
      # chatgpt.com). Without buffering we'd silently drop the first
      # frame.
      pending_client_frames: [],
      client_req_headers: conn.req_headers,
      client_path: request_path_with_query(conn),
      gate_context_base: gate_context_base,
      gate_error_kind: nil,
      admission: nil,
      turn_active?: false,
      tool_receipts: [],
      admission_index: 0,
      terminal_pushes: [],
      # Sub-3.4 changes shape: was `[ToolUseIntent.t()]`; now
      # `[{ToolUseIntent.t(), CedarToolUseGate.decision()}]`.
      intents_seen: []
    }

    # WebSockAdapter.upgrade/4 hands control to Bandit; on negotiation
    # success this module's init/1 fires inside the new WebSocket
    # process.
    WebSockAdapter.upgrade(conn, __MODULE__, initial_state, [])
  end

  # ---------------------------------------------------------------------------
  # WebSock callbacks
  # ---------------------------------------------------------------------------

  @impl WebSock
  def init(state) do
    # Sub-3.8 fix: WebSocket transport carries one event per frame
    # (R-013). The OpenaiResponses parser needs `transport: :ws` so
    # `parse_chunk/2` treats each frame payload as one already-extracted
    # event JSON instead of routing through the SSE-buffer reassembly
    # path (which would never match `data: <json>\n\n` framing on raw
    # WS frames). Without this, function_call intents never emit and
    # Cedar evaluations never fire on the WS path.
    parser_state = state.parser_module.init(transport: :ws)

    case if(Admission.ready?(),
           do: open_upstream_websocket(state),
           else: {:error, :admission_unavailable}
         ) do
      {:ok, mint_conn, mint_ref} ->
        # Upstream upgrade is in-flight; the actual `:upgrade` response
        # will arrive as a Mint message in our mailbox and be handled
        # via handle_info/2 → Mint.HTTP.stream/2 → on `:status` /
        # `:headers` / Mint.WebSocket.new/4. Mark upstream_open? false
        # until the 101 lands.
        {:ok,
         %{
           state
           | parser_state: parser_state,
             mint_conn: mint_conn,
             mint_ref: mint_ref,
             upstream_open?: false
         }}

      {:error, reason} ->
        Logger.warning(fn ->
          "ws_bridge: upstream upgrade failed reason=#{inspect(reason)}"
        end)

        # Close the client conn with a server-error close code. The
        # 1011 frame propagates "internal error" to Codex; agent loop
        # handles via its own retry.
        {:stop, :normal, {1011, "upstream connect failed"}, %{state | parser_state: parser_state}}
    end
  end

  # Each model request crosses admission before any frame is forwarded.
  @impl WebSock
  def handle_in({_payload, opcode: :text}, %{turn_active?: true} = state) do
    {:stop, :normal, {1008, "overlapping model requests are unsupported"}, state}
  end

  def handle_in({payload, opcode: :text}, state) do
    with {:ok, %{"type" => "response.create", "model" => model} = request}
         when is_binary(model) and model != "" <- Jason.decode(payload),
         context <- turn_context(state, payload, request),
         {:ok, admission} <- Admission.open(payload, context, opening_metadata(state)) do
      state = %{
        state
        | admission: admission,
          turn_active?: true,
          tool_receipts: [],
          admission_index: 0,
          terminal_pushes: [],
          gate_context_base: admission.context,
          started_at: context.started_at,
          attestation_emitted?: false,
          intents_seen: [],
          gate_error_kind: nil,
          parser_failed?: false,
          parser_summary: %{},
          parser_state: state.parser_module.init(transport: :ws),
          request_body_hasher: BodyHasher.init(),
          response_body_hasher: BodyHasher.init(),
          request_capture: evidence_capture(),
          response_capture: evidence_capture()
      }

      state = update_request_body_hasher(state, {:text, payload})
      forward_to_upstream(state, {:text, payload})
    else
      _ -> {:stop, :normal, {1008, "model request was not admitted"}, state}
    end
  end

  def handle_in({payload, opcode: :binary}, state) do
    # This protocol accepts JSON text requests; unparsed binary requests
    # cannot enter the governed upstream path.
    state = update_request_body_hasher(state, {:binary, payload})
    {:stop, :normal, {1003, "binary requests are unsupported"}, %{state | parser_failed?: true}}
  end

  @impl WebSock
  def handle_control({_payload, opcode: :ping}, state) do
    # Bandit auto-replies with pong. We could also forward pings to
    # upstream but Mint.WebSocket auto-replies upstream pings too; the
    # ping cycles are independent per leg.
    {:ok, state}
  end

  def handle_control({_payload, opcode: :pong}, state) do
    {:ok, state}
  end

  # Mint message arrived — could be the upgrade response (101 Switching
  # Protocols), a WS data frame from upstream, or a transport error.
  @impl WebSock
  def handle_info(message, state) do
    case mint_stream(state, message) do
      {:cont, state, frames} ->
        # Frames from upstream — push to client (after parser).
        push_frames_to_client(state, frames)

      {:upgrade_complete, state} ->
        flush_pending_client_frames(%{state | upstream_open?: true})

      {:closed, state, frames} ->
        # Drain any final frames, then close the client side.
        case push_frames_to_client(state, frames) do
          {:push, push_frames, st} ->
            {:push, push_frames ++ [{:close, ""}], st}

          {:ok, st} ->
            {:stop, :normal, {1000, "upstream closed"}, st}

          {:stop, _, _, _} = stopped ->
            stopped
        end

      {:error, state, _reason} ->
        {:stop, :normal, {1011, "upstream error"}, state}

      :ignored ->
        {:ok, state}
    end
  end

  @impl WebSock
  def terminate(_reason, state) do
    # Sub-3.7 — emit per-call attestation as the LAST step before the
    # WebSock process exits (Invariant I-004). On failure we log + emit
    # telemetry but do not block the terminate path; the audit gap is
    # observable via [:recurse, :llm_proxy, :attestation, :emit_failed].
    if Map.get(state, :turn_active?, false),
      do: finish_turn(state, "upstream_connection_failed")

    # Close upstream conn if still open. Best-effort.
    if state.mint_conn do
      _ = MintHttp.close(state.mint_conn)
    end

    :ok
  end

  # Defensive emitter wrapping. ProviderRegistry may not be installed
  # in unit tests; we treat that case as "no audit substrate available"
  # rather than a request-blocking error. Production deployments always
  # install the registry — `Recurse.Gateway.Application` boots it before
  # the endpoint accepts requests.
  defp safe_emit_attestation(state) do
    if Map.get(state, :attestation_emitted?, false) do
      :ok
    else
      do_safe_emit_attestation(state)
    end
  end

  defp do_safe_emit_attestation(state) do
    case maybe_build_call_state(state) do
      {:ok, call_state} ->
        emit_legacy_attestation(call_state)

      :skip ->
        # Same rationale as `streaming_proxy.ex`: ProviderRegistry not
        # installed (dev / local-only). Visible-but-not-loud log line
        # so the live-demo BEAM window shows the path was taken.
        Logger.info(fn ->
          "ws_bridge: ProviderRegistry not installed; skipping attestation emit " <>
            "(set R5E_PROVIDER_LEDGER_IMPL+ for persisted rows)"
        end)

        :telemetry.execute(
          [:recurse, :llm_proxy, :attestation, :emit_skipped],
          %{count: 1},
          %{reason: :provider_registry_not_installed, transport: :wss}
        )

        :ok
    end
  rescue
    error ->
      Logger.error(fn ->
        "ws_bridge: attestation emit raised #{inspect(error)}"
      end)

      :telemetry.execute(
        [:recurse, :llm_proxy, :attestation, :emit_failed],
        %{count: 1},
        %{reason: {:raised, error}, transport: :wss}
      )

      :error
  end

  defp emit_legacy_attestation(call_state) do
    case AttestationEmitter.emit_call_attestation(call_state) do
      {:ok, _run_id} ->
        :ok

      {:error, reason} ->
        Logger.error(fn ->
          "ws_bridge: attestation emit failed reason=#{inspect(reason)}"
        end)

        :telemetry.execute(
          [:recurse, :llm_proxy, :attestation, :emit_failed],
          %{count: 1},
          %{reason: reason, transport: :wss}
        )

        :error
    end
  end

  defp maybe_build_call_state(state) do
    case Recurse.Gateway.ProviderRegistry.fetch() do
      {:ok, _registry} -> {:ok, build_call_state(state)}
      {:error, :not_installed} -> :skip
    end
  end

  # Build the `AttestationEmitter.call_state()` payload from the WebSock
  # state.
  #
  # Sub-3.7-followon (US1 production-grade plumbing) — real audit data:
  #
  #   * `principal_id` / `principal_kind` / `chatgpt_account_id` —
  #     extracted from inbound JWT via PrincipalExtractor at upgrade.
  #   * `model` / token counts — from parser_summary populated as
  #     response.created + response.completed events flow through.
  #   * `prompt_hash` / `response_hash` — real SHA-256 over the
  #     bytes that crossed the WS in each direction, computed
  #     incrementally as frames are forwarded.
  defp build_call_state(state) do
    base = state.gate_context_base
    cfg = state.llm_provider_config
    principal = state.principal
    summary = state.parser_summary
    completed_at = DateTime.utc_now()
    started_at = state.started_at || completed_at
    latency_ms = DateTime.diff(completed_at, started_at, :millisecond) |> max(0)

    %{
      tenant_id: state.tenant_id,
      principal_id: principal.principal_id,
      principal_kind: principal_kind_to_string(principal.principal_kind),
      session_id: Map.get(base, :session_id, state.tenant_id),
      started_at: started_at,
      completed_at: completed_at,
      model: Map.get(summary, :model) || Map.get(base, :model) || "unknown",
      provider: Map.get(cfg, :provider, "unknown"),
      upstream_host: cfg.upstream_host,
      transport: :wss,
      api_format: cfg.api_format,
      request_path: state.client_path,
      prompt_hash: BodyHasher.final(state.request_body_hasher),
      response_hash: BodyHasher.final(state.response_body_hasher),
      # Spec 012 S6b — the bytes behind those hashes, when retained.
      request_payload: PayloadCapture.result(state.request_capture),
      response_payload: PayloadCapture.result(state.response_capture),
      prompt_token_count: Map.get(summary, :prompt_token_count) || 0,
      completion_token_count: Map.get(summary, :completion_token_count) || 0,
      reasoning_token_count: Map.get(summary, :reasoning_token_count),
      cedar_bundle_hash: Map.get(base, :cedar_bundle_hash),
      admission: state.admission,
      tool_receipts: state.tool_receipts,
      upstream_status_code: state.upstream_status || 0,
      error_kind: error_kind_for(state),
      intents: state.intents_seen,
      latency_ms: latency_ms,
      added_latency_ms: 0,
      chatgpt_account_id: principal.chatgpt_account_id,
      # Spec 012 S4 (plan §11) — recognizer identity + completeness.
      parser: AttestationEmitter.parser_identity(state.parser_module, summary, cfg.api_format),
      parse: AttestationEmitter.parse_completeness(summary)
    }
  end

  defp principal_kind_to_string(:obo_human), do: "obo_human"
  defp principal_kind_to_string(:service_account), do: "service_account"
  defp principal_kind_to_string(:autonomous), do: "autonomous"
  defp principal_kind_to_string(s) when is_binary(s), do: s
  defp principal_kind_to_string(_), do: "service_account"

  # Sub-3.7-followon — extract principal from inbound headers; fail-OPEN
  # to :anonymous synthetic on any error. Same posture as
  # `StreamingProxy.principal_or_anonymous/1`.
  defp principal_or_anonymous(headers) do
    case PrincipalExtractor.extract_from_headers(headers) do
      {:ok, principal} ->
        principal

      {:error, reason} ->
        Logger.warning(fn ->
          "ws_bridge: principal extract fail-OPEN reason=#{inspect(reason)} " <>
            "→ using :anonymous synthetic"
        end)

        %{
          principal_id: "anonymous",
          principal_kind: :service_account,
          principal_source: :anonymous,
          chatgpt_account_id: nil,
          claims: %{}
        }
    end
  end

  defp error_kind_for(%{gate_error_kind: kind}) when not is_nil(kind),
    do: "policy_evaluation_failure"

  defp error_kind_for(%{parser_failed?: true}), do: "parser_failure"

  defp error_kind_for(%{upstream_status: status}) when is_integer(status) and status >= 500,
    do: "upstream_5xx"

  defp error_kind_for(%{upstream_status: status}) when is_integer(status) and status >= 400,
    do: "upstream_4xx"

  defp error_kind_for(_), do: nil

  # ---------------------------------------------------------------------------
  # Upstream WS handshake — Mint.WebSocket
  # ---------------------------------------------------------------------------

  defp open_upstream_websocket(state) do
    %LlmProviderConfig{
      upstream_host: host,
      upstream_port: port_or_nil
    } = state.llm_provider_config

    port = port_or_nil || 443
    {scheme, ws_scheme} = ws_schemes(state.llm_provider_config)

    # Mint.WebSocket.upgrade/4 generates its OWN Sec-WebSocket-Key,
    # Sec-WebSocket-Version, Connection, and Upgrade headers — these
    # are part of the upgrade-request shape Mint emits. If we ALSO
    # pass the client's Sec-WebSocket-* values through, the upstream
    # rejects the upgrade with a "duplicate header" 400. So strip the
    # WS-handshake-specific headers from the forwarded set; the
    # R-012 contract says "preserve all Sec-WebSocket-*" but that's
    # client→proxy correctness — we re-derive the upstream-bound
    # versions inside Mint.WebSocket. End-to-end the client still
    # gets a valid handshake because WebSockAdapter (inbound) +
    # Mint.WebSocket (outbound) produce a fresh handshake on each leg.
    fwd_headers =
      state.client_req_headers
      |> HeaderFilter.forward_request_headers(
        %{trace_id: state.trace_id, tenant_id: state.tenant_id},
        websocket_upgrade?: true
      )
      |> Enum.reject(fn {k, _v} -> ws_handshake_header?(k) end)

    with {:ok, mint_conn} <- open_mint_http(scheme, host, port),
         {:ok, mint_conn, ref} <-
           MintWs.upgrade(ws_scheme, mint_conn, state.client_path, fwd_headers) do
      {:ok, mint_conn, ref}
    else
      {:error, %Mint.TransportError{reason: reason}} -> {:error, reason}
      {:error, _conn, reason} -> {:error, reason}
      {:error, reason} -> {:error, reason}
    end
  end

  # On upstream upgrade complete, push any client frames that
  # arrived during the handshake window in FIFO order. Each
  # forward_to_upstream call rebuilds state; we drain the queue.
  defp flush_pending_client_frames(state) do
    pending = state.pending_client_frames
    state = %{state | pending_client_frames: []}

    Enum.reduce(pending, {:ok, state}, fn frame, acc ->
      case acc do
        {:ok, st} ->
          forward_to_upstream(st, frame)

        other ->
          other
      end
    end)
  end

  # WS-handshake-specific request headers that Mint.WebSocket regenerates
  # on its own. We strip these from the forwarded set to avoid duplicate
  # values when the upstream sees the upgrade request.
  defp ws_handshake_header?(name) do
    name = String.downcase(name, :ascii)

    name in [
      "sec-websocket-key",
      "sec-websocket-version",
      "connection",
      "upgrade",
      "host",
      "content-length"
    ]
  end

  defp open_mint_http(scheme, host, port) do
    case BypassDnsResolver.resolve(host) do
      {:ok, [ip | _]} ->
        MintHttp.connect(scheme, ip_to_string(ip), port,
          hostname: host,
          transport_opts: tls_opts(scheme),
          protocols: [:http1]
        )

      {:ok, []} ->
        {:error, :nxdomain}

      {:error, _} ->
        # Fall back to system DNS for test stubs.
        MintHttp.connect(scheme, host, port,
          transport_opts: tls_opts(scheme),
          protocols: [:http1]
        )
    end
  end

  # WS over the same transport as the LLM provider's HTTPS surface —
  # in practice always TLS (`wss`). The `:http` / `:ws` paths are
  # test-only seams. Picks the scheme via `:upstream_port == 80` OR
  # via the `"scheme"` key in the config metadata (the test seam
  # mirrors `StreamingProxy.upstream_scheme/1`).
  defp ws_schemes(%LlmProviderConfig{upstream_port: 80}), do: {:http, :ws}
  defp ws_schemes(%LlmProviderConfig{metadata: %{"scheme" => "http"}}), do: {:http, :ws}
  defp ws_schemes(%LlmProviderConfig{metadata: %{"scheme" => "https"}}), do: {:https, :wss}
  defp ws_schemes(_cfg), do: {:https, :wss}

  defp tls_opts(:https) do
    Application.get_env(:recurse_gateway, :llm_proxy_outbound_tls_opts,
      verify: :verify_peer,
      cacerts: :public_key.cacerts_get()
    )
  rescue
    _ -> [verify: :verify_peer]
  end

  defp tls_opts(:http), do: []

  # ---------------------------------------------------------------------------
  # Mint stream dispatch — transforms a Mint mailbox message into our
  # bridge state-transition tuple.
  # ---------------------------------------------------------------------------

  # When upstream is OPEN, frames arrive as Mint.WebSocket-encoded
  # data; decode them into [text|binary|close|...] frames.
  defp mint_stream(%{upstream_open?: true} = state, message) do
    case MintWs.stream(state.mint_conn, message) do
      {:ok, mint_conn, mint_messages} ->
        state = %{state | mint_conn: mint_conn}
        decode_ws_frames(state, mint_messages)

      {:error, mint_conn, _reason, _resp} ->
        {:error, %{state | mint_conn: mint_conn}, :upstream_stream_error}

      :unknown ->
        :ignored
    end
  end

  # When upstream NOT open yet, Mint messages drive the upgrade
  # handshake. We need :status + :headers, then call Mint.WebSocket.new/4.
  defp mint_stream(%{upstream_open?: false} = state, message) do
    case MintHttp.stream(state.mint_conn, message) do
      {:ok, mint_conn, responses} ->
        process_upgrade_responses(%{state | mint_conn: mint_conn}, responses)

      {:error, mint_conn, _reason, _responses} ->
        {:error, %{state | mint_conn: mint_conn}, :upstream_upgrade_error}

      :unknown ->
        :ignored
    end
  end

  # During upgrade: collect status + headers; once both are in, call
  # Mint.WebSocket.new/4 to flip to WS mode.
  defp process_upgrade_responses(state, responses) do
    state =
      Enum.reduce(responses, state, fn
        {:status, ref, status}, st when ref == st.mint_ref ->
          Map.put(st, :_pending_status, status)

        {:headers, ref, headers}, st when ref == st.mint_ref ->
          Map.put(st, :_pending_headers, headers)

        {:done, ref}, st when ref == st.mint_ref ->
          Map.put(st, :_upgrade_done?, true)

        _other, st ->
          st
      end)

    case state do
      %{_pending_status: 101, _pending_headers: headers} ->
        case MintWs.new(state.mint_conn, state.mint_ref, 101, headers) do
          {:ok, mint_conn, mint_ws} ->
            state =
              state
              |> Map.put(:mint_conn, mint_conn)
              |> Map.put(:mint_ws, mint_ws)
              |> Map.delete(:_pending_status)
              |> Map.delete(:_pending_headers)

            {:upgrade_complete, state}

          {:error, mint_conn, _reason} ->
            {:error, %{state | mint_conn: mint_conn}, :upstream_upgrade_error}
        end

      %{_pending_status: status, _upgrade_done?: true} when is_integer(status) ->
        # Upstream rejected the upgrade with a non-101 — close the
        # client with the same status. Codex falls back to HTTPS+SSE.
        {:error, state, {:upstream_status, status}}

      _ ->
        # Status / headers not in yet; wait for next message.
        {:cont, state, []}
    end
  end

  defp decode_ws_frames(state, mint_messages) do
    Enum.reduce(mint_messages, {:cont, state, []}, fn
      {:data, ref, payload}, {tag, st, acc_frames} when ref == st.mint_ref ->
        case MintWs.decode(st.mint_ws, payload) do
          {:ok, mint_ws, frames} ->
            {tag, %{st | mint_ws: mint_ws}, acc_frames ++ frames}

          {:error, mint_ws, _reason} ->
            {tag, %{st | mint_ws: mint_ws}, acc_frames}
        end

      {:done, ref}, {_tag, st, acc_frames} when ref == st.mint_ref ->
        {:closed, st, acc_frames}

      {:error, ref, _reason}, {_tag, st, acc_frames} when ref == st.mint_ref ->
        {:closed, st, acc_frames}

      _other, acc ->
        acc
    end)
  end

  # ---------------------------------------------------------------------------
  # Outbound: upstream frames → client
  # ---------------------------------------------------------------------------

  defp push_frames_to_client(state, []), do: {:ok, state}

  defp push_frames_to_client(state, frames) do
    {state, push_messages} =
      Enum.reduce(frames, {state, []}, fn frame, {st, acc} ->
        case classify_upstream_frame(frame) do
          {:text, payload} ->
            {st, new_pushes} = process_text_frame(st, payload)
            {st, acc ++ new_pushes}

          {:binary, payload} ->
            st = update_response_body_hasher(st, payload)
            {%{st | parser_failed?: true}, acc}

          {:close, _code, _reason} ->
            {st, acc ++ [{:close, ""}]}

          :skip ->
            {st, acc}
        end
      end)

    cond do
      state.parser_failed? ->
        {:stop, :normal, {1011, "response could not be governed"}, state}

      push_messages == [] ->
        {:ok, state}

      true ->
        {:push, push_messages, state}
    end
  end

  # Phase 6 byte-precise suppression in WS-mode. Parses the upstream
  # text frame, walks the directive stream in order, and at every
  # `{:cedar_eval, call_id}` marker calls `apply_verdict/3` on the
  # parser to drain the held bytes into either forward (allow) or
  # suppress (deny) directives. Denied calls trigger synthetic-frame
  # injection AFTER the suppressed bytes are dropped.
  defp process_text_frame(%{turn_active?: false} = state, _payload),
    do: {%{state | parser_failed?: true}, []}

  defp process_text_frame(state, payload) do
    {state, parser_state, intents, directives} = parse_text_frame(state, payload)

    intent_by_call_id = Map.new(intents, fn intent -> {intent.call_id, intent} end)

    initial_acc = %{
      pushes: [],
      parser_state: parser_state,
      intent_decisions: [],
      tool_receipts: [],
      admission_index: state.admission_index,
      gate_error_kind: nil,
      parser_failed?: false
    }

    final_acc =
      Enum.reduce_while(directives, initial_acc, fn directive, acc ->
        ws_dispatch_directive(directive, acc, state, intent_by_call_id)
      end)

    new_state = %{
      state
      | parser_state: final_acc.parser_state,
        parser_failed?: state.parser_failed? or final_acc.parser_failed?,
        intents_seen: state.intents_seen ++ final_acc.intent_decisions,
        tool_receipts: state.tool_receipts ++ final_acc.tool_receipts,
        admission_index: final_acc.admission_index,
        gate_error_kind: final_acc.gate_error_kind || state.gate_error_kind
    }

    new_state =
      if terminal_response?(payload) and not new_state.parser_failed? do
        finish_turn(new_state)
      else
        new_state
      end

    {new_state,
     if(new_state.parser_failed?, do: [], else: final_acc.pushes ++ new_state.terminal_pushes)}
  end

  defp ws_dispatch_directive({:parser_error, _reason}, acc, _state, _intent_by_call_id),
    do: {:halt, %{acc | parser_failed?: true}}

  defp ws_dispatch_directive({:forward, bytes}, acc, _state, _intent_by_call_id) do
    {:cont, %{acc | pushes: acc.pushes ++ [{:text, bytes}]}}
  end

  defp ws_dispatch_directive({:suppress, _bytes}, acc, _state, _intent_by_call_id) do
    # Bytes explicitly dropped — codex never sees these frames.
    {:cont, acc}
  end

  defp ws_dispatch_directive(:flush_pending, acc, _state, _intent_by_call_id) do
    {:cont, acc}
  end

  defp ws_dispatch_directive({:cedar_eval, call_id}, acc, state, intent_by_call_id) do
    case Map.fetch(intent_by_call_id, call_id) do
      {:ok, intent} ->
        ws_process_cedar_eval(intent, acc, state)

      :error ->
        {:halt, %{acc | parser_failed?: true}}
    end
  end

  defp ws_process_cedar_eval(intent, acc, state) do
    decision = ws_evaluate_intent(state, intent, acc.admission_index)
    acc = %{acc | admission_index: acc.admission_index + 1}

    case decision do
      {:error, reason} ->
        Logger.warning(fn ->
          "ws_bridge: cedar gate ERROR (fail-CLOSED) " <>
            "tool=#{inspect(intent.tool_name)} reason=#{inspect(reason)}"
        end)

        {:halt,
         %{
           acc
           | gate_error_kind: reason,
             parser_failed?: true,
             intent_decisions: acc.intent_decisions ++ [{intent, {:error, reason}}]
         }}

      {:ok, {:allow}, receipt} ->
        acc = %{acc | tool_receipts: acc.tool_receipts ++ [receipt]}

        {parser_state, drained} =
          state.parser_module.apply_verdict(acc.parser_state, intent.call_id, :allow)

        new_pushes = drained_to_pushes(drained)

        {:cont,
         %{
           acc
           | pushes: acc.pushes ++ new_pushes,
             parser_state: parser_state,
             intent_decisions: acc.intent_decisions ++ [{intent, {:allow}}]
         }}

      {:ok, {:deny, deny_payload}, receipt} ->
        acc = %{acc | tool_receipts: acc.tool_receipts ++ [receipt]}

        Logger.warning(fn ->
          "ws_bridge: cedar gate DENY (Phase 6 byte-suppression) " <>
            "tool=#{inspect(intent.tool_name)} rule=#{inspect(deny_payload.rule_id)}"
        end)

        {parser_state, drained} =
          state.parser_module.apply_verdict(acc.parser_state, intent.call_id, :deny)

        # Drained directives are all `{:suppress, _}` — codex never sees
        # the original function_call frames. Synthetic denial frames
        # follow.
        suppressed_pushes = drained_to_pushes(drained)

        synth_pushes =
          DenialInjector.inject_denial(
            state.api_format,
            intent,
            deny_payload,
            state.denial_template,
            audit_context: ws_audit_context_for_denial(state)
          )
          |> Enum.map(fn ev -> {:text, ev} end)

        {:cont,
         %{
           acc
           | pushes: acc.pushes ++ suppressed_pushes ++ synth_pushes,
             parser_state: parser_state,
             intent_decisions: acc.intent_decisions ++ [{intent, {:deny, deny_payload}}]
         }}
    end
  end

  defp ws_evaluate_intent(state, intent, index) do
    ctx =
      CedarToolUseGate.gate_context_for_intent(state.gate_context_base, intent)
      |> Map.put(:admission_index, index)
      |> Map.put(:response_so_far_hash, BodyHasher.final(state.response_body_hasher))

    Admission.admit_tool(state.admission, intent, ctx)
  end

  defp drained_to_pushes(directives) do
    Enum.flat_map(directives, fn
      {:forward, b} -> [{:text, b}]
      {:suppress, _} -> []
      _ -> []
    end)
  end

  # Build the audit-context map threaded into the denial injector.
  # Mirrors `StreamingProxy.audit_context_for_denial/1` — same shape so
  # both transports share the same template grammar.
  #
  # Per-tenant `appeal_uri` and `appeal_contact` (R5E-104) are read
  # from `LlmProviderConfig.metadata` — same precedent as
  # `denial_template`. `policy_source_uri` is reserved for R5E-105.
  defp ws_audit_context_for_denial(state) do
    base = state.gate_context_base || %{}
    principal = Map.get(base, :principal, %{})
    metadata = (state.llm_provider_config || %{}) |> Map.get(:metadata, %{}) || %{}

    %{
      tenant_id: state.tenant_id,
      principal_id: Map.get(principal, :id),
      principal_kind: principal_kind_to_string(Map.get(principal, :kind)),
      session_id: Map.get(base, :session_id),
      cedar_bundle_hash: Map.get(base, :cedar_bundle_hash),
      appeal_uri: ws_nonempty_string(Map.get(metadata, "appeal_uri")),
      appeal_contact: ws_nonempty_string(Map.get(metadata, "appeal_contact")),
      policy_source_uri: nil
    }
  end

  # Treat empty strings as nil so the template's optional-clause
  # grammar drops the appeal line cleanly when a tenant has the
  # metadata key but with an empty value.
  defp ws_nonempty_string(s) when is_binary(s) and s != "", do: s
  defp ws_nonempty_string(_), do: nil

  defp classify_upstream_frame({:text, payload}) when is_binary(payload), do: {:text, payload}
  defp classify_upstream_frame({:binary, payload}) when is_binary(payload), do: {:binary, payload}
  defp classify_upstream_frame({:close, code, reason}), do: {:close, code, reason}
  defp classify_upstream_frame(:close), do: {:close, 1000, ""}
  defp classify_upstream_frame(_), do: :skip

  defp parse_text_frame(%{parser_failed?: true} = state, payload) do
    state = update_response_body_hasher(state, payload)
    {state, state.parser_state, [], []}
  end

  defp parse_text_frame(state, payload) do
    # Sub-3.7-followon — feed every upstream text frame into the
    # response body hasher BEFORE parsing. Constitution Principle III
    # — the hash MUST cover the bytes upstream actually sent;
    # synthetic-denial frames the proxy injects later are NOT part of
    # the upstream response for hash purposes.
    state = update_response_body_hasher(state, payload)

    {parser_state, intents, directives} =
      try do
        if state.response_capture.truncated? do
          {state.parser_state, [], [{:parser_error, :evidence_limit}]}
        else
          state.parser_module.parse_chunk(state.parser_state, payload)
        end
      rescue
        e ->
          Logger.warning(fn ->
            "ws_bridge: parser raised (fail-CLOSED); module=#{inspect(state.parser_module)} " <>
              "error=#{inspect(e)}"
          end)

          {state.parser_state, [], [{:parser_error, :raised}]}
      catch
        _, _ -> {state.parser_state, [], [{:parser_error, :failed}]}
      end

    # Phase 6: Cedar evaluation happens INLINE at `{:cedar_eval, call_id}`
    # markers in the directive stream (see `process_text_frame/2`), not
    # up-front. This is what gives us byte-precise suppression — the
    # parser's `apply_verdict/3` only fires after Cedar decides, and
    # only at the stream position where the intent emerged.

    # Sub-3.7-followon — capture parser summary on each frame so
    # `build_call_state` (called from terminate/2) reads the latest
    # model + token counts. Use the parser-specific non-destructive
    # accessor when present (e.g. OpenaiResponses.current_summary/1);
    # fall back to noop preservation for parsers that don't expose
    # one (Phase 6 implementations should add this accessor for WS-
    # transport correctness).
    parser_summary =
      current_parser_summary(state.parser_module, parser_state, state.parser_summary)

    {%{state | parser_summary: parser_summary}, parser_state, intents, directives}
  end

  defp current_parser_summary(parser_module, parser_state, fallback) do
    if function_exported?(parser_module, :current_summary, 1) do
      try do
        parser_module.current_summary(parser_state)
      rescue
        _ -> fallback
      end
    else
      fallback
    end
  end

  # ---------------------------------------------------------------------------
  # Body-hash plumbing — Sub-3.7-followon (US1 plumbing)
  # ---------------------------------------------------------------------------

  # Feed an outbound (client→upstream) frame's text payload into the
  # request hasher. Binary frames are not on the LLM-API-protocol path
  # (the payload format is JSON text per R-013) but we still hash the
  # bytes so the audit row reflects everything that crossed the wire.
  defp update_request_body_hasher(state, {:text, payload}) when is_binary(payload) do
    %{
      state
      | request_body_hasher: BodyHasher.update(state.request_body_hasher, payload),
        request_capture: PayloadCapture.append(state.request_capture, payload)
    }
  end

  defp update_request_body_hasher(state, {:binary, payload}) when is_binary(payload) do
    %{
      state
      | request_body_hasher: BodyHasher.update(state.request_body_hasher, payload),
        request_capture: PayloadCapture.append(state.request_capture, payload)
    }
  end

  defp update_request_body_hasher(state, _other), do: state

  defp update_response_body_hasher(state, payload) when is_binary(payload) do
    %{
      state
      | response_body_hasher: BodyHasher.update(state.response_body_hasher, payload),
        response_capture: PayloadCapture.append(state.response_capture, payload)
    }
  end

  defp update_response_body_hasher(state, _other), do: state

  # Old Sub-3.5 helpers (`evaluate_intents_through_gate/2`,
  # `directive_to_push/3`, `denial_text_frames/1`, `log_deny_decisions/1`)
  # were removed in Phase 6: Cedar evaluation now happens INLINE at
  # `{:cedar_eval, call_id}` markers — see `ws_dispatch_directive/4` +
  # `ws_process_cedar_eval/3` above. The new design enforces byte-
  # precise suppression: denied function_call frames never reach codex.

  # ---------------------------------------------------------------------------
  # Inbound: client frames → upstream
  # ---------------------------------------------------------------------------

  # Upstream not yet handshake-complete: queue the frame so we can
  # flush on upgrade completion. WebSockAdapter sends the inbound 101
  # to the client immediately, while the outbound upgrade is still
  # in-flight; the client's first frame frequently arrives in this
  # window, especially against fast localhost upstreams.
  defp forward_to_upstream(%{upstream_open?: false} = state, frame) do
    {:ok, %{state | pending_client_frames: state.pending_client_frames ++ [frame]}}
  end

  defp forward_to_upstream(state, frame) do
    case MintWs.encode(state.mint_ws, frame) do
      {:ok, mint_ws, data} ->
        # Use `Mint.WebSocket.stream_request_body/3` rather than
        # `Mint.HTTP.stream_request_body/3` — the WS-aware variant
        # writes raw bytes to the socket after the upgrade has flipped
        # the conn into WebSocket mode. The plain HTTP variant
        # FunctionClauseError's against the WS-mode conn.
        case MintWs.stream_request_body(state.mint_conn, state.mint_ref, data) do
          {:ok, mint_conn} ->
            {:ok, %{state | mint_conn: mint_conn, mint_ws: mint_ws}}

          {:error, mint_conn, _reason} ->
            {:stop, :normal, {1011, "upstream send error"},
             %{state | mint_conn: mint_conn, mint_ws: mint_ws}}
        end

      {:error, mint_ws, _reason} ->
        {:ok, %{state | mint_ws: mint_ws}}
    end
  end

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  defp ip_to_string({a, b, c, d}), do: "#{a}.#{b}.#{c}.#{d}"
  defp ip_to_string(other) when is_binary(other), do: other

  defp request_path_with_query(%Plug.Conn{request_path: path, query_string: ""}), do: path

  defp request_path_with_query(%Plug.Conn{request_path: path, query_string: q}),
    do: path <> "?" <> q

  defp parser_for_format(:openai_responses),
    do: Recurse.Shared.LlmProxy.Parsers.OpenaiResponses

  defp parser_for_format(:openai_chat_completions),
    do: Recurse.Shared.LlmProxy.Parsers.OpenaiResponses

  defp parser_for_format(_other),
    do: Recurse.Shared.LlmProxy.Parsers.OpenaiResponses

  # Sub-3.4 — Cedar gate context base. Same shape as `StreamingProxy`'s
  # equivalent but transport=:wss + no body (the WS upgrade itself
  # carries no LLM-request body; per-frame requests arrive after the
  # upgrade and aren't captured in the gate-context base — the per-
  # intent invocation gets them via `intent.tool_args`). Principal
  # synthesis stays a Sub-3.7 surface.
  # Resolve the denial template: per-tenant override in
  # `LlmProviderConfig.metadata["denial_template"]` if a non-empty
  # string; else the default template.
  defp resolve_denial_template(%LlmProviderConfig{metadata: %{"denial_template" => tmpl}})
       when is_binary(tmpl) and tmpl != "",
       do: tmpl

  defp resolve_denial_template(_cfg), do: DenialInjector.Template.default()

  defp evidence_capture do
    PayloadCapture.init(
      enabled?: true,
      max_bytes: Application.get_env(:r5e, :cas_max_bytes, 16 * 1024 * 1024)
    )
  end

  defp turn_context(state, payload, request) do
    state.gate_context_base
    |> Map.merge(%{
      model: request["model"],
      started_at: DateTime.utc_now(),
      prompt_hash: :crypto.hash(:sha256, payload),
      response_so_far_hash: <<0::256>>
    })
    |> CedarToolUseGate.populate_estimated_tokens(%{
      prompt_byte_size: byte_size(payload),
      request_params: request
    })
  end

  defp opening_metadata(state) do
    %{
      trace_id: state.trace_id,
      provider: state.llm_provider_config.provider,
      upstream_host: state.llm_provider_config.upstream_host,
      transport: :wss,
      api_format: state.api_format,
      request_path: state.client_path
    }
  end

  defp terminal_response?(payload) do
    case Jason.decode(payload) do
      {:ok, %{"type" => "response.completed"}} -> true
      _ -> false
    end
  end

  defp finish_turn(state, error \\ nil) do
    {summary, directives} = state.parser_module.finalize(state.parser_state)

    unsafe? =
      Enum.any?(directives, fn
        {:parser_error, _} -> true
        {:cedar_eval, _} -> true
        _ -> false
      end)

    state = %{state | parser_summary: summary, parser_failed?: state.parser_failed? or unsafe?}
    call = build_call_state(state)
    call = if error, do: Map.put(call, :error_kind, call.error_kind || error), else: call

    result = Admission.complete(state.admission, call, state.tool_receipts)
    safe_emit_attestation(state)

    case result do
      {:ok, _receipt} ->
        %{
          state
          | turn_active?: false,
            attestation_emitted?: true,
            terminal_pushes: drained_to_pushes(directives)
        }

      {:error, reason} ->
        Logger.error("ws_bridge: completion admission failed #{inspect(reason)}")

        :telemetry.execute([:recurse, :llm_proxy, :admission, :completion_failed], %{count: 1}, %{
          reason: reason
        })

        %{state | turn_active?: false, attestation_emitted?: true, parser_failed?: true}
    end
  rescue
    _ -> %{state | turn_active?: false, attestation_emitted?: true, parser_failed?: true}
  catch
    _, _ -> %{state | turn_active?: false, attestation_emitted?: true, parser_failed?: true}
  end

  defp build_gate_context_base(%LlmProviderConfig{} = cfg, tenant_id, principal) do
    threshold = CedarToolUseGate.resolve_args_inline_threshold(cfg.metadata)

    %{
      principal: %{
        id: principal.principal_id,
        kind: principal.principal_kind,
        # R1-F4: the same provenance the HTTP path carries.
        source: principal.principal_source,
        chatgpt_account_id: principal.chatgpt_account_id,
        claims: principal.claims
      },
      model: "unknown",
      tenant: tenant_id,
      session_id: tenant_id <> ":" <> Recurse.Shared.Ulid.generate(),
      prompt_hash: <<0::256>>,
      response_so_far_hash: <<0::256>>,
      estimated_completion_tokens: 0,
      cedar_bundle_hash: nil,
      upstream_domain: cfg.upstream_host,
      transport: :wss,
      started_at: DateTime.utc_now(),
      args_inline_threshold_bytes: threshold,
      parallel_tool_call_index: nil
    }
  end
end
