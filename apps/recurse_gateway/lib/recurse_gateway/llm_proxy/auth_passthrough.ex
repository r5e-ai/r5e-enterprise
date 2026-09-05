defmodule Recurse.Gateway.LlmProxy.AuthPassthrough do
  @moduledoc """
  Special-case forwarder for `auth.openai.com` traffic.

  Spec source of truth:
  `specs/009-llm-api-proxy/contracts/streaming_proxy.md` §"Auth flow
  special cases" + spec.md FR-002 + research.md R-014.

  When the customer's DNS override routes `auth.openai.com` →
  recurse-gateway, the OAuth flow (authorize / token / refresh-grant)
  passes through without parser invocation. There are no `tool_use`
  intents in OAuth flows; running the parser would burn cycles and
  potentially mishandle non-LLM JSON.

  This module mirrors `StreamingProxy.proxy/2`'s shape but skips the
  per-chunk parser invocation and skips Cedar gating (Cedar-gating-of-
  login is Phase 2 enhancement per R-006). Header preservation + DNS
  bypass + TLS-to-real-upstream still apply.

  ## Why a separate module rather than a flag on StreamingProxy?

  The Cedar gate (Sub-3.4) wires into the parser-emitted-intent loop
  in `StreamingProxy`. An `auth.openai.com` request must not even
  *enter* that loop, otherwise an empty-intents code path will accrete
  Cedar-eval logic by mistake. Splitting the dispatch at the router
  layer (per `ProxyRouter.dispatch/3`) makes the auth-passthrough
  guarantee structural rather than convention-by-flag. The price is
  ~30 LOC of conditional dispatch in the router; the gain is no
  accidental Cedar-eval-in-OAuth-flow regression vector.

  ## Iron-Law check (`elixir:elixir-thinking`, `otp-thinking`)

  Plain functions invoked from the per-request Bandit worker. No
  process. No state across calls. The Mint outbound conn is opened
  per-call and closed when the upstream stream ends.
  """

  alias Recurse.Gateway.LlmProxy.BypassDnsResolver
  alias Recurse.Gateway.LlmProxy.HeaderFilter

  require Logger

  @doc """
  Returns `true` when the inbound request's Host header matches a
  byte-for-byte-only upstream (currently only `auth.openai.com`).

  Per R-014 sequence diagram, this is the ONLY hostname for which
  the proxy skips parser invocation entirely.
  """
  @spec passthrough_host?(String.t()) :: boolean()
  def passthrough_host?(host) when is_binary(host) do
    String.downcase(host, :ascii) == "auth.openai.com"
  end

  def passthrough_host?(_), do: false

  @doc """
  Forward an HTTPS request byte-for-byte to `auth.openai.com`.

  ## Steps

    1. Resolve real upstream IP via BypassDnsResolver (corp DNS routes
       this hostname to recurse-gateway; we need to bypass).
    2. Open Mint HTTP/1.1 or HTTP/2 connection (TLS).
    3. Forward request headers (R-012 strip + inject) + body unchanged.
    4. Stream response status + headers + body back to client. Does
       NOT invoke the parser. Does NOT Cedar-gate.
    5. Close conn on stream end.

  Returns the (possibly-chunked) `Plug.Conn`.
  """
  @spec proxy(Plug.Conn.t(), keyword()) :: Plug.Conn.t()
  def proxy(%Plug.Conn{} = conn, opts) do
    upstream_host = Keyword.fetch!(opts, :upstream_host)
    upstream_port = Keyword.get(opts, :upstream_port, 443)
    upstream_scheme = Keyword.get(opts, :upstream_scheme, :https)
    tenant_id = Keyword.fetch!(opts, :tenant_id)

    case Plug.Conn.read_body(conn, length: 10_000_000) do
      {:ok, body, conn} when byte_size(body) <= 10_000_000 ->
        connect_and_proxy(conn, body, upstream_scheme, upstream_host, upstream_port, tenant_id)

      {:more, _, conn} ->
        Plug.Conn.send_resp(conn, 413, "authentication request too large")

      {:ok, _, conn} ->
        Plug.Conn.send_resp(conn, 413, "authentication request too large")

      {:error, _} ->
        Plug.Conn.send_resp(conn, 400, "authentication request could not be read")
    end
  end

  defp connect_and_proxy(conn, body, upstream_scheme, upstream_host, upstream_port, tenant_id) do
    case open_upstream(upstream_scheme, upstream_host, upstream_port) do
      {:ok, mint_conn} ->
        do_proxy(conn, body, mint_conn, upstream_host, tenant_id)

      {:error, reason} ->
        Logger.warning(fn ->
          "auth_passthrough: upstream connect failed host=#{upstream_host} reason=#{inspect(reason)}"
        end)

        send_503(conn, "upstream_connection_failed")
    end
  end

  # Resolve real upstream IP via the BypassDnsResolver (corp DNS routes
  # the LLM hostnames back to recurse-gateway; we need to bypass to
  # actually reach upstream). Mint's `:hostname` opt sets the SNI/Host
  # header even when address is an IP tuple.
  @spec open_upstream(:http | :https, String.t(), pos_integer()) ::
          {:ok, Mint.HTTP.t()} | {:error, term()}
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

      {:error, _} = err ->
        # Fall back to system DNS (Mint resolves via `:inet.getaddrs/3`)
        # — avoids hard-failing on test-time stubs that don't seed a
        # bypass entry. Production paths should always resolve via
        # bypass.
        case Mint.HTTP.connect(scheme, host, port,
               transport_opts: tls_opts(scheme),
               protocols: [:http2, :http1]
             ) do
          {:ok, conn} -> {:ok, conn}
          {:error, _} -> err
        end
    end
  end

  defp tls_opts(:https) do
    # Use system trust store. WS/HTTPS to real upstreams (auth.openai.com,
    # chatgpt.com, api.openai.com) all use real CA certs. Test-only:
    # `:llm_proxy_outbound_tls_opts` overrides for self-signed mock
    # upstreams. Default is :verify_peer with the OTP-supplied cacerts.
    Application.get_env(:recurse_gateway, :llm_proxy_outbound_tls_opts, [
      verify: :verify_peer,
      cacerts: :public_key.cacerts_get()
    ])
  rescue
    _ -> [verify: :verify_peer]
  end

  defp tls_opts(:http), do: []

  defp ip_to_string({a, b, c, d}), do: "#{a}.#{b}.#{c}.#{d}"
  defp ip_to_string(other) when is_binary(other), do: other

  defp do_proxy(conn, body, mint_conn, upstream_host, tenant_id) do
    trace_id = ensure_trace_id(conn)

    meta = %{trace_id: trace_id, tenant_id: tenant_id}
    fwd_headers = HeaderFilter.forward_request_headers(conn.req_headers, meta)

    method = String.upcase(conn.method)
    path = request_path_with_query(conn)

    case Mint.HTTP.request(mint_conn, method, path, fwd_headers, body) do
      {:ok, mint_conn, request_ref} ->
        receive_loop(conn, mint_conn, request_ref, upstream_host)

      {:error, mint_conn, reason} ->
        Mint.HTTP.close(mint_conn)

        Logger.warning(fn ->
          "auth_passthrough: request send failed host=#{upstream_host} reason=#{inspect(reason)}"
        end)

        send_503(conn, "upstream_connection_failed")
    end
  end

  # The proxy receives Mint messages on its mailbox via the request
  # worker process. We loop until we see :done | :error. Per spec, we
  # do NOT buffer — once response status + headers are received, we
  # send_chunked + chunk each :data immediately.
  defp receive_loop(conn, mint_conn, request_ref, upstream_host) do
    receive_loop(conn, mint_conn, request_ref, upstream_host, %{
      headers_sent?: false,
      conn: conn
    })
  end

  defp receive_loop(plug_conn, mint_conn, request_ref, upstream_host, state) do
    receive do
      message ->
        case Mint.HTTP.stream(mint_conn, message) do
          {:ok, mint_conn, responses} ->
            {plug_conn, state, halt?} =
              Enum.reduce_while(responses, {plug_conn, state, false}, fn
                {:status, ^request_ref, status}, {pc, st, _h} ->
                  st = Map.put(st, :status, status)
                  {:cont, {pc, st, false}}

                {:headers, ^request_ref, headers}, {pc, st, _h} ->
                  pc = send_response_head(pc, st, headers)
                  st = Map.put(st, :headers_sent?, true)
                  {:cont, {pc, st, false}}

                {:data, ^request_ref, data}, {pc, st, _h} ->
                  pc =
                    if st.headers_sent? do
                      case Plug.Conn.chunk(pc, data) do
                        {:ok, pc} -> pc
                        {:error, _reason} -> pc
                      end
                    else
                      # Status arrived but headers not yet — buffer status only;
                      # in practice Mint emits status+headers together but
                      # be defensive.
                      pc
                    end

                  {:cont, {pc, st, false}}

                {:done, ^request_ref}, {pc, st, _h} ->
                  {:halt, {pc, st, true}}

                {:error, ^request_ref, _reason}, {pc, st, _h} ->
                  {:halt, {pc, st, true}}

                _other, acc ->
                  {:cont, acc}
              end)

            if halt? do
              _ = Mint.HTTP.close(mint_conn)
              plug_conn
            else
              receive_loop(plug_conn, mint_conn, request_ref, upstream_host, state)
            end

          {:error, _mint_conn, _reason, _responses} ->
            _ = Mint.HTTP.close(mint_conn)
            plug_conn

          :unknown ->
            receive_loop(plug_conn, mint_conn, request_ref, upstream_host, state)
        end
    after
      300_000 ->
        _ = Mint.HTTP.close(mint_conn)
        plug_conn
    end
  end

  defp send_response_head(plug_conn, %{status: status}, headers) do
    fwd_headers = HeaderFilter.forward_response_headers(headers)

    plug_conn =
      Enum.reduce(fwd_headers, plug_conn, fn {name, value}, acc ->
        Plug.Conn.put_resp_header(acc, name, value)
      end)

    Plug.Conn.send_chunked(plug_conn, status)
  end

  defp send_response_head(plug_conn, _state_no_status, _headers) do
    # Defensive: status not yet observed.
    Plug.Conn.send_chunked(plug_conn, 502)
  end

  defp send_503(plug_conn, error_kind) do
    body =
      JSON.encode!(%{
        "error" => %{
          "code" => "ERR_UPSTREAM_UNAVAILABLE",
          "kind" => error_kind,
          "message" => "Upstream unavailable; recurse-gateway could not complete the proxied request."
        }
      })

    plug_conn
    |> Plug.Conn.put_resp_content_type("application/json")
    |> Plug.Conn.send_resp(503, body)
  end

  defp request_path_with_query(%Plug.Conn{request_path: path, query_string: ""}), do: path

  defp request_path_with_query(%Plug.Conn{request_path: path, query_string: q}),
    do: path <> "?" <> q

  defp ensure_trace_id(conn) do
    case Plug.Conn.get_req_header(conn, HeaderFilter.trace_id_header()) do
      [id | _] when is_binary(id) and id != "" -> id
      _ -> Recurse.Shared.Ulid.generate()
    end
  rescue
    _ ->
      # Fallback if the Ulid module isn't available in this build path —
      # any monotonic-ish unique id works for tracing.
      Integer.to_string(System.unique_integer([:positive, :monotonic]))
  end
end
