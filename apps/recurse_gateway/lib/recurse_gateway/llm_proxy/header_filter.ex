defmodule Recurse.Gateway.LlmProxy.HeaderFilter do
  @moduledoc """
  R-012 header preservation + RFC 7230 hop-by-hop stripping for the LLM
  API proxy.

  Spec source of truth:
  `specs/009-llm-api-proxy/contracts/streaming_proxy.md` §"Header
  preservation (CRITICAL — R-012)" + research.md R-012.

  Two distinct use sites:

    * **Request side** (`forward_request_headers/2`) — strips hop-by-hop
      headers per RFC 7230 §6.1, but preserves every header in the R-012
      whitelist (`Authorization`, `chatgpt-account-id`, `OpenAI-Beta`,
      `originator`, `session_id`, `User-Agent`, all `Sec-WebSocket-*`,
      all `x-anthropic-*`, all `x-goog-*`, plus Content-* / Accept-*).
      Then injects `X-Recurse-Trace-Id` (one ULID per request) +
      `X-Recurse-Tenant-Id` (already-resolved tenant ULID).

    * **Response side** (`forward_response_headers/1`) — forwards every
      upstream response header EXCEPT hop-by-hop (CT-005 / FR-015). The
      explicit purpose: preserve `x-ratelimit-*`, `request-id`,
      `openai-organization`, `openai-processing-ms`, `openai-version`,
      `Retry-After`, etc. We do NOT enumerate the response-side
      whitelist — we enumerate the strip list, because the FR-015
      contract is "client behavior MUST be indistinguishable from
      talking to upstream directly except for the policy-deny case."

  ## Hop-by-hop strip list (RFC 7230 §6.1)

  These headers describe the connection between two adjacent hops, so
  they MUST NOT propagate end-to-end:

      Connection
      Keep-Alive
      Proxy-Authenticate
      Proxy-Authorization
      TE
      Trailers
      Transfer-Encoding
      Upgrade   (preserved on WS upgrade — see `forward_request_headers/2`)

  ## Iron-Law check (`elixir:elixir-thinking`)

  Pure functions. No process, no state. Module-level documented
  contract; tested via `header_filter_test.exs` directly.

  ## Why no whitelist on the response side

  The FR-015 contract is *transparency* — every byte the upstream sends
  back, the client sees, except for headers that describe a hop-only
  property (RFC 7230 §6.1). Maintaining a positive allowlist would
  silently drop new upstream metadata as providers add fields. Strip
  list (closed) + everything-else (open) is the right shape.
  """

  @typedoc """
  HTTP headers in `Plug.Conn` shape — list of `{name, value}` 2-tuples
  with name lower-cased per HTTP/2 normalization. Mint also expects this
  shape outbound.
  """
  @type headers :: [{String.t(), String.t()}]

  @typedoc """
  Resolved per-request context the proxy threads in for header
  injection. `trace_id` is a ULID minted at request entry;
  `tenant_id` is the already-resolved tenant from upstream config.
  """
  @type proxy_meta :: %{
          required(:trace_id) => String.t(),
          required(:tenant_id) => String.t()
        }

  # Hop-by-hop strip list per RFC 7230 §6.1 (lower-cased; comparisons
  # are case-insensitive). `Upgrade` is conditionally preserved when
  # forwarding a WS upgrade — see opts on `forward_request_headers/2`.
  @hop_by_hop_request ~w[
    connection
    keep-alive
    proxy-authenticate
    proxy-authorization
    te
    trailers
    transfer-encoding
  ]

  # Same list for response-side stripping. Upgrade is normally hop-by-hop;
  # WS upgrade response (101) is handled by Mint/WebSockAdapter directly,
  # so the response-side path never sees an Upgrade header on the data
  # plane. Strip it defensively.
  @hop_by_hop_response ~w[
    connection
    keep-alive
    proxy-authenticate
    proxy-authorization
    te
    trailers
    transfer-encoding
    upgrade
  ]

  # Trace id header name + tenant id header name. Spec calls these out
  # as the only headers the proxy MAY ADD to the request (per R-012:
  # "the proxy MAY add: X-Recurse-Trace-Id ..., MUST NOT remove any
  # client-supplied headers").
  @trace_id_header "x-recurse-trace-id"
  @tenant_id_header "x-recurse-tenant-id"

  # Headers whose VALUE is a credential. Never logged verbatim — see
  # `redact_credential/1` (spec 012 S2: the Claude Code OAuth bearer and
  # `x-api-key` both cross this proxy).
  @credential_headers ~w[authorization x-api-key proxy-authorization]

  @doc """
  Filter request headers for forwarding upstream.

  ## Steps

    1. Strip hop-by-hop headers per RFC 7230 §6.1.
       - When `:websocket_upgrade?` is true (default false), the
         `Upgrade` and `Connection` headers ARE preserved because
         WebSocket framing requires `Connection: upgrade` +
         `Upgrade: websocket` to traverse end-to-end. The rest of
         the hop-by-hop list still applies.
    2. Inject `X-Recurse-Trace-Id` + `X-Recurse-Tenant-Id` (overwriting
       any client-supplied value to prevent spoofing — these are
       proxy-controlled).
    3. When `:upstream_host` is given (spec 012 S2 default-upstream
       mode), replace the client's `Host` header with it. In the DNS-
       override (Codex) mode the inbound Host already IS the upstream,
       so the rewrite is a no-op there; in default-upstream mode the
       inbound Host is `localhost:4443` and MUST NOT reach
       `api.anthropic.com` (Mint sends the regular `host` header
       alongside HTTP/2 `:authority`, and a mismatch is rejected).

  ## Invariants

    * **No client-supplied header is silently dropped** beyond the
      RFC 7230 strip list. Per R-012: every entry in the whitelist
      passes through unchanged.
    * **The R-012 whitelist is documented for clarity but NOT
      enforced as an allowlist** — the strip-list-only approach
      future-proofs against new client headers (e.g., a future Codex
      adds `x-codex-session-tier`; we don't want a stale whitelist
      to drop it).

  ## Examples

      iex> headers = [
      ...>   {"authorization", "Bearer abc"},
      ...>   {"chatgpt-account-id", "uuid"},
      ...>   {"connection", "keep-alive"},
      ...>   {"transfer-encoding", "chunked"}
      ...> ]
      iex> meta = %{trace_id: "01ARZ", tenant_id: "01TENANT"}
      iex> result = Recurse.Gateway.LlmProxy.HeaderFilter.forward_request_headers(headers, meta)
      iex> Enum.find(result, fn {k, _v} -> k == "authorization" end)
      {"authorization", "Bearer abc"}
      iex> Enum.find(result, fn {k, _v} -> k == "transfer-encoding" end)
      nil
      iex> Enum.find(result, fn {k, _v} -> k == "x-recurse-trace-id" end)
      {"x-recurse-trace-id", "01ARZ"}
  """
  @spec forward_request_headers(headers(), proxy_meta(), keyword()) :: headers()
  def forward_request_headers(headers, %{trace_id: trace_id, tenant_id: tenant_id}, opts \\ [])
      when is_list(headers) and is_binary(trace_id) and is_binary(tenant_id) do
    websocket_upgrade? = Keyword.get(opts, :websocket_upgrade?, false)
    upstream_host = Keyword.get(opts, :upstream_host)

    strip_set =
      if websocket_upgrade? do
        # WS upgrade preserves Upgrade + Connection: upgrade end-to-end.
        # The rest of hop-by-hop still applies.
        @hop_by_hop_request -- ~w[connection]
      else
        @hop_by_hop_request
      end

    headers
    |> Enum.reject(fn {name, _value} -> downcase(name) in strip_set end)
    # Strip `accept-encoding` so the upstream replies identity-encoded.
    #
    # This proxy is not a dumb relay: it PARSES the response stream to
    # extract tool-use intents for Cedar. Codex sends
    # `accept-encoding: gzip`, and forwarding that had upstream compress
    # the SSE stream — so `parse_chunk/2` was handed gzip bytes, matched
    # no events, and extracted no intents. The visible symptom is a
    # receipt whose `model` is "unknown" and whose
    # `tool_use_intent_count` is 0 even though the model demonstrably
    # called a tool: policy silently degrades to allow-everything
    # because the gate never sees anything to evaluate.
    #
    # Trading client-side transfer bytes for the ability to enforce
    # policy at all is the right trade for an inspecting proxy. The WS
    # path is unaffected (frames are not content-encoded).
    |> Enum.reject(fn {name, _value} -> downcase(name) == "accept-encoding" end)
    # Strip any incoming client-set X-Recurse-* — never trust client to
    # set our own injection headers (spoofing defense).
    |> Enum.reject(fn {name, _value} ->
      downcase(name) in [@trace_id_header, @tenant_id_header]
    end)
    |> rewrite_host(upstream_host)
    |> List.insert_at(-1, {@trace_id_header, trace_id})
    |> List.insert_at(-1, {@tenant_id_header, tenant_id})
  end

  defp rewrite_host(headers, nil), do: headers

  defp rewrite_host(headers, upstream_host) when is_binary(upstream_host) do
    headers
    |> Enum.reject(fn {name, _value} -> downcase(name) == "host" end)
    |> List.insert_at(-1, {"host", upstream_host})
  end

  @doc """
  Filter response headers for forwarding back to the client.

  Strips hop-by-hop per RFC 7230. Forwards all other upstream headers
  unchanged (FR-015 transparency: rate-limit headers, request-id,
  openai-organization, etc. all pass through).

  `content-length` is ALSO stripped, for framing rather than hop-by-hop
  reasons: `StreamingProxy` re-frames every response with
  `Plug.Conn.send_chunked/2`, which emits `Transfer-Encoding: chunked`.
  A response carrying both that and the upstream's `Content-Length` is
  malformed — RFC 7230 §3.3.3 has recipients treat the combination as an
  error or ignore the length. In practice curl reports
  `0 out of N bytes received` and hangs, and Codex CLI's rustls client
  fails the turn with `error decoding response body`. The upstream's
  length describes the upstream's framing, which stops being true the
  moment we re-chunk.

  This mirrors the same lesson already learned on the request side, where
  `WebSocketBridge` strips `content-length` from the forwarded upgrade
  headers because `Mint.WebSocket` regenerates its own.

  ## Invariants (CT-005)

    * `x-ratelimit-limit-requests`, `x-ratelimit-remaining-requests`,
      `x-ratelimit-reset-requests`, `openai-organization`,
      `openai-processing-ms`, `request-id` MUST round-trip unchanged.
    * `content-encoding` is deliberately NOT stripped — we forward the
      upstream body bytes verbatim without decompressing, so the client
      still needs the encoding to decode them.
  """
  @spec forward_response_headers(headers()) :: headers()
  def forward_response_headers(headers) when is_list(headers) do
    Enum.reject(headers, fn {name, _value} ->
      downcase(name) in @hop_by_hop_response or downcase(name) == "content-length"
    end)
  end

  @doc """
  Returns the canonical R-012 whitelist for telemetry / docs purposes.

  This list is NOT consulted at filter time (we strip hop-by-hop and
  forward everything else); it's exposed so contract tests + audit
  documentation can iterate the named-explicitly headers from a single
  source of truth.
  """
  @spec r012_whitelist() :: [String.t()]
  def r012_whitelist do
    [
      "authorization",
      "chatgpt-account-id",
      "openai-beta",
      "originator",
      "session_id",
      "user-agent",
      "content-type",
      "accept",
      "accept-encoding",
      # Spec 012 S2 — Claude Code / Anthropic Messages (spike-s0.md U1).
      # `anthropic-beta` carries `oauth-2025-04-20`; without it upstream
      # rejects the OAuth bearer. All forwarded VERBATIM, never normalised.
      "x-api-key",
      "anthropic-version",
      "anthropic-beta",
      "anthropic-dangerous-direct-browser-access",
      "x-app",
      "x-claude-code-session-id"
      # Plus prefixed families: "sec-websocket-*", "x-anthropic-*",
      # "x-goog-*", "x-stainless-*". Prefix-membership is by
      # `String.starts_with?/2`, not enumerable, so we don't list every
      # variant.
    ]
  end

  @doc """
  Header names whose value is a credential (`authorization`, `x-api-key`,
  `proxy-authorization`). Lower-cased.
  """
  @spec credential_headers() :: [String.t()]
  def credential_headers, do: @credential_headers

  @doc """
  True when `name` is a credential-bearing header (case-insensitive).
  """
  @spec credential_header?(String.t()) :: boolean()
  def credential_header?(name) when is_binary(name), do: downcase(name) in @credential_headers
  def credential_header?(_), do: false

  @doc """
  Redact a credential value for logging: the first 8 characters plus the
  total length, never the value. Same convention as the S0 spike stub
  (`Bearer s…<redacted len=115>`), so log lines and fixture header dumps
  read the same way.

      iex> Recurse.Gateway.LlmProxy.HeaderFilter.redact_credential("Bearer sk-ant-oat01-abcdefghij")
      "Bearer s…<redacted len=30>"

      iex> Recurse.Gateway.LlmProxy.HeaderFilter.redact_credential("short")
      "…<redacted len=5>"
  """
  @spec redact_credential(String.t() | nil) :: String.t()
  def redact_credential(value) when is_binary(value) do
    len = String.length(value)

    if len > 8 do
      String.slice(value, 0, 8) <> "…<redacted len=#{len}>"
    else
      "…<redacted len=#{len}>"
    end
  end

  def redact_credential(_), do: "…<redacted len=0>"

  @doc """
  Return `headers` with every credential value replaced by its
  `redact_credential/1` form. The ONLY shape in which request headers may
  be logged or inspected.
  """
  @spec redact_headers(headers()) :: headers()
  def redact_headers(headers) when is_list(headers) do
    Enum.map(headers, fn {name, value} ->
      if credential_header?(name), do: {name, redact_credential(value)}, else: {name, value}
    end)
  end

  @doc """
  Returns the hop-by-hop request strip list (lower-cased). Test-only
  visibility for CT-005 strip-list-only assertions.
  """
  @spec hop_by_hop_request() :: [String.t()]
  def hop_by_hop_request, do: @hop_by_hop_request

  @doc "Returns the hop-by-hop response strip list (lower-cased)."
  @spec hop_by_hop_response() :: [String.t()]
  def hop_by_hop_response, do: @hop_by_hop_response

  @doc "Returns the canonical X-Recurse-Trace-Id header name."
  @spec trace_id_header() :: String.t()
  def trace_id_header, do: @trace_id_header

  @doc "Returns the canonical X-Recurse-Tenant-Id header name."
  @spec tenant_id_header() :: String.t()
  def tenant_id_header, do: @tenant_id_header

  # Cheap inline downcase: HTTP/2 normalizes header names to lower-case;
  # `Plug.Conn.req_headers` does the same. We re-downcase defensively in
  # case some callers hand us mixed-case (older HTTP/1.1 paths).
  defp downcase(name), do: String.downcase(name, :ascii)
end
