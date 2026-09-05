defmodule Recurse.Gateway.LlmProxy.ProxyRouter do
  @moduledoc """
  Plug router for the LLM API proxy surface (Phase 3 Sub-3.3 / T027 +
  T028).

  Spec source of truth:
  `specs/009-llm-api-proxy/contracts/streaming_proxy.md` §"Routing".

  ## Match strategy

  This router uses the **catch-all + dispatch** pattern rather than
  enumerating per-provider paths in the `Plug.Router` macro DSL. The
  reason: routing is `(Host header, request path)`-driven, not
  `path-only`-driven. Codex's preferred path is
  `wss://chatgpt.com/backend-api/codex/responses` — but the same
  recurse-gateway also fronts `https://api.openai.com/v1/responses`,
  `https://api.anthropic.com/v1/messages`, etc. The Host header is
  what selects the upstream; the path is forwarded verbatim.

  So `match _, do: dispatch_or_fall_through(conn)` matches everything,
  and dispatch_or_fall_through:

    1. Tenant-resolves from request context (Sub-3.7 will add per-conn
       tenant binding via SPIFFE/JWT; this MR uses a default-tenant
       env-var seam so we can wire the router into the supervision
       tree before the tenant-binding work lands).
    2. Looks up `LlmProviderConfig` via `UpstreamResolver.resolve/2`.
    3. If `auth.openai.com` Host header → dispatch to `AuthPassthrough`.
    4. If WebSocket upgrade headers present → dispatch to
       `WebSocketBridge.upgrade/2`.
    5. Else → dispatch to `StreamingProxy.proxy/2`.
    6. If no upstream config → halt with 502 (no fall-through to the
       audit-plane router; this hostname was forwarded here in error).

  ## Default-upstream mode (spec 012 D3)

  Claude Code is pointed at the proxy with `ANTHROPIC_BASE_URL=
  http://localhost:4443`, so the inbound Host is the gateway itself, not
  the upstream. When `:llm_proxy_default_upstream_host` is configured
  (`R5E_LLM_PROXY_DEFAULT_UPSTREAM_HOST`, default `api.anthropic.com`
  whenever the proxy is enabled; `none` disables):

    * a Host that names the gateway itself (`localhost`, `127.0.0.1`,
      `::1`, `0.0.0.0`, `host.docker.internal`, the container's own
      hostname) resolves the `LlmProviderConfig` for the default upstream
      host instead;
    * any other Host keeps plain Host-header routing: no row →
      `ERR_NO_UPSTREAM_CONFIG`. Only with `R5E_LLM_PROXY_FALLBACK_UNKNOWN_HOSTS=
      true` (`:llm_proxy_fallback_unknown_hosts`, default false) does a
      Host with no row fall back to the default row too — logged at
      warning per request, because it forwards that request's credential
      to a provider the client did not name. A row that exists but is
      disabled never falls back (`provider_disabled` is an operator
      decision).

  The outbound `Host` header is rewritten to the upstream by
  `HeaderFilter.forward_request_headers/3` (`:upstream_host`), and the
  path + query string (`/v1/messages?beta=true`) are forwarded verbatim
  by `StreamingProxy`. Host-header routing for DNS-override clients
  (Codex → `chatgpt.com`) is unchanged: a Host that matches a row keeps
  matching that row first.

  `HEAD /api/hello` (and `GET`) is Claude Code's unauthenticated
  connectivity probe, sent before the first turn. When the Host is the
  gateway itself or has an `:anthropic_messages` row it is answered
  locally with `200 {}` rather than proxied: it carries no credential,
  produces nothing worth attesting, and answering it here keeps the probe
  working even when the upstream row is missing (the next `/v1/messages`
  then returns the structured `ERR_NO_UPSTREAM_CONFIG`). For any other
  Host the path is an ordinary proxy request.

  ## Mounting (T028)

  This router is mounted by the application supervisor BEFORE the
  audit-plane router so the LLM hostnames hit it first. The mount
  surface is a separate Bandit child (port + endpoint module
  configurable) — a single Bandit doesn't multiplex two Plug-shaped
  routers, but two Bandit endpoints on different ports do. For
  Phase 3 we ship as a sibling Bandit child; the audit-plane port
  stays on 4000 and the LLM-proxy port lives on (default) 4443.

  Operators can disable the proxy entirely with
  `config :recurse_gateway, :llm_proxy_enabled?, false` (the default
  in tests + non-LLM-proxy deployments).

  ## Iron-Law check (`elixir:phoenix-thinking`)

  `Plug.Router` is pure function composition. No GenServer. The
  per-request worker is owned by Bandit; per-WS process is owned by
  WebSockAdapter. Nothing in this router holds state across requests.
  """

  use Plug.Router

  alias Recurse.Gateway.LlmProxy.AuthPassthrough
  alias Recurse.Gateway.LlmProxy.HeaderFilter
  alias Recurse.Gateway.LlmProxy.StreamingProxy
  alias Recurse.Gateway.LlmProxy.UpstreamResolver
  alias Recurse.Gateway.LlmProxy.WebSocketBridge
  alias Recurse.Providers.Schemas.LlmProviderConfig

  require Logger

  # NOTE: do NOT plug Plug.Parsers here. The proxy must forward request
  # bodies upstream UNCHANGED — including their original Content-Type +
  # Content-Length. Running JSON parser would consume the body
  # (`Plug.Conn.read_body/2` returns `:ok` only once) and re-encoding
  # would re-canonicalize the JSON, changing whitespace and breaking
  # any provider that hashes the body for replay protection.
  #
  # The downstream modules (StreamingProxy, AuthPassthrough,
  # WebSocketBridge) call `Plug.Conn.read_body/2` themselves to drain
  # the inbound bytes once and forward them verbatim.

  plug(:match)
  plug(:dispatch)

  # ---------------------------------------------------------------------------
  # Healthz/readyz on this port — no auth, no proxying. Useful for
  # container orchestrators that scrape the LLM-proxy port directly.
  # ---------------------------------------------------------------------------

  get "/healthz" do
    send_resp(conn, 200, "ok")
  end

  get "/readyz" do
    Recurse.Gateway.Observability.Readyz.call(conn, [])
  end

  # Claude Code connectivity probe (spike-s0.md "Requests Claude Code
  # makes per -p turn", row 1). No auth, no proxying, no receipt — but
  # only for the gateway's own Host or one with an Anthropic row; any
  # other Host is routed like every other path.
  match "/api/hello", via: [:head, :get] do
    if hello_host?(conn) do
      conn
      |> Plug.Conn.put_resp_content_type("application/json")
      |> send_resp(200, "{}")
    else
      dispatch_proxy(conn)
    end
  end

  # ---------------------------------------------------------------------------
  # Catch-all — everything else is a candidate proxy request.
  # ---------------------------------------------------------------------------

  match _ do
    dispatch_proxy(conn)
  end

  # ---------------------------------------------------------------------------
  # Dispatch logic
  # ---------------------------------------------------------------------------

  @spec dispatch_proxy(Plug.Conn.t()) :: Plug.Conn.t()
  def dispatch_proxy(%Plug.Conn{} = conn) do
    host = request_host(conn)
    tenant_id = resolve_tenant_id(conn)

    if AuthPassthrough.passthrough_host?(host) do
      AuthPassthrough.proxy(conn,
        upstream_host: host,
        upstream_port: 443,
        upstream_scheme: :https,
        tenant_id: tenant_id
      )
    else
      case select_upstream(tenant_id, host) do
        {:ok, %LlmProviderConfig{enabled: true} = cfg} ->
          dispatch_for_config(conn, cfg, tenant_id)

        {:ok, _disabled_cfg} ->
          send_unconfigured(conn, "provider_disabled")

        {:error, :not_configured} ->
          send_unconfigured(conn, "no_config_for_host")

        {:error, :not_allowed} ->
          send_unconfigured(conn, "provider_disabled")
      end
    end
  end

  @doc """
  Pick the `LlmProviderConfig` for an inbound `(tenant_id, host)`.

  Pure routing decision, exposed so the default-upstream rule (D3) can be
  unit-tested without a network hop:

    * gateway-self Host + default upstream configured → the default
      upstream's row
    * any other Host → that Host's row; `:not_configured` when there is
      none, unless `:llm_proxy_fallback_unknown_hosts` is true, in which
      case the default upstream's row (logged at warning)
    * `:not_allowed` (row exists, disabled) is returned as-is; never
      falls back
    * no default upstream configured → plain Host-header routing
  """
  @spec select_upstream(String.t(), String.t()) :: UpstreamResolver.result()
  def select_upstream(tenant_id, host) do
    default = default_upstream_host()

    if is_binary(default) and self_host?(host) do
      resolve_default(tenant_id, host, default)
    else
      case UpstreamResolver.resolve(tenant_id, host) do
        {:error, :not_configured} = miss when is_binary(default) and default != host ->
          resolve_unknown_host(tenant_id, host, default, miss)

        other ->
          other
      end
    end
  end

  # A Host with no row: `:not_configured` unless the operator opted into
  # the wide fallback, which forwards this request's credential to a
  # provider the client did not name — hence the per-request warning.
  defp resolve_unknown_host(tenant_id, host, default, miss) do
    if fallback_unknown_hosts?() do
      Logger.warning(fn ->
        "proxy_router: Host #{inspect(host)} has no LlmProviderConfig; redirecting to " <>
          "default upstream #{inspect(default)} (R5E_LLM_PROXY_FALLBACK_UNKNOWN_HOSTS=true)"
      end)

      resolve_default(tenant_id, host, default)
    else
      miss
    end
  end

  @doc """
  True when a Host with no `LlmProviderConfig` row may be redirected to
  the default upstream (`R5E_LLM_PROXY_FALLBACK_UNKNOWN_HOSTS=true`).
  Default false.
  """
  @spec fallback_unknown_hosts?() :: boolean()
  def fallback_unknown_hosts? do
    Application.get_env(:recurse_gateway, :llm_proxy_fallback_unknown_hosts, false) == true
  end

  defp resolve_default(tenant_id, inbound_host, default) do
    result = UpstreamResolver.resolve(tenant_id, default)

    Logger.debug(fn ->
      "proxy_router: default-upstream inbound_host=#{inspect(inbound_host)} " <>
        "upstream=#{inspect(default)} result=#{inspect(elem(result, 0))}"
    end)

    result
  end

  @doc """
  The configured default upstream host (`:llm_proxy_default_upstream_host`),
  or `nil` when default-upstream mode is off.
  """
  @spec default_upstream_host() :: String.t() | nil
  def default_upstream_host do
    case Application.get_env(:recurse_gateway, :llm_proxy_default_upstream_host) do
      host when is_binary(host) and host != "" and host != "none" ->
        String.downcase(host, :ascii)

      _ ->
        nil
    end
  end

  # Loopback / self names plus the container's own hostname. `host.docker.
  # internal` covers a Claude Code running in a sibling container that
  # reaches the gateway through the Docker host.
  @self_hosts ~w[localhost 127.0.0.1 ::1 0.0.0.0 host.docker.internal gateway recurse-gateway]

  @doc """
  True when `host` (already lower-cased, port stripped) names the gateway
  itself rather than an upstream.
  """
  @spec self_host?(String.t()) :: boolean()
  def self_host?(host) when is_binary(host) do
    host in @self_hosts or host == local_hostname() or String.starts_with?(host, "127.")
  end

  def self_host?(_), do: false

  defp local_hostname do
    case System.get_env("HOSTNAME") do
      name when is_binary(name) and name != "" ->
        String.downcase(name, :ascii)

      _ ->
        case :inet.gethostname() do
          {:ok, charlist} -> charlist |> List.to_string() |> String.downcase(:ascii)
          _ -> nil
        end
    end
  end

  # `/api/hello` is answered locally for the gateway's own Host and for
  # Hosts that carry an Anthropic Messages row (the DNS-override shape).
  defp hello_host?(%Plug.Conn{} = conn) do
    host = request_host(conn)

    self_host?(host) or
      match?(
        {:ok, %LlmProviderConfig{api_format: :anthropic_messages}},
        UpstreamResolver.resolve(resolve_tenant_id(conn), host)
      )
  end

  defp dispatch_for_config(conn, %LlmProviderConfig{} = cfg, tenant_id) do
    if websocket_upgrade?(conn) do
      WebSocketBridge.upgrade(conn,
        llm_provider_config: cfg,
        tenant_id: tenant_id
      )
    else
      StreamingProxy.proxy(conn, %{
        llm_provider_config: cfg,
        tenant_id: tenant_id
      })
    end
  end

  # ---------------------------------------------------------------------------
  # Header / context extraction
  # ---------------------------------------------------------------------------

  defp request_host(%Plug.Conn{} = conn) do
    case Plug.Conn.get_req_header(conn, "host") do
      [host | _] -> downcase_host(host)
      _ -> downcase_host(conn.host)
    end
  end

  # Strip port if present (RFC 7230: Host = uri-host [ ":" port ]). An
  # IPv6 literal is bracketed (`[::1]:4443`) — take the part inside the
  # brackets rather than splitting on its colons.
  defp downcase_host("[" <> rest) do
    rest
    |> String.split("]", parts: 2)
    |> List.first()
    |> String.downcase(:ascii)
  end

  defp downcase_host(host) when is_binary(host) do
    host
    |> String.split(":", parts: 2)
    |> List.first()
    |> String.downcase(:ascii)
  end

  defp downcase_host(_), do: ""

  # Sub-3.7 will replace this with the per-connection tenant binding
  # extracted from SPIFFE/JWT identity. For Sub-3.3 we resolve from a
  # configured default so the proxy router can be exercised end-to-end
  # without identity-context wiring.
  defp resolve_tenant_id(%Plug.Conn{} = conn) do
    case Plug.Conn.get_req_header(conn, HeaderFilter.tenant_id_header()) do
      [tenant_id | _] when is_binary(tenant_id) and tenant_id != "" ->
        tenant_id

      _ ->
        Application.get_env(:recurse_gateway, :llm_proxy_default_tenant_id, "default")
    end
  end

  defp websocket_upgrade?(%Plug.Conn{} = conn) do
    upgrade =
      conn
      |> Plug.Conn.get_req_header("upgrade")
      |> List.first()

    is_binary(upgrade) and String.downcase(upgrade, :ascii) == "websocket"
  end

  defp send_unconfigured(conn, reason) do
    body =
      JSON.encode!(%{
        "error" => %{
          "code" => "ERR_NO_UPSTREAM_CONFIG",
          "kind" => reason,
          "message" =>
            "No LlmProviderConfig matches this Host header (or the default upstream) for the " <>
              "resolved tenant. Seed one with R5E_LLM_PROXY_UPSTREAMS=anthropic, configure the " <>
              "provider in recurse_providers, or correct the customer DNS override."
        }
      })

    conn
    |> Plug.Conn.put_resp_content_type("application/json")
    |> Plug.Conn.send_resp(502, body)
  end
end
