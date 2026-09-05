defmodule Recurse.Gateway.LlmProxy.UpstreamResolver do
  @moduledoc """
  Maps an inbound proxy request `(tenant_id, host_header)` to the
  `LlmProviderConfig` row that drives upstream forwarding.

  Spec source of truth:
  `specs/009-llm-api-proxy/contracts/streaming_proxy.md` §UpstreamResolver
  + `specs/009-llm-api-proxy/data-model.md` §LlmProviderConfig.

  This is the boundary between the inbound proxy (Phase 3.3 onward) and
  the persisted per-tenant routing config in `recurse_providers`. The
  resolver is intentionally a thin wrapper — `Recurse.Providers.LlmProviders.lookup/2`
  already does the SQL-level work; this module exists so the proxy
  doesn't reach across the umbrella-app boundary directly (Principle V
  Provider-Interface Neutrality: gateway code reads providers' contexts
  through documented seams, not raw Repo calls).

  ## Return shapes

    * `{:ok, %LlmProviderConfig{}}` — row exists AND `enabled = true`
    * `{:error, :not_configured}` — no row matches `(tenant_id, host_header)`
    * `{:error, :not_allowed}` — row exists but is disabled

  Both error tags are surfaced distinctly so the attestation emitter
  (Phase 5) can record the precise failure-mode tag rather than
  collapsing both into one bucket. `:not_allowed` is operator-induced
  (someone disabled the provider mid-flight); `:not_configured` is
  customer-config-shape (this tenant never declared this upstream).

  ## How `host_header` is supplied

  The request's `Host` HTTP header. After the customer's DNS override
  routes `chatgpt.com` (etc.) to recurse-gateway, the inbound TLS
  termination preserves the original Host header — that header IS the
  upstream the customer wants forwarded. The proxy router pulls
  `host_header` from `Plug.Conn.host/0` (or the WS upgrade headers) and
  forwards it here.
  """

  alias Recurse.Providers.LlmProviders
  alias Recurse.Providers.Schemas.LlmProviderConfig

  @type tenant_id :: String.t()
  @type host_header :: String.t()

  @type resolve_error :: :not_configured | :not_allowed

  @typedoc """
  Result returned to the proxy. `:ok` carries the full config row so
  downstream stages (BypassDnsResolver lookup, header preservation,
  parser selection by `api_format`) all read from the same struct.
  """
  @type result :: {:ok, LlmProviderConfig.t()} | {:error, resolve_error()}

  @doc """
  Look up the `LlmProviderConfig` for this tenant + Host header.

  ## Examples

      iex> UpstreamResolver.resolve("01ARZ...", "chatgpt.com")
      {:ok, %LlmProviderConfig{provider: "openai_chatgpt", ...}}

      iex> UpstreamResolver.resolve("01ARZ...", "unknown.example.com")
      {:error, :not_configured}
  """
  @spec resolve(tenant_id(), host_header()) :: result()
  def resolve(tenant_id, host_header)
      when is_binary(tenant_id) and is_binary(host_header) do
    LlmProviders.lookup(tenant_id, host_header)
  end

  # Defensive guard for unexpected non-binary inputs from upstream
  # plumbing (e.g. nil tenant_id when a request arrives unauthenticated).
  # Without this clause the bare `is_binary` guard would throw
  # FunctionClauseError; we'd rather degrade to `:not_configured`.
  def resolve(_tenant_id, _host_header), do: {:error, :not_configured}
end
