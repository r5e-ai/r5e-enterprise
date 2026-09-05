defmodule Recurse.Providers.LlmProviders do
  @moduledoc """
  Context-style helper for the `llm_provider_configs` table.

  Spec source of truth: `specs/009-llm-api-proxy/data-model.md` §LlmProviderConfig
  + `contracts/streaming_proxy.md` §UpstreamResolver.

  This module is the seam Phase-3's `Recurse.Gateway.LlmProxy.UpstreamResolver`
  reads through to map an inbound request `(tenant_id, host_header)` to the
  upstream the proxy should forward to. Returning explicit error tuples
  (`:not_configured` vs `:not_allowed`) lets the proxy emit precise
  attestation failure-mode tags rather than collapsing both into a single
  "config missing" code.

  ## Cross-context FK by ID, not association

  `LlmProviderConfig.tenant_id` is a foreign key to `tenants.tenant_id` —
  this is the only association we model. Per Ecto-thinking ("cross-context
  references: IDs, not associations"), Phase-3 callers query
  `lookup/2` by `tenant_id` directly rather than chasing associations
  across context boundaries.
  """

  import Ecto.Query, only: [from: 2]

  alias Recurse.Providers.Repo
  alias Recurse.Providers.Schemas.LlmProviderConfig

  @typedoc """
  The lookup result. `:not_configured` means no matching row;
  `:not_allowed` means a row exists but `enabled = false`. Phase 3's
  `UpstreamResolver` translates both into proxy-level 5xx + attestation
  but they tag distinctly in the audit row.
  """
  @type lookup_error :: :not_configured | :not_allowed
  @type lookup_result :: {:ok, LlmProviderConfig.t()} | {:error, lookup_error()}

  @doc """
  Look up the active provider config for a tenant by upstream host.

  The match key is `(tenant_id, upstream_host)` — `host_header` is the
  HTTP `Host` header value of the inbound request, which after DNS
  override is the real upstream the customer wants the proxy to
  forward to (e.g. `"chatgpt.com"`, `"api.openai.com"`).

  Returns:
    * `{:ok, %LlmProviderConfig{}}` — row exists AND `enabled = true`
    * `{:error, :not_allowed}` — row exists but `enabled = false`
    * `{:error, :not_configured}` — no row matches

  ## Examples

      iex> Recurse.Providers.LlmProviders.lookup("01ARZ...", "api.openai.com")
      {:ok, %Recurse.Providers.Schemas.LlmProviderConfig{...}}

      iex> Recurse.Providers.LlmProviders.lookup("01ARZ...", "unknown.example.com")
      {:error, :not_configured}
  """
  @spec lookup(tenant_id :: String.t(), host_header :: String.t()) :: lookup_result()
  def lookup(tenant_id, host_header)
      when is_binary(tenant_id) and is_binary(host_header) do
    query =
      from c in LlmProviderConfig,
        where: c.tenant_id == ^tenant_id and c.upstream_host == ^host_header

    case Repo.one(query) do
      nil -> {:error, :not_configured}
      %LlmProviderConfig{enabled: false} -> {:error, :not_allowed}
      %LlmProviderConfig{} = cfg -> {:ok, cfg}
    end
  end
end
