defmodule Recurse.Gateway.ProviderRegistry do
  @moduledoc """
  Per-BEAM registry of Provider Interface impls + their opaque states, backed
  by `:persistent_term` (F002 Wave 3E-2 — T050/T051/T052 support).

  ## Iron Law check (`elixir:otp-thinking`)

    1. Mutable state across calls? Yes — but rarely-written, frequently-read.
       That's `:persistent_term` territory, not GenServer.
    2. Concurrent execution needed? No — reads are wait-free, writes happen
       once at boot.
    3. Fault isolation needed? No — provider state is immutable after `init/1`
       returns; there is no runtime state to lose on a restart.

  A GenServer would serialize every Data-Plane request through a single
  mailbox and defeat the point of per-request HTTP/2 multiplexing at the
  Finch layer (`research.md` D3). `:persistent_term` reads compile down
  to a direct memory fetch — exactly the right hot-path primitive for
  provider lookups.

  ## Boot-time flow

  `RecurseGateway.Application.start/2` calls `install/1` with a map of
  `{key, {impl_module, config_map}}` entries. `install/1` invokes each
  impl's `init/1`, caches the returned `{module, state}` tuple in
  `:persistent_term`, and raises (fail-closed per Constitution Principle
  III) if any provider refuses to initialize.

  Subsequent request handlers read through the narrow accessor functions
  (`llm_provider/0`, `ledger_provider/0`, etc.), each of which returns
  `{module, state}` — suitable for direct `module.callback(state, ...)`
  dispatch.

  ## Deployment vs tenant

  Under Standalone (F002) the deployment is single-tenant. `tenant_id/0`
  returns the pinned deployment `tenant_id` from Tier Config (FR-031).
  """

  @persistent_term_key {__MODULE__, :state}

  @type provider_key :: :llm | :ledger | :storage | :secrets
  @type provider_entry :: {module(), term()}

  @typedoc """
  The `:llm` slot is OPTIONAL. Standalone audit-console + spec-009
  LLM-proxy deployments do not synthesize chat-completion output from
  the gateway itself (the proxy forwards client-bearing traffic
  verbatim through `LlmProxy.StreamingProxy`); requiring an LLMProvider
  at boot would force operators to provision an unused
  `OPENAI_API_KEY`. Consumers that DO need the LLM provider
  (suggestion-engine, audit-agent chat skills, data-plane
  `/v1/chat/completions`) MUST handle the `{:error, :not_configured}`
  return from `llm_provider/0`. Constitution Principle V lists eight
  Provider Interfaces, but the principle does NOT require every PI to
  install in every deploy — only that every consumed PI go through the
  registry seam.

  All other slots stay required: an audit-plane deploy without a
  ledger or signing-secrets impl cannot satisfy Principle III
  ("everything attestable").
  """
  @type install_map :: %{
          optional(:llm) => {module(), map()},
          required(:ledger) => {module(), map()},
          required(:storage) => {module(), map()},
          required(:secrets) => {module(), map()},
          required(:tenant_id) => String.t(),
          optional(:signer) => String.t()
        }

  @type cached_state :: %{
          llm: provider_entry() | :not_configured,
          ledger: provider_entry(),
          storage: provider_entry(),
          secrets: provider_entry(),
          tenant_id: String.t(),
          signer: String.t()
        }

  @doc """
  Initialize every provider from `install_map` and cache the resulting
  `{module, state}` tuples in `:persistent_term`. Raises on any init
  failure for a present slot — the Gateway MUST NOT come up with a
  partially-initialized provider.

  The `:llm` slot is optional (per the install_map type doc). When
  omitted, the cached state stores `:not_configured` for that role and
  `llm_provider/0` returns `{:error, :not_configured}`.

  Safe to call multiple times (idempotent): the last successful install
  wins. Tests use this to inject mocks.
  """
  @spec install!(install_map()) :: :ok
  def install!(install_map) when is_map(install_map) do
    tenant_id = Map.fetch!(install_map, :tenant_id)
    signer = Map.get(install_map, :signer, "observed://gateway")

    llm = init_optional_provider!(install_map, :llm)
    ledger = init_provider!(install_map, :ledger)
    storage = init_provider!(install_map, :storage)
    secrets = init_provider!(install_map, :secrets)

    cached = %{
      llm: llm,
      ledger: ledger,
      storage: storage,
      secrets: secrets,
      tenant_id: tenant_id,
      signer: signer
    }

    :persistent_term.put(@persistent_term_key, cached)
    :ok
  end

  @doc """
  Install pre-initialized provider tuples directly. Unlike `install!/1`
  this skips `init/1` — callers pass the `{module, state}` shape already
  materialized. Primarily a test affordance: hand-built stub state can
  bypass the Provider Interface's `init/1` contract.

  The `:llm` slot is optional (mirrors `install!/1`). Pass
  `:not_configured` or omit the key entirely to install a registry
  without an LLMProvider.
  """
  @spec install_raw!(%{
          optional(:llm) => provider_entry() | :not_configured,
          required(:ledger) => provider_entry(),
          required(:storage) => provider_entry(),
          required(:secrets) => provider_entry(),
          required(:tenant_id) => String.t(),
          optional(:signer) => String.t() | nil
        }) :: :ok
  def install_raw!(
        %{
          ledger: ledger,
          storage: storage,
          secrets: secrets,
          tenant_id: tenant_id
        } = raw
      )
      when is_binary(tenant_id) do
    cached = %{
      llm: Map.get(raw, :llm, :not_configured),
      ledger: ledger,
      storage: storage,
      secrets: secrets,
      tenant_id: tenant_id,
      signer: Map.get(raw, :signer) || "observed://gateway"
    }

    :persistent_term.put(@persistent_term_key, cached)
    :ok
  end

  @doc """
  Remove the cached providers. Used in tests to reset between cases.
  """
  @spec uninstall() :: :ok
  def uninstall do
    _ = :persistent_term.erase(@persistent_term_key)
    :ok
  end

  @doc """
  Return `{module, state}` for the LLM provider when configured, or
  the atom `:not_configured` when the registry was installed without
  an `:llm` slot (a deliberate posture for proxy-only deployments —
  see `install_map` typedoc). Raises if the registry itself isn't
  installed (a config bug — every deploy must call `install!/1` at
  boot).

  ### Backward-compatibility note

  The configured-LLM return shape (`{module, state}`) is unchanged so
  existing call sites that destructure
  `{llm_mod, llm_state} = ProviderRegistry.llm_provider()` keep
  working on every deploy where the LLM slot IS populated:

    * `Recurse.Gateway.SuggestionEngine.LlmRunner.do_llm_provider_call/4`
    * `Recurse.Gateway.Admin.AuditAgent.Tools.ExplainDenial.call_llm/2`
    * `Recurse.Gateway.DataPlane.ChatCompletionsHandler.handle_sync/4`
    * `Recurse.Gateway.DataPlane.SseProxy.proxy/4`

  These four call sites will pattern-match-fail with `MatchError`
  if invoked on a deploy where the LLM slot is omitted. Audit-dev's
  normal traffic does NOT exercise any of those paths today
  (suggestion-engine + audit-agent are feature-gated UI; the
  data-plane `/v1/chat/completions` handler is a Standalone-Gateway
  route, distinct from the spec-009 LLM proxy on port 4443).
  Migrating these four to gracefully degrade on `:not_configured` is
  a scoped follow-on cleanup, NOT part of this MR.
  """
  @spec llm_provider() :: provider_entry() | :not_configured
  def llm_provider, do: fetch!().llm

  @doc """
  Return `{module, state}` for the Ledger provider. Raises if not installed.
  """
  @spec ledger_provider() :: provider_entry()
  def ledger_provider, do: fetch!().ledger

  @doc """
  Return `{module, state}` for the Storage provider. Raises if not installed.
  """
  @spec storage_provider() :: provider_entry()
  def storage_provider, do: fetch!().storage

  @doc """
  Return `{module, state}` for the Secrets provider. Raises if not installed.
  """
  @spec secrets_provider() :: provider_entry()
  def secrets_provider, do: fetch!().secrets

  @doc """
  Return the deployment-pinned `tenant_id` (Standalone is single-tenant).
  """
  @spec tenant_id() :: String.t()
  def tenant_id, do: fetch!().tenant_id

  @doc """
  Return the Gateway's emitter identity string (stamped into signed
  predicates as `signer`).
  """
  @spec signer() :: String.t()
  def signer, do: fetch!().signer

  @doc """
  Return the full cached map. Mostly for tests + diagnostics; prefer the
  narrow accessors for production call sites.
  """
  @spec fetch() :: {:ok, cached_state()} | {:error, :not_installed}
  def fetch do
    case :persistent_term.get(@persistent_term_key, :not_installed) do
      :not_installed -> {:error, :not_installed}
      cached when is_map(cached) -> {:ok, cached}
    end
  end

  # ---------------------------------------------------------------------------
  # Private helpers
  # ---------------------------------------------------------------------------

  defp fetch! do
    case fetch() do
      {:ok, cached} ->
        cached

      {:error, :not_installed} ->
        raise "Recurse.Gateway.ProviderRegistry not installed — call install!/1 at boot"
    end
  end

  defp init_provider!(install_map, key) do
    {mod, config} = Map.fetch!(install_map, key)

    case mod.init(config) do
      {:ok, state} ->
        {mod, state}

      {:error, reason} ->
        raise "ProviderRegistry: #{inspect(mod)}.init/1 failed for #{inspect(key)}: " <>
                inspect(reason)
    end
  end

  # Same as `init_provider!/2` but returns `:not_configured` when the
  # slot is absent from the install_map (rather than raising on
  # `Map.fetch!/2`). The optional-slot semantics live ONLY in the
  # public install_map type's `optional(...)` declaration plus this
  # helper; every other slot stays `init_provider!/2`-strict.
  defp init_optional_provider!(install_map, key) do
    case Map.get(install_map, key) do
      nil -> :not_configured
      :not_configured -> :not_configured
      {_mod, _config} -> init_provider!(install_map, key)
    end
  end
end
