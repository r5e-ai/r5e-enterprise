defmodule Recurse.Gateway.McpRegistry.Loader do
  @moduledoc """
  Loads + caches the static Trusted MCP Registry from
  `apps/recurse_gateway/priv/mcp_registry/registry.json`.

  Phase-1 vertical slice (the MCP/SBOM/Trusted-Registry "Path B" demo):
  the catalog is a hand-curated JSON file that ships in `priv/`. Phase-2+
  replaces this with a per-tenant dynamic registry backed by Postgres +
  signed-SBOM verification.

  ## Iron Law check (`elixir:elixir-thinking`)

    1. Mutable state persisting across calls? No — boot-time `init/0`
       loads + parses the JSON once into `:persistent_term`. Subsequent
       `list/0` / `get/1` calls are pure reads.
    2. Concurrent execution? No — `:persistent_term.get/1` is lock-free
       and runs on the caller process.
    3. Fault isolation? Boot-time corruption of the registry file is
       fatal (the file ships in the artifact). Per-call lookups never
       raise — `get/1` returns `:error` for unknown ids.

  All three NO at the per-call layer → plain functions; no GenServer.

  ## Path resolution at RUNTIME, not compile-time

  `:code.priv_dir(:recurse_gateway)` is called at module init time, not
  baked into a `Path.expand("../priv/...", __DIR__)` module attribute.
  Same idiom as `WellKnownManifest`, `SchemaPublication`, `Plug.AdminStatic`,
  and `SuggestionEngine.LlmRunner`. Compile-time `__DIR__`-relative paths
  freeze the GitLab-CI source path into the BEAM file and crash on the
  EC2 release host where the file lives at
  `/opt/r5e/audit/current/lib/recurse_gateway-<vsn>/priv/...`. Caught
  twice this project (MR !57 + the F7 trilogy); enforced by manifest
  contract test Invariant 5.

  ## Sibling-module note (Constitution Principle VII surfaced)

  This module is the **third** consumer in the umbrella of the same
  load-once-cache-in-persistent-term pattern (after `WellKnownManifest`
  and `SchemaPublication`). The shapes diverge meaningfully — those two
  serve raw JSON bytes over HTTP with hostname rewriting; this one
  exposes typed Elixir map accessors with no rewriting — but the
  underlying "load JSON from priv at boot, cache via persistent_term"
  primitive is duplicated. Recommend extracting a shared
  `Recurse.Gateway.Plug.PrivJsonCache` helper in a follow-up MR;
  surfaced in this MR's reflect rather than blocking the demo.
  """

  require Logger

  alias Recurse.Shared.Attestation.SignedPredicate

  @persistent_term_key {__MODULE__, :registry}

  @typedoc "Trust tier vocabulary — must match `mcp_registry_entry.json#/properties/trust_tier`."
  @type trust_tier :: :verified | :community | :quarantined

  @typedoc "Single CVE / GHSA record attached to an SBOM component."
  @type vulnerability :: %{
          required(:id) => String.t(),
          required(:severity) => String.t(),
          required(:summary) => String.t(),
          optional(:source) => String.t(),
          optional(:fixed_versions) => [String.t()]
        }

  @typedoc "Single SBOM component (one dependency)."
  @type component :: %{
          required(:name) => String.t(),
          required(:version) => String.t(),
          optional(:license) => String.t(),
          optional(:purl) => String.t(),
          optional(:vulnerabilities) => [vulnerability()]
        }

  @typedoc "Parsed registry entry — atom keys."
  @type entry :: %{
          required(:id) => String.t(),
          required(:name) => String.t(),
          required(:description) => String.t(),
          required(:source) => String.t(),
          required(:version) => String.t(),
          required(:transport) => String.t(),
          required(:trust_tier) => trust_tier(),
          required(:publisher) => String.t(),
          required(:capabilities) => map(),
          required(:policy_constraints) => map(),
          required(:sbom) => map()
        }

  @typedoc "Full registry catalog."
  @type catalog :: %{
          required(:version) => String.t(),
          required(:generated_at) => String.t(),
          required(:description) => String.t(),
          required(:entries) => [entry()]
        }

  @doc """
  Resolve the registry JSON path at runtime.

  Honors a `:registry_path` override under `:recurse_gateway` app config
  for tests that need to point at a fixture file. Production-default is
  the in-priv catalog.
  """
  @spec registry_path() :: String.t()
  def registry_path do
    case Application.get_env(:recurse_gateway, :mcp_registry_path) do
      nil ->
        Path.join([:code.priv_dir(:recurse_gateway), "mcp_registry", "registry.json"])

      override when is_binary(override) ->
        override
    end
  end

  @doc """
  Load + parse the registry JSON, populate the persistent_term cache.

  Called once at application boot. Idempotent — re-loading is cheap
  enough that tests can call it freely between fixtures.

  Raises on file-not-found or invalid JSON: this is fatal-by-design
  because the registry ships in the artifact; a missing file is a
  build problem, not a runtime configuration problem.
  """
  @spec load!() :: :ok
  def load! do
    catalog =
      registry_path()
      |> File.read!()
      |> JSON.decode!()
      |> normalize_catalog()

    :persistent_term.put(@persistent_term_key, catalog)
    :ok
  end

  @doc """
  Return the parsed catalog. Loads on first call if not yet primed
  (test ergonomics — production primes via `Application.start/2`).
  """
  @spec catalog() :: catalog()
  def catalog do
    case :persistent_term.get(@persistent_term_key, :__not_loaded__) do
      :__not_loaded__ ->
        :ok = load!()
        :persistent_term.get(@persistent_term_key)

      cached ->
        cached
    end
  end

  @doc "Return the list of registry entries in declaration order."
  @spec list() :: [entry()]
  def list, do: catalog().entries

  @doc """
  Look up a single registry entry by id.

  Returns `{:ok, entry}` on hit, `:error` on miss. Callers translate
  the miss into a 404 F001 error envelope.
  """
  @spec get(String.t()) :: {:ok, entry()} | :error
  def get(id) when is_binary(id) do
    case Enum.find(list(), &(&1.id == id)) do
      nil -> :error
      entry -> {:ok, entry}
    end
  end

  @doc """
  Convert a parsed entry back to a JSON-shaped map (string keys) for
  HTTP-response serialization. Inverse of `normalize_entry/1`.
  """
  @spec entry_to_json(entry()) :: map()
  def entry_to_json(%{} = entry) do
    %{
      "id" => entry.id,
      "name" => entry.name,
      "description" => entry.description,
      "source" => entry.source,
      "version" => entry.version,
      "transport" => entry.transport,
      "trust_tier" => Atom.to_string(entry.trust_tier),
      "publisher" => entry.publisher,
      "capabilities" => entry.capabilities,
      "policy_constraints" => entry.policy_constraints,
      "sbom" => entry.sbom
    }
  end

  # ---------------------------------------------------------------------------
  # Private — JSON parsing + normalization
  # ---------------------------------------------------------------------------

  defp normalize_catalog(%{"entries" => entries} = raw) when is_list(entries) do
    %{
      version: Map.get(raw, "version", "0.0.0"),
      generated_at: Map.get(raw, "generated_at", ""),
      description: Map.get(raw, "description", ""),
      entries: Enum.map(entries, &normalize_entry/1)
    }
  end

  defp normalize_entry(%{} = raw) do
    %{
      id: fetch_string!(raw, "id"),
      name: fetch_string!(raw, "name"),
      description: Map.get(raw, "description", ""),
      source: fetch_string!(raw, "source"),
      version: fetch_string!(raw, "version"),
      transport: fetch_string!(raw, "transport"),
      trust_tier: parse_trust_tier!(Map.fetch!(raw, "trust_tier")),
      publisher: Map.get(raw, "publisher", ""),
      capabilities: Map.get(raw, "capabilities", %{"tools" => []}),
      policy_constraints: Map.get(raw, "policy_constraints", %{}),
      sbom: Map.get(raw, "sbom", %{})
    }
  end

  defp parse_trust_tier!("verified"), do: :verified
  defp parse_trust_tier!("community"), do: :community
  defp parse_trust_tier!("quarantined"), do: :quarantined

  defp parse_trust_tier!(other),
    do: raise(ArgumentError, "Unknown trust_tier: #{inspect(other)}")

  defp fetch_string!(raw, key) do
    case Map.fetch!(raw, key) do
      v when is_binary(v) -> v
      v -> raise ArgumentError, "Expected string at #{key}, got: #{inspect(v)}"
    end
  end

  @doc """
  Drift guard — assert the `:mcp_tool_call` event_kind atom is present
  in the canonical `SignedPredicate.event_kinds/0` list.

  This is the cross-module contract: every MCP tool call emits an
  `:mcp_tool_call` attestation, and that atom MUST be accepted by the
  ledger's Ecto.Enum + DB CHECK constraint. If a future refactor drops
  the atom from the canonical list (or this module forgets to extend
  the loader to emit it), this assertion fails LOUD at boot.
  """
  @spec assert_event_kind_registered!() :: :ok
  def assert_event_kind_registered! do
    if :mcp_tool_call in SignedPredicate.event_kinds() do
      :ok
    else
      raise """
      Recurse.Gateway.McpRegistry.Loader requires :mcp_tool_call to be \
      registered in Recurse.Shared.Attestation.SignedPredicate.@event_kinds, \
      but it is not. Add it (and update the ledger Ecto.Enum + the DB CHECK \
      migration) before this module can boot.
      """
    end
  end
end
