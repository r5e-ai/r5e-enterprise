defmodule Recurse.Providers.Impls.FilesystemPolicyProvider do
  @moduledoc """
  Filesystem-backed `Recurse.Providers.PolicyProvider` — reads a Cedar
  policy bundle + entity schema from the local filesystem. This is the
  Standalone Gateway tier's simplest distribution path; OCI / offline-signed
  manifest impls land in later features.

  ## Callback surface (F002 T045)

  | Callback | Behaviour |
  |---|---|
  | `init/1` | Reads `bundle_path` + `entity_schema_path`, parses the bundle via `Recurse.Cedar.validate_policy_syntax/1`, computes the canonical hash, caches both in the opaque state. |
  | `fetch_active_bundle/1` | Returns the cached bundle triple (`digest`, `bytes`, `canonical_hash`). Also surfaces `:source => :filesystem`, `:cedar_version`, and `:loaded_at` fields alongside the F001-behaviour-required triple. |
  | `fetch_bundle/2` | Filesystem provider stores only the currently-loaded bundle on disk; lookup by historical digest returns `{:error, :not_found}` unless the digest matches the active bundle. |
  | `subscribe_supersede_notifications/2` | Filesystem provider does NOT push supersede events — operator triggers reloads via SIGHUP handled in `Recurse.Gateway.Policy.BundleLoader` (T046). Returns `:ok`. |
  | `simulate/3`, `blast_radius/4`, `propose_from_event/2` | Cedar Playground surfaces (F005+); returns `{:error, {:not_applicable, :standalone_slice}}` in F002. |
  | `capabilities/1` | `[:filesystem_reload, :canonical_hash_computation]`. |
  | `healthcheck/1` | Stats the bundle + schema files; `:ok` when both are readable, `{:down, reason}` otherwise. |
  | `terminate/2` | `:ok` — no resources to release. |

  ## Contract

    * Contract — `specs/002-standalone-gateway-vertical-slice/contracts/provider_impls.md` §`FilesystemPolicyProvider`.
    * Behaviour — `Recurse.Providers.PolicyProvider` (F001).
    * Cedar version pin — `Recurse.Cedar` (content-addressed per research D2).
  """

  @behaviour Recurse.Providers.PolicyProvider

  @cedar_version "4.9.1"

  @typedoc "Active bundle record. Internal shape — callers consume via `fetch_active_bundle/1`."
  @type active_bundle :: %{
          bundle_bytes: binary(),
          canonical_hash: <<_::256>>,
          digest: <<_::256>>,
          cedar_version: String.t(),
          loaded_at: DateTime.t(),
          schema_bytes: binary()
        }

  @typedoc "Opaque state — callers must not inspect."
  @type state :: %{
          required(:config) => map(),
          required(:bundle_path) => Path.t(),
          required(:entity_schema_path) => Path.t(),
          required(:active) => active_bundle() | nil
        }

  @doc """
  Read the bundle + schema from disk, parse the bundle via the Cedar NIF,
  compute `canonical_hash`, cache the active bundle in state. Fails loudly
  if either file is missing or the bundle fails parse — Gateway boot MUST
  be fail-closed on bundle integrity (FR-010).
  """
  @impl true
  @spec init(Recurse.Providers.PolicyProvider.config()) :: {:ok, state()} | {:error, term()}
  def init(config) when is_map(config) do
    with {:ok, bundle_path} <- require_path(config, :bundle_path),
         {:ok, schema_path} <- require_path(config, :entity_schema_path),
         {:ok, bundle_bytes} <- read_file(bundle_path, :bundle),
         {:ok, schema_bytes} <- read_file(schema_path, :entity_schema),
         :ok <- validate_bundle_syntax(bundle_bytes),
         {:ok, canonical_hash} <- compute_canonical_hash(bundle_bytes) do
      active = %{
        bundle_bytes: bundle_bytes,
        canonical_hash: canonical_hash,
        digest: canonical_hash,
        cedar_version: @cedar_version,
        loaded_at: DateTime.utc_now(),
        schema_bytes: schema_bytes
      }

      state = %{
        config: config,
        bundle_path: bundle_path,
        entity_schema_path: schema_path,
        active: active
      }

      {:ok, state}
    end
  end

  @doc """
  Return the currently-loaded bundle triple (F001-contract-required fields)
  plus F002 extensions (`cedar_version`, `loaded_at`, `source`).
  """
  @impl true
  @spec fetch_active_bundle(state()) ::
          {:ok,
           %{
             digest: Recurse.Providers.PolicyProvider.bundle_digest(),
             bytes: Recurse.Providers.PolicyProvider.bundle_bytes(),
             canonical_hash: Recurse.Providers.PolicyProvider.policy_canonical_hash(),
             cedar_version: String.t(),
             loaded_at: DateTime.t(),
             source: :filesystem
           }}
          | {:error, term()}
  def fetch_active_bundle(%{active: nil}), do: {:error, :no_active_bundle}

  def fetch_active_bundle(%{active: active}) do
    {:ok,
     %{
       digest: active.digest,
       bytes: active.bundle_bytes,
       canonical_hash: active.canonical_hash,
       cedar_version: active.cedar_version,
       loaded_at: active.loaded_at,
       source: :filesystem
     }}
  end

  @doc """
  Historical-bundle lookup by digest. Filesystem provider keeps only the
  active bundle on disk; callers asking for a non-active digest receive
  `{:error, :not_found}`.
  """
  @impl true
  @spec fetch_bundle(state(), Recurse.Providers.PolicyProvider.bundle_digest()) ::
          {:ok,
           %{
             bytes: Recurse.Providers.PolicyProvider.bundle_bytes(),
             canonical_hash: Recurse.Providers.PolicyProvider.policy_canonical_hash()
           }}
          | {:error, :not_found | term()}
  def fetch_bundle(%{active: nil}, _digest), do: {:error, :not_found}

  def fetch_bundle(%{active: active}, digest) when is_binary(digest) do
    if active.digest == digest do
      {:ok, %{bytes: active.bundle_bytes, canonical_hash: active.canonical_hash}}
    else
      {:error, :not_found}
    end
  end

  @doc """
  Filesystem provider has no push-notification mechanism — operator
  triggers reloads via SIGHUP, handled in
  `Recurse.Gateway.Policy.BundleLoader`. Returns `:ok` so the contract is
  satisfied without spinning up a watcher.
  """
  @impl true
  @spec subscribe_supersede_notifications(state(), callback :: pid() | function()) ::
          {:ok, Recurse.Providers.PolicyProvider.subscription()} | {:error, term()}
  def subscribe_supersede_notifications(_state, _callback), do: {:ok, :noop_subscription}

  @doc """
  Cedar Playground simulation is out-of-scope for the F002 Standalone
  slice; F005+ surfaces this via a dedicated policy-authoring flow.
  """
  @impl true
  @spec simulate(
          state(),
          Recurse.Providers.PolicyProvider.cedar_policy_source(),
          Recurse.Providers.PolicyProvider.mock_request()
        ) ::
          {:ok,
           %{
             decision: Recurse.Providers.PolicyProvider.decision(),
             matched_rules: [String.t()],
             evaluation_micros: non_neg_integer()
           }}
          | {:error, term()}
  def simulate(_state, _candidate_policy, _mock_request) do
    {:error, {:not_applicable, :standalone_slice}}
  end

  @doc """
  Blast-radius analysis is an F005+ Playground surface; not applicable in
  the Standalone slice.
  """
  @impl true
  @spec blast_radius(
          state(),
          Recurse.Providers.PolicyProvider.cedar_policy_source(),
          historical_window_seconds :: pos_integer(),
          Recurse.Shared.IdentityContext.t()
        ) ::
          {:ok,
           %{
             impacted_runs: non_neg_integer(),
             impacted_agents: non_neg_integer(),
             sample_divergences: [map()]
           }}
          | {:error, term()}
  def blast_radius(_state, _candidate_policy, _window_seconds, _identity_ctx) do
    {:error, {:not_applicable, :standalone_slice}}
  end

  @doc """
  Discovery-to-Policy proposal is an F005+ Playground surface; not
  applicable in the Standalone slice.
  """
  @impl true
  @spec propose_from_event(state(), flagged_event :: map()) ::
          {:ok,
           %{
             proposed_policy: Recurse.Providers.PolicyProvider.cedar_policy_source(),
             scope_suggestions: [String.t()]
           }}
          | {:error, term()}
  def propose_from_event(_state, _flagged_event) do
    {:error, {:not_applicable, :standalone_slice}}
  end

  @doc """
  Advertise the capability flags this impl actually honors.
  """
  @impl true
  @spec capabilities(state()) :: [Recurse.Providers.PolicyProvider.capability()]
  def capabilities(_state), do: [:filesystem_reload, :canonical_hash_computation]

  @doc """
  Healthcheck: bundle + schema files exist and are readable.
  """
  @impl true
  @spec healthcheck(state()) :: :ok | {:degraded, term()} | {:down, term()}
  def healthcheck(%{bundle_path: bundle_path, entity_schema_path: schema_path}) do
    cond do
      not File.regular?(bundle_path) -> {:down, {:bundle_missing, bundle_path}}
      not File.regular?(schema_path) -> {:down, {:entity_schema_missing, schema_path}}
      true -> :ok
    end
  end

  @doc """
  No background resources to release — filesystem provider is stateless
  beyond its cached bundle bytes, which are GC'd with the caller.
  """
  @impl true
  @spec terminate(state(), reason :: term()) :: :ok
  def terminate(_state, _reason), do: :ok

  # ---------------------------------------------------------------------------
  # Internal helpers.
  # ---------------------------------------------------------------------------

  defp require_path(config, key) do
    case Map.fetch(config, key) do
      {:ok, path} when is_binary(path) and byte_size(path) > 0 -> {:ok, path}
      {:ok, _} -> {:error, {:invalid_config, key, :non_binary}}
      :error -> {:error, {:missing_config, key}}
    end
  end

  defp read_file(path, kind) do
    case File.read(path) do
      {:ok, bytes} -> {:ok, bytes}
      {:error, reason} -> {:error, {:file_read_failure, kind, path, reason}}
    end
  end

  defp validate_bundle_syntax(bundle_bytes) do
    case Recurse.Cedar.validate_policy_syntax(bundle_bytes) do
      :ok -> :ok
      {:error, reason} -> {:error, {:bundle_parse_failure, reason}}
    end
  end

  defp compute_canonical_hash(bundle_bytes) do
    {:ok, Recurse.Cedar.canonical_hash(bundle_bytes)}
  rescue
    error in ArgumentError ->
      {:error, {:canonical_hash_failure, Exception.message(error)}}
  end
end
