defmodule Recurse.Gateway.Policy.OciBundleManager do
  @moduledoc """
  OCI-registry Cedar policy bundle loader (MR !119, Spec A — Recurse
  API Substrate + MCP Fluency).

  ## Role

  One of several loaders that populate the canonical
  `Recurse.Gateway.Policy.Active` store. This loader handles the
  OCI-registry path — pulling cosign-verified bundles from ECR / GHCR
  / Harbor / Quay; the filesystem path is handled by
  `Recurse.Gateway.Policy.BundleLoader`. Future loaders that will
  also funnel through `Active`:

    * `Recurse.Gateway.Policy.DbBundleLoader` — UI-authored policies
      from audit-console (planned; not yet implemented).
    * `Recurse.Gateway.Policy.CustomerFeedLoader` — existing customer
      policy-management systems via `PolicyProvider` impls (planned;
      not yet implemented).

  ALL Cedar-evaluating call sites read from
  `Recurse.Gateway.Policy.Active.current/0`, NOT from any specific
  loader. Hot-swap is atomic via `Active.update/1`'s
  `:persistent_term.put/2`.

  ## Boot sequence

    1. Read required env vars:
         * `R5E_CEDAR_BUNDLE_REGISTRY` — OCI registry hostname.
         * `R5E_CEDAR_BUNDLE_REPOSITORY` — repo path.
         * `R5E_CEDAR_BUNDLE_REF` — tag or digest.
         * `R5E_CEDAR_COSIGN_KEY_ARN` — KMS key ARN / alias.
         * `R5E_CEDAR_BUNDLE_AUTH` — JSON object describing the per-registry
           auth shape (see `parse_auth_env/1`).
       Any missing env var → log + raise → fail-closed boot
       (Constitution Principle III).
    2. Call `OciPolicyProvider.init/1` with the resolved config. On
       success, build a `%PolicyBundleRef{}` from the fetched bundle,
       wrap it in a `%Recurse.Gateway.Policy.Active{source: :oci,
       source_ref: <oci ref>, metadata: %{manifest, digest, ...}}`
       envelope, and write it via `Active.update/1`.
    3. On init failure, the GenServer fails to start so the OTP
       supervisor cascades the failure up the boot chain — the gateway
       MUST NOT come up with a missing or unverified bundle.

  ## Hot-reload via `activate/2`

  Operator-driven via `POST /v1/admin/cedar-bundle/activate` (Plug handler
  is `Recurse.Gateway.Admin.CedarBundleActivateHandler`). The activate
  flow:

    1. Calls `OciPolicyProvider.init/1` with the new ref. This pulls the
       OCI manifest, layers, cosign signature, and verifies against the
       configured KMS public key — same boot pipeline.
    2. On success: build the new `%Active{}` envelope and call
       `Active.update/1`. That atomically swaps the canonical
       persistent_term entry AND broadcasts on the
       `policy_active:supersede` PubSub topic. We additionally retain
       the legacy `policy_provider:supersede` broadcast for backwards
       compat with `OciPolicyProvider.subscribe_supersede_notifications/2`
       subscribers; new subscribers should use `Active.subscribe/0`.
    3. On failure (registry unreachable, cosign mismatch, Cedar parse,
       canonical-hash failure): the OLD bundle remains active in
       `Active.current/0`. Returns `{:error, reason}` to the caller;
       the admin handler converts to a 502.

  ## Iron Law check (`elixir:otp-thinking`)

    1. Mutable state? Yes — provider state. (The active bundle itself
       is in `Active`'s persistent_term store, not in this GenServer's
       state.)
    2. Concurrent execution? No — activate is operator-driven, RARE.
    3. Fault isolation? Yes — failed activate keeps the previous bundle.

  All three → singleton GenServer, name-registered, supervised in the
  Gateway supervision tree behind `:oci_policy_provider_enabled?` config.

  ## Cross-references

    * `apps/recurse_gateway/lib/recurse_gateway/policy/active.ex`
      (canonical reader; this loader writes here)
    * `apps/recurse_providers/lib/recurse_providers/impls/oci_policy_provider.ex`
    * `apps/recurse_gateway/lib/recurse_gateway/policy/bundle_loader.ex`
      (sister loader — filesystem path)
    * `apps/recurse_gateway/lib/recurse_gateway/admin/cedar_bundle_activate_handler.ex`
      (admin endpoint that drives `activate/2`)
  """

  use GenServer

  alias Recurse.Gateway.Policy.Active
  alias Recurse.Gateway.PolicyBundleRef
  alias Recurse.Providers.Impls.OciPolicyProvider

  require Logger

  @persistent_term_key {:recurse_active_cedar_bundle, :default}
  @pubsub_topic "policy_provider:supersede"

  @typedoc "Active bundle record returned to callers from `active_bundle/0`."
  @type active_bundle :: %{
          digest: <<_::256>>,
          bytes: binary(),
          canonical_hash: <<_::256>>,
          cedar_version: String.t(),
          loaded_at: DateTime.t(),
          source: :oci,
          source_ref: String.t(),
          manifest: map()
        }

  # ---------------------------------------------------------------------------
  # Public API
  # ---------------------------------------------------------------------------

  @doc """
  Start the OciBundleManager.

  Required options:
    * `:config` — a map passed verbatim to `OciPolicyProvider.init/1`.
      Required keys: `:registry`, `:repository`, `:ref`, `:cosign_key_arn`,
      `:auth`. Optional: `:http_client`, `:cosign_verifier`,
      `:provider_module` (defaults to `OciPolicyProvider`; tests inject
      a fake), `:persistent_term_key` (defaults to the canonical key;
      tests override to avoid VM-wide collisions).

  Optional options:
    * `:name` — process name registration, defaults to `__MODULE__`.
    * `:pubsub` — Phoenix.PubSub server name, defaults to `Recurse.PubSub`.
  """
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts) do
    {name, opts} = Keyword.pop(opts, :name, __MODULE__)
    gen_opts = if is_nil(name), do: [], else: [name: name]
    GenServer.start_link(__MODULE__, opts, gen_opts)
  end

  @doc """
  Read the active bundle. Fast path — `:persistent_term.get/2` lookup
  with no GenServer round-trip.

  Returns `{:ok, active_bundle()}` or `{:error, :not_loaded}` if the
  manager has not finished its initial load (should not happen in
  practice because the Gateway supervisor waits for `start_link/1` to
  return `{:ok, _}`).
  """
  @spec active_bundle() :: {:ok, active_bundle()} | {:error, :not_loaded}
  @spec active_bundle(term()) :: {:ok, active_bundle()} | {:error, :not_loaded}
  def active_bundle(key \\ @persistent_term_key) do
    case :persistent_term.get(key, :not_loaded) do
      :not_loaded -> {:error, :not_loaded}
      bundle when is_map(bundle) -> {:ok, bundle}
    end
  end

  @doc """
  Activate a new bundle reference. Synchronous — the caller blocks
  while the manager pulls + verifies + swaps. Returns
  `{:ok, %{old_digest, new_digest, ref, activated_at}}` on success or
  `{:error, reason}` on failure (the previous bundle remains active).

  Options:
    * `:digest` — optional `sha256:<hex>` string; if supplied, the
      handler MAY assert manifest_digest equality post-pull (currently
      logged for forensics; future hardening can fail-closed on
      mismatch).
  """
  @spec activate(String.t(), keyword()) ::
          {:ok,
           %{
             old_digest: String.t(),
             new_digest: String.t(),
             ref: String.t(),
             activated_at: DateTime.t()
           }}
          | {:error, term()}
  def activate(new_ref, opts \\ []) when is_binary(new_ref) do
    server = Keyword.get(opts, :server, __MODULE__)
    GenServer.call(server, {:activate, new_ref, opts}, 60_000)
  end

  @doc """
  Phoenix.PubSub topic that broadcasts `{:bundle_superseded, payload}`
  events on every successful `activate/3`.

  Subscribers should call:

      Phoenix.PubSub.subscribe(Recurse.PubSub, OciBundleManager.pubsub_topic())
  """
  @spec pubsub_topic() :: String.t()
  def pubsub_topic, do: @pubsub_topic

  @doc """
  Return the canonical persistent_term key. Cedar evaluator callsites
  use this for direct reads to skip a GenServer round-trip.
  """
  @spec persistent_term_key() :: term()
  def persistent_term_key, do: @persistent_term_key

  # ---------------------------------------------------------------------------
  # Boot-time env var helpers (called from supervision tree)
  # ---------------------------------------------------------------------------

  @doc """
  Build the start_link option keyword from the standard env-var set.
  Called from the Gateway application's supervision tree builder.

  Raises with a structured message if any required env is unset — boot
  fails closed.
  """
  @spec config_from_env!() :: keyword()
  def config_from_env! do
    registry = require_env!("R5E_CEDAR_BUNDLE_REGISTRY")
    repository = require_env!("R5E_CEDAR_BUNDLE_REPOSITORY")
    ref = require_env!("R5E_CEDAR_BUNDLE_REF")
    cosign_key_arn = require_env!("R5E_CEDAR_COSIGN_KEY_ARN")
    auth_json = require_env!("R5E_CEDAR_BUNDLE_AUTH")

    auth = parse_auth_env!(auth_json)

    [
      config: %{
        registry: registry,
        repository: repository,
        ref: ref,
        cosign_key_arn: cosign_key_arn,
        auth: auth
      }
    ]
  end

  # ---------------------------------------------------------------------------
  # GenServer callbacks
  # ---------------------------------------------------------------------------

  @impl true
  def init(opts) do
    config = Keyword.fetch!(opts, :config)
    provider_module = Keyword.get(opts, :provider_module, OciPolicyProvider)
    pubsub = Keyword.get(opts, :pubsub, Recurse.PubSub)
    pt_key = Keyword.get(opts, :persistent_term_key, @persistent_term_key)
    # Production: this manager IS the canonical writer.
    # Tests that exercise the activate-API surface in isolation
    # (without overwriting a sibling-loader-populated Active store)
    # pass `write_to_active?: false`.
    write_to_active? = Keyword.get(opts, :write_to_active?, true)

    case provider_module.init(config) do
      {:ok, provider_state} ->
        with {:ok, bundle} <- provider_module.fetch_active_bundle(provider_state),
             :ok <- maybe_activate(bundle, write_to_active?) do
          # Legacy persistent_term key — kept for backwards-compat
          # with `active_bundle/0` callers (none in production today,
          # but the public function shape is part of MR !119's
          # contract). Canonical store is `Active`, populated below.
          :persistent_term.put(pt_key, bundle)

          Logger.info(
            "OciBundleManager initialized — digest=#{digest_hex(bundle.digest)} " <>
              "ref=#{bundle.source_ref}"
          )

          :telemetry.execute(
            [:recurse, :policy, :oci_bundle, :load],
            %{count: 1},
            %{digest_hex: digest_hex(bundle.digest), source_ref: bundle.source_ref}
          )

          {:ok,
           %{
             provider_module: provider_module,
             provider_state: provider_state,
             config: config,
             pubsub: pubsub,
             persistent_term_key: pt_key,
             write_to_active?: write_to_active?
           }}
        else
          {:error, reason} ->
            terminate_failed_provider(provider_module, provider_state)
            # Provider initialized but no active bundle materialized —
            # treat as fail-closed boot.
            {:stop, {:oci_bundle_load_failure, reason}}
        end

      {:error, reason} ->
        # Constitution Principle III — fail-closed on policy. The gateway
        # MUST NOT come up if the configured bundle cannot be fetched +
        # verified.
        {:stop, {:oci_bundle_load_failure, reason}}
    end
  end

  @impl true
  def handle_call({:activate, new_ref, opts}, _from, state) do
    %{
      provider_module: provider_module,
      provider_state: %{} = old_provider_state,
      config: old_config,
      pubsub: pubsub,
      persistent_term_key: pt_key
    } = state

    write_to_active? = Map.get(state, :write_to_active?, true)

    new_config = Map.put(old_config, :ref, new_ref)

    case provider_module.init(new_config) do
      {:ok, new_provider_state} ->
        with {:ok, new_bundle} <- provider_module.fetch_active_bundle(new_provider_state),
             :ok <- maybe_activate(new_bundle, write_to_active?) do
          old_bundle = current_bundle_or_nil(pt_key)
          old_digest_hex = digest_hex(old_bundle && old_bundle.digest)
          new_digest_hex = digest_hex(new_bundle.digest)
          activated_at = DateTime.utc_now()

          # Optional digest assertion — currently advisory only. Logged
          # for forensics; future hardening may fail-closed on mismatch.
          maybe_log_digest_assertion(opts, new_digest_hex)

          # Legacy persistent_term key — backwards-compat for
          # `active_bundle/0` callers.
          :persistent_term.put(pt_key, new_bundle)

          # Legacy supersede broadcast — kept for backwards-compat
          # with `OciPolicyProvider.subscribe_supersede_notifications/2`
          # subscribers. New subscribers should call
          # `Recurse.Gateway.Policy.Active.subscribe/0`.
          Phoenix.PubSub.broadcast(
            pubsub,
            @pubsub_topic,
            {:bundle_superseded,
             %{
               old_digest: old_digest_hex,
               new_digest: new_digest_hex,
               source_ref: new_bundle.source_ref,
               activated_at: activated_at
             }}
          )

          Logger.info(
            "OciBundleManager activated new bundle — old_digest=#{old_digest_hex} " <>
              "new_digest=#{new_digest_hex} ref=#{new_bundle.source_ref}"
          )

          :telemetry.execute(
            [:recurse, :policy, :oci_bundle, :activated],
            %{count: 1},
            %{
              old_digest_hex: old_digest_hex,
              new_digest_hex: new_digest_hex,
              source_ref: new_bundle.source_ref
            }
          )

          new_state = %{state | provider_state: new_provider_state, config: new_config}

          {:reply,
           {:ok,
            %{
              old_digest: old_digest_hex,
              new_digest: new_digest_hex,
              ref: new_ref,
              activated_at: activated_at
            }}, new_state}
        else
          {:error, reason} ->
            terminate_failed_provider(provider_module, new_provider_state)
            log_and_telemetry_activate_failure(reason, new_ref)
            {:reply, {:error, reason}, %{state | provider_state: old_provider_state}}
        end

      {:error, reason} ->
        log_and_telemetry_activate_failure(reason, new_ref)
        {:reply, {:error, reason}, %{state | provider_state: old_provider_state}}
    end
  end

  @impl true
  def terminate(_reason, %{provider_module: mod, provider_state: state}) do
    if function_exported?(mod, :terminate, 2) do
      mod.terminate(state, :shutdown)
    end

    :ok
  end

  def terminate(_reason, _state), do: :ok

  # ---------------------------------------------------------------------------
  # Private helpers
  # ---------------------------------------------------------------------------

  defp current_bundle_or_nil(pt_key) do
    :persistent_term.get(pt_key, nil)
  end

  # Build a `%PolicyBundleRef{}` from the OCI provider's active-bundle
  # map and write it to the canonical `Active` store. Maps the OCI
  # field names onto the canonical struct shape:
  #
  #   OCI provider's map      | %PolicyBundleRef{}      | %Active{}
  #   ────────────────────────┼─────────────────────────┼────────────────
  #   :digest                 | :bundle_id (hex)        | metadata.digest
  #   :canonical_hash         | :canonical_hash         | (provenance via metadata)
  #   :bytes                  | :bundle_bytes           | —
  #   :loaded_at              | :loaded_at              | :loaded_at
  #   :source_ref             | —                       | :source_ref
  #   :manifest               | —                       | metadata.manifest
  #   :cedar_version          | —                       | metadata.cedar_version
  defp write_to_active(%{
         digest: digest,
         canonical_hash: canonical_hash,
         bytes: bytes,
         loaded_at: loaded_at,
         source_ref: source_ref,
         manifest: manifest,
         cedar_version: cedar_version
       }) do
    bundle_ref = %PolicyBundleRef{
      bundle_id: digest_hex(digest) || Base.encode16(canonical_hash, case: :lower),
      canonical_hash: canonical_hash,
      loaded_at: loaded_at,
      evaluator_handle: bytes,
      bundle_bytes: bytes
    }

    envelope = %Active{
      source: :oci,
      source_ref: source_ref,
      loaded_at: loaded_at,
      metadata: %{
        digest: digest_hex(digest),
        manifest: manifest,
        cedar_version: cedar_version
      },
      bundle: bundle_ref
    }

    with :ok <- Active.update(envelope) do
      _ = Recurse.Gateway.Policy.BundleArchive.archive(envelope)
      :ok
    end
  end

  defp maybe_activate(bundle, true), do: write_to_active(bundle)
  defp maybe_activate(_bundle, false), do: :ok

  defp digest_hex(nil), do: nil

  defp digest_hex(digest) when is_binary(digest) and byte_size(digest) == 32 do
    "sha256:" <> Base.encode16(digest, case: :lower)
  end

  defp digest_hex(other) when is_binary(other), do: other

  defp digest_hex(_), do: nil

  defp maybe_log_digest_assertion(opts, new_digest_hex) do
    case Keyword.get(opts, :digest) do
      nil ->
        :ok

      asserted when is_binary(asserted) ->
        if asserted != new_digest_hex do
          Logger.warning(
            "OciBundleManager digest assertion mismatch — " <>
              "asserted=#{asserted} actual=#{new_digest_hex} " <>
              "(advisory only; activation proceeded)"
          )
        end
    end
  end

  defp terminate_failed_provider(provider_module, provider_state) do
    if function_exported?(provider_module, :terminate, 2) do
      provider_module.terminate(provider_state, :init_failed_after_partial)
    end

    :ok
  end

  defp log_and_telemetry_activate_failure(reason, new_ref) do
    Logger.error(
      "OciBundleManager activate failed — keeping previous bundle. " <>
        "reason=#{inspect(reason)} new_ref=#{inspect(new_ref)}"
    )

    :telemetry.execute(
      [:recurse, :policy, :oci_bundle, :activate_failure],
      %{count: 1},
      %{reason: reason, new_ref: new_ref}
    )
  end

  defp require_env!(name) do
    case System.get_env(name) do
      nil ->
        raise """
        OciBundleManager is enabled but the required environment variable
        #{name} is unset. The gateway cannot boot the OCI policy provider
        without this value.

        Either export #{name} in the deployment environment, or disable
        the OCI bundle manager via
        `config :recurse_gateway, :oci_policy_provider_enabled?, false`.
        """

      "" ->
        raise """
        OciBundleManager required environment variable #{name} is set
        but empty. Provide a non-empty value or unset the variable
        and disable the OCI bundle manager.
        """

      value ->
        value
    end
  end

  # `R5E_CEDAR_BUNDLE_AUTH` shape examples:
  #   {"type": "ecr_irsa", "region": "us-west-2"}
  #   {"type": "bearer", "token": "..."}
  #   {"type": "basic_auth", "username": "...", "password": "..."}
  #   {"type": "none"}
  defp parse_auth_env!(json) do
    decoded =
      case JSON.decode(json) do
        {:ok, %{} = m} ->
          m

        other ->
          raise """
          R5E_CEDAR_BUNDLE_AUTH must be a JSON object. Got: #{inspect(other)}.
          Examples:
            {"type": "ecr_irsa", "region": "us-west-2"}
            {"type": "bearer", "token": "..."}
          """
      end

    case Map.get(decoded, "type") do
      "ecr_irsa" ->
        region = require_auth_field(decoded, "region", "ecr_irsa")
        {:ecr_irsa, region}

      "bearer" ->
        token = require_auth_field(decoded, "token", "bearer")
        {:bearer, token}

      "basic_auth" ->
        username = require_auth_field(decoded, "username", "basic_auth")
        password = require_auth_field(decoded, "password", "basic_auth")
        {:basic_auth, username, password}

      "none" ->
        :none

      other ->
        raise """
        R5E_CEDAR_BUNDLE_AUTH `type` must be one of:
        "ecr_irsa" | "bearer" | "basic_auth" | "none". Got: #{inspect(other)}.
        """
    end
  end

  defp require_auth_field(map, field, type) do
    case Map.get(map, field) do
      v when is_binary(v) and v != "" ->
        v

      _ ->
        raise """
        R5E_CEDAR_BUNDLE_AUTH type=#{type} requires field "#{field}"
        (non-empty string).
        """
    end
  end
end
