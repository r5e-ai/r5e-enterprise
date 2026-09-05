defmodule Recurse.Providers.Impls.OciPolicyProvider do
  @moduledoc """
  OCI-backed `Recurse.Providers.PolicyProvider` — pulls Cedar policy
  bundles from an OCI registry (ECR, GHCR, Harbor, Quay), verifies a
  cosign signature against a configured KMS-backed public key, and
  caches the active bundle in the Provider state.

  Designed for Recurse-managed deploys (audit-dev, audit-demo, audit-prod)
  AND BYOC customer deploys where the customer brings their own registry
  + their own cosign key. Hot-reload via `subscribe_supersede_notifications/2`
  + a separate `BundleManager` GenServer that reacts to admin-API
  activate calls.

  ## Bundle artifact layout

  An OCI artifact at `<registry>/<repository>:<tag>` (e.g.
  `123456789012.dkr.ecr.us-west-2.amazonaws.com/cedar-policies/platform-roles:0.1.0-abc1234`)
  with media type `application/vnd.cedar.policy.v1`. The artifact is a
  manifest pointing at three layers:

    * `policy.cedar` — the Cedar policy bundle source
    * `entities.cedarschema.json` — Cedar entity schema
    * `manifest.json` — bundle metadata (`{name, version, parent_digest,
      author, created_at, scope_hint}`)

  Cosign signature attached as a sibling OCI ref (`<digest>.sig` per
  cosign convention) signed by `awskms:///alias/r5e-cosign` (Recurse) or
  the customer's equivalent.

  ## State + caching

  The `state` map holds the active bundle's bytes + canonical_hash +
  digest after a successful `init/1`. Cedar evaluator reads the active
  bundle via `fetch_active_bundle/1` (bypasses the parser on the hot
  path; bundle is parsed once at activation time).

  Historical lookup via `fetch_bundle/2(digest)` re-pulls from the
  registry by digest; ECR's IMMUTABLE tag policy guarantees the digest
  resolves to the exact bytes that were signed. Lookup is for receipt
  replay verification (audit traces a receipt's `policy_bundle_digest`
  back to the bundle that was active at evaluation time).

  ## Authentication

  Multi-registry: the impl uses `Req` with a registry-specific auth
  hook resolved from config:

    * `:ecr_irsa` — AWS IRSA-injected creds → `aws ecr
      get-authorization-token` (cached for the token's TTL)
    * `:basic_auth` — username/password from config or env
    * `:bearer` — pre-issued bearer token (e.g., GitLab Container Registry,
      Harbor robot account)
    * `:none` — public registry, no auth

  Customer onboarding: each customer's deploy passes their own auth
  config via Helm values → `R5E_CEDAR_BUNDLE_REGISTRY_AUTH` env shape.

  ## Cosign verification

  Verification uses `:crypto.verify/4` against the KMS-backed public
  key (fetched once at boot via `aws kms get-public-key` + cached). No
  external `cosign` binary required at runtime — the verification
  primitive is ECDSA-P256-SHA256 against a SHA-256 hash of the bundle
  bytes (cosign's `--key awskms:///` mode wraps exactly this).

  This avoids: extra binaries in the runtime image, fork/exec on every
  bundle pull, and dependency on cosign's CLI evolution.

  ## Capabilities

  Reports `[:oci_distribution, :supersede_notifications,
  :cosign_verification, :historical_lookup, :canonical_hash_computation]`.
  Cedar Playground surfaces (`simulate/3`, `blast_radius/4`,
  `propose_from_event/2`) deferred to F005+ — return
  `{:not_applicable, :standalone_slice}` matching the Filesystem impl.

  ## Cross-references

    * Behaviour — `Recurse.Providers.PolicyProvider`
    * Sibling impl — `Recurse.Providers.Impls.FilesystemPolicyProvider`
      (retained for tests + air-gapped tier)
    * Bundle manager — `Recurse.Gateway.Policy.OciBundleManager` (handles
      hot-reload via admin API)
    * Contract — `specs/001-api-jido-foundations/contracts/policy_bundle_contract.md`
  """

  @behaviour Recurse.Providers.PolicyProvider

  alias Recurse.Cedar

  require Logger

  @cedar_version "4.9.1"

  @cedar_media_type "application/vnd.cedar.policy.v1"

  # Cosign key cache TTL — KMS public keys are stable across the key's
  # lifetime; refetch once an hour to pick up rotation.
  @kms_pubkey_cache_ttl_ms :timer.hours(1)

  @typedoc "Active bundle record cached in state."
  @type active_bundle :: %{
          bundle_bytes: binary(),
          schema_bytes: binary(),
          manifest: map(),
          canonical_hash: <<_::256>>,
          digest: <<_::256>>,
          cedar_version: String.t(),
          loaded_at: DateTime.t(),
          source_ref: String.t()
        }

  @typedoc "Opaque state — callers must not inspect."
  @type state :: %{
          required(:config) => map(),
          required(:registry) => String.t(),
          required(:repository) => String.t(),
          required(:cosign_key_arn) => String.t(),
          required(:auth) => auth_config(),
          required(:active) => active_bundle() | nil
        }

  @typedoc "Per-registry authentication config."
  @type auth_config ::
          {:ecr_irsa, region :: String.t()}
          | {:basic_auth, username :: String.t(), password :: String.t()}
          | {:bearer, token :: String.t()}
          | :none

  @doc """
  Fetch the bundle at the configured ref, cosign-verify, parse Cedar,
  cache.

  Required config keys:

    * `:registry` — OCI registry hostname (e.g.
      `123456789012.dkr.ecr.us-west-2.amazonaws.com`)
    * `:repository` — repo path (e.g. `cedar-policies/platform-roles`)
    * `:ref` — tag or digest (e.g. `0.1.0-abc1234` or
      `sha256:abcd...`)
    * `:cosign_key_arn` — KMS key ARN or alias (e.g.
      `arn:aws:kms:us-west-2:123456789012:key/...` or `alias/r5e-cosign`)
    * `:auth` — `auth_config()` per-registry

  Optional:

    * `:fetch_timeout_ms` (default 30_000)
    * `:http_client` (default `Recurse.Providers.Impls.OciPolicyProvider.HttpClient`,
      tests inject a fake)
  """
  @impl true
  @spec init(Recurse.Providers.PolicyProvider.config()) :: {:ok, state()} | {:error, term()}
  def init(config) when is_map(config) do
    with {:ok, registry} <- require_key(config, :registry),
         {:ok, repository} <- require_key(config, :repository),
         {:ok, ref} <- require_key(config, :ref),
         {:ok, cosign_key_arn} <- require_key(config, :cosign_key_arn),
         {:ok, auth} <- require_key(config, :auth),
         {:ok, fetched} <-
           fetch_and_verify(%{
             registry: registry,
             repository: repository,
             ref: ref,
             cosign_key_arn: cosign_key_arn,
             auth: auth,
             config: config
           }),
         :ok <- validate_bundle_syntax(fetched.bundle_bytes),
         {:ok, canonical_hash} <- compute_canonical_hash(fetched.bundle_bytes) do
      active = %{
        bundle_bytes: fetched.bundle_bytes,
        schema_bytes: fetched.schema_bytes,
        manifest: fetched.manifest,
        canonical_hash: canonical_hash,
        digest: fetched.manifest_digest,
        cedar_version: @cedar_version,
        loaded_at: DateTime.utc_now(),
        source_ref: "#{registry}/#{repository}:#{ref}"
      }

      state = %{
        config: config,
        registry: registry,
        repository: repository,
        cosign_key_arn: cosign_key_arn,
        auth: auth,
        active: active
      }

      Logger.info(fn ->
        "OciPolicyProvider initialized — bundle digest=#{Base.encode16(active.digest, case: :lower)} canonical_hash=#{Base.encode16(canonical_hash, case: :lower)} ref=#{active.source_ref}"
      end)

      {:ok, state}
    end
  end

  @doc """
  Return the currently-loaded bundle triple + OCI extensions
  (`source_ref`, `manifest`).
  """
  @impl true
  def fetch_active_bundle(%{active: nil}), do: {:error, :no_active_bundle}

  def fetch_active_bundle(%{active: active}) do
    {:ok,
     %{
       digest: active.digest,
       bytes: active.bundle_bytes,
       canonical_hash: active.canonical_hash,
       cedar_version: active.cedar_version,
       loaded_at: active.loaded_at,
       source: :oci,
       source_ref: active.source_ref,
       manifest: active.manifest
     }}
  end

  @doc """
  Historical bundle lookup. If the requested digest matches the active
  bundle, return from cache. Otherwise re-pull from the registry by
  digest (ECR immutability guarantees the digest resolves to the same
  bytes that were originally signed). Verifies cosign sig on the
  re-pulled bytes.
  """
  @impl true
  def fetch_bundle(%{active: nil}, _digest), do: {:error, :not_found}

  def fetch_bundle(%{active: active} = state, digest) when is_binary(digest) do
    if active.digest == digest do
      {:ok, %{bytes: active.bundle_bytes, canonical_hash: active.canonical_hash}}
    else
      digest_hex = "sha256:" <> Base.encode16(digest, case: :lower)

      with {:ok, fetched} <-
             fetch_and_verify(%{
               registry: state.registry,
               repository: state.repository,
               ref: digest_hex,
               cosign_key_arn: state.cosign_key_arn,
               auth: state.auth,
               config: state.config
             }),
           :ok <- validate_bundle_syntax(fetched.bundle_bytes),
           {:ok, canonical_hash} <- compute_canonical_hash(fetched.bundle_bytes) do
        {:ok, %{bytes: fetched.bundle_bytes, canonical_hash: canonical_hash}}
      end
    end
  end

  @doc """
  Subscribe to bundle-supersede events. The `OciBundleManager` GenServer
  publishes to `Recurse.Providers.PolicyProvider:supersede` on
  Phoenix.PubSub when a new bundle has been activated via the admin
  API. The subscription handle is the topic name; the caller
  unsubscribes via `Phoenix.PubSub.unsubscribe/2`.
  """
  @impl true
  def subscribe_supersede_notifications(_state, callback) when is_pid(callback) do
    topic = "policy_provider:supersede"

    case Phoenix.PubSub.subscribe(Recurse.PubSub, topic) do
      :ok -> {:ok, topic}
      {:error, reason} -> {:error, reason}
    end
  end

  def subscribe_supersede_notifications(_state, _callback) do
    {:error, :callback_must_be_pid}
  end

  @impl true
  def simulate(_state, _candidate_policy, _mock_request) do
    {:error, {:not_applicable, :standalone_slice}}
  end

  @impl true
  def blast_radius(_state, _candidate_policy, _window_seconds, _identity_ctx) do
    {:error, {:not_applicable, :standalone_slice}}
  end

  @impl true
  def propose_from_event(_state, _flagged_event) do
    {:error, {:not_applicable, :standalone_slice}}
  end

  @impl true
  def capabilities(_state) do
    [
      :oci_distribution,
      :supersede_notifications,
      :cosign_verification,
      :historical_lookup,
      :canonical_hash_computation
    ]
  end

  @impl true
  def healthcheck(%{registry: registry, active: active}) do
    cond do
      is_nil(active) -> {:down, :no_active_bundle}
      stale?(active) -> {:degraded, {:cache_stale, active.loaded_at}}
      true -> probe_registry(registry)
    end
  end

  @impl true
  def terminate(_state, _reason), do: :ok

  # ---------------------------------------------------------------------------
  # Internals — fetch + verify pipeline
  # ---------------------------------------------------------------------------

  # Pulls the OCI manifest, fetches each layer's blob, cosign-verifies
  # the artifact, returns the parsed contents. Returns
  # `{:ok, %{bundle_bytes, schema_bytes, manifest, manifest_digest}}` on
  # success.
  #
  # NOTE: actual OCI HTTP plumbing + cosign signature retrieval lives in
  # sibling modules (Fetcher / CosignVerifier) so this function stays a
  # readable pipeline. Stubs raise until those land in the next commit
  # of this MR — explicit so tests can mock the http_client config.
  defp fetch_and_verify(%{} = ctx) do
    http_client =
      Map.get(ctx.config, :http_client, Recurse.Providers.Impls.OciPolicyProvider.Fetcher)

    cosign_verifier =
      Map.get(ctx.config, :cosign_verifier, Recurse.Providers.Impls.OciPolicyProvider.Cosign)

    with {:ok, manifest_doc, manifest_digest, manifest_bytes} <-
           http_client.fetch_manifest(ctx),
         :ok <- assert_media_type(manifest_doc),
         {:ok, layers} <- http_client.fetch_layers(ctx, manifest_doc),
         {:ok, sig_artifact} <- http_client.fetch_signature_artifact(ctx, manifest_digest),
         :ok <- cosign_verifier.verify(manifest_bytes, sig_artifact, ctx.cosign_key_arn),
         {:ok, bundle_bytes} <- pluck_layer(layers, "policy.cedar"),
         {:ok, schema_bytes} <- pluck_layer(layers, "entities.cedarschema.json"),
         {:ok, manifest_meta_bytes} <- pluck_layer(layers, "manifest.json"),
         {:ok, manifest_meta} <- decode_json(manifest_meta_bytes) do
      {:ok,
       %{
         bundle_bytes: bundle_bytes,
         schema_bytes: schema_bytes,
         manifest: manifest_meta,
         manifest_digest: manifest_digest
       }}
    end
  end

  defp assert_media_type(%{"artifactType" => @cedar_media_type}), do: :ok
  defp assert_media_type(%{"mediaType" => @cedar_media_type}), do: :ok

  defp assert_media_type(other) do
    {:error,
     {:wrong_media_type,
      Map.get(other, "artifactType") || Map.get(other, "mediaType") || :missing}}
  end

  defp pluck_layer(layers, filename) do
    case Enum.find(layers, &(&1.filename == filename)) do
      %{bytes: bytes} -> {:ok, bytes}
      _ -> {:error, {:layer_missing, filename}}
    end
  end

  defp decode_json(bytes) do
    case JSON.decode(bytes) do
      {:ok, decoded} -> {:ok, decoded}
      {:error, reason} -> {:error, {:malformed_manifest_json, reason}}
    end
  end

  defp validate_bundle_syntax(bundle_bytes) do
    case Cedar.validate_policy_syntax(bundle_bytes) do
      :ok -> :ok
      {:error, reason} -> {:error, {:cedar_parse_failed, reason}}
    end
  end

  # `Cedar.canonical_hash/1` returns the raw 32-byte hash and raises on
  # error; `Cedar.canonical_hash_result/1` is the tagged-tuple variant
  # we actually want for the `with`-chain in `init/1`. The original code
  # pattern-matched `{:ok, hash}` against the raw-binary returner — which
  # never matched, surfacing as a `CaseClauseError` at provider init
  # (caught 2026-05-08 once OciPolicyProvider's full pipeline finally
  # ran end-to-end on audit-dev).
  defp compute_canonical_hash(bundle_bytes) do
    case Cedar.canonical_hash_result(bundle_bytes) do
      {:ok, hash} -> {:ok, hash}
      {:error, reason} -> {:error, {:canonical_hash_failed, reason}}
    end
  end

  defp stale?(%{loaded_at: loaded_at}) do
    DateTime.diff(DateTime.utc_now(), loaded_at, :millisecond) > @kms_pubkey_cache_ttl_ms
  end

  defp probe_registry(registry) do
    # Cheap probe: the registry's `/v2/` endpoint returns 200 (or 401
    # if auth-protected — both are signs of life). DNS or TCP failure
    # surfaces as `{:down, ...}`.
    url = "https://#{registry}/v2/"

    case Req.head(url, retry: false, receive_timeout: 5_000) do
      {:ok, %{status: status}} when status in [200, 401] -> :ok
      {:ok, %{status: status}} -> {:degraded, {:registry_probe_status, status}}
      {:error, reason} -> {:down, {:registry_unreachable, reason}}
    end
  end

  defp require_key(map, key) do
    case Map.get(map, key) do
      nil -> {:error, {:missing_required_config, key}}
      value -> {:ok, value}
    end
  end
end
