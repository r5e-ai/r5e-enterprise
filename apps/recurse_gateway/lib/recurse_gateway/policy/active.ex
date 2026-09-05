defmodule Recurse.Gateway.Policy.Active do
  @moduledoc """
  Canonical "active Cedar bundle" store + reader.

  ## Role

  Multiple loaders write the active bundle here:

    * `Recurse.Gateway.Policy.BundleLoader` — filesystem-path loader
      (dev, air-gapped, customer-mounted bundles).
    * `Recurse.Gateway.Policy.OciBundleManager` — OCI registry loader
      (managed-SaaS, customer-published bundles via cosign-verified
      ECR / GHCR / Harbor / Quay).
    * Future: `Recurse.Gateway.Policy.DbBundleLoader` — UI-authored
      policies in audit-console (not implemented; named here so the
      protocol's intent is clear for later readers).
    * Future: `Recurse.Gateway.Policy.CustomerFeedLoader` — existing
      customer policy-management systems via PolicyProvider impls
      (not implemented; reserves the namespace).

  All Cedar-evaluating call sites READ FROM HERE via `current/0`, NOT
  from any specific loader. Hot-swap is atomic via
  `:persistent_term.put/2`; broadcasts a `policy_active:supersede`
  event so subscribers (e.g. the LLM proxy's Cedar gate decision
  cache) can invalidate cached decisions on bundle change.

  ## Envelope vs. payload (the "C" decision)

  The `t/0` struct is an ENVELOPE that carries provenance
  (`:source`, `:source_ref`, `:loaded_at`, `:metadata`) around an
  inner `%Recurse.Gateway.PolicyBundleRef{}` payload. Callers that
  only need bundle data destructure
  `%Active{bundle: %PolicyBundleRef{} = pb}` and use `pb.bundle_bytes`
  / `pb.canonical_hash` exactly as they did before. Callers that need
  provenance (e.g. the attestation emitter writing "what bundle was
  active at call-start") read the envelope's `:source`, `:source_ref`.

  ## Architectural background

  See `specs/009-llm-api-proxy/` and `specs/005-api-substrate-mcp/`
  (MR !119 OciPolicyProvider) for the historical context. Constitution
  Principle V (Provider-Interface Neutrality): each loader is a
  Provider impl; this module is the consumer-side seam they all funnel
  through. Constitution Principle III (Fail-Closed on Policy):
  `current/0` returns `{:error, :not_loaded}` when no loader has
  populated the canonical entry — callers MUST fail-closed.

  ## Iron-Law check (`elixir:otp-thinking`)

  Loader metadata lives in `:persistent_term`; the admitted bundle is the
  authority. A local activation lock serializes writes across all loaders,
  and readers reject projections whose source no longer matches the chain.

  ## Cross-references

    * `apps/recurse_gateway/lib/recurse_gateway/policy/bundle_loader.ex`
      (filesystem loader; calls `update/1`)
    * `apps/recurse_gateway/lib/recurse_gateway/policy/oci_bundle_manager.ex`
      (OCI loader; calls `update/1`)
    * `apps/recurse_gateway/lib/recurse_gateway/policy/policy_bundle_ref.ex`
      (inner payload struct shared across all loaders)
  """

  alias Recurse.Gateway.PolicyBundleRef

  @persistent_term_key {__MODULE__, :current}
  @pubsub_topic "policy_active:supersede"

  @typedoc """
  Loader source discriminator. Identifies WHICH loader populated the
  current entry. Used by attestation emitters and audit trails.
  """
  @type source :: :filesystem | :oci | :db | :customer_feed | atom()

  @typedoc """
  Active-bundle envelope. The inner `:bundle` is the canonical
  `%PolicyBundleRef{}` that all callers consume. The other fields are
  provenance.

    * `:source` — which loader wrote this entry.
    * `:source_ref` — source-specific reference (OCI ref string,
      filesystem path, DB row id). May be `nil` for sources that lack
      a stable handle.
    * `:loaded_at` — when this entry was written (UTC).
    * `:metadata` — source-specific blob. Examples: `%{file_path: ...}`
      for filesystem, `%{manifest: ..., digest: ..., source_ref: ...}`
      for OCI, `%{policy_set_id: ...}` for db.
    * `:bundle` — the canonical inner payload.
  """
  @type t :: %__MODULE__{
          source: source(),
          source_ref: String.t() | nil,
          loaded_at: DateTime.t(),
          metadata: map(),
          bundle: PolicyBundleRef.t()
        }

  @enforce_keys [:source, :loaded_at, :bundle]
  defstruct [:source, :source_ref, :loaded_at, :bundle, metadata: %{}]

  @typedoc "Supersede broadcast payload. Sent on `:pubsub_topic`."
  @type supersede_event :: %{
          old_canonical_hash_hex: String.t() | nil,
          new_canonical_hash_hex: String.t(),
          source: source(),
          source_ref: String.t() | nil,
          activated_at: DateTime.t()
        }

  # ---------------------------------------------------------------------------
  # Public API
  # ---------------------------------------------------------------------------

  @doc """
  Read the current active-bundle envelope.

  Reads the local loader projection and verifies its source against the
  currently admitted bundle. A stale projection is unavailable.

  Returns `{:error, :not_loaded}` if no loader has populated the
  entry yet (boot-pending or test fixture without a loader). Callers
  MUST fail-closed on `:not_loaded` (Constitution Principle III).
  """
  @spec current() :: {:ok, t()} | {:error, :not_loaded}
  def current do
    case :persistent_term.get(@persistent_term_key, :not_loaded) do
      :not_loaded ->
        {:error, :not_loaded}

      %__MODULE__{} = active ->
        if admitted_projection?(active), do: {:ok, active}, else: {:error, :not_loaded}
    end
  end

  @doc """
  Atomically replace the active bundle and broadcast a supersede
  event on `pubsub_topic/0`.

  Loaders call this after they've successfully fetched + verified +
  parsed a new bundle. The write is `:persistent_term.put/2` — atomic
  with respect to readers; readers either see the old or the new
  envelope, never a torn intermediate. Per OTP docs, `:persistent_term`
  writes trigger a global GC of processes referencing the prior term,
  which is why we restrict writes to operator-driven loader events
  (boot, OCI activation, SIGHUP-triggered reload) — never on the hot
  path.

  The supersede broadcast lets subscribers (decision caches,
  per-call snapshot consumers) invalidate cached state. Subscribers
  use `subscribe/0`.

  Returns `:ok`.
  """
  @spec update(t()) :: :ok | {:error, term()}
  def update(%__MODULE__{bundle: %PolicyBundleRef{} = bundle} = active) do
    # Serialize all local loaders through one activation lock. The admission
    # and its projection cannot be reordered by two different loader processes.
    :global.trans(
      {{__MODULE__, :activation}, self()},
      fn ->
        case Recurse.Gateway.Fold.Submitter.submit_bundle(active) do
          {:ok, _address} ->
            old = :persistent_term.get(@persistent_term_key, :not_loaded)
            :persistent_term.put(@persistent_term_key, active)
            broadcast_supersede(old, active, bundle)
            :ok

          failure ->
            {:error, {:policy_admission, failure}}
        end
      end,
      [node()]
    )
  end

  defp admitted_projection?(%__MODULE__{bundle: %{bundle_bytes: bytes}}) when is_binary(bytes) do
    expected = "bytes:sha256:" <> Base.encode16(:crypto.hash(:sha256, bytes), case: :lower)

    case Recurse.Fold.Policy.Cedar.active_bundle() do
      {:ok, entry} -> get_in(entry, ["spec", "sourceRef", "$ref"]) == expected
      _ -> false
    end
  rescue
    _ -> false
  catch
    :exit, _ -> false
  end

  defp admitted_projection?(_), do: false

  @doc """
  Erase the active bundle entry. Test-only — production code never
  calls this.

  Used by ExUnit setup blocks that need a clean slate between tests.
  """
  @spec erase() :: :ok
  def erase do
    _ = :persistent_term.erase(@persistent_term_key)
    :ok
  end

  @doc """
  Subscribe the calling process to supersede events. Each event is
  delivered as a Phoenix.PubSub message with the topic
  `pubsub_topic/0` and payload `{:active_bundle_superseded,
  supersede_event()}`.

  Returns `:ok` on success. Returns `{:error, reason}` if the PubSub
  server is unreachable (e.g. test process started before
  `Recurse.PubSub` came up).
  """
  @spec subscribe(atom()) :: :ok | {:error, term()}
  def subscribe(pubsub \\ Recurse.PubSub) do
    Phoenix.PubSub.subscribe(pubsub, @pubsub_topic)
  end

  @doc "Phoenix.PubSub topic where supersede events are broadcast."
  @spec pubsub_topic() :: String.t()
  def pubsub_topic, do: @pubsub_topic

  @doc """
  Return the persistent_term key. Tests + introspection only;
  production callers should use `current/0`.
  """
  @spec persistent_term_key() :: term()
  def persistent_term_key, do: @persistent_term_key

  # ---------------------------------------------------------------------------
  # Internal helpers
  # ---------------------------------------------------------------------------

  defp broadcast_supersede(old, %__MODULE__{} = new_active, %PolicyBundleRef{} = new_bundle) do
    payload = %{
      old_canonical_hash_hex: old_hash_hex(old),
      new_canonical_hash_hex: Base.encode16(new_bundle.canonical_hash, case: :lower),
      source: new_active.source,
      source_ref: new_active.source_ref,
      activated_at: new_active.loaded_at
    }

    # Best-effort broadcast. PubSub may not be up in unit tests that
    # exercise update/1 directly; the swap itself already succeeded
    # (the chain has already admitted the activation).
    case Phoenix.PubSub.broadcast(
           Recurse.PubSub,
           @pubsub_topic,
           {:active_bundle_superseded, payload}
         ) do
      :ok -> :ok
      {:error, _reason} -> :ok
    end
  rescue
    # PubSub server might not be registered (test/script context).
    # Treat broadcast failure as non-fatal — the persistent_term write
    # is only a projection of the admitted state.
    ArgumentError -> :ok
  end

  defp old_hash_hex(:not_loaded), do: nil

  defp old_hash_hex(%__MODULE__{bundle: %PolicyBundleRef{canonical_hash: hash}}),
    do: Base.encode16(hash, case: :lower)
end
