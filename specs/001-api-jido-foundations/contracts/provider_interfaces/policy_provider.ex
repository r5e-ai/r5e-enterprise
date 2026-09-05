defmodule Recurse.Providers.PolicyProvider do
  @moduledoc """
  Provider Interface — PolicyProvider.

  Spec source: FR-003, FR-039, FR-052, FR-049 (simulation API). Cedar policy bundle
  distribution + retrieval. The Cedar engine itself is committed (Constitution Principle V);
  this interface abstracts WHERE policy bundles come from and HOW updates are distributed.

  Phase-1 distribution paths:
  - **OCI Artifacts** (`application/vnd.cedar.policy.v1`) for Managed SaaS / VPC Runner /
    Standalone Gateway with reachable OCI registries (per Phase-1 research recommendation 1).
  - **Offline signed manifests** for Air-Gapped Appliance per FR-052 — signed bundle drops
    via USB / customer offline-update channel.

  Reference implementations:
  - `OciPolicyProvider` — pulls from OCI registries (ECR, GHCR, Harbor, etc.)
  - `OfflineSignedPolicyProvider` — accepts manifest-driven offline bundle drops

  **No Phase-2-forward-compat hooks for intent-aware JIT minting** are pre-allocated.
  When intent classification ships in Phase 2, this interface will be extended at that time
  per `feedback_no_premature_metaapi.md`.
  """

  alias Recurse.Shared.IdentityContext

  @type config :: map()
  @type state :: term()

  @typedoc "OCI artifact digest (SHA-256) — bundle's distribution-time identity"
  @type bundle_digest :: binary()

  @typedoc "Cedar policy bundle bytes (the OCI artifact contents)"
  @type bundle_bytes :: binary()

  @typedoc "SHA-256 of JCS(PolicySet::to_json()) — what receipts reference per FR-039"
  @type policy_canonical_hash :: binary()

  @typedoc "Cedar policy text (input to Playground per FR-049 surface 1)"
  @type cedar_policy_source :: String.t()

  @typedoc "Mock request for policy simulation"
  @type mock_request :: %{
          principal: map(),
          action: map(),
          resource: map(),
          context: map()
        }

  @typedoc "Cedar evaluation decision"
  @type decision :: :allow | :deny

  @callback init(config) :: {:ok, state} | {:error, term()}

  @doc """
  Fetch the currently-active bundle. Called by the Gateway's policy cache at startup
  and on supersede notifications.
  """
  @callback fetch_active_bundle(state) ::
              {:ok, %{digest: bundle_digest, bytes: bundle_bytes, canonical_hash: policy_canonical_hash}}
              | {:error, term()}

  @doc """
  Fetch a specific historical bundle by digest. Used for receipt verification — old
  receipts reference old policy_canonical_hash; auditor needs to retrieve the bundle
  that produced that hash to replay the evaluation.
  """
  @callback fetch_bundle(state, bundle_digest) ::
              {:ok, %{bytes: bundle_bytes, canonical_hash: policy_canonical_hash}} | {:error, :not_found | term()}

  @doc """
  Subscribe to bundle-supersede notifications. Implementation may push events when a new
  bundle is available (OCI registry webhook, polling, file-watcher for offline manifests).
  """
  @callback subscribe_supersede_notifications(state, callback :: pid() | function()) ::
              {:ok, subscription :: term()} | {:error, term()}

  @doc """
  Run a Cedar simulation against a candidate policy text + mock request, used by the
  Cedar Playground (FR-049 surface 1) for sub-millisecond ALLOW/DENY feedback.

  Returns the decision, the matched-rule attribution, and the evaluation time in microseconds.
  This is a server-side endpoint backing the policy editor's right-pane.
  """
  @callback simulate(state, cedar_policy_source, mock_request) ::
              {:ok, %{decision: decision, matched_rules: [String.t()], evaluation_micros: non_neg_integer()}}
              | {:error, term()}

  @doc """
  Run a Cedar policy proposal against historical attestations (FR-049 surface 3 — Blast Radius).
  Implementation streams historical attestations from the Audit Plane / Ledger, evaluates each
  against the proposed policy, returns impact summary. May be long-running; Phase-1 implementation
  may be synchronous-with-deadline and tasks may make it async-with-job-id (deferred per v6 GAN).
  """
  @callback blast_radius(
              state,
              candidate_cedar_policy :: cedar_policy_source,
              historical_window_seconds :: pos_integer(),
              IdentityContext.t()
            ) ::
              {:ok,
               %{
                 impacted_runs: non_neg_integer(),
                 impacted_agents: non_neg_integer(),
                 sample_divergences: [map()]
               }}
              | {:error, term()}

  @doc """
  Generate a candidate Cedar policy proposal that would have ALLOWed a flagged event.
  This is FR-049 surface 2 — the Discovery-to-Policy "Wiz pattern" wedge.
  """
  @callback propose_from_event(state, flagged_event :: map()) ::
              {:ok, %{proposed_policy: cedar_policy_source, scope_suggestions: [String.t()]}}
              | {:error, term()}

  @callback capabilities(state) :: [
              :oci_distribution
              | :offline_signed_manifest
              | :supersede_notifications
              | :simulation
              | :blast_radius
              | :propose_from_event
            ]

  @callback healthcheck(state) :: :ok | {:degraded, term()} | {:down, term()}

  @callback terminate(state, term()) :: :ok
end
