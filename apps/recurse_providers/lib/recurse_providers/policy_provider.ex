defmodule Recurse.Providers.PolicyProvider do
  @moduledoc """
  Provider Interface — PolicyProvider.

  Spec source: FR-003, FR-039, FR-049, FR-052. Cedar policy bundle distribution
  and retrieval, plus the server-side endpoints that back the Cedar Playground
  and Discovery-to-Policy flows.

  The Cedar engine itself is committed (Constitution Principle V); this
  interface abstracts WHERE policy bundles come from and HOW updates are
  distributed, not the evaluation engine.

  Phase-1 distribution paths:

  - **OCI Artifacts** (`application/vnd.cedar.policy.v1`) for Managed SaaS /
    VPC Runner / Standalone Gateway with reachable OCI registries (per
    Phase-1 research recommendation 1).
  - **Offline signed manifests** for Air-Gapped Appliance per FR-052 — signed
    bundle drops via USB or the customer's offline-update channel.

  Reference implementations (Feature 002+ per task T068):

  - `OciPolicyProvider` — pulls from OCI registries (ECR, GHCR, Harbor, etc.)
  - `OfflineSignedPolicyProvider` — accepts manifest-driven offline bundle drops

  No Phase-2-forward-compat hooks for intent-aware JIT minting are
  pre-allocated. When intent classification ships in Phase 2, this interface
  will be extended at that time per `feedback_no_premature_metaapi.md`.
  """

  @type config :: map()
  @type state :: term()

  @typedoc "OCI artifact digest (SHA-256) — the bundle's distribution-time identity."
  @type bundle_digest :: binary()

  @typedoc "Cedar policy bundle bytes (the OCI artifact contents)."
  @type bundle_bytes :: binary()

  @typedoc "SHA-256 of `JCS(PolicySet::to_json())` — what receipts reference per FR-039."
  @type policy_canonical_hash :: binary()

  @typedoc "Cedar policy text — input to Playground per FR-049 surface 1."
  @type cedar_policy_source :: String.t()

  @typedoc "Mock request for policy simulation (principal / action / resource / context)."
  @type mock_request :: %{
          principal: map(),
          action: map(),
          resource: map(),
          context: map()
        }

  @typedoc "Cedar evaluation decision."
  @type decision :: :allow | :deny

  @typedoc "Subscription handle returned by `subscribe_supersede_notifications/2`."
  @type subscription :: term()

  @typedoc """
  Optional-feature capability flags an implementation declares via `capabilities/1`.
  """
  @type capability ::
          :oci_distribution
          | :offline_signed_manifest
          | :supersede_notifications
          | :simulation
          | :blast_radius
          | :propose_from_event

  @doc """
  Initialize the provider with deployment-time configuration.
  """
  @callback init(config) :: {:ok, state} | {:error, term()}

  @doc """
  Fetch the currently-active bundle. Called by the Gateway's policy cache at
  startup and on supersede notifications.
  """
  @callback fetch_active_bundle(state) ::
              {:ok,
               %{
                 digest: bundle_digest,
                 bytes: bundle_bytes,
                 canonical_hash: policy_canonical_hash
               }}
              | {:error, term()}

  @doc """
  Fetch a specific historical bundle by digest.

  Used for receipt verification — old receipts reference the
  `policy_canonical_hash` at decision time; auditors need the bundle that
  produced that hash to replay the evaluation.
  """
  @callback fetch_bundle(state, bundle_digest) ::
              {:ok, %{bytes: bundle_bytes, canonical_hash: policy_canonical_hash}}
              | {:error, :not_found | term()}

  @doc """
  Subscribe to bundle-supersede notifications. Implementations may push events
  when a new bundle is available (OCI registry webhook, polling, file-watcher
  for offline manifests).

  The callback is either a pid that receives messages or a function invoked
  per notification, at the implementation's discretion; the returned
  `subscription` term is the handle used to tear the subscription down.
  """
  @callback subscribe_supersede_notifications(
              state,
              callback :: pid() | function()
            ) :: {:ok, subscription} | {:error, term()}

  @doc """
  Run a Cedar simulation against a candidate policy text + mock request, used
  by the Cedar Playground (FR-049 surface 1) for sub-millisecond ALLOW/DENY
  feedback.

  Returns the decision, the matched-rule attribution, and the evaluation time
  in microseconds. Backs the policy editor's right-pane.
  """
  @callback simulate(state, cedar_policy_source, mock_request) ::
              {:ok,
               %{
                 decision: decision,
                 matched_rules: [String.t()],
                 evaluation_micros: non_neg_integer()
               }}
              | {:error, term()}

  @doc """
  Run a Cedar policy proposal against historical attestations (FR-049 surface 3
  — Blast Radius).

  Implementations stream historical attestations from the Audit Plane / Ledger,
  evaluate each against the proposed policy, and return an impact summary.
  May be long-running; Phase-1 impls MAY be synchronous-with-deadline.
  Async-with-job-id was explicitly deferred per the v6 GAN.
  """
  @callback blast_radius(
              state,
              candidate_cedar_policy :: cedar_policy_source,
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

  @doc """
  Generate a candidate Cedar policy proposal that would have ALLOWed a flagged
  event.

  FR-049 surface 2 — the Discovery-to-Policy "Wiz pattern" wedge from
  `research_round2_outcomes.md`.
  """
  @callback propose_from_event(state, flagged_event :: map()) ::
              {:ok,
               %{
                 proposed_policy: cedar_policy_source,
                 scope_suggestions: [String.t()]
               }}
              | {:error, term()}

  @doc """
  Optional-feature capability flags. See `t:capability/0` for allowed values.
  """
  @callback capabilities(state) :: [capability]

  @doc """
  Healthcheck for `/healthz` aggregation (FR-014).
  """
  @callback healthcheck(state) :: :ok | {:degraded, term()} | {:down, term()}

  @doc """
  Graceful shutdown — cancel watchers, close registry connections.
  """
  @callback terminate(state, reason :: term()) :: :ok
end
