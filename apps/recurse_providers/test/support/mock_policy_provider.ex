defmodule Recurse.Providers.Support.MockPolicyProvider do
  @moduledoc """
  Fixed-data stub implementation of `Recurse.Providers.PolicyProvider`
  (T068).

  Returns a canonical bundle (`mock://oci/recurse/policy@sha256:<32-byte
  digest>`) with a tiny hard-coded Cedar policy text. Advertises the
  `:oci_distribution` + `:simulation` + `:blast_radius` +
  `:propose_from_event` capabilities.

  **TODO — offline-signed-manifest path** (`:offline_signed_manifest`):
  not advertised by this stub. The full offline-bundle flow (FR-052,
  signed manifest + customer trust-root verification) is US5 / Polish
  territory; the concrete `OfflineSignedPolicyProvider` impl and its
  contract-test extensions ship with task T083.
  """

  @behaviour Recurse.Providers.PolicyProvider

  @mock_bundle_bytes """
  // Mock Cedar bundle — fixed for contract tests only.
  permit(principal, action == Action::"chat", resource);
  forbid(principal, action == Action::"delete", resource == Resource::"prod-db");
  """

  @impl true
  def init(_config), do: {:ok, %{mode: :mock_oci}}

  @impl true
  def fetch_active_bundle(_state) do
    bytes = @mock_bundle_bytes
    digest = :crypto.hash(:sha256, bytes)

    {:ok,
     %{
       digest: digest,
       bytes: bytes,
       canonical_hash: :crypto.hash(:sha256, "canonical::" <> bytes)
     }}
  end

  @impl true
  def fetch_bundle(_state, digest) do
    bytes = @mock_bundle_bytes
    expected_digest = :crypto.hash(:sha256, bytes)

    if digest == expected_digest do
      {:ok,
       %{
         bytes: bytes,
         canonical_hash: :crypto.hash(:sha256, "canonical::" <> bytes)
       }}
    else
      {:error, :not_found}
    end
  end

  @impl true
  def subscribe_supersede_notifications(_state, _callback) do
    {:ok, make_ref()}
  end

  @impl true
  def simulate(_state, policy_source, _mock_request) when is_binary(policy_source) do
    {:ok, %{decision: :allow, matched_rules: ["mock-policy-0"], evaluation_micros: 42}}
  end

  @impl true
  def blast_radius(_state, _policy, _window, _identity_ctx) do
    {:ok, %{impacted_runs: 0, impacted_agents: 0, sample_divergences: []}}
  end

  @impl true
  def propose_from_event(_state, _event) do
    {:ok,
     %{
       proposed_policy: "permit(principal, action, resource) when { true };\n",
       scope_suggestions: ["mock.scope.*"]
     }}
  end

  @impl true
  def capabilities(_state),
    do: [
      :oci_distribution,
      :supersede_notifications,
      :simulation,
      :blast_radius,
      :propose_from_event
    ]

  @impl true
  def healthcheck(_state), do: :ok

  @impl true
  def terminate(_state, _reason), do: :ok
end
