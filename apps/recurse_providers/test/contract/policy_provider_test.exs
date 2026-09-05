defmodule Recurse.Providers.ContractTest.PolicyProviderTest do
  @moduledoc """
  Contract test for `Recurse.Providers.PolicyProvider` (T068).

  Covers the OCI-distribution path (`:oci_distribution` capability):
  fetch_active_bundle, fetch_bundle by digest (happy + miss),
  subscribe_supersede_notifications, simulate, blast_radius,
  propose_from_event.

  **TODO — offline signed manifest path** (`:offline_signed_manifest` /
  FR-052): this contract test deliberately stops at OCI coverage.
  Offline-manifest bundle distribution is US5 / Polish territory and
  will be covered by a separate contract test extension authored
  alongside the concrete `OfflineSignedPolicyProvider` impl (task T083).
  """

  use Recurse.Providers.ContractTest,
    for: Recurse.Providers.PolicyProvider,
    mock: Recurse.Providers.Mocks.PolicyProvider,
    stub_with: Recurse.Providers.Support.MockPolicyProvider

  alias Recurse.Providers.Mocks.PolicyProvider, as: Mock

  describe "PolicyProvider — OCI distribution path (FR-039)" do
    test "fetch_active_bundle/1 returns digest + bytes + canonical_hash" do
      state = init_state()

      assert {:ok, %{digest: digest, bytes: bytes, canonical_hash: canonical_hash}} =
               Mock.fetch_active_bundle(state)

      assert is_binary(digest) and byte_size(digest) == 32
      assert is_binary(bytes) and byte_size(bytes) > 0
      assert is_binary(canonical_hash) and byte_size(canonical_hash) == 32
    end

    test "fetch_bundle/2 returns bundle for known digest" do
      state = init_state()
      {:ok, %{digest: digest}} = Mock.fetch_active_bundle(state)
      assert {:ok, %{bytes: _, canonical_hash: _}} = Mock.fetch_bundle(state, digest)
    end

    test "fetch_bundle/2 returns :not_found for unknown digest" do
      state = init_state()
      assert {:error, :not_found} = Mock.fetch_bundle(state, :crypto.hash(:sha256, "unknown"))
    end

    test "subscribe_supersede_notifications/2 returns a teardown handle" do
      state = init_state()
      assert {:ok, handle} = Mock.subscribe_supersede_notifications(state, self())
      assert handle != nil
    end
  end

  describe "PolicyProvider — Cedar Playground surfaces (FR-049)" do
    test "simulate/3 returns decision + matched_rules + evaluation_micros" do
      state = init_state()
      policy = "permit(principal, action, resource);"
      request = %{principal: %{}, action: %{}, resource: %{}, context: %{}}

      assert {:ok, %{decision: decision, matched_rules: rules, evaluation_micros: micros}} =
               Mock.simulate(state, policy, request)

      assert decision in [:allow, :deny]
      assert is_list(rules)
      assert is_integer(micros) and micros >= 0
    end

    test "blast_radius/4 returns impact summary" do
      state = init_state()
      {:ok, identity_ctx} = build_identity_context()

      assert {:ok, %{impacted_runs: runs, impacted_agents: agents, sample_divergences: samples}} =
               Mock.blast_radius(
                 state,
                 "permit(principal, action, resource);",
                 3600,
                 identity_ctx
               )

      assert is_integer(runs) and runs >= 0
      assert is_integer(agents) and agents >= 0
      assert is_list(samples)
    end

    test "propose_from_event/2 returns a candidate policy + scope_suggestions" do
      state = init_state()
      event = %{"action" => "chat", "principal" => %{"kind" => "obo_human"}}

      assert {:ok, %{proposed_policy: policy, scope_suggestions: suggestions}} =
               Mock.propose_from_event(state, event)

      assert is_binary(policy)
      assert is_list(suggestions)
    end
  end

  defp build_identity_context do
    principal =
      Recurse.Shared.Principal.obo_human(%{
        issuer: "https://mock-idp.recurse.test",
        subject: "appsec-engineer"
      })

    {:ok,
     Recurse.Shared.IdentityContext.new(%{
       machine_identity: "spiffe://mock.recurse.test/workload/contract-test",
       principal: principal,
       tenant_id: "tenant-test",
       correlation_id: "01HZZZZZZZZZZZZZZZZZZZZZZZ"
     })}
  end
end
