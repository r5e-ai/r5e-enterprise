defmodule Recurse.Providers.Impls.StandaloneIdentityProviderTest do
  @moduledoc """
  Contract test for `Recurse.Providers.Impls.StandaloneIdentityProvider` (T022).

  **Status:** architecturally no-op — NOT a Phase-2 stub. All non-lifecycle
  callbacks permanently return `{:error, {:not_applicable, :standalone_gateway}}`
  (or `{:error, :not_applicable}` for the simpler `validate_x509_svid/2`
  signature). There is no Phase-3 work that flips these on; the Standalone
  Gateway deliberately has no SPIFFE surface. For that reason most tests in
  this file are NOT `@tag :pending` — they assert the permanent shape.
  """

  use ExUnit.Case, async: true

  alias Recurse.Providers.Impls.StandaloneIdentityProvider

  setup do
    {:ok, state} = StandaloneIdentityProvider.init(%{})
    %{state: state}
  end

  describe "init/1" do
    test "returns {:ok, inert_state_marker}", %{state: state} do
      assert %{stub: true, reason: :standalone_gateway_has_no_spiffe} = state
    end
  end

  describe "fetch_x509_svid/1" do
    test "returns {:error, {:not_applicable, :standalone_gateway}}", %{state: state} do
      assert {:error, {:not_applicable, :standalone_gateway}} =
               StandaloneIdentityProvider.fetch_x509_svid(state)
    end
  end

  describe "fetch_jwt_svid/2" do
    test "returns {:error, {:not_applicable, :standalone_gateway}}", %{state: state} do
      assert {:error, {:not_applicable, :standalone_gateway}} =
               StandaloneIdentityProvider.fetch_jwt_svid(state, "aud")
    end
  end

  describe "fetch_trust_bundle/1" do
    test "returns {:error, {:not_applicable, :standalone_gateway}}", %{state: state} do
      assert {:error, {:not_applicable, :standalone_gateway}} =
               StandaloneIdentityProvider.fetch_trust_bundle(state)
    end
  end

  describe "validate_x509_svid/2" do
    test "returns {:error, :not_applicable} (validation_failure-shape)", %{state: state} do
      assert {:error, :not_applicable} =
               StandaloneIdentityProvider.validate_x509_svid(state, "cert-bytes")
    end
  end

  describe "provision_workload_svid/3" do
    test "returns {:error, {:not_applicable, :standalone_gateway}}", %{state: state} do
      assert {:error, {:not_applicable, :standalone_gateway}} =
               StandaloneIdentityProvider.provision_workload_svid(state, "netns_1", %{})
    end
  end

  describe "capabilities/1" do
    test "advertises an empty capability list by design", %{state: state} do
      assert [] = StandaloneIdentityProvider.capabilities(state)
    end
  end

  describe "healthcheck/1" do
    test "always :ok — no external dependency to be unhealthy", %{state: state} do
      assert :ok = StandaloneIdentityProvider.healthcheck(state)
    end
  end

  describe "terminate/2" do
    test "returns :ok", %{state: state} do
      assert :ok = StandaloneIdentityProvider.terminate(state, :normal)
    end
  end
end
