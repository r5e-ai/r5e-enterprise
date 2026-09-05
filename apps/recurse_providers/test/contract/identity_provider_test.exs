defmodule Recurse.Providers.ContractTest.IdentityProviderTest do
  @moduledoc """
  Contract test for `Recurse.Providers.IdentityProvider` (T066).

  Covers SPIFFE X.509 + JWT SVID fetch, trust-bundle retrieval,
  validation, and netns-workload SVID provisioning. Only structural —
  the real SPIRE workload-API behaviour lives in the concrete impls
  (SpireIdentity, etc.) shipping in Feature 002+.
  """

  use Recurse.Providers.ContractTest,
    for: Recurse.Providers.IdentityProvider,
    mock: Recurse.Providers.Mocks.IdentityProvider,
    stub_with: Recurse.Providers.Support.MockIdentityProvider

  alias Recurse.Providers.Mocks.IdentityProvider, as: Mock

  describe "IdentityProvider — SVID lifecycle" do
    test "fetch_x509_svid/1 returns cert_chain + private_key + expires_at" do
      state = init_state()

      assert {:ok, svid} = Mock.fetch_x509_svid(state)
      assert is_list(svid.cert_chain)
      assert Enum.all?(svid.cert_chain, &is_binary/1)
      assert is_binary(svid.private_key)
      assert %DateTime{} = svid.expires_at
    end

    test "fetch_jwt_svid/2 returns a token + expires_at" do
      state = init_state()
      assert {:ok, %{token: token, expires_at: %DateTime{}}} = Mock.fetch_jwt_svid(state, "aud")
      assert is_binary(token)
    end

    test "fetch_trust_bundle/1 returns a bundle with the trust domain populated" do
      state = init_state()

      assert {:ok, %{trust_domain: td, x509_authorities: auths}} = Mock.fetch_trust_bundle(state)
      assert is_binary(td)
      assert is_list(auths)
      assert Enum.all?(auths, &is_binary/1)
    end

    test "validate_x509_svid/2 returns a SPIFFE ID string on success" do
      state = init_state()

      assert {:ok, spiffe_id} =
               Mock.validate_x509_svid(state, <<0x30, 0x82, 0x00, 0x00>>)

      assert String.starts_with?(spiffe_id, "spiffe://")
    end

    test "provision_workload_svid/3 returns spiffe_id + workload_handle" do
      state = init_state()

      assert {:ok, %{spiffe_id: id, workload_handle: handle}} =
               Mock.provision_workload_svid(state, "netns-001", %{pid: 42})

      assert String.starts_with?(id, "spiffe://")
      assert is_binary(handle)
    end
  end
end
