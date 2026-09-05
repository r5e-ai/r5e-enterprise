defmodule Recurse.Providers.ContractTest.SecretsProviderTest do
  @moduledoc """
  Contract test for `Recurse.Providers.SecretsProvider` (T065).

  Covers the FR-046 signing-key-release path and the FR-047 RFC 8693
  token-exchange path. Does not verify actual cryptographic signature
  correctness — concrete impls (VaultSecrets, KmsSecrets) own that in
  Feature 002+.
  """

  use Recurse.Providers.ContractTest,
    for: Recurse.Providers.SecretsProvider,
    mock: Recurse.Providers.Mocks.SecretsProvider,
    stub_with: Recurse.Providers.Support.MockSecretsProvider

  alias Recurse.Providers.Mocks.SecretsProvider, as: Mock

  describe "SecretsProvider — FR-046 signing key release" do
    test "active_signing_key/1 returns a handle with key_id + key_version + algorithm" do
      state = init_state()

      assert {:ok, handle} = Mock.active_signing_key(state)
      assert is_binary(handle.key_id)
      assert is_integer(handle.key_version)
      assert handle.algorithm in [:ed25519, :ecdsa_p256, :rsa_pss_2048]
    end

    test "sign/3 returns a binary signature without exposing key material" do
      state = init_state()
      {:ok, handle} = Mock.active_signing_key(state)
      payload = "canonical-bytes-to-sign"

      assert {:ok, signature} = Mock.sign(state, handle, payload)
      assert is_binary(signature)
      # Defense-in-depth: signature must not be the payload itself.
      refute signature == payload
    end

    test "public_key/2 returns PEM" do
      state = init_state()
      {:ok, handle} = Mock.active_signing_key(state)

      assert {:ok, pem} = Mock.public_key(state, handle)
      assert String.contains?(pem, "-----BEGIN PUBLIC KEY-----")
      assert String.contains?(pem, "-----END PUBLIC KEY-----")
    end
  end

  describe "SecretsProvider — FR-047 RFC 8693 token exchange" do
    test "store_user_token/4 accepts a user token + TTL" do
      state = init_state()
      {:ok, identity_ctx} = build_identity_context()
      assert :ok = Mock.store_user_token(state, identity_ctx, "mock-user-oidc", 300)
    end

    test "exchange_for_downstream_token/4 returns a scoped token" do
      state = init_state()
      {:ok, identity_ctx} = build_identity_context()

      assert {:ok, %{token: token, expires_at: expires_at, scope: scope}} =
               Mock.exchange_for_downstream_token(state, identity_ctx, "jira", ["read"])

      assert is_binary(token)
      assert %DateTime{} = expires_at
      assert scope == ["read"]
    end
  end

  defp build_identity_context do
    principal =
      Recurse.Shared.Principal.obo_human(%{
        issuer: "https://mock-idp.recurse.test",
        subject: "mock-user-1"
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
