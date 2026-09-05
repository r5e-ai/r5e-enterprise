defmodule Recurse.Providers.ContractTest.StorageProviderTest do
  @moduledoc """
  Contract test for `Recurse.Providers.StorageProvider` (T064).

  Round-trips a byte blob through put → get → delete and asserts the
  SHA-256 payload-hash surfaces in the put response (FR-021 payload_hash
  field downstream).
  """

  use Recurse.Providers.ContractTest,
    for: Recurse.Providers.StorageProvider,
    mock: Recurse.Providers.Mocks.StorageProvider,
    stub_with: Recurse.Providers.Support.MockStorageProvider

  alias Recurse.Providers.Mocks.StorageProvider, as: Mock

  describe "StorageProvider behaviour-specific round-trips" do
    test "put_payload/3 → get_payload/3 round-trips bytes identically" do
      state = init_state()
      {:ok, identity_ctx} = build_identity_context()
      payload = :crypto.strong_rand_bytes(128)

      assert {:ok, %{uri: uri, hash: hash}} = Mock.put_payload(state, payload, identity_ctx)
      assert is_binary(uri)
      assert hash == :crypto.hash(:sha256, payload)

      assert {:ok, retrieved} = Mock.get_payload(state, uri, identity_ctx)
      assert retrieved == payload
    end

    test "delete_payload/3 removes the blob and subsequent get_payload returns an error" do
      state = init_state()
      {:ok, identity_ctx} = build_identity_context()
      payload = "goodbye"

      {:ok, %{uri: uri}} = Mock.put_payload(state, payload, identity_ctx)
      assert :ok = Mock.delete_payload(state, uri, identity_ctx)
      assert {:error, _} = Mock.get_payload(state, uri, identity_ctx)
    end
  end

  defp build_identity_context do
    principal =
      Recurse.Shared.Principal.service_account(%{
        issuer: "https://mock-idp.recurse.test",
        account_id: "contract-test"
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
