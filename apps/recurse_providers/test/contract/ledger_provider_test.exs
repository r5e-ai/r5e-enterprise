defmodule Recurse.Providers.ContractTest.LedgerProviderTest do
  @moduledoc """
  Contract test for `Recurse.Providers.LedgerProvider` (T063).

  Asserts round-trip of `commit_epoch/4`, `inclusion_proof/3`,
  `current_root/1`, and the RFC 9162 TransItem binary shape of the
  proof (structural only — real TransItem decoding is surface-d of
  SC-014 and lives in `recurse_shared`'s RFC 9162 property tests).
  """

  use Recurse.Providers.ContractTest,
    for: Recurse.Providers.LedgerProvider,
    mock: Recurse.Providers.Mocks.LedgerProvider,
    stub_with: Recurse.Providers.Support.MockLedgerProvider

  alias Recurse.Providers.Mocks.LedgerProvider, as: Mock

  describe "LedgerProvider behaviour-specific round-trips" do
    test "commit_epoch/4 returns index/tree_size/root triplet" do
      state = init_state()

      assert {:ok, %{index: idx, tree_size: size, root: root}} =
               Mock.commit_epoch(state, "session-01", 0, :crypto.hash(:sha256, "epoch-0"))

      assert is_integer(idx) and idx >= 0
      assert is_integer(size) and size > 0
      assert is_binary(root)
      assert byte_size(root) == 32
    end

    test "inclusion_proof/3 returns a binary proof" do
      state = init_state()
      assert {:ok, proof} = Mock.inclusion_proof(state, 0, 42)
      assert is_binary(proof)
      assert byte_size(proof) > 0
    end

    test "current_root/1 returns a map with tree_size + 32-byte root" do
      state = init_state()
      assert {:ok, %{tree_size: size, root: root}} = Mock.current_root(state)
      assert is_integer(size)
      assert is_binary(root) and byte_size(root) == 32
    end
  end
end
