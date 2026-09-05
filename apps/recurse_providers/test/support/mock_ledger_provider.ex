defmodule Recurse.Providers.Support.MockLedgerProvider do
  @moduledoc """
  Fixed-data stub implementation of `Recurse.Providers.LedgerProvider` (T063).

  Returns canonical RFC 9162 TransItem-shaped byte blobs so the contract
  harness can assert shape without standing up a Trillian or
  Postgres-Merkle backend.

  All bytes are deterministic: the "Merkle proof" is a 32-byte pattern
  (`0x00..0x1F`); root hashes are the SHA-256 of the string
  `"mock-ledger-root-<index>"`. Real impls live in
  `apps/recurse_providers/lib/recurse_providers/impls/` (Feature 002+).
  """

  @behaviour Recurse.Providers.LedgerProvider

  @fixed_proof <<0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                 23, 24, 25, 26, 27, 28, 29, 30, 31>>

  @impl true
  def init(_config), do: {:ok, %{tree_size: 42}}

  @impl true
  def commit_epoch(_state, _session_id, epoch_index, _epoch_root) do
    {:ok,
     %{
       index: epoch_index,
       tree_size: 43 + epoch_index,
       root: :crypto.hash(:sha256, "mock-ledger-root-#{epoch_index}")
     }}
  end

  @impl true
  def inclusion_proof(_state, _index, _tree_size), do: {:ok, @fixed_proof}

  @impl true
  def consistency_proof(_state, _from, _to), do: {:ok, @fixed_proof}

  @impl true
  def current_root(_state) do
    {:ok, %{tree_size: 42, root: :crypto.hash(:sha256, "mock-ledger-root-current")}}
  end

  @impl true
  def capabilities(_state), do: [:commit_epoch, :inclusion_proofs, :rfc9162_native]

  @impl true
  def healthcheck(_state), do: :ok

  @impl true
  def terminate(_state, _reason), do: :ok
end
