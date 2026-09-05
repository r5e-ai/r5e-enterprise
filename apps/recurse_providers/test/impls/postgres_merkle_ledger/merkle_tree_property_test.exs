defmodule Recurse.Providers.Impls.PostgresMerkleLedger.MerkleTreePropertyTest do
  @moduledoc """
  Math-only slice of Surface R (property_test_surface_catalog_f002.md).

  Full Surface R is T068 and also exercises the Postgres-Merkle ledger impl;
  this file covers the pure-math layer T034 delivers:

    1. Self-consistency — generated proofs verify against the same tree's root.
    2. Tamper-detection — flipping a byte in the proof makes verify/5 fail.
    3. Wrong-index rejection — verify/5 rejects a correct proof at a wrong index.
    4. Wrong-leaf rejection — verify/5 rejects a correct proof with wrong leaf data.
    5. Single-leaf boundary — tree of size 1 has an empty proof that verifies.

  Generators use `bind` to tie `index` to the list length constructively
  (`stream_data_thinking` trap: `filter` would shrink badly).
  """

  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Recurse.Providers.Impls.PostgresMerkleLedger.MerkleTree

  @moduletag :property

  # Surface R is heavier per catalog; 200 iterations on the math slice.
  @iterations 200

  describe "inclusion proofs (Surface R math slice)" do
    property "generated inclusion proof verifies against the built root" do
      check all({leaves, index} <- leaves_and_index(), max_runs: @iterations) do
        root = MerkleTree.build_root(leaves)
        assert {:ok, proof} = MerkleTree.generate_inclusion_proof(leaves, index)
        leaf = Enum.at(leaves, index)

        assert MerkleTree.verify_inclusion_proof(leaf, index, length(leaves), proof, root),
               "proof failed to verify for tree_size=#{length(leaves)}, index=#{index}"
      end
    end

    property "tampering with any byte of the proof makes verification fail" do
      check all({leaves, index} <- leaves_and_index(min_length: 2), max_runs: @iterations) do
        root = MerkleTree.build_root(leaves)
        {:ok, proof} = MerkleTree.generate_inclusion_proof(leaves, index)
        leaf = Enum.at(leaves, index)

        # Only meaningful when proof is non-empty. leaves_and_index/1 with
        # min_length: 2 guarantees a non-empty proof.
        assert proof != []

        tampered = flip_first_byte_of_first_hash(proof)
        refute tampered == proof

        refute MerkleTree.verify_inclusion_proof(
                 leaf,
                 index,
                 length(leaves),
                 tampered,
                 root
               ),
               "tampered proof unexpectedly verified for tree_size=#{length(leaves)}, index=#{index}"
      end
    end

    property "using the wrong index with a valid proof fails verification" do
      check all({leaves, index, wrong_index} <- leaves_index_and_wrong(), max_runs: @iterations) do
        root = MerkleTree.build_root(leaves)
        {:ok, proof} = MerkleTree.generate_inclusion_proof(leaves, index)
        leaf = Enum.at(leaves, index)

        refute MerkleTree.verify_inclusion_proof(
                 leaf,
                 wrong_index,
                 length(leaves),
                 proof,
                 root
               ),
               "wrong-index verify passed (tree_size=#{length(leaves)}, right=#{index}, wrong=#{wrong_index})"
      end
    end

    property "using wrong leaf data with a valid proof fails verification" do
      check all(
              {leaves, index, wrong_leaf} <- leaves_index_and_wrong_leaf(),
              max_runs: @iterations
            ) do
        root = MerkleTree.build_root(leaves)
        {:ok, proof} = MerkleTree.generate_inclusion_proof(leaves, index)

        refute MerkleTree.verify_inclusion_proof(
                 wrong_leaf,
                 index,
                 length(leaves),
                 proof,
                 root
               ),
               "wrong-leaf verify passed (tree_size=#{length(leaves)}, index=#{index})"
      end
    end

    property "single-leaf tree produces empty proof that verifies" do
      check all(leaf <- binary(min_length: 1, max_length: 128), max_runs: @iterations) do
        leaves = [leaf]
        root = MerkleTree.build_root(leaves)

        assert {:ok, []} = MerkleTree.generate_inclusion_proof(leaves, 0)
        assert MerkleTree.verify_inclusion_proof(leaf, 0, 1, [], root)
      end
    end
  end

  # --- generators ---

  # Leaf data blobs. Non-empty binaries, length-bounded to keep iteration fast
  # while still exercising edge cases (1-byte leaves exercise the boundary
  # between the SHA-256 block size and the leaf-data length).
  defp leaf_blob do
    binary(min_length: 1, max_length: 128)
  end

  # `gen all` (flattened `bind`) to constructively tie index to list length.
  # catalog-R shrinking trap: filtering on `index < length(leaves)` produces
  # unshrinkable pairs because StreamData shrinks leaves and index
  # independently.
  defp leaves_and_index(opts \\ []) do
    min_len = Keyword.get(opts, :min_length, 1)

    gen all(
          leaves <- list_of(leaf_blob(), min_length: min_len, max_length: 500),
          index <- integer(0..(length(leaves) - 1))
        ) do
      {leaves, index}
    end
  end

  # For the wrong-index property we need tree_size >= 2 so we can pick
  # a `wrong_index` that differs from `index`.
  defp leaves_index_and_wrong do
    gen all(
          leaves <- list_of(leaf_blob(), min_length: 2, max_length: 500),
          index <- integer(0..(length(leaves) - 1)),
          maybe_wrong <- integer(0..(length(leaves) - 1))
        ) do
      # Guarantee distinctness by adding 1 mod n when they happen to
      # coincide. This is constructive — no filter, no lost shrinks.
      wrong =
        if maybe_wrong == index,
          do: rem(index + 1, length(leaves)),
          else: maybe_wrong

      {leaves, index, wrong}
    end
  end

  # For wrong-leaf property, draw an extra blob and guarantee it differs
  # from the indexed leaf by prepending a marker byte. Constructive.
  defp leaves_index_and_wrong_leaf do
    gen all(
          {leaves, index} <- leaves_and_index(),
          candidate <- binary(min_length: 1, max_length: 128)
        ) do
      real = Enum.at(leaves, index)
      # Guarantee distinctness by prepending a byte that SHA-256 will propagate.
      wrong = if candidate == real, do: <<0xFF>> <> candidate, else: candidate
      {leaves, index, wrong}
    end
  end

  # Flip the low bit of the first byte of the first hash in the proof.
  # Precondition: proof non-empty.
  defp flip_first_byte_of_first_hash([<<b, rest::binary>> | tail]) do
    [<<Bitwise.bxor(b, 1), rest::binary>> | tail]
  end
end
