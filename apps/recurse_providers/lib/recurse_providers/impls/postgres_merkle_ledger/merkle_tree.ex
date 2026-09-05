defmodule Recurse.Providers.Impls.PostgresMerkleLedger.MerkleTree do
  @moduledoc """
  RFC 9162-adjacent Merkle hashing used by the Postgres-Merkle LedgerProvider.
  Pure functions: hashing primitives + inclusion-proof generation/verification.

  The tree itself is stored in the `merkle_nodes` Postgres table (append-only
  per migration T005). This module does the math; the ledger impl (T033) does
  the I/O.

  RFC 9162 §2 hash definitions:

      hash_leaf(data)     = SHA-256(0x00 || data)
      hash_interior(l, r) = SHA-256(0x01 || l || r)

  RFC 9162 §2.1 recursive Merkle Tree Hash (MTH) definition, for D[n] a list
  of `n` data entries (n ≥ 1):

      MTH({d0})   = hash_leaf(d0)
      MTH(D[n>1]) = hash_interior(MTH(D[0:k]), MTH(D[k:n]))

  where `k` is the largest power of 2 strictly less than `n`.

  The inclusion-proof audit path (§2.1.1) is returned **deepest-to-root** —
  the first element is the sibling of the leaf, the last element is the
  sibling of the subtree whose root is the tree root.

  Cross-reference: F001 `Recurse.Shared.Attestation.Rfc9162` owns the
  wire-format TransItem serialization; this module produces the 32-byte
  hashes that go into a TransItem.
  """

  import Bitwise, only: [<<<: 2, >>>: 2]

  @leaf_prefix <<0x00>>
  @interior_prefix <<0x01>>

  @type hash32 :: <<_::256>>

  @doc """
  RFC 9162 §2: `hash_leaf(d) = SHA-256(0x00 || d)`.
  """
  @spec hash_leaf(binary()) :: hash32()
  def hash_leaf(data) when is_binary(data) do
    :crypto.hash(:sha256, @leaf_prefix <> data)
  end

  @doc """
  RFC 9162 §2: `hash_interior(l, r) = SHA-256(0x01 || l || r)`.
  """
  @spec hash_interior(hash32(), hash32()) :: hash32()
  def hash_interior(<<_::256>> = left, <<_::256>> = right) do
    :crypto.hash(:sha256, @interior_prefix <> left <> right)
  end

  @doc """
  Compute the Merkle root over an ordered list of leaf **data** blobs
  (not pre-hashed — `hash_leaf/1` is applied internally). Returns a
  32-byte root.
  """
  @spec build_root([binary(), ...]) :: hash32()
  def build_root([single]) when is_binary(single), do: hash_leaf(single)

  def build_root([_ | _] = leaves) do
    n = length(leaves)
    k = largest_power_of_two_lt(n)
    {left, right} = Enum.split(leaves, k)
    hash_interior(build_root(left), build_root(right))
  end

  @doc """
  Generate an RFC 9162 §2.1.1 audit path (inclusion proof) for the leaf at
  `index` in the given ordered leaf-data list. Returns a list of 32-byte
  sibling hashes, ordered deepest-to-root.

  Returns `{:error, :index_out_of_range}` if `index` is not a valid
  position in `leaves`.

  For a single-leaf tree the proof is `[]`.
  """
  @spec generate_inclusion_proof([binary(), ...], non_neg_integer()) ::
          {:ok, [hash32()]} | {:error, :index_out_of_range}
  def generate_inclusion_proof(leaves, index)
      when is_list(leaves) and is_integer(index) and index >= 0 do
    cond do
      leaves == [] -> {:error, :index_out_of_range}
      index >= length(leaves) -> {:error, :index_out_of_range}
      true -> {:ok, audit_path(leaves, index)}
    end
  end

  def generate_inclusion_proof(_, _), do: {:error, :index_out_of_range}

  # RFC 9162 §2.1.1 PATH(m, D[n]):
  # Base: PATH(0, {d0}) = {}.
  # Recursive: split D[n] at k = largest_power_of_two_lt(n).
  #   If m < k: PATH(m, D[0:k]) ++ [MTH(D[k:n])].
  #   Else:     PATH(m - k, D[k:n]) ++ [MTH(D[0:k])].
  defp audit_path([_one], 0), do: []

  defp audit_path(leaves, index) do
    n = length(leaves)
    k = largest_power_of_two_lt(n)
    {left, right} = Enum.split(leaves, k)

    if index < k do
      audit_path(left, index) ++ [build_root(right)]
    else
      audit_path(right, index - k) ++ [build_root(left)]
    end
  end

  @doc """
  Verify an RFC 9162 §2.1.2 inclusion proof. Returns `true` iff the proof,
  combined with the leaf data at `index` within a tree of `tree_size` leaves,
  reconstructs `expected_root`.

  This implements the standard iterative verifier: walk the proof
  deepest-to-root tracking `(fn_, sn) = (leaf_index, tree_size - 1)` and
  halve both each step. At each step, the parity of `fn_` (and the special
  case `fn_ == sn`, where the leaf is the trailing odd-one-out) tells us
  whether the sibling is on the left or the right — or, in the skip case,
  that there is no sibling at this level.
  """
  @spec verify_inclusion_proof(
          binary(),
          non_neg_integer(),
          pos_integer(),
          [hash32()],
          hash32()
        ) :: boolean()
  def verify_inclusion_proof(leaf_data, index, tree_size, proof, <<_::256>> = expected_root)
      when is_binary(leaf_data) and is_integer(index) and index >= 0 and
             is_integer(tree_size) and tree_size > 0 and is_list(proof) do
    with true <- index < tree_size,
         true <- valid_proof_shape?(proof),
         {:ok, hash} <- fold_proof(hash_leaf(leaf_data), index, tree_size - 1, proof) do
      hash == expected_root
    else
      _ -> false
    end
  end

  def verify_inclusion_proof(_, _, _, _, _), do: false

  defp valid_proof_shape?(proof), do: Enum.all?(proof, &match?(<<_::256>>, &1))

  # Base: single-leaf tree. Proof must be empty; reconstructed hash is the leaf hash.
  defp fold_proof(hash, 0, 0, []), do: {:ok, hash}
  defp fold_proof(_hash, _fn_, 0, [_ | _]), do: :error
  defp fold_proof(_hash, _fn_, _sn, []), do: :error

  defp fold_proof(hash, fn_, sn, [sibling | rest]) do
    # At each level: if fn_ is the right child (odd) OR the trailing stray
    # (fn_ == sn with fn_ even and sn even → "last unpaired left"), the
    # sibling is on the left. Otherwise it's on the right.
    cond do
      # Skip layers where leaf is a stray last-node (no sibling at this level).
      # Detect by: fn_ == sn AND fn_ is even. Halve without consuming the proof.
      fn_ == sn and rem(fn_, 2) == 0 ->
        fold_proof(hash, fn_ >>> 1, sn >>> 1, [sibling | rest])

      # Leaf is a right child at this level — sibling is on the left.
      rem(fn_, 2) == 1 ->
        new_hash = hash_interior(sibling, hash)
        next_fn = fn_ >>> 1
        next_sn = sn >>> 1
        terminate_or_continue(new_hash, next_fn, next_sn, rest)

      # Leaf is a left child with a right sibling.
      true ->
        new_hash = hash_interior(hash, sibling)
        next_fn = fn_ >>> 1
        next_sn = sn >>> 1
        terminate_or_continue(new_hash, next_fn, next_sn, rest)
    end
  end

  defp terminate_or_continue(hash, 0, 0, []), do: {:ok, hash}
  defp terminate_or_continue(_hash, _fn_, _sn, []), do: :error
  defp terminate_or_continue(hash, fn_, sn, rest), do: fold_proof(hash, fn_, sn, rest)

  # Largest power of 2 strictly less than n (for n > 1).
  defp largest_power_of_two_lt(n) when is_integer(n) and n > 1 do
    1 <<< (bit_length(n - 1) - 1)
  end

  # Number of bits required to represent `n` (n ≥ 1).
  defp bit_length(n) when is_integer(n) and n >= 1 do
    do_bit_length(n, 0)
  end

  defp do_bit_length(0, acc), do: acc
  defp do_bit_length(n, acc), do: do_bit_length(n >>> 1, acc + 1)
end
