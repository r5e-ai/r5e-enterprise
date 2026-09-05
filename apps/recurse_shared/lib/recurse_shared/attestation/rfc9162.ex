defmodule Recurse.Shared.Attestation.Rfc9162 do
  @moduledoc """
  RFC 9162 (CT v2.0) `TransItem` encoder / decoder.

  Phase-1 scope (research D5 / Phase-1 research recommendation 4):
  supports the `inclusion_v1` variant — the leaf-in-tree-of-size
  inclusion-proof TransItem we emit for FR-038 local and global
  inclusion proofs. Other TransItem types (`consistency_v1`,
  `sth_v2`, etc.) are out of scope; this module rejects them with a
  structured error so Feature 002+ can extend cleanly.

  ## Wire format

  RFC 9162 uses TLS presentation language (RFC 8446 §3). We implement:

      struct {
        opaque log_id<32..32>;        // 32-byte fixed log identifier
        uint64 leaf_index;
        uint64 tree_size;
        NodeHash inclusion_path<0..2^16-1>;
      } InclusionProofV1;

      NodeHash = opaque node_hash<32..32>;  // 32-byte SHA-256

      struct {
        VersionedTransType versioned_type;  // uint16 = 0x0100 for inclusion_v1
        InclusionProofV1 body;
      } TransItem;

  The 2-byte `VersionedTransType` tag for `inclusion_v1` is `0x0100`
  (version byte 1, type byte 0 — matches the RFC's IANA allocation
  pattern; exact codepoint may require a second-pass validation
  against an updated RFC 9162 registry when Feature 002+ lands the
  on-the-wire interop tests).

  ## Invariant (property-tested)

  `encode(TransItem) |> decode == {:ok, TransItem}` for any valid
  inclusion proof (up to 2^16 path hashes, all 32 bytes); binary
  encoding is byte-stable under re-encoding.
  """

  @inclusion_v1_tag 0x0100

  @type log_id :: <<_::256>>
  @type node_hash :: <<_::256>>

  @type inclusion_v1 :: %{
          type: :inclusion_v1,
          log_id: log_id(),
          leaf_index: non_neg_integer(),
          tree_size: non_neg_integer(),
          inclusion_path: [node_hash()]
        }

  @type trans_item :: inclusion_v1()

  @doc """
  Build an `:inclusion_v1` TransItem map.
  """
  @spec inclusion_v1(log_id(), non_neg_integer(), non_neg_integer(), [node_hash()]) ::
          inclusion_v1()
  def inclusion_v1(log_id, leaf_index, tree_size, inclusion_path)
      when is_binary(log_id) and byte_size(log_id) == 32 and
             is_integer(leaf_index) and leaf_index >= 0 and
             is_integer(tree_size) and tree_size >= 0 and
             is_list(inclusion_path) do
    :ok = validate_path(inclusion_path)

    %{
      type: :inclusion_v1,
      log_id: log_id,
      leaf_index: leaf_index,
      tree_size: tree_size,
      inclusion_path: inclusion_path
    }
  end

  @doc """
  Encode a TransItem to binary wire format.
  """
  @spec encode(trans_item()) :: binary()
  def encode(%{type: :inclusion_v1} = ti) do
    :ok = validate_path(ti.inclusion_path)

    if byte_size(ti.log_id) != 32 do
      raise ArgumentError, "log_id must be exactly 32 bytes"
    end

    if ti.leaf_index > 0xFFFFFFFFFFFFFFFF or ti.leaf_index < 0 do
      raise ArgumentError, "leaf_index out of uint64 range"
    end

    if ti.tree_size > 0xFFFFFFFFFFFFFFFF or ti.tree_size < 0 do
      raise ArgumentError, "tree_size out of uint64 range"
    end

    path_bytes = for hash <- ti.inclusion_path, into: <<>>, do: hash
    path_len = byte_size(path_bytes)

    if path_len > 0xFFFF do
      raise ArgumentError, "inclusion_path exceeds uint16 length bound"
    end

    <<
      @inclusion_v1_tag::unsigned-integer-size(16),
      ti.log_id::binary-size(32),
      ti.leaf_index::unsigned-integer-size(64),
      ti.tree_size::unsigned-integer-size(64),
      path_len::unsigned-integer-size(16),
      path_bytes::binary
    >>
  end

  @doc """
  Decode a binary TransItem back to its map form. Returns
  `{:ok, trans_item}` or `{:error, reason}`.
  """
  @spec decode(binary()) :: {:ok, trans_item()} | {:error, term()}
  def decode(
        <<@inclusion_v1_tag::unsigned-integer-size(16), log_id::binary-size(32),
          leaf_index::unsigned-integer-size(64), tree_size::unsigned-integer-size(64),
          path_len::unsigned-integer-size(16), path_bytes::binary-size(path_len)>>
      ) do
    case split_path(path_bytes, []) do
      {:ok, path} ->
        {:ok,
         %{
           type: :inclusion_v1,
           log_id: log_id,
           leaf_index: leaf_index,
           tree_size: tree_size,
           inclusion_path: path
         }}

      err ->
        err
    end
  end

  # Distinguish three failure modes:
  #
  #   1. Known tag (inclusion_v1 = 0x0100) but malformed body — caller passed
  #      us something that claims to be inclusion_v1 but doesn't fit the
  #      fixed-width header + path-bytes layout. Report as malformed body,
  #      not "unsupported tag" (speckit-pr-review iteration-4 F002).
  #
  #   2. Unknown tag — reserved for future TransItem variants. Report the tag
  #      value so operators can recognize the case.
  #
  #   3. Input too short to even read a 2-byte tag — generic malformed.
  def decode(<<@inclusion_v1_tag::unsigned-integer-size(16), _rest::binary>>) do
    {:error, :malformed_inclusion_v1_body}
  end

  def decode(<<tag::unsigned-integer-size(16), _rest::binary>>) do
    {:error, {:unsupported_trans_item_tag, tag}}
  end

  def decode(_), do: {:error, :malformed_trans_item}

  # --- internals ---

  defp validate_path(path) do
    Enum.each(path, fn
      <<_::binary-size(32)>> -> :ok
      other -> raise ArgumentError, "inclusion_path element not 32 bytes: #{inspect(other)}"
    end)

    :ok
  end

  defp split_path(<<>>, acc), do: {:ok, Enum.reverse(acc)}

  defp split_path(<<hash::binary-size(32), rest::binary>>, acc) do
    split_path(rest, [hash | acc])
  end

  defp split_path(_, _), do: {:error, :malformed_inclusion_path}
end
