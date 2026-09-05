defmodule Recurse.Shared.Attestation.Rfc9162PropertyTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Recurse.Shared.Attestation.Rfc9162

  describe "inclusion_v1 TransItem round-trip (SC-014.d)" do
    property "encode |> decode == {:ok, trans_item}" do
      check all(ti <- inclusion_v1_gen()) do
        bin = Rfc9162.encode(ti)
        assert {:ok, decoded} = Rfc9162.decode(bin)
        assert decoded == ti
      end
    end

    property "binary encoding is byte-stable" do
      check all(ti <- inclusion_v1_gen()) do
        assert Rfc9162.encode(ti) == Rfc9162.encode(ti)
      end
    end

    property "decode rejects truncated inputs" do
      check all(ti <- inclusion_v1_gen()) do
        bin = Rfc9162.encode(ti)
        # Truncating below the minimum header (2 + 32 + 8 + 8 + 2 = 52 bytes)
        # yields a malformed result.
        truncated = binary_part(bin, 0, min(byte_size(bin), 30))
        assert {:error, _} = Rfc9162.decode(truncated)
      end
    end
  end

  # --- generators ---

  defp hash32 do
    StreamData.binary(length: 32)
  end

  defp inclusion_v1_gen do
    gen all(
          log_id <- hash32(),
          leaf_index <- StreamData.integer(0..1_000_000),
          tree_size <- StreamData.integer(1..1_000_000),
          path <- StreamData.list_of(hash32(), max_length: 16)
        ) do
      Rfc9162.inclusion_v1(log_id, leaf_index, tree_size, path)
    end
  end
end
