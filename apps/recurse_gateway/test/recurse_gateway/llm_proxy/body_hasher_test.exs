defmodule Recurse.Gateway.LlmProxy.BodyHasherTest do
  @moduledoc """
  Unit + property tests for `Recurse.Gateway.LlmProxy.BodyHasher`.

  Spec source of truth:
    * Constitution Principle III (Cryptographic Provenance) — every
      LLM call carries a real SHA-256 hash of the prompt + response
      bytes, not a placeholder.
    * Constitution Principle IV (Detached Payloads) — only the hash
      ends up in the predicate; raw bytes never persist to the ledger.

  ## What this validates

    * `init/0` + `update/2` + `final/1` is a thin wrapper around
      `:crypto.hash_init(:sha256)` — same output as a single-shot
      `:crypto.hash(:sha256, bytes)` for any byte sequence.
    * Property: SHA-256 chunking-canonicality — for any byte sequence
      chunked into N pieces, the streaming hash equals the single-shot
      hash. This is the foundation of trustworthy `prompt_hash` /
      `response_hash` values: the proxy chunks the response stream as
      it forwards each frame, but the hash MUST equal what an offline
      verifier computes by hashing the canonical reassembled bytes.
  """

  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Recurse.Gateway.LlmProxy.BodyHasher

  describe "init/0 + update/2 + final/1 — basic correctness" do
    test "empty input hashes to SHA-256 of empty string" do
      hash = BodyHasher.init() |> BodyHasher.final()

      assert hash == :crypto.hash(:sha256, "")
      assert byte_size(hash) == 32
    end

    test "single-shot hash of 'hello' matches :crypto.hash" do
      hash =
        BodyHasher.init()
        |> BodyHasher.update("hello")
        |> BodyHasher.final()

      assert hash == :crypto.hash(:sha256, "hello")
    end

    test "two-update equivalent to single-shot of concatenation" do
      streamed =
        BodyHasher.init()
        |> BodyHasher.update("foo")
        |> BodyHasher.update("bar")
        |> BodyHasher.final()

      assert streamed == :crypto.hash(:sha256, "foobar")
    end

    test "multiple updates with binary chunks of varying sizes" do
      streamed =
        BodyHasher.init()
        |> BodyHasher.update(<<0, 1, 2>>)
        |> BodyHasher.update(<<>>)
        |> BodyHasher.update(<<3>>)
        |> BodyHasher.update(<<4, 5, 6, 7>>)
        |> BodyHasher.final()

      assert streamed == :crypto.hash(:sha256, <<0, 1, 2, 3, 4, 5, 6, 7>>)
    end

    test "different inputs produce different hashes" do
      h1 = BodyHasher.init() |> BodyHasher.update("alpha") |> BodyHasher.final()
      h2 = BodyHasher.init() |> BodyHasher.update("beta") |> BodyHasher.final()

      refute h1 == h2
    end
  end

  describe "chunking-canonicality property" do
    @doc """
    For any byte sequence, regardless of how it is chunked, the
    streaming SHA-256 equals the single-shot hash. This is the
    correctness invariant the proxy relies on: the response is
    streamed in chunks but the auditor (hashing offline) sees a
    different chunking yet must compute the same hash.
    """
    property "streaming hash equals single-shot hash regardless of chunking" do
      check all bytes <- StreamData.binary(min_length: 0, max_length: 4096),
                chunk_sizes <- chunking_strategy(byte_size(bytes)),
                max_runs: 200 do
        chunks = chunkify(bytes, chunk_sizes)

        # Sanity: chunks reassemble to the original.
        assert IO.iodata_to_binary(chunks) == bytes

        streamed =
          Enum.reduce(chunks, BodyHasher.init(), &BodyHasher.update(&2, &1))
          |> BodyHasher.final()

        single_shot = :crypto.hash(:sha256, bytes)

        assert streamed == single_shot
      end
    end

    property "result is always exactly 32 bytes" do
      check all bytes <- StreamData.binary(max_length: 1024) do
        hash =
          BodyHasher.init()
          |> BodyHasher.update(bytes)
          |> BodyHasher.final()

        assert byte_size(hash) == 32
      end
    end
  end

  # ---------------------------------------------------------------------------
  # Generators
  # ---------------------------------------------------------------------------

  # Pick a list of chunk sizes that partition a byte string of length n
  # into pieces. We construct directly (no filter) so shrinking stays
  # productive — see stream-data-thinking "Filter Is a Trap".
  #
  # Edge cases naturally covered by the generator:
  #   * n == 0 → empty list, single empty chunk
  #   * 1-chunk partition (whole bytes in one update)
  #   * many small chunks (down to 1 byte each)
  defp chunking_strategy(0), do: StreamData.constant([])

  defp chunking_strategy(n) when n > 0 do
    StreamData.bind(StreamData.integer(1..n), fn num_chunks ->
      # Build a list of `num_chunks` positive sizes that sum to n.
      sizes_for(n, num_chunks)
    end)
  end

  defp sizes_for(n, 1), do: StreamData.constant([n])

  defp sizes_for(n, k) when k > 1 and n >= k do
    # Pick a first chunk of size ∈ [1, n - k + 1] (leaving at least 1 per
    # remaining chunk), then recurse.
    StreamData.bind(StreamData.integer(1..(n - k + 1)), fn first ->
      StreamData.bind(sizes_for(n - first, k - 1), fn rest ->
        StreamData.constant([first | rest])
      end)
    end)
  end

  defp sizes_for(n, k) when k > n do
    # Asked for more chunks than bytes; degrade to one-byte-per-chunk
    # for the first n then ignore the rest.
    StreamData.constant(List.duplicate(1, n))
  end

  defp chunkify(bytes, []) when bytes == "", do: []
  defp chunkify(bytes, []), do: [bytes]
  defp chunkify(bytes, sizes), do: do_chunkify(bytes, sizes, [])

  defp do_chunkify(<<>>, _, acc), do: Enum.reverse(acc)
  defp do_chunkify(rest, [], acc), do: Enum.reverse([rest | acc])

  defp do_chunkify(bytes, [n | rest_sizes], acc) do
    case bytes do
      <<chunk::binary-size(n), rest::binary>> ->
        do_chunkify(rest, rest_sizes, [chunk | acc])

      _ ->
        # Sizes exceed remaining; emit what's left.
        Enum.reverse([bytes | acc])
    end
  end
end
