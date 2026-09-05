defmodule Recurse.Gateway.Policy.ActiveTest do
  @moduledoc """
  Tests for the canonical `Recurse.Gateway.Policy.Active` store +
  reader.

  Covers:

    * `current/0` returns `{:error, :not_loaded}` when no loader has
      written.
    * `update/1` writes atomically + `current/0` returns the written
      envelope.
    * Successive `update/1` calls swap the entry with no torn read in
      between (property test — `stream-data-thinking`).
    * Subscribers receive a `{:active_bundle_superseded, payload}`
      broadcast on each update.

  `async: false` because `Active`'s store is a VM-global
  `:persistent_term` entry. We `erase/0` between tests.
  """

  use ExUnit.Case, async: false

  setup_all do
    Recurse.Gateway.Test.KernelFixture.boot()
  end
  use ExUnitProperties

  alias Recurse.Gateway.Policy.Active
  alias Recurse.Gateway.PolicyBundleRef

  setup do
    Active.erase()
    :ok
  end

  defp build_envelope(opts \\ []) do
    canonical_hash = Keyword.get(opts, :canonical_hash, :crypto.strong_rand_bytes(32))
    bytes = Keyword.get(opts, :bytes, "permit(principal, action, resource);\n")
    source = Keyword.get(opts, :source, :filesystem)
    source_ref = Keyword.get(opts, :source_ref, "/tmp/test-bundle.cedar")
    loaded_at = Keyword.get(opts, :loaded_at, DateTime.utc_now())

    bundle = %PolicyBundleRef{
      bundle_id: Base.encode16(canonical_hash, case: :lower),
      canonical_hash: canonical_hash,
      loaded_at: loaded_at,
      evaluator_handle: bytes,
      bundle_bytes: bytes
    }

    %Active{
      source: source,
      source_ref: source_ref,
      loaded_at: loaded_at,
      metadata: Keyword.get(opts, :metadata, %{}),
      bundle: bundle
    }
  end

  describe "current/0" do
    test "returns {:error, :not_loaded} when nothing has been written" do
      assert {:error, :not_loaded} = Active.current()
    end

    test "returns the written envelope after update/1" do
      envelope = build_envelope()
      :ok = Active.update(envelope)

      assert {:ok, ^envelope} = Active.current()
    end
  end

  describe "update/1" do
    test "atomically replaces the entry" do
      first = build_envelope(source: :filesystem, source_ref: "/tmp/first.cedar")
      :ok = Active.update(first)
      assert {:ok, ^first} = Active.current()

      second = build_envelope(source: :oci, source_ref: "ecr/cedar:1.0.0")
      :ok = Active.update(second)
      assert {:ok, ^second} = Active.current()
      assert second != first
    end

    test "broadcasts a supersede event to subscribers" do
      # Subscribe via the canonical helper.
      :ok = Active.subscribe()

      envelope = build_envelope(source: :oci, source_ref: "ecr/cedar:test")
      :ok = Active.update(envelope)

      assert_receive {:active_bundle_superseded, payload}, 500

      assert payload.source == :oci
      assert payload.source_ref == "ecr/cedar:test"

      assert payload.new_canonical_hash_hex ==
               Base.encode16(envelope.bundle.canonical_hash, case: :lower)

      assert is_nil(payload.old_canonical_hash_hex)
    end

    test "supersede event carries the prior canonical hash on subsequent updates" do
      :ok = Active.subscribe()

      first = build_envelope()
      :ok = Active.update(first)

      # Drain the first event before issuing the second.
      assert_receive {:active_bundle_superseded, _}, 500

      second = build_envelope()
      :ok = Active.update(second)

      assert_receive {:active_bundle_superseded, payload}, 500

      assert payload.old_canonical_hash_hex ==
               Base.encode16(first.bundle.canonical_hash, case: :lower)

      assert payload.new_canonical_hash_hex ==
               Base.encode16(second.bundle.canonical_hash, case: :lower)
    end
  end

  describe "atomic-swap property (stream-data-thinking)" do
    @describetag timeout: 30_000

    property "after each update/1, current/0 returns exactly that envelope" do
      check all(
              hashes <- list_of(binary(length: 32), min_length: 2, max_length: 20),
              source_refs <-
                list_of(string(:alphanumeric, min_length: 1, max_length: 32),
                  min_length: length(hashes),
                  max_length: length(hashes)
                ),
              length(hashes) == length(source_refs),
              max_runs: 30
            ) do
        Active.erase()

        Enum.zip(hashes, source_refs)
        |> Enum.each(fn {hash, ref} ->
          envelope = build_envelope(canonical_hash: hash, source_ref: ref, source: :filesystem)
          :ok = Active.update(envelope)

          # Read-back invariant: every update yields a `current/0` that
          # matches the envelope just written. Atomic swap means no torn
          # intermediate.
          assert {:ok, %Active{bundle: %PolicyBundleRef{canonical_hash: ^hash}, source_ref: ^ref}} =
                   Active.current()
        end)
      end
    end
  end
end
