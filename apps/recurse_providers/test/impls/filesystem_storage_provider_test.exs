defmodule Recurse.Providers.Impls.FilesystemStorageProviderTest do
  @moduledoc """
  Real-impl tests for `Recurse.Providers.Impls.FilesystemStorageProvider`
  (spec 012 S1, shortname `filesystem`): SHA-256 content addressing,
  `file://` URIs, idempotent put/delete, and root confinement.
  """

  use ExUnit.Case, async: true

  alias Recurse.Providers.Impls.FilesystemStorageProvider, as: Provider

  setup do
    root =
      Path.join(
        System.tmp_dir!(),
        "fs_cas_test_#{System.unique_integer([:positive])}"
      )

    on_exit(fn -> File.rm_rf!(root) end)
    {:ok, state} = Provider.init(%{root: Path.join(root, "cas")})
    {:ok, state: state, root: root}
  end

  test "init/1 creates the root and reports healthy", %{state: state} do
    assert File.dir?(state.root)
    assert Provider.healthcheck(state) == :ok
    assert Provider.capabilities(state) == [:put, :get, :delete]
  end

  test "put_payload/3 is content-addressed by SHA-256 and returns a file:// URI", %{state: state} do
    payload = :crypto.strong_rand_bytes(256)
    expected_hash = :crypto.hash(:sha256, payload)
    hex = Base.encode16(expected_hash, case: :lower)

    assert {:ok, %{uri: uri, hash: ^expected_hash}} = Provider.put_payload(state, payload, nil)
    assert uri == "file://" <> Path.join(state.root, hex)
    assert File.read!(Path.join(state.root, hex)) == payload
  end

  test "put → get round-trips bytes identically", %{state: state} do
    payload = "the detached payload"
    {:ok, %{uri: uri}} = Provider.put_payload(state, payload, nil)
    assert {:ok, ^payload} = Provider.get_payload(state, uri, nil)
  end

  test "put_payload/3 is idempotent for identical bytes", %{state: state} do
    payload = "same bytes twice"
    assert {:ok, first} = Provider.put_payload(state, payload, nil)
    assert {:ok, second} = Provider.put_payload(state, payload, nil)
    assert first == second
    assert length(File.ls!(state.root)) == 1
  end

  test "delete_payload/3 removes the object; get then reports :not_found; delete is idempotent",
       %{state: state} do
    {:ok, %{uri: uri}} = Provider.put_payload(state, "goodbye", nil)
    assert :ok = Provider.delete_payload(state, uri, nil)
    assert {:error, :not_found} = Provider.get_payload(state, uri, nil)
    assert :ok = Provider.delete_payload(state, uri, nil)
  end

  test "get_payload/3 rejects an object whose bytes no longer match its address",
       %{state: state} do
    {:ok, %{uri: uri}} = Provider.put_payload(state, "original bytes", nil)
    "file://" <> path = uri
    File.write!(path, "tampered bytes")

    assert {:error, :integrity_mismatch} = Provider.get_payload(state, uri, nil)
    # Delete still works on the tampered object so a sweep can remove it.
    assert :ok = Provider.delete_payload(state, uri, nil)
  end

  test "URIs are confined to the CAS root", %{state: state, root: root} do
    outside = Path.join(root, "secret.txt")
    File.write!(outside, "not for you")

    traversal = "file://" <> Path.join(state.root, "../secret.txt")
    assert {:error, :uri_outside_cas_root} = Provider.get_payload(state, traversal, nil)
    assert {:error, :uri_outside_cas_root} = Provider.delete_payload(state, traversal, nil)
    assert File.exists?(outside)

    assert {:error, :uri_outside_cas_root} =
             Provider.get_payload(state, "file://" <> outside, nil)
  end

  test "non-file URI schemes are rejected", %{state: state} do
    assert {:error, :unknown_uri_scheme} = Provider.get_payload(state, "s3://bucket/key", nil)
    assert {:error, :unknown_uri_scheme} = Provider.delete_payload(state, "s3://bucket/key", nil)
  end

  test "healthcheck reports :down when the root vanishes", %{state: state} do
    File.rm_rf!(state.root)
    assert {:down, {:cas_root_missing, _}} = Provider.healthcheck(state)
  end
end
