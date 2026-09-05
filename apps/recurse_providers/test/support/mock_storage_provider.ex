defmodule Recurse.Providers.Support.MockStorageProvider do
  @moduledoc """
  Fixed-data stub implementation of `Recurse.Providers.StorageProvider`
  (T064). Round-trips a byte blob through an in-memory ETS-free
  process-dictionary stash scoped to the calling test.

  The harness uses this to verify the put/get/delete shape; real
  tenancy / GDPR-deletion semantics are the concern of concrete impls
  (S3, Splunk HEC, MinIO) authored in Feature 002+.
  """

  @behaviour Recurse.Providers.StorageProvider

  @pd_key {__MODULE__, :blobs}

  @impl true
  def init(_config) do
    Process.put(@pd_key, %{})
    {:ok, %{backend: :in_memory}}
  end

  @impl true
  def put_payload(_state, payload, _identity_ctx) when is_binary(payload) do
    uri = "mock://storage/" <> Base.url_encode64(:crypto.strong_rand_bytes(8), padding: false)
    hash = :crypto.hash(:sha256, payload)

    blobs = Process.get(@pd_key, %{})
    Process.put(@pd_key, Map.put(blobs, uri, payload))

    {:ok, %{uri: uri, hash: hash}}
  end

  @impl true
  def get_payload(_state, uri, _identity_ctx) do
    blobs = Process.get(@pd_key, %{})

    case Map.fetch(blobs, uri) do
      {:ok, payload} -> {:ok, payload}
      :error -> {:error, :not_found}
    end
  end

  @impl true
  def delete_payload(_state, uri, _identity_ctx) do
    blobs = Process.get(@pd_key, %{})
    Process.put(@pd_key, Map.delete(blobs, uri))
    :ok
  end

  @impl true
  def capabilities(_state), do: [:put, :get, :delete]

  @impl true
  def healthcheck(_state), do: :ok

  @impl true
  def terminate(_state, _reason), do: :ok
end
