defmodule Recurse.Providers.Impls.FilesystemStorageProvider do
  @moduledoc """
  `Recurse.Providers.StorageProvider` backed by a content-addressed
  directory on the local filesystem (spec 012 D4, registry shortname
  `filesystem`).

  Payloads are stored under `<root>/<sha256-hex>` and addressed by the
  URI `file://<root>/<sha256-hex>`. The hash returned from `put_payload/3`
  is the raw 32-byte SHA-256 digest, which is what the attestation
  envelope's `payload_hash` field expects (FR-021) and what
  `recurse-verify` Step 5 recomputes.

  Ported from `FableDemo.DevFsStorage` (`scripts/fable_demo/demo.exs`)
  for the Docker Compose quickstart, where the `cas` volume is mounted at
  `R5E_CAS_ROOT` (default `/data/cas`). The S3 provider
  (`Recurse.Providers.Impls.S3StorageProvider`) is the production shape.

  ## Config

    * `:root` — directory for the store. Created on `init/1` if absent.
      Default `/data/cas`.

  ## Properties

    * **Idempotent writes.** Content addressing means a second `put` of the
      same bytes is a no-op that returns the same URI + hash.
    * **Atomic writes.** Bytes land in a temp file that is renamed into
      place, so a crash mid-write never leaves a truncated object at the
      addressed path.
    * **Root-confined reads/deletes.** A URI is resolved and checked to lie
      under `root` before any filesystem call, so a crafted
      `file://../../etc/passwd` URI is rejected with
      `{:error, :uri_outside_cas_root}` rather than read.
    * **Idempotent deletes.** Deleting an already-deleted object returns
      `:ok` (GDPR Art. 17 sweeps can be re-run safely).
    * **Integrity-checked reads.** `get_payload/3` re-hashes the bytes and
      compares them to the digest in the object's name; a mismatch (a
      tampered or bit-rotted file on the `cas` volume) returns
      `{:error, :integrity_mismatch}` rather than bytes the receipt's
      `payload_hash` no longer covers.
  """

  @behaviour Recurse.Providers.StorageProvider

  @default_root "/data/cas"
  @uri_scheme "file://"

  @type state :: %{root: String.t()}

  @impl true
  def init(config) when is_map(config) do
    root = config |> Map.get(:root, @default_root) |> Path.expand()

    case File.mkdir_p(root) do
      :ok -> {:ok, %{root: root}}
      {:error, reason} -> {:error, {:cas_root_unavailable, root, reason}}
    end
  end

  def init(_config), do: {:error, :config_must_be_a_map}

  @impl true
  def put_payload(%{root: root}, payload, _identity_ctx) when is_binary(payload) do
    hash = :crypto.hash(:sha256, payload)
    path = Path.join(root, Base.encode16(hash, case: :lower))

    case write_if_absent(path, payload) do
      :ok -> {:ok, %{uri: @uri_scheme <> path, hash: hash}}
      {:error, reason} -> {:error, {:cas_write_failed, reason}}
    end
  end

  @impl true
  def get_payload(state, uri, _identity_ctx) when is_binary(uri) do
    with {:ok, path} <- resolve(state, uri),
         {:ok, bytes} <- read(path) do
      verify_integrity(path, bytes)
    end
  end

  @impl true
  def delete_payload(state, uri, _identity_ctx) when is_binary(uri) do
    with {:ok, path} <- resolve(state, uri) do
      case File.rm(path) do
        :ok -> :ok
        {:error, :enoent} -> :ok
        {:error, reason} -> {:error, reason}
      end
    end
  end

  @impl true
  def capabilities(_state), do: [:put, :get, :delete]

  @impl true
  def healthcheck(%{root: root}) do
    if File.dir?(root) do
      :ok
    else
      {:down, {:cas_root_missing, root}}
    end
  end

  @impl true
  def terminate(_state, _reason), do: :ok

  # ---------------------------------------------------------------------------
  # Internals
  # ---------------------------------------------------------------------------

  # Resolve a `file://` URI to an absolute path and confine it to `root`.
  defp resolve(%{root: root}, @uri_scheme <> raw_path) do
    path = Path.expand(raw_path)

    if String.starts_with?(path, root <> "/") do
      {:ok, path}
    else
      {:error, :uri_outside_cas_root}
    end
  end

  defp resolve(_state, _uri), do: {:error, :unknown_uri_scheme}

  defp read(path) do
    case File.read(path) do
      {:ok, bytes} -> {:ok, bytes}
      {:error, :enoent} -> {:error, :not_found}
      {:error, reason} -> {:error, reason}
    end
  end

  # The object's name IS its SHA-256; bytes that no longer hash to it are
  # not the payload the receipt attested.
  defp verify_integrity(path, bytes) do
    expected = Path.basename(path)
    actual = Base.encode16(:crypto.hash(:sha256, bytes), case: :lower)

    if actual == expected, do: {:ok, bytes}, else: {:error, :integrity_mismatch}
  end

  defp write_if_absent(path, payload) do
    if File.regular?(path) do
      :ok
    else
      tmp = path <> ".tmp-" <> Integer.to_string(System.unique_integer([:positive]))

      with :ok <- File.write(tmp, payload, [:exclusive]),
           :ok <- File.rename(tmp, path) do
        :ok
      else
        {:error, reason} ->
          _ = File.rm(tmp)
          {:error, reason}
      end
    end
  end
end
