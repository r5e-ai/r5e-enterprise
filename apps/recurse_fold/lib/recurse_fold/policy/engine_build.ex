defmodule Recurse.Fold.Policy.EngineBuild do
  @moduledoc """
  The engine build descriptor of schema-lite v2 §8: the bytes that say
  *which engine* produced a decision, admitted once per build as a
  `core.r5e.io/v1/CasObject` and cited by address from every receipt.

      {format: "r5e.engine-build/1", engine: "cedar", crate: "cedar-policy",
       crateVersion: "4.9.1", cargoLockSha256: "<64 hex>",
       nifSha256: "<64 hex>", module: "Recurse.Fold.Policy.Cedar",
       moduleSha256: "<64 hex of the module's beam bytes>",
       platform: "<target triple>"}

  Format, engine, crate and module labels are declared. Artifact-dependent
  fields are read or measured: the crate version is read out
  of `native/recurse_cedar/Cargo.lock`, the lockfile hash is that file's
  bytes, the NIF hash is the deployed shared-object file read at measurement,
  the module hash is the deployed compiled beam file, and the platform is
  what OTP says it is running on.

  What that buys, and no more (§8): *equal descriptor addresses mean the
  same measured artifact bytes on the same reported platform.* These are
  process-produced measurements, not independent attestation of loaded code
  or process integrity. They do not establish source-to-binary provenance,
  engine correctness, or that different builds decide differently.
  """

  @format "r5e.engine-build/1"
  @engine "cedar"
  @crate "cedar-policy"
  @module Recurse.Fold.Policy.Cedar

  # Resolved at compile time from this file's own location: the umbrella
  # root is five levels up from `apps/recurse_fold/lib/recurse_fold/policy`.
  @cargo_lock Path.expand("../../../../../native/recurse_cedar/Cargo.lock", __DIR__)

  @doc """
  The descriptor as a map, measured from this deployment's own artifacts.

  Raises when an artifact it must measure is missing: a build descriptor
  with a guessed field would be worse than none, because the whole of its
  meaning is that equal addresses mean equal bytes.
  """
  @spec descriptor() :: map()
  def descriptor do
    lock = cargo_lock_path()

    %{
      "format" => @format,
      "engine" => @engine,
      "crate" => @crate,
      "crateVersion" => crate_version(lock),
      "cargoLockSha256" => sha256_file(lock, "the Cargo.lock at #{lock}"),
      "nifSha256" => sha256_file(nif_path(), "the Cedar NIF at #{nif_path()}"),
      "module" => inspect(@module),
      "moduleSha256" => sha256_file(beam_path(), "the beam for #{inspect(@module)}"),
      "platform" => to_string(:erlang.system_info(:system_architecture))
    }
  end

  @doc "The descriptor's canonical bytes — what a `CasObject` admission puts on the record."
  @spec bytes() :: binary()
  def bytes, do: R5e.Canonical.encode(descriptor())

  @doc "The `bytes:sha256:…` address those bytes land at, computable before admission."
  @spec address() :: String.t()
  def address, do: "bytes:" <> R5e.Canonical.hash_bytes(bytes())

  @doc "Where the descriptor is remembered between the boot that admitted it and every decision."
  @spec cached_address() :: String.t() | nil
  def cached_address, do: Application.get_env(:recurse_fold, :engine_build_address)

  @doc false
  @spec cache_address(String.t()) :: :ok
  def cache_address(address),
    do: Application.put_env(:recurse_fold, :engine_build_address, address)

  # -- measurement -------------------------------------------------------

  @doc "Path to the Cargo lockfile the NIF was built from."
  @spec cargo_lock_path() :: Path.t()
  def cargo_lock_path,
    do: Application.get_env(:recurse_fold, :cargo_lock_path, @cargo_lock)

  @doc "Path to the deployed Cedar NIF file measured for the descriptor."
  @spec nif_path() :: Path.t()
  def nif_path do
    priv = :code.priv_dir(:recurse_shared) |> to_string()

    Path.join(priv, "native")
    |> Path.join("recurse_cedar*")
    |> Path.wildcard()
    |> Enum.sort()
    |> List.first() || Path.join([priv, "native", "recurse_cedar.so"])
  end

  @doc "Path to the compiled beam of the engine module."
  @spec beam_path() :: Path.t()
  def beam_path, do: @module |> :code.which() |> to_string()

  defp crate_version(lock) do
    text = read!(lock, "the Cargo.lock at #{lock}")

    case Regex.run(~r/name\s*=\s*"#{@crate}"\s*\nversion\s*=\s*"([^"]+)"/, text) do
      [_, version] ->
        version

      nil ->
        raise """
        recurse_fold: #{lock} carries no [[package]] entry for #{@crate}.
        The engine build descriptor (schema-lite-v2 §8) records the crate
        version that decided; guessing it would make the descriptor a claim
        nobody measured.
        """
    end
  end

  # §8 writes these three as bare `<64 hex>`, not as `sha256:` addresses:
  # they measure a file this deployment holds, they are not citations of
  # anything on the chain, and a `sha256:` prefix would read as one.
  defp sha256_file(path, label),
    do: :crypto.hash(:sha256, read!(path, label)) |> Base.encode16(case: :lower)

  defp read!(path, label) do
    case File.read(path) do
      {:ok, bytes} ->
        bytes

      {:error, reason} ->
        raise """
        recurse_fold: could not read #{label} (#{:file.format_error(reason)}).
        The engine build descriptor (schema-lite-v2 §8) measures the artifacts
        present on disk; a descriptor with an unmeasured field would
        assert something nobody checked.
        """
    end
  end
end
