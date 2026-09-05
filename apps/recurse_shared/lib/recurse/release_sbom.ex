defmodule Recurse.ReleaseSbom do
  @moduledoc """
  Builds the release SBOM for the standalone Audit Console gateway.
  """

  @cyclonedx_spec_version "1.5"
  @tool_name "Recurse.ReleaseSbom"

  @type metadata :: %{
          required(:release_name) => String.t(),
          required(:release_version) => String.t(),
          required(:release_tag) => String.t(),
          required(:vcs_ref) => String.t(),
          required(:build_time) => String.t(),
          required(:elixir_version) => String.t(),
          required(:otp_version) => String.t(),
          required(:erts_version) => String.t(),
          required(:rust_version) => String.t(),
          required(:openssl_version) => String.t(),
          optional(:release_tarball_name) => String.t(),
          optional(:release_tarball_sha256) => String.t()
        }

  @spec main([String.t()]) :: :ok
  def main(argv) do
    opts = parse_args(argv)
    repo_root = File.cwd!()
    release_root = required_path!(opts, :release_root)
    output_path = required_option!(opts, :output)

    bom =
      build_bom(repo_root, release_root, %{
        release_name: Keyword.get(opts, :release_name, "audit_console"),
        release_version: Keyword.get(opts, :release_version) || project_version(),
        release_tag: Keyword.get(opts, :release_tag, "unknown"),
        vcs_ref: Keyword.get(opts, :vcs_ref, "unknown"),
        build_time: Keyword.get(opts, :build_time) || timestamp_now(),
        elixir_version: Keyword.get(opts, :elixir_version, System.version()),
        otp_version: Keyword.get(opts, :otp_version, System.otp_release()),
        erts_version: Keyword.get(opts, :erts_version, to_string(:erlang.system_info(:version))),
        rust_version: Keyword.get(opts, :rust_version, "unknown"),
        openssl_version: Keyword.get(opts, :openssl_version, "unknown"),
        release_tarball_name: release_tarball_name(opts),
        release_tarball_sha256: release_tarball_sha256!(opts)
      })

    output_path
    |> Path.dirname()
    |> File.mkdir_p!()

    File.write!(output_path, [encode_json(bom), ?\n])
    IO.puts("[release-sbom] wrote #{output_path}")
    :ok
  end

  @spec build_bom(Path.t(), Path.t(), metadata()) :: map()
  def build_bom(repo_root, release_root, metadata) do
    components =
      []
      |> Kernel.++(mix_components(repo_root))
      |> Kernel.++(cargo_components(repo_root))
      |> Kernel.++(runtime_components(metadata))
      |> Kernel.++(openssl_components(release_root, metadata.openssl_version))
      |> dedupe_components()

    bom =
      without_empty(%{
        "bomFormat" => "CycloneDX",
        "specVersion" => @cyclonedx_spec_version,
        "version" => 1,
        "metadata" => metadata_section(metadata),
        "components" => components,
        "externalReferences" => release_external_references(metadata)
      })

    Map.put(bom, "serialNumber", "urn:uuid:#{deterministic_uuid(bom)}")
  end

  @spec mix_components(Path.t()) :: [map()]
  def mix_components(repo_root) do
    lock_path = Path.join(repo_root, "mix.lock")
    dep_filter = installed_dep_filter(repo_root)

    lock_path
    |> read_mix_lock!()
    |> Enum.flat_map(fn
      {name, {:hex, package, version, checksum, managers, _deps, repo, package_hash}} ->
        name = to_string(name)

        if include_dep?(dep_filter, name) do
          hash = first_present([package_hash, checksum])

          [
            without_empty(%{
              "type" => "library",
              "bom-ref" => "pkg:hex/#{package}@#{version}",
              "name" => to_string(package),
              "version" => version,
              "purl" => "pkg:hex/#{package}@#{version}",
              "hashes" => hashes(hash),
              "externalReferences" => [
                %{"type" => "distribution", "url" => "https://hex.pm/packages/#{package}"}
              ],
              "properties" =>
                properties(%{
                  "r5e:ecosystem" => "hex",
                  "r5e:hex_repo" => repo,
                  "r5e:lock_name" => name,
                  "r5e:build_managers" => Enum.map_join(managers, ",", &to_string/1)
                })
            })
          ]
        else
          []
        end

      {name, {:git, url, ref, _opts}} ->
        name = to_string(name)

        if include_dep?(dep_filter, name) do
          [
            without_empty(%{
              "type" => "library",
              "bom-ref" => "pkg:generic/#{name}@#{ref}",
              "name" => name,
              "version" => ref,
              "externalReferences" => [%{"type" => "vcs", "url" => url}],
              "properties" => properties(%{"r5e:ecosystem" => "git"})
            })
          ]
        else
          []
        end

      _other ->
        []
    end)
    |> Enum.sort_by(& &1["bom-ref"])
  end

  @spec cargo_components(Path.t()) :: [map()]
  def cargo_components(repo_root) do
    [
      {"recurse_cedar", Path.join(repo_root, "native/recurse_cedar/Cargo.lock")},
      {"recurse_spiffe", Path.join(repo_root, "native/recurse_spiffe/Cargo.lock")}
    ]
    |> Enum.flat_map(fn {nif, lock_path} ->
      lock_path
      |> parse_cargo_lock()
      |> Enum.map(&cargo_component(&1, nif, Path.relative_to(lock_path, repo_root)))
    end)
    |> dedupe_components()
  end

  @spec parse_cargo_lock(Path.t()) :: [map()]
  def parse_cargo_lock(lock_path) do
    lock_path
    |> File.read!()
    |> String.split("\n")
    |> Enum.reduce({[], nil, nil}, &parse_cargo_line/2)
    |> finalize_cargo_packages()
  end

  @spec openssl_components(Path.t(), String.t()) :: [map()]
  def openssl_components(release_root, openssl_version) do
    openssl_root = Path.join(release_root, "support/openssl/lib")

    if File.dir?(openssl_root) do
      openssl_root
      |> Path.join("**/*")
      |> Path.wildcard()
      |> Enum.filter(&File.regular?/1)
      |> Enum.sort()
      |> Enum.map(fn path ->
        relative_path = Path.relative_to(path, release_root)

        %{
          "type" => "file",
          "bom-ref" => "file:#{relative_path}",
          "name" => Path.basename(path),
          "version" => openssl_version,
          "hashes" => hashes(sha256_file(path)),
          "properties" =>
            properties(%{
              "r5e:ecosystem" => "openssl",
              "r5e:release_path" => relative_path
            })
        }
      end)
    else
      []
    end
  end

  @spec runtime_components(metadata()) :: [map()]
  def runtime_components(metadata) do
    [
      %{
        "type" => "framework",
        "bom-ref" => "pkg:generic/elixir@#{metadata.elixir_version}",
        "name" => "Elixir",
        "version" => metadata.elixir_version,
        "purl" => "pkg:generic/elixir@#{metadata.elixir_version}",
        "properties" => properties(%{"r5e:ecosystem" => "beam"})
      },
      %{
        "type" => "framework",
        "bom-ref" => "pkg:generic/erlang-otp@#{metadata.otp_version}",
        "name" => "Erlang/OTP",
        "version" => metadata.otp_version,
        "purl" => "pkg:generic/erlang-otp@#{metadata.otp_version}",
        "properties" => properties(%{"r5e:ecosystem" => "beam"})
      },
      %{
        "type" => "framework",
        "bom-ref" => "pkg:generic/erlang-erts@#{metadata.erts_version}",
        "name" => "Erlang Runtime System",
        "version" => metadata.erts_version,
        "purl" => "pkg:generic/erlang-erts@#{metadata.erts_version}",
        "properties" =>
          properties(%{
            "r5e:ecosystem" => "beam",
            "r5e:otp_version" => metadata.otp_version
          })
      }
    ]
  end

  @spec encode_json(term()) :: String.t()
  def encode_json(value) do
    value
    |> JSON.encode_to_iodata!()
    |> IO.iodata_to_binary()
  end

  defp metadata_section(metadata) do
    %{
      "timestamp" => metadata.build_time,
      "tools" => [
        %{
          "vendor" => "r5e",
          "name" => @tool_name,
          "version" => "1"
        }
      ],
      "component" => %{
        "type" => "application",
        "bom-ref" => "pkg:generic/#{metadata.release_name}@#{metadata.release_version}",
        "name" => metadata.release_name,
        "version" => metadata.release_version,
        "purl" => "pkg:generic/#{metadata.release_name}@#{metadata.release_version}",
        "properties" =>
          properties(%{
            "r5e:release_tag" => metadata.release_tag,
            "r5e:vcs_ref" => metadata.vcs_ref
          })
      },
      "properties" =>
        properties(%{
          "r5e:release_name" => metadata.release_name,
          "r5e:release_version" => metadata.release_version,
          "r5e:release_tag" => metadata.release_tag,
          "r5e:vcs_ref" => metadata.vcs_ref,
          "r5e:elixir_version" => metadata.elixir_version,
          "r5e:otp_version" => metadata.otp_version,
          "r5e:erts_version" => metadata.erts_version,
          "r5e:rust_version" => metadata.rust_version,
          "r5e:openssl_version" => metadata.openssl_version,
          "r5e:release_tarball_name" => Map.get(metadata, :release_tarball_name),
          "r5e:release_tarball_sha256" => Map.get(metadata, :release_tarball_sha256)
        })
    }
  end

  defp release_external_references(metadata) do
    case Map.get(metadata, :release_tarball_sha256) do
      nil ->
        []

      sha256 ->
        [
          %{
            "type" => "distribution",
            "url" => "file:#{Map.get(metadata, :release_tarball_name) || "release.tar.gz"}",
            "hashes" => hashes(sha256),
            "comment" => "SHA-256 of the release tarball this SBOM sidecar describes"
          }
        ]
    end
  end

  defp parse_args(["--" | argv]), do: parse_args(argv)

  defp parse_args(argv) do
    {opts, rest, invalid} =
      OptionParser.parse(argv,
        strict: [
          output: :string,
          release_root: :string,
          release_name: :string,
          release_version: :string,
          release_tag: :string,
          vcs_ref: :string,
          build_time: :string,
          elixir_version: :string,
          otp_version: :string,
          erts_version: :string,
          rust_version: :string,
          openssl_version: :string,
          release_tarball_path: :string,
          release_tarball_name: :string,
          release_tarball_sha256: :string
        ]
      )

    if rest != [] or invalid != [] do
      raise ArgumentError, "invalid arguments: #{inspect(rest ++ invalid)}"
    end

    opts
  end

  defp required_option!(opts, key) do
    Keyword.get(opts, key) ||
      raise ArgumentError, "missing required --#{String.replace(to_string(key), "_", "-")}"
  end

  defp required_path!(opts, key) do
    path = required_option!(opts, key)

    if File.dir?(path) do
      path
    else
      raise ArgumentError,
            "--#{String.replace(to_string(key), "_", "-")} is not a directory: #{path}"
    end
  end

  defp release_tarball_name(opts) do
    Keyword.get(opts, :release_tarball_name) ||
      case Keyword.get(opts, :release_tarball_path) do
        nil -> nil
        path -> Path.basename(path)
      end
  end

  defp release_tarball_sha256!(opts) do
    case {Keyword.get(opts, :release_tarball_path), Keyword.get(opts, :release_tarball_sha256)} do
      {nil, nil} ->
        nil

      {nil, sha256} ->
        validate_sha256!(sha256)

      {path, nil} ->
        sha256_file!(path)

      {path, expected} ->
        actual = sha256_file!(path)

        if actual == validate_sha256!(expected) do
          actual
        else
          raise ArgumentError,
                "--release-tarball-sha256 does not match #{path}: expected #{expected}, got #{actual}"
        end
    end
  end

  defp validate_sha256!(value) when is_binary(value) do
    sha256 = String.downcase(value)

    if Regex.match?(~r/\A[0-9a-f]{64}\z/, sha256) do
      sha256
    else
      raise ArgumentError, "invalid SHA-256 digest: #{inspect(value)}"
    end
  end

  defp project_version do
    Mix.Project.config()[:version] || "unknown"
  rescue
    _ -> "unknown"
  catch
    :exit, _ -> "unknown"
  end

  defp read_mix_lock!(path) do
    Mix.start()
    Mix.Dep.Lock.read(path)
  end

  defp installed_dep_filter(repo_root) do
    deps_dir = Path.join(repo_root, "deps")

    if File.dir?(deps_dir) do
      deps_dir
      |> File.ls!()
      |> MapSet.new()
    else
      :all
    end
  end

  defp include_dep?(:all, _name), do: true
  defp include_dep?(dep_names, name), do: MapSet.member?(dep_names, name)

  defp cargo_component(package, nif, lockfile) do
    name = Map.fetch!(package, "name")
    version = Map.get(package, "version", "0.0.0")
    source = Map.get(package, "source")
    checksum = Map.get(package, "checksum")

    without_empty(%{
      "type" => if(source, do: "library", else: "application"),
      "bom-ref" => "pkg:cargo/#{name}@#{version}",
      "name" => name,
      "version" => version,
      "purl" => "pkg:cargo/#{name}@#{version}",
      "hashes" => hashes(checksum),
      "properties" =>
        properties(%{
          "r5e:ecosystem" => "cargo",
          "r5e:nif" => nif,
          "r5e:lockfile" => lockfile,
          "r5e:cargo_source" => source
        })
    })
  end

  defp parse_cargo_line("[[package]]", {packages, package, _deps_mode}) do
    {push_package(packages, package), %{}, nil}
  end

  defp parse_cargo_line(line, {packages, package, deps_mode}) do
    trimmed = String.trim(line)

    cond do
      package == nil ->
        {packages, package, deps_mode}

      deps_mode == :dependencies and trimmed == "]" ->
        {packages, package, nil}

      deps_mode == :dependencies ->
        {packages, package, deps_mode}

      trimmed == "dependencies = [" ->
        {packages, package, :dependencies}

      match = Regex.run(~r/^([A-Za-z0-9_-]+)\s*=\s*"([^"]*)"$/, trimmed) ->
        [_, key, value] = match
        {packages, Map.put(package, key, value), deps_mode}

      true ->
        {packages, package, deps_mode}
    end
  end

  defp finalize_cargo_packages({packages, package, _deps_mode}) do
    packages
    |> push_package(package)
    |> Enum.reverse()
  end

  defp push_package(packages, nil), do: packages
  defp push_package(packages, package), do: [package | packages]

  defp dedupe_components(components) do
    components
    |> Enum.reduce(%{}, fn component, acc ->
      Map.put_new(acc, component["bom-ref"], component)
    end)
    |> Map.values()
    |> Enum.sort_by(& &1["bom-ref"])
  end

  defp properties(map) do
    map
    |> Enum.reject(fn {_key, value} -> value in [nil, ""] end)
    |> Enum.sort_by(fn {key, _value} -> key end)
    |> Enum.map(fn {key, value} -> %{"name" => key, "value" => to_string(value)} end)
  end

  defp hashes(nil), do: []
  defp hashes(""), do: []
  defp hashes(hash), do: [%{"alg" => "SHA-256", "content" => hash}]

  defp sha256_file!(path) do
    if File.regular?(path) do
      sha256_file(path)
    else
      raise ArgumentError, "--release-tarball-path is not a file: #{path}"
    end
  end

  defp sha256_file(path) do
    :crypto.hash(:sha256, File.read!(path))
    |> Base.encode16(case: :lower)
  end

  defp first_present(values) do
    Enum.find(values, fn value -> is_binary(value) and value != "" end)
  end

  defp without_empty(map) do
    Enum.reduce(map, %{}, fn
      {_key, value}, acc when value in [nil, [], %{}] -> acc
      {key, value}, acc -> Map.put(acc, key, value)
    end)
  end

  defp timestamp_now do
    DateTime.utc_now()
    |> DateTime.truncate(:second)
    |> DateTime.to_iso8601()
  end

  defp deterministic_uuid(value) do
    <<a::32, b::16, c0::16, d0::16, e::48, _rest::binary>> =
      :crypto.hash(:sha256, :erlang.term_to_binary(canonicalize(value)))

    c = Bitwise.bor(Bitwise.band(c0, 0x0FFF), 0x5000)
    d = Bitwise.bor(Bitwise.band(d0, 0x3FFF), 0x8000)

    [a, b, c, d, e]
    |> Enum.zip([8, 4, 4, 4, 12])
    |> Enum.map_join("-", fn {part, width} ->
      part
      |> Integer.to_string(16)
      |> String.downcase()
      |> String.pad_leading(width, "0")
    end)
  end

  defp canonicalize(value) when is_map(value) do
    value
    |> Enum.map(fn {key, val} -> {to_string(key), canonicalize(val)} end)
    |> Enum.sort_by(fn {key, _val} -> key end)
  end

  defp canonicalize(value) when is_list(value), do: Enum.map(value, &canonicalize/1)
  defp canonicalize(value), do: value
end
