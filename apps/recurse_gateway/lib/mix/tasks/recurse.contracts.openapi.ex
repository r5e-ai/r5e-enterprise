defmodule Mix.Tasks.Recurse.Contracts.Openapi do
  @shortdoc "Emit a JSON copy of the OpenAPI spec from contracts/openapi.yaml"

  @moduledoc """
  Build-time OpenAPI artifact generation (T056 / FR-005 — the sole permitted
  build-time / CI-generated artifact alongside the static `/v1/version`
  endpoint).

  Reads `specs/001-api-jido-foundations/contracts/openapi.yaml` (the
  authoritative human-maintained source) and emits a JSON copy at
  `contracts/openapi.json` at the repo root. The `contracts/` output directory
  is created if missing.

  ## YAML-to-JSON conversion

  The umbrella has no Elixir YAML-parsing dependency (no `yaml_elixir`,
  `yamerl`, or similar). Rather than pulling in a runtime parser for what is
  purely build tooling, this task shells out to `yq`. `yq` is a tiny Go
  binary, ubiquitous in operator tooling, and readily available via Homebrew
  (`brew install yq`), `apt` (`apt install yq`), or GitHub Releases.

  If `yq` is not on `$PATH` when this task runs, it prints a clear error and
  exits 1 with install instructions. Operators running into that should
  install yq locally; CI environments install it in the workflow setup step.

  ## Usage

      mix recurse.contracts.openapi
      mix recurse.contracts.openapi --source path/to/openapi.yaml --out path/to/out.json

  ## Exit codes

    * 0 — success
    * 1 — source file missing, yq missing, or conversion failed

  This task is build tooling, not runtime — a shellout to an external tool is
  acceptable by the FR-005 framing ("build-time / CI-generated artifacts
  published as repository documentation").
  """

  use Mix.Task

  @default_source "specs/001-api-jido-foundations/contracts/openapi.yaml"
  @default_output "contracts/openapi.json"

  @impl Mix.Task
  def run(argv) do
    {opts, _, _} =
      OptionParser.parse(argv,
        strict: [source: :string, out: :string],
        aliases: [s: :source, o: :out]
      )

    source = Keyword.get(opts, :source, @default_source)
    output = Keyword.get(opts, :out, @default_output)

    ensure_file!(source)
    ensure_yq!()

    out_dir = Path.dirname(output)
    File.mkdir_p!(out_dir)

    case System.cmd("yq", ["-o=json", "eval", source], stderr_to_stdout: true) do
      {json, 0} ->
        File.write!(output, json)
        Mix.shell().info("wrote #{output} (#{byte_size(json)} bytes) from #{source}")

      {out, status} ->
        Mix.shell().error("yq exited #{status}:\n#{out}")
        exit({:shutdown, 1})
    end
  end

  defp ensure_file!(path) do
    unless File.exists?(path) do
      Mix.shell().error("openapi source file not found: #{path}")
      exit({:shutdown, 1})
    end
  end

  defp ensure_yq! do
    case System.find_executable("yq") do
      nil ->
        Mix.shell().error("""
        `yq` not found on PATH.

        This task converts the OpenAPI YAML to JSON via the `yq` tool.
        Install via one of:
          macOS     : brew install yq
          Debian/Ubuntu: sudo apt install -y yq
          Other     : https://github.com/mikefarah/yq/releases

        Then re-run `mix recurse.contracts.openapi`.
        """)

        exit({:shutdown, 1})

      _path ->
        :ok
    end
  end
end
