defmodule Mix.Tasks.Recurse.Contracts.Validate do
  @shortdoc "Validate the OpenAPI contract + streaming-matrix consistency"

  @moduledoc """
  T057 — CI gate for the Feature 001 contract artifacts.

  Runs locally AND in CI. The Mix-task form is preferred over an inline CI
  `run:` step so engineers can reproduce the gate on their workstations with
  `mix recurse.contracts.validate`.

  ## Checks

    1. `specs/001-api-jido-foundations/contracts/openapi.yaml` exists.
    2. No occurrences of `NEEDS CLARIFICATION` anywhere in the file
       (supports SC-003).
    3. Every path entry declares `x-recurse-tiers:` (supports SC-008 /
       SC-007 enforcement that every endpoint has a tier-applicability
       declaration).
    4. Every path entry declares `x-recurse-streaming:`.
    5. Every path listed in the OpenAPI appears in
       `streaming_policy_matrix.md` (supports FR-012 — the matrix is
       authoritative and MUST stay in lockstep with openapi.yaml).
    6. If `yq` is available on PATH, additionally validates that the OpenAPI
       document parses as legal YAML → JSON (via `yq -o=json eval`). When yq
       is unavailable, skip this check with a warning (the Elixir-side
       structural checks already cover most drift).

  ## Usage

      mix recurse.contracts.validate
      mix recurse.contracts.validate --openapi other.yaml --matrix other.md

  ## Exit codes

    * 0 — all checks passed
    * 1 — any check failed
  """

  use Mix.Task

  @default_openapi "specs/001-api-jido-foundations/contracts/openapi.yaml"
  @default_matrix "specs/001-api-jido-foundations/contracts/streaming_policy_matrix.md"

  @impl Mix.Task
  def run(argv) do
    {opts, _, _} =
      OptionParser.parse(argv,
        strict: [openapi: :string, matrix: :string],
        aliases: [o: :openapi, m: :matrix]
      )

    openapi = Keyword.get(opts, :openapi, @default_openapi)
    matrix = Keyword.get(opts, :matrix, @default_matrix)

    case run_checks(openapi, matrix) do
      :ok ->
        Mix.shell().info("recurse.contracts.validate: all checks passed")
        :ok

      {:error, reasons} ->
        Mix.shell().error("recurse.contracts.validate FAILED:")
        Enum.each(reasons, fn r -> Mix.shell().error("  - #{r}") end)
        exit({:shutdown, 1})
    end
  end

  defp run_checks(openapi_path, matrix_path) do
    failures = []

    failures =
      if File.exists?(openapi_path) do
        failures
      else
        ["openapi source file not found: #{openapi_path}" | failures]
      end

    failures =
      if File.exists?(matrix_path) do
        failures
      else
        ["streaming_policy_matrix.md not found: #{matrix_path}" | failures]
      end

    if failures != [] do
      {:error, Enum.reverse(failures)}
    else
      openapi = File.read!(openapi_path)
      matrix = File.read!(matrix_path)

      # Per speckit-pr-review F009: prefer the parsed-JSON path when `yq` is
      # available (structural correctness over line-counting heuristics);
      # fall back to the line-based checks only when yq is absent.
      failures =
        case parse_openapi_via_yq(openapi_path) do
          {:ok, parsed} ->
            failures
            |> check_no_needs_clarification(openapi)
            |> check_tiers_present_parsed(parsed)
            |> check_streaming_present_parsed(parsed)
            |> check_matrix_coverage_parsed(parsed, matrix)

          {:error, yq_error} ->
            # yq exists but choked; surface the parse error.
            [yq_error | failures]

          :yq_unavailable ->
            failures
            |> check_no_needs_clarification(openapi)
            |> check_tiers_present(openapi)
            |> check_streaming_present(openapi)
            |> check_matrix_coverage(openapi, matrix)
        end

      case failures do
        [] -> :ok
        _ -> {:error, Enum.reverse(failures)}
      end
    end
  end

  defp check_no_needs_clarification(failures, yaml) do
    if String.contains?(yaml, "NEEDS CLARIFICATION") do
      [
        "openapi.yaml contains `NEEDS CLARIFICATION` — resolve before /speckit-plan (SC-003)"
        | failures
      ]
    else
      failures
    end
  end

  defp check_tiers_present(failures, yaml) do
    operations = count_operations(yaml)
    tiers = count_line_prefix(yaml, "x-recurse-tiers:")

    if tiers < operations do
      [
        "openapi.yaml: #{tiers} `x-recurse-tiers:` declarations but #{operations} operations — every endpoint must declare tier applicability (FR-013)"
        | failures
      ]
    else
      failures
    end
  end

  defp check_streaming_present(failures, yaml) do
    operations = count_operations(yaml)
    streaming = count_line_prefix(yaml, "x-recurse-streaming:")

    if streaming < operations do
      [
        "openapi.yaml: #{streaming} `x-recurse-streaming:` declarations but #{operations} operations — every endpoint must declare streaming policy (FR-012)"
        | failures
      ]
    else
      failures
    end
  end

  defp check_matrix_coverage(failures, openapi, matrix) do
    paths = extract_yaml_paths(openapi)

    missing =
      paths
      |> Enum.reject(fn path -> String.contains?(matrix, "`#{path}`") end)

    if missing == [] do
      failures
    else
      [
        "streaming_policy_matrix.md missing path(s) present in openapi.yaml: #{Enum.join(missing, ", ")}"
        | failures
      ]
    end
  end

  # Parse the OpenAPI YAML via yq → JSON and decode. Returns one of:
  #
  #   * `{:ok, %{"paths" => %{...}, ...}}` — parsed successfully
  #   * `{:error, reason}` — yq is present but parsing failed
  #   * `:yq_unavailable` — yq not on PATH; caller falls back to line heuristics
  defp parse_openapi_via_yq(openapi_path) do
    case System.find_executable("yq") do
      nil ->
        Mix.shell().info(
          "(yq not on PATH — falling back to line-based structural checks; " <>
            "install via `brew install yq` for a real parsed-JSON pass)"
        )

        :yq_unavailable

      _yq ->
        yq_parse_openapi(openapi_path)
    end
  end

  defp yq_parse_openapi(openapi_path) do
    case System.cmd("yq", ["-o=json", "eval", openapi_path], stderr_to_stdout: true) do
      {json, 0} ->
        decode_openapi_json(json)

      {out, status} ->
        {:error,
         "yq failed to parse openapi.yaml (status #{status}): " <>
           String.slice(out, 0, 500)}
    end
  end

  defp decode_openapi_json(json) do
    case :json.decode(json) do
      doc when is_map(doc) -> {:ok, doc}
      other -> {:error, "yq produced non-map JSON: #{inspect(other, limit: 3)}"}
    end
  rescue
    ArgumentError -> {:error, "yq produced invalid JSON"}
  end

  # --- Parsed-JSON checks (preferred when yq is available) ---

  defp check_tiers_present_parsed(failures, doc) do
    {operations, missing} = collect_operations_missing(doc, "x-recurse-tiers")

    if missing == [] do
      failures
    else
      [
        "openapi.yaml: #{length(missing)} of #{operations} operations missing " <>
          "`x-recurse-tiers` (FR-013): " <> Enum.join(missing, ", ")
        | failures
      ]
    end
  end

  defp check_streaming_present_parsed(failures, doc) do
    {operations, missing} = collect_operations_missing(doc, "x-recurse-streaming")

    if missing == [] do
      failures
    else
      [
        "openapi.yaml: #{length(missing)} of #{operations} operations missing " <>
          "`x-recurse-streaming` (FR-012): " <> Enum.join(missing, ", ")
        | failures
      ]
    end
  end

  defp check_matrix_coverage_parsed(failures, doc, matrix) do
    paths = extract_paths_parsed(doc)

    missing =
      paths
      |> Enum.reject(fn path -> String.contains?(matrix, "`#{path}`") end)

    if missing == [] do
      failures
    else
      [
        "streaming_policy_matrix.md missing path(s) present in openapi.yaml: " <>
          Enum.join(missing, ", ")
        | failures
      ]
    end
  end

  # Walk `paths.{path}.{http_verb}` and return `{operation_count, missing_paths}`
  # where `missing_paths` is `{path, method}` identifiers that don't carry the
  # given `x-recurse-*` extension key.
  @http_verbs ~w(get post put patch delete head options trace)

  defp collect_operations_missing(doc, extension_key) do
    paths = Map.get(doc, "paths") || %{}

    {ops, missing} =
      Enum.reduce(paths, {0, []}, fn {path, path_item}, acc ->
        reduce_verbs(path, path_item, extension_key, acc)
      end)

    {ops, Enum.reverse(missing)}
  end

  defp reduce_verbs(path, path_item, extension_key, init) do
    Enum.reduce(@http_verbs, init, fn verb, {ops, missing} ->
      tally_verb(Map.get(path_item, verb), verb, path, extension_key, ops, missing)
    end)
  end

  defp tally_verb(op, verb, path, extension_key, ops, missing) when is_map(op) do
    if Map.has_key?(op, extension_key) do
      {ops + 1, missing}
    else
      {ops + 1, ["#{verb} #{path}" | missing]}
    end
  end

  defp tally_verb(_op, _verb, _path, _extension_key, ops, missing), do: {ops, missing}

  defp extract_paths_parsed(doc) do
    doc
    |> Map.get("paths", %{})
    |> Map.keys()
  end

  # ------ helpers ------

  defp count_operations(yaml) do
    ~w(get: post: put: patch: delete:)
    |> Enum.map(fn verb -> count_line_prefix(yaml, verb) end)
    |> Enum.sum()
  end

  # Counts lines whose trimmed-leading-whitespace form starts with `prefix`.
  # The YAML verb markers (`get:`, `post:`, etc.) occur at a fixed
  # indentation inside `paths:`, but we don't want to hard-code that depth.
  defp count_line_prefix(yaml, prefix) do
    yaml
    |> String.split("\n")
    |> Enum.count(fn line ->
      trimmed = String.trim_leading(line)
      String.starts_with?(trimmed, prefix)
    end)
  end

  # Pulls top-level `paths:` entries from the YAML. Matches lines at the
  # "two spaces + / + identifier + :" indentation pattern. Good enough for
  # drift detection; not a general YAML parser.
  defp extract_yaml_paths(yaml) do
    yaml
    |> String.split("\n")
    |> Enum.filter(fn line ->
      String.match?(line, ~r/^  \/[a-z0-9_\/{}\-\.]+:\s*$/)
    end)
    |> Enum.map(fn line ->
      line
      |> String.trim()
      |> String.trim_trailing(":")
    end)
    |> Enum.uniq()
  end
end
