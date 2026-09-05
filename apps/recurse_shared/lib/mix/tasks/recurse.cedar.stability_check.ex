defmodule Mix.Tasks.Recurse.Cedar.StabilityCheck do
  @shortdoc "Assert the three-component Cedar pin (research D2 / FR-039)"

  @moduledoc """
  CI gate that verifies the content-addressed Cedar pin.

  Three assertions run in order; any failure exits with status 1:

    1. `priv/test_fixtures/cedar_stability/cedar_crate_digest.txt` matches
       the `checksum = "..."` value under the `cedar-policy` package entry
       in `native/recurse_cedar/Cargo.lock`.
    2. `priv/test_fixtures/cedar_stability/cedar_version.txt` matches the
       `version = "..."` value under the same Cargo.lock entry.
    3. `Recurse.Cedar.canonical_hash/1` applied to
       `priv/test_fixtures/cedar_stability/representative_policy_set.cedar`
       produces the bytes recorded in
       `priv/test_fixtures/cedar_stability/expected_hash.txt`.

  On success prints a one-line confirmation and exits 0.

  Run via:

      mix recurse.cedar.stability_check
  """

  use Mix.Task

  @fixture_dir "test_fixtures/cedar_stability"
  @cargo_lock_relative "native/recurse_cedar/Cargo.lock"

  @impl Mix.Task
  def run(_args) do
    Mix.Task.run("app.start")

    priv = :code.priv_dir(:recurse_shared) |> to_string()
    fixture_dir = Path.join(priv, @fixture_dir)

    pinned_version = read_trimmed!(Path.join(fixture_dir, "cedar_version.txt"))
    pinned_digest = read_trimmed!(Path.join(fixture_dir, "cedar_crate_digest.txt"))
    pinned_hash = read_trimmed!(Path.join(fixture_dir, "expected_hash.txt"))
    policy_source = File.read!(Path.join(fixture_dir, "representative_policy_set.cedar"))

    {lock_version, lock_digest} = cedar_from_cargo_lock!()

    assert_eq!(
      "cedar_version",
      pinned_version,
      lock_version,
      "cedar_version.txt vs Cargo.lock"
    )

    assert_eq!(
      "cedar_crate_digest",
      pinned_digest,
      lock_digest,
      "cedar_crate_digest.txt vs Cargo.lock"
    )

    computed_hash = Recurse.Cedar.canonical_hash_hex(policy_source)

    assert_eq!(
      "cedar_fixture_hash",
      pinned_hash,
      computed_hash,
      "expected_hash.txt vs Recurse.Cedar.canonical_hash/1 output"
    )

    digest_prefix = String.slice(pinned_digest, 0, 8)

    IO.puts(
      "✓ Cedar stability fixture OK " <>
        "(#{pinned_version}, digest sha256:#{digest_prefix}, hash #{pinned_hash})"
    )
  end

  defp read_trimmed!(path) do
    path |> File.read!() |> String.trim()
  end

  defp assert_eq!(_name, expected, actual, _context) when expected == actual, do: :ok

  defp assert_eq!(name, expected, actual, context) do
    Mix.shell().error("""

    FAIL: Cedar stability drift detected (#{name}).
      context:  #{context}
      expected: #{inspect(expected)}
      actual:   #{inspect(actual)}

    This usually means the Cedar engine or the fixture diverged from the
    committed pin. See apps/recurse_shared/priv/test_fixtures/cedar_stability/README.md
    for the lockstep-upgrade procedure.
    """)

    exit({:shutdown, 1})
  end

  # Parse Cargo.lock for the cedar-policy package entry and return the
  # (version, checksum) pair. We parse minimally rather than pulling a TOML dep.
  defp cedar_from_cargo_lock! do
    lock_path = Path.expand(@cargo_lock_relative, File.cwd!())

    unless File.exists?(lock_path) do
      Mix.shell().error("FAIL: Cargo.lock not found at #{lock_path}")
      exit({:shutdown, 1})
    end

    lock_path
    |> File.read!()
    |> extract_cedar_policy_entry()
    |> case do
      {:ok, version, checksum} ->
        {version, checksum}

      :not_found ->
        Mix.shell().error(
          "FAIL: no cedar-policy entry found in #{lock_path}. " <>
            "Did cargo fetch run?"
        )

        exit({:shutdown, 1})
    end
  end

  defp extract_cedar_policy_entry(lock_text) do
    lock_text
    |> String.split("[[package]]", trim: true)
    |> Enum.find_value(:not_found, &cedar_fields/1)
  end

  defp cedar_fields(block) do
    lines = String.split(block, "\n")

    name = field(lines, "name")
    version = field(lines, "version")
    checksum = field(lines, "checksum")

    cond do
      name != "cedar-policy" -> nil
      is_nil(version) or is_nil(checksum) -> nil
      true -> {:ok, version, checksum}
    end
  end

  defp field(lines, key) do
    prefix = key <> " = "

    Enum.find_value(lines, fn line ->
      trimmed = String.trim(line)

      case String.starts_with?(trimmed, prefix) do
        false ->
          nil

        true ->
          trimmed
          |> String.slice(byte_size(prefix), byte_size(trimmed))
          |> String.trim()
          |> String.trim("\"")
      end
    end)
  end
end
