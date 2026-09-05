defmodule Recurse.CedarPropertyTest do
  @moduledoc """
  Property tests for `Recurse.Cedar.canonical_hash/1` (SC-014 surface c).

  The invariant: `policy_canonical_hash` is stable under source-level
  reformatting that preserves AST identity. Concretely:

    * Arbitrary whitespace (spaces, tabs, blank lines) between tokens.
    * Line comments inserted between top-level policies.
    * Block-level indentation variation.
    * Trailing blank lines at EOF.

  Each generator produces a *formatted* variant of a hand-written baseline
  policy set; the property asserts all variants hash identically to the
  baseline.
  """
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Recurse.Cedar

  @baseline """
  permit (
    principal in Role::"admin",
    action,
    resource
  );

  permit (
    principal,
    action == Action::"read",
    resource
  )
  when { resource is Dataset };

  forbid (
    principal,
    action,
    resource
  )
  when {
    resource has tags &&
    resource.tags.contains("sensitive")
  };
  """

  test "baseline policy set parses and produces a stable 32-byte hash" do
    hash = Cedar.canonical_hash(@baseline)
    assert is_binary(hash)
    assert byte_size(hash) == 32
  end

  property "canonical hash is invariant under extra whitespace between tokens" do
    baseline_hash = Cedar.canonical_hash(@baseline)

    check all(padding <- whitespace(), max_runs: 25) do
      reformatted = String.replace(@baseline, ",\n", "," <> padding <> "\n")
      assert Cedar.canonical_hash(reformatted) == baseline_hash
    end
  end

  property "canonical hash is invariant under inserted line comments" do
    baseline_hash = Cedar.canonical_hash(@baseline)

    check all(comment <- cedar_line_comment(), max_runs: 25) do
      # Insert the comment at the start of every logical `permit`/`forbid` block.
      reformatted =
        @baseline
        |> String.replace("permit (", comment <> "\npermit (")
        |> String.replace("forbid (", comment <> "\nforbid (")

      assert Cedar.canonical_hash(reformatted) == baseline_hash
    end
  end

  property "canonical hash is invariant under trailing blank lines" do
    baseline_hash = Cedar.canonical_hash(@baseline)

    check all(n <- integer(0..10)) do
      reformatted = @baseline <> String.duplicate("\n", n)
      assert Cedar.canonical_hash(reformatted) == baseline_hash
    end
  end

  property "canonical hash is invariant under leading whitespace on each line" do
    baseline_hash = Cedar.canonical_hash(@baseline)

    check all(indent <- string([?\s, ?\t], min_length: 0, max_length: 4)) do
      # Re-indent every non-blank line that doesn't already start a policy
      # keyword — preserves structure while perturbing whitespace.
      reformatted =
        @baseline
        |> String.split("\n")
        |> Enum.map(fn line ->
          cond do
            line == "" -> line
            String.starts_with?(String.trim_leading(line), ["permit", "forbid"]) -> line
            true -> indent <> line
          end
        end)
        |> Enum.join("\n")

      assert Cedar.canonical_hash(reformatted) == baseline_hash
    end
  end

  # ---- Generators ----

  defp whitespace do
    string([?\s, ?\t], min_length: 0, max_length: 8)
  end

  defp cedar_line_comment do
    bind(string(:alphanumeric, min_length: 0, max_length: 24), fn body ->
      constant("// " <> body)
    end)
  end
end
