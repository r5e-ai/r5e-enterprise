defmodule Recurse.Fold.DemoReportTest do
  @moduledoc """
  The demo's chain, and the verifier's **whole output** on it, frozen.

  `scripts/fold-demo.sh` and this file run the same sequence
  (`Recurse.Fold.Demo.run/0`) so that the thing an operator watches and the
  thing CI pins cannot drift apart. What is frozen here is not a summary of
  the run: it is every line `recurse_verify` prints, byte for byte, under
  `--posture house`.

  Two inputs are fixed so the report can be frozen at all — the keys (a
  report names key ids) and the clock (the checkpoint carries a `ts`).
  Everything else in the report is a fact about the acts.

  One line legitimately moves without anything being wrong: the
  `derivedFrom` address in the gateway Kinds' epistemic scope is the hash
  of `specs/010-gateway-api-group/spec.md`, so editing that document
  changes it. Regenerate with `R5E_WRITE_GOLDEN=1 mix test` and read the
  diff — it should be that line and nothing else.
  """
  use ExUnit.Case, async: false

  @golden Path.expand("reports/fold-demo.txt", __DIR__)
  @external_resource @golden

  setup_all do
    Recurse.Fold.FreshKernel.boot(fixed_keys: true, clock: "2026-09-02T00:00:00Z")
  end

  test "the demo's chain verifies with no findings, and the report is the frozen one" do
    result = Recurse.Fold.Demo.run()
    assert result.denied["outcome"] == "denied"

    # Step 11: the restart. The bundle a reader is handed is the
    # post-restart one on purpose — an export that only verifies while the
    # node that wrote it is still up is not an offline claim.
    :ok = Recurse.Fold.FreshKernel.bounce()

    dest = Path.join(System.tmp_dir!(), "fold-demo-#{System.unique_integer([:positive])}")
    on_exit(fn -> File.rm_rf(dest) end)
    {:ok, ^dest, _manifest} = R5e.Export.run(dest)

    {:ok, report} = RecurseVerify.run(dest, posture: "house")
    assert report.findings == [], Enum.join(report.findings, "\n")

    text = report |> RecurseVerify.format() |> String.replace(dest, "<bundle>")

    if System.get_env("R5E_WRITE_GOLDEN") do
      File.mkdir_p!(Path.dirname(@golden))
      File.write!(@golden, text)
    else
      assert File.read!(@golden) == text, """
      the verifier's output on the demo's chain differs from the frozen report.

      Read the diff before regenerating: every line of that report is a fact
      about the acts, and the only one that moves for an innocent reason is
      the `derivedFrom` address of the reviewed specification.

      #{text}
      """
    end
  end
end
