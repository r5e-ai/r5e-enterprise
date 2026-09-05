defmodule Recurse.Fold.FreshKernel do
  @moduledoc """
  A kernel per test file: its own data directory, its own log, booted from
  event one, with the fold's own seeding replayed into it.

  Modelled on the kernel's `R5e.Vectors.with_fresh_kernel/1`, and here for
  the same reason a conformance vector needs one. The kernel's log, CAS,
  resource store and reference index are **global** — one `:r5e`
  application, one data directory — so a suite that shares them shares a
  chain. Everything the fold asserts is a statement about a chain: how
  many admissions it carries, which `PolicyShape` governs a Kind, which
  bundle was in force when a decision was made. Sharing one chain made
  those statements depend on file order, and the fold-v2 report logged the
  workarounds that grew out of it (debt #24):

    * a shape test that reached for `AgentSession` because it was the one
      Kind no other file admitted a shape for;
    * a fail-closed test that installed its broken bundle straight into
      the resource store partly so the end-to-end test's event count would
      not move;
    * counts asserted as deltas around a `log_counts()` taken at the top.

  Those are all one workaround: *do not disturb the chain another file is
  asserting on*. A fresh kernel per file removes the premise. The
  fail-closed test still bypasses the gate, because that reason was always
  the load-bearing one — with a broken bundle active, every later
  admission fails closed, including the one that would restore the good
  bundle — but it no longer has to explain itself in terms of another
  file's assertions.

  ## Use

      setup_all do
        Recurse.Fold.FreshKernel.boot()
      end

  `boot/0` stops the fold and the kernel, points `:r5e, :data_dir` at a
  fresh temporary directory, starts them again — which re-runs
  `Recurse.Fold.Application.seed/0`, so the file gets the nine Kinds, the
  default bundle and the three shapes on a chain of its own — and
  registers an `on_exit` that puts the previous data directory back and
  removes the temporary one.

  It is deliberately **not** `async: true`. A fresh kernel per file is
  still one kernel at a time: the `:r5e` application is a singleton and
  two files booting their own concurrently would fight over it.
  """

  @doc """
  Boot a kernel on a fresh data directory, seeded by the fold. Call from
  `setup_all`; returns `:ok`.
  """
  @spec boot(keyword()) :: :ok
  def boot(opts \\ []) do
    previous = Application.fetch_env!(:r5e, :data_dir)
    previous_clock = Application.get_env(:r5e, :clock)
    dir = Path.join(System.tmp_dir!(), "r5e-fold-#{System.unique_integer([:positive])}")

    # A golden report names key ids and carries a checkpoint timestamp, so
    # a report over generated keys and a live clock is different bytes on
    # every run and cannot be frozen. Both are fixed here, before the
    # application starts — the only window in which what the kernel finds
    # on disk is still a decision.
    if opts[:fixed_keys], do: write_fixed_keys(dir)
    if instant = opts[:clock], do: set_clock(instant)

    restart(dir)

    ExUnit.Callbacks.on_exit(fn ->
      Application.put_env(:r5e, :clock, previous_clock)
      restart(previous)
      File.rm_rf(dir)
    end)

    :ok
  end

  defp set_clock(instant) do
    {:ok, at} = RecurseVerify.Instant.parse(instant)
    Application.put_env(:r5e, :clock, at)
  end

  # Chosen rather than generated: the node key, the retention key and the
  # fold key. An ed25519 private key is 32 arbitrary bytes, so
  # `sha256(<label>)` is one. Nothing here is secret; these keys exist only
  # inside a throwaway data directory that is removed when the file ends.
  defp write_fixed_keys(dir) do
    keys = Path.join(dir, "keys")
    File.mkdir_p!(keys)

    for role <- ~w(node retention fold) do
      private = :crypto.hash(:sha256, "r5e-golden-key:" <> role)
      {public, ^private} = :crypto.generate_key(:eddsa, :ed25519, private)
      File.write!(Path.join(keys, "#{role}_ed25519.key"), private)
      File.chmod!(Path.join(keys, "#{role}_ed25519.key"), 0o600)
      File.write!(Path.join(keys, "#{role}_ed25519.pub"), public)
    end
  end

  @doc """
  Stop and start the kernel over the **same** data directory: a restart,
  with nothing thrown away. `R5e.Bootstrap.replay/0` runs on the way back
  up and rebuilds the registry, the resource store and the reference index
  from the log alone, so anything still true afterwards is true because
  the chain says so.

  This is the only way to reach that state from a test. `replay/0` called
  in-process rebuilds the views but leaves the rest of the VM as it was;
  a real restart also drops every cache a boot re-establishes, which is
  where the fold-v2 defect lived.
  """
  @spec bounce() :: :ok
  def bounce, do: restart(Application.fetch_env!(:r5e, :data_dir))

  # The fold is stopped first and started last: it is a dependent
  # application whose `start/2` seeds through the kernel's gate, so
  # bringing it up before the kernel would seed into a store that is not
  # there, and leaving it up across the swap would leave its cached engine
  # build address pointing at an object on the old chain.
  defp restart(dir) do
    _ = Application.stop(:recurse_fold)

    case Application.stop(:r5e) do
      :ok -> :ok
      {:error, {:not_started, :r5e}} -> :ok
    end

    Application.put_env(:r5e, :data_dir, dir)
    # The engine build address is cached in application env and survives a
    # stop. A fresh data directory is a fresh *deployment*, which has
    # measured nothing yet: leaving the cache set would have the kernel's
    # own bootstrap seeds — admitted before the fold's first act — cite a
    # descriptor no admission on that chain had put there.
    Application.delete_env(:recurse_fold, :engine_build_address)
    {:ok, _} = Application.ensure_all_started(:recurse_fold)
    :ok
  end
end
