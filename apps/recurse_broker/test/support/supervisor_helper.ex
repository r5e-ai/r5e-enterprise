defmodule RecurseBroker.Test.SupervisorHelper do
  @moduledoc """
  Test helper for coordinating broker-owned supervision state between
  ExUnit's `start_supervised/2` and `RecurseBroker.Application`'s
  auto-started children.

  `RecurseBroker.Application` boots `RecurseBroker.OIDC.DiscoveryCache`
  and `RecurseBroker.JWT.KeyRing` under module-registered names at app
  start. Several broker and gateway test modules need to reset those
  children between property-test iterations or between scenarios,
  under test-injected config (JWKS plug-mock, ephemeral signing keys,
  etc.). The shape of that reset is duplicated across 7 test files
  (property tests, contract tests, integration scenarios, quickstart).
  This module centralizes the sequence.

  ## Why it's in `apps/recurse_broker/test/support/`

  The helper manipulates `RecurseBroker.Supervisor` directly and names
  broker-owned modules. Gateway tests that exercise the real broker
  already cross-app-alias `RecurseBroker.Test.MockOidcIssuer` from this
  same directory (brought in by broker's `elixirc_paths(:test)` which
  includes `test/support`), so this helper is a zero-incremental-cost
  addition. It is intentionally NOT placed in `recurse_shared` — it
  depends on broker internals and must travel with the broker app's
  test support.

  ## Shape

  The body below is the "hardened" variant previously inlined in
  `apps/recurse_gateway/test/integration/us1_with_real_broker_test.exs`
  (pre-refactor). It layers belt-and-braces cleanup on top of the
  shorter form some broker property tests used:

    1. `Supervisor.terminate_child/2` + `Supervisor.delete_child/2`
       against `RecurseBroker.Supervisor` — the normal path.
    2. **Plus** a `GenServer.stop/3` call on the registered-name pid,
       monitored by `Process.monitor/1`. The explicit stop drains the
       mailbox synchronously, which prevents the "registered name is
       still owned by a lingering process at the moment we return"
       race that the Gateway-side integration tests hit in CI under
       load.

  The shorter form (terminate + delete only) was sufficient for the
  broker's own property tests but not for the gateway integration
  tests, where test-suite parallelism with the rest of the umbrella
  created tight timing windows. Standardizing on the hardened shape
  costs nothing at test-run time and removes a flaky-test vector.

  Returns `:ok` in every path, including when the supervisor is not
  running (useful for `setup_all` blocks that do not `use
  ExUnit.Case`).
  """

  @doc """
  Terminate-and-delete the given broker-auto-started child from the
  `RecurseBroker.Supervisor` tree, then additionally ensure the
  registered name is fully released.

  ## Parameters

    * `module` — the broker-registered module name, e.g.
      `RecurseBroker.OIDC.DiscoveryCache` or
      `RecurseBroker.JWT.KeyRing`.

  Always returns `:ok`.
  """
  @spec stop_auto_started(module()) :: :ok
  def stop_auto_started(module) when is_atom(module) do
    sup = RecurseBroker.Supervisor

    case Process.whereis(sup) do
      nil ->
        :ok

      _pid ->
        _ = Supervisor.terminate_child(sup, module)
        _ = Supervisor.delete_child(sup, module)
        :ok
    end

    case Process.whereis(module) do
      nil ->
        :ok

      pid ->
        ref = Process.monitor(pid)

        # Use `GenServer.stop/2` instead of `Process.exit/2`: the
        # former is synchronous and drains the mailbox, which avoids
        # a surviving registered name at the moment we return. Catch
        # because the process may already be exiting from the
        # `terminate_child/2` above.
        try do
          GenServer.stop(pid, :normal, 1_000)
        catch
          :exit, _ -> :ok
        end

        receive do
          {:DOWN, ^ref, :process, _, _} -> :ok
        after
          1_000 -> :ok
        end
    end
  end
end
