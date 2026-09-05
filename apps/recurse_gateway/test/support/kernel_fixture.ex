defmodule Recurse.Gateway.Test.KernelFixture do
  @moduledoc """
  A fresh, governed kernel for synchronous gateway test modules.

  Call `boot/0` from `setup_all`. Each module gets an isolated data directory
  and real kernel policy, fold authority, and admission. Cleanup restores
  application environments, prior running state, and the loader projection.
  """

  alias Recurse.Gateway.Policy.Active

  def boot do
    apps = [:r5e, :recurse_fold]
    previous = Map.new(apps, &{&1, Application.get_all_env(&1)})
    running = MapSet.new(Application.started_applications(), &elem(&1, 0))
    projection = :persistent_term.get(Active.persistent_term_key(), :not_loaded)
    dir = Path.join(System.tmp_dir!(), "gateway-kernel-#{System.unique_integer([:positive])}")

    # Register cleanup before boot so a failed seed cannot contaminate later tests.
    ExUnit.Callbacks.on_exit(fn ->
      stop()

      for app <- apps do
        restore_env(app, previous[app])
      end

      Active.erase()

      for app <- apps,
          MapSet.member?(running, app),
          do: {:ok, _} = Application.ensure_all_started(app)

      if projection != :not_loaded do
        :persistent_term.put(Active.persistent_term_key(), projection)
      end

      File.rm_rf!(dir)
    end)

    stop()
    Active.erase()
    Application.put_env(:r5e, :data_dir, dir)
    Application.put_env(:r5e, :start_server, false)
    Application.put_env(:r5e, :seed_kernel_policy, true)
    Application.put_env(:r5e, :policy, Recurse.Fold.Policy.Cedar)
    Application.put_env(:recurse_fold, :enabled?, true)
    Application.delete_env(:recurse_fold, :engine_build_address)
    {:ok, _} = Application.ensure_all_started(:recurse_fold)
    true = R5e.Policy.KernelCedar.ready?()
    :ok
  end

  defp restore_env(app, previous) do
    for {key, _} <- Application.get_all_env(app), do: Application.delete_env(app, key)
    for {key, value} <- previous, do: Application.put_env(app, key, value)
  end

  defp stop do
    Application.stop(:recurse_fold)
    Application.stop(:r5e)
  end
end
