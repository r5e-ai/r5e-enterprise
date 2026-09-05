defmodule Recurse.Fold.MixProject do
  @moduledoc """
  The fold: enterprise's Cedar policy engine speaking the r5e kernel's
  admission protocol.

  This app owns no HTTP surface and no database. It exists to make one
  sentence true: *the policy that decided an act is on the same chain as
  the act, and both verify offline with the unchanged r5e-core verifier.*

  Two deps, on purpose:

    * `:recurse_shared` — the only enterprise app with no in-umbrella deps.
      It carries the Cedar Rustler NIF (`Recurse.Cedar`). Depending on
      `recurse_gateway` instead would drag Postgres into a slice that has
      no state of its own.
    * `:r5e` — the kernel, as a path dependency outside this umbrella. The
      kernel does not know this app exists; it is plugged in through the
      `R5e.Policy` behaviour and the `:r5e, :policy` config key, both of
      which predate the fold.
  """
  use Mix.Project

  def project do
    [
      app: :recurse_fold,
      version: "0.1.0",
      package: package(),
      build_path: "../../_build",
      config_path: "../../config/config.exs",
      deps_path: "../../deps",
      lockfile: "../../mix.lock",
      elixir: "~> 1.19",
      start_permanent: Mix.env() == :prod,
      # `test/support` carries `Recurse.Fold.FreshKernel`, which every test
      # file's `setup_all` uses to get a kernel of its own (debt #24).
      elixirc_paths: elixirc_paths(Mix.env()),
      deps: deps()
    ]
  end

  # The licence, stated where a scanner looks for it. AGPL-3.0-only is the
  # decision recorded in `LICENSE.md`: `-only`, not `-or-later`.
  defp package do
    [
      licenses: ["AGPL-3.0-only"],
      links: %{"Source" => "https://gitlab.com/r5e-group/r5e-enterprise"}
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_env), do: ["lib"]

  def application do
    [
      extra_applications: [:logger],
      mod: {Recurse.Fold.Application, []}
    ]
  end

  defp deps do
    [
      # Listed first so the release/start ordering prefers having the Cedar
      # NIF's app up before the kernel's.
      {:recurse_shared, in_umbrella: true},
      # The kernel. Its own nested path dep on r5e-core/verifier resolves
      # relative to the kernel directory, so `RecurseVerify` is available
      # here transitively — which is what lets the end-to-end test verify a
      # bundle in-process with the same code the standalone escript runs.
      # `runtime: false` (spec 012 S9a): the kernel is compiled and loaded
      # with the fold but is NOT started by the boot script — the fold's
      # own `Application.start/2` starts it, and only when
      # `config :recurse_fold, enabled?: true` (`R5E_FOLD_ENABLED`). That is
      # what lets the audit_console release carry the fold while the
      # public quickstart stays fold-less by default: a kernel that starts
      # writes a genesis chain and a node key to its data dir, and a
      # deployment that did not ask for one must not get one.
      {:r5e, path: "../../../r5e-kernel", runtime: false}
    ]
  end
end
