defmodule RecurseIntegration.MixProject do
  @moduledoc """
  Cross-app integration tests (no runtime code). Phase-1 stays empty; Feature 002+
  populates the end-to-end test harness (Gateway + Runtime + synthetic providers).
  """
  use Mix.Project

  def project do
    [
      app: :recurse_integration,
      version: "0.1.0",
      package: package(),
      build_path: "../../_build",
      config_path: "../../config/config.exs",
      deps_path: "../../deps",
      lockfile: "../../mix.lock",
      elixir: "~> 1.19",
      start_permanent: Mix.env() == :prod,
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

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp deps do
    [
      {:recurse_shared, in_umbrella: true},
      {:recurse_providers, in_umbrella: true},
      {:recurse_gateway, in_umbrella: true},
      {:recurse_runtime, in_umbrella: true},
      {:stream_data, "~> 1.3", only: :test},
      {:mox, "~> 1.2", only: :test}
    ]
  end
end
