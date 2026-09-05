defmodule RecurseShared.MixProject do
  @moduledoc """
  Shared types + attestation envelope + Cedar/SPIFFE NIF wrappers.

  This app owns:
    - IdentityContext, Principal, CorrelationId, ULID (FR-018/026)
    - Attestation envelope: SignedPredicate + OuterContainer + DSSE + RFC 9162 TransItem (FR-021)
    - Session + Epoch + StateMachine (FR-036/037/044)
    - Cedar NIF wrapper (Recurse.Cedar; FR-039)
    - SPIFFE NIF wrapper (Recurse.Spiffe; research D7)
    - Custom Credo PI-neutrality check (Recurse.Credo.ProviderNeutrality; D16)
  """
  use Mix.Project

  def project do
    [
      app: :recurse_shared,
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
      extra_applications: [:logger, :crypto],
      mod: {RecurseShared.Application, []}
    ]
  end

  defp deps do
    [
      # NIF bridge for Cedar (FR-039) + SPIFFE (D7).
      {:rustler, "~> 0.37"},
      # JWT / DSSE signing.
      {:jose, "~> 1.11"},
      # YAML parser for deployment config files. Gateway uses the shared
      # wrapper to keep parser-module calls out of ProviderNeutrality scope.
      {:yaml_elixir, "~> 2.11"},
      # Intra-node Gateway <-> Runtime message bus (FR-034).
      {:phoenix_pubsub, "~> 2.1"},
      # Observability.
      {:telemetry, "~> 1.4"},
      # Test-only.
      {:stream_data, "~> 1.3", only: :test},
      {:mox, "~> 1.2", only: :test},
      # Dev/test-only — hosts the custom `Recurse.Credo.ProviderNeutrality`
      # check (FR-004 / Constitution Principle V). The check module lives in
      # `lib/` rather than a `mix` task path because Credo discovers checks
      # at runtime via `requires` in `.credo.exs`; it must compile in the
      # same env where Credo runs.
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false}
    ]
  end
end
