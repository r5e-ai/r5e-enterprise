defmodule RecurseProviders.MixProject do
  @moduledoc """
  Provider Interface behaviours + concrete reference implementations (FR-003).

  This app hosts the seven Provider Interface behaviours:
  LLMProvider, LedgerProvider, StorageProvider, SecretsProvider, IdentityProvider,
  PrincipalProvider, PolicyProvider — plus concrete implementations under
  `lib/recurse_providers/impls/`.

  **Provider-Interface Neutrality (Constitution Principle V):** vendor SDK imports
  (ex_aws*, req to specific vendor endpoints, etc.) are ALLOWED ONLY in
  `lib/recurse_providers/impls/` — never in `recurse_gateway` or `recurse_runtime`.
  Enforced by the custom Credo check `Recurse.Credo.ProviderNeutrality` (D16).
  """
  use Mix.Project

  def project do
    [
      app: :recurse_providers,
      version: "0.1.0",
      package: package(),
      build_path: "../../_build",
      config_path: "../../config/config.exs",
      deps_path: "../../deps",
      lockfile: "../../mix.lock",
      elixir: "~> 1.19",
      start_permanent: Mix.env() == :prod,
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

  # Test-support modules (Mox mocks, contract-test helpers) live under
  # `test/support/`. Compile them only in :test env so production builds
  # stay lean and test-only deps (Mox) don't leak into prod.
  defp elixirc_paths(:test), do: ["lib", "test/support", "test/contract", "test/impls"]
  defp elixirc_paths(_), do: ["lib"]

  def application do
    [
      extra_applications: [:logger],
      mod: {RecurseProviders.Application, []}
    ]
  end

  defp deps do
    [
      {:recurse_shared, in_umbrella: true},
      # Outbound HTTP — upstream LLM, KMS, downstream-service calls (FR-030/047).
      {:req, "~> 0.6.3"},
      # Named HTTP connection pools (F002 T016: :openai_pool, :kms_pool, :s3_pool,
      # :jwks_pool). Finch is referenced directly by the Gateway supervision
      # tree's child specs; declared here so transitively-available in Gateway
      # without Gateway declaring a direct vendor dep (preserves Principle V).
      {:finch, "~> 0.23.0"},
      # AWS — reference impls for Managed SaaS shape.
      {:ex_aws, "~> 2.6"},
      {:ex_aws_s3, "~> 2.5"},
      {:ex_aws_kms, "~> 2.5"},
      {:ex_aws_secretsmanager, "~> 2.0"},
      # Postgres-Merkle LedgerProvider backend. ecto_sql + postgrex are
      # scoped to the Postgres-Merkle impl under lib/recurse_providers/impls/
      # per Provider-Interface Neutrality (Principle V); the Repo module
      # (Recurse.Providers.Repo) is the concrete boundary.
      {:ecto_sql, "~> 3.14"},
      {:postgrex, "~> 0.22.4"},
      # Test-only.
      {:mox, "~> 1.2", only: :test},
      {:stream_data, "~> 1.3", only: :test},
      # Mock HTTP upstream for provider contract tests (T029 onward). We
      # pin `plug_cowboy` + `plug` here as the substrate for an inlined
      # Bypass-style mock server (see `test/support/mock_http_upstream.ex`).
      # Bypass itself is incompatible with the umbrella's ranch-2.x
      # resolution (bypass 2.1 locks `ranch ~> 1.3`, cowboy 2.14 needs
      # ranch >= 1.8); `plug_cowboy` is already transitive through
      # Bandit's sibling stack, so pinning it explicitly as a test-only
      # dep is the zero-conflict path. Scoped `only: :test` so it never
      # appears in the production dependency tree.
      {:plug_cowboy, "~> 2.9", only: :test},
      {:plug, "~> 1.20.3", only: :test}
    ]
  end
end
