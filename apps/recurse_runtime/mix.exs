defmodule RecurseRuntime.MixProject do
  @moduledoc """
  Compute Plane (:recurse_runtime OTP app).

  Phase-1 scope: agent-container lifecycle, netns + iptables provisioning via port-owned
  `ip` / `iptables` binaries, SPIFFE bootstrap for agent containers, session state +
  epoch management (FR-036/037/044), Postgres-Merkle session-chain CAS, global-ledger
  commit pipeline (FR-040), blast-radius simulation (FR-049.3), Discovery-to-Policy
  generator (FR-049.2).

  Absent or inactive in the Standalone AI Gateway deployment shape (FR-050).
  """
  use Mix.Project

  def project do
    [
      app: :recurse_runtime,
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
      extra_applications: [:logger],
      mod: {RecurseRuntime.Application, []}
    ]
  end

  # Scoped Principle V exception (speckit-pr-review iteration-2 F003):
  # Runtime declares ecto_sql + postgrex directly because Runtime owns
  # its own persistent state (Sessions, SessionEpochs, the session-chain
  # local CAS per FR-040) — a Postgres-backed schema that is NOT a
  # Provider Interface boundary.
  #
  # The Provider Interface boundaries live elsewhere:
  #   - LedgerProvider abstracts the transparency-log ledger (Postgres-
  #     Merkle for dev, Trillian for prod). Its Postgres-Merkle reference
  #     impl lives in apps/recurse_providers/lib/recurse_providers/impls/
  #     and owns its OWN ecto/postgrex imports there.
  #   - StorageProvider abstracts detached-payload storage (S3 / Splunk
  #     HEC / MinIO).
  #   - The seven Provider Interfaces (FR-003) together cover every
  #     EXTERNAL dependency.
  #
  # Runtime's internal session/epoch persistence is deliberately NOT
  # behind a "PersistenceProvider" interface in Phase 1 because:
  #   (a) no pluggability requirement has surfaced — every Phase-1
  #       deployment shape uses Postgres;
  #   (b) abstracting it now would fail the forward-stub test in
  #       feedback_no_premature_metaapi.md — the callback signatures
  #       aren't knowable with confidence yet.
  #
  # If a deployment shape ever needs non-Postgres Runtime state, the
  # right move is to lift the schema into a new Provider Interface at
  # that time, not pre-allocate one now.
  defp deps do
    [
      {:recurse_shared, in_umbrella: true},
      {:recurse_providers, in_umbrella: true},
      # Runtime's own persistent state — NOT a Provider Interface boundary.
      # See the scoped-exception comment above.
      {:ecto_sql, "~> 3.14"},
      {:postgrex, "~> 0.22.4"},
      # Async pipeline for session-chain commit workflow.
      {:broadway, "~> 1.3"},
      # Scheduled jobs: interim-epoch ticks, SVID rotation reminders, ledger backoff retry.
      {:oban, "~> 2.21"},
      # Test-only.
      {:stream_data, "~> 1.3", only: :test},
      {:mox, "~> 1.2", only: :test}
    ]
  end
end
