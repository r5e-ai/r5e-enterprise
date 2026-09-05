defmodule Recurse.MixProject do
  @moduledoc """
  Root umbrella mix project for Recurse Enterprise (Feature 001).

  Per-app dependencies live in `apps/*/mix.exs` (standard umbrella pattern). This
  root is the canonical reference for umbrella-wide version pins and the shared
  dev/test tooling set.

  Pins (per research D1, bumped from the Apr-2026 baseline):
    - Elixir 1.19.5 / OTP 28 (see `.tool-versions`)
    - Rust 1.92 for Rustler NIFs (see `.tool-versions`)
    - Postgres 16+ (tested at 17)

  Key Phase-1 dependencies and the apps that own them (for quick reference):

  | Dep                           | Owner app          | Purpose                     | FR link              |
  |-------------------------------|--------------------|-----------------------------|----------------------|
  | bandit                        | recurse_gateway    | HTTP/1.1 + HTTP/2 + SSE     | FR-002, FR-012       |
  | plug                          | recurse_gateway    | Router middleware           | FR-002               |
  | rustler                       | recurse_shared     | Cedar + SPIFFE NIF bridge   | FR-039, FR-025       |
  | ecto_sql + postgrex           | recurse_runtime    | Persistent state + ledger   | FR-036/037/040       |
  | broadway                      | recurse_runtime    | Session commit pipeline     | FR-040               |
  | oban                          | recurse_runtime    | Scheduled jobs              | FR-037 interim ticks |
  | phoenix_pubsub                | recurse_shared     | Intra-node G<->R messaging  | FR-034               |
  | jose                          | recurse_shared     | JWT + DSSE signing          | FR-017, FR-021, FR-046/047 |
  | req                           | recurse_providers  | Outbound HTTP               | FR-030, FR-047       |
  | ex_aws, ex_aws_s3, ex_aws_kms | recurse_providers  | AWS provider impls          | Managed SaaS shape   |
  | stream_data                   | all (test)         | Property tests              | SC-014               |
  | mox                           | recurse_providers  | Provider Interface mocks    | FR-004               |
  | telemetry + prometheus        | recurse_shared     | FR-014 /metrics             | FR-014               |
  | credo + custom neutrality     | root (dev)         | FR-004 neutrality CI gate   | D16                  |

  See each app's mix.exs for the actual dependency declarations.
  """
  use Mix.Project

  def project do
    [
      apps_path: "apps",
      version: "0.1.0",
      package: package(),
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      aliases: aliases(),
      releases: releases()
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

  # Releases for the Standalone Gateway tier (F002 + F004 — Audit Console).
  #
  # Build with: `scripts/build-release.sh` (runs `mix release audit_console`
  # inside a linux-arm64 Docker container so the resulting tarball matches
  # the t4g.large dogfood target — Graviton2 ARM64).
  #
  # Apps included:
  #   recurse_shared      — common types, DSSE, attestation primitives
  #   recurse_providers   — Postgres-Merkle ledger, S3 storage, KMS signing impls
  #   recurse_gateway     — HTTP surface (Bandit), F004 Audit Console SPA + APIs
  #   recurse_broker      — RFC 8693 token-exchange + OIDC browser-flow handler
  #
  # Apps excluded:
  #   recurse_runtime     — Phase-2 (Runtime tier); standalone_gateway.exs
  #                         explicitly sets `config :recurse_runtime, start?: false`
  #   recurse_integration — test-support harness only; no runtime modules to ship
  #
  # ERTS is bundled (`include_erts: true`) so the deploy host does not need
  # Erlang installed; this is why the build must run on linux-arm64 to match
  # the target architecture (Graviton2 t4g.large).
  defp releases do
    [
      audit_console: [
        include_executables_for: [:unix],
        applications: [
          recurse_shared: :permanent,
          recurse_providers: :permanent,
          # Required dependency: the fold seeds kernel admission before the
          # gateway can activate policy or accept executable traffic.
          recurse_fold: :permanent,
          recurse_gateway: :permanent,
          recurse_broker: :permanent,
          r5e: :load
        ],
        steps: [:assemble, &remove_build_cookie/1, :tar],
        include_erts: true,
        strip_beams: true
      ]
    ]
  end

  # Mix creates releases/COOKIE during assembly. Runtime env.sh supplies a
  # deployment cookie; remove the build secret before either tar or image COPY.
  defp remove_build_cookie(release) do
    File.rm!(Path.join(release.path, "releases/COOKIE"))
    release
  end

  def cli do
    [
      preferred_envs: [
        "recurse.cedar.stability_check": :test
      ]
    ]
  end

  # Umbrella-level dev/test tooling only. Per-app runtime deps live in apps/*/mix.exs.
  defp deps do
    [
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false},
      {:ex_doc, "~> 0.40", only: :dev, runtime: false},
      {:excoveralls, "~> 0.18", only: :test}
    ]
  end

  defp aliases do
    [
      # Guard rails — run before pushing.
      check: [
        "compile --warnings-as-errors",
        "credo --strict",
        "test",
        "recurse.cedar.stability_check"
      ]
    ]
  end
end
