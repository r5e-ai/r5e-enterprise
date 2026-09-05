# Shared compile-time config for all umbrella apps.
# Per-tier overrides live in config/<tier>.exs, loaded by config/runtime.exs.
# See FR-015 for the Tier Configuration Model (YAML) which governs runtime behavior
# independently of this Mix config.

import Config

# Umbrella apps — compile-time only; runtime wiring lives in config/runtime.exs.
config :recurse_gateway, start_http?: false
config :recurse_runtime, start?: false

# `POST /admin/test/login` — the dev/test cookie-mint route
# (`Recurse.Gateway.Admin.BrowserAuth.DevLoginHandler`). OFF here, which is
# the value every env inherits unless it overrides: `config/dev.exs` sets it
# true, and `config/runtime.exs` applies `R5E_DEV_LOGIN_ENABLED` when that
# env var is set (spec 012: the Compose quickstart runs a prod release with
# no IdP and needs the switch at runtime). Unset env + non-dev build = off.
config :recurse_gateway, dev_login_enabled?: false

# F004 T044 — Oban supervisor config for the Audit Console background work.
#
# Single :recurse_providers Repo (no separate Oban DB; Constitution Principle I
# Air-Gap Native — no new external services). Three queues, sized for their
# workload:
#
#   * `:retention`         — daily soft/hard-delete sweeps (T045-T047). Bounded
#                            row counts; concurrency=1 so sibling purgers
#                            interleave without contending the same partition.
#   * `:suggestion_engine` — heuristic (hourly) + LLM (daily) generators
#                            (T131/T133, Phase 7). Concurrency=2 lets the
#                            heuristic run while a refresh-on-demand LLM run
#                            is in flight; both are coarse-grained.
#   * `:blast_radius`      — async dry-run jobs >10K-receipt windows (T087,
#                            US3). Concurrency=2 limits parallel long-running
#                            scans; jobs may stream for minutes.
#
# Cron table is assembled at boot in `RecurseGateway.Application.oban_cron_crontab/0`
# rather than here — Oban's Cron plugin validates the worker module exists at
# init time, but the Phase-2 supervisor must boot cleanly even when the
# Phase-7 / W2-A worker modules haven't landed yet. Doing the assembly at
# boot (option 2 from T048: `Code.ensure_loaded?(...)`) lets us *include*
# entries only when their worker is compiled, which is more robust than
# the alternative `enabled: false` placeholder pattern (Oban 2.21 still
# resolves the module reference for `enabled: false` entries — option 1
# would fail boot here).
#
# `:plugins` order matters only for log readability; functional behaviour is
# independent of the listing.
config :recurse_gateway, Oban,
  repo: Recurse.Providers.Repo,
  queues: [
    retention: 1,
    suggestion_engine: 2,
    blast_radius: 2
  ]

# F004 T044 — `console.retention.*` defaults (FR-029a / FR-035a / FR-041a /
# FR-041b). The retention-purger workers read these via `Application.get_env`.
# Operators override per deploy via env vars wired through
# `config/runtime.exs`; the in-tree defaults are authoritative when no
# env override is present. All values are integers; the workers cast to
# `Duration` units inline.
config :recurse_gateway, :console_retention,
  policy_drafts_days: 365,
  policy_suggestions_days: 180,
  chat_history_days: 30,
  chat_history_preserved_messages: 5,
  grace_window_days: 30,
  chat_conversation_grace_days: 90

# recurse_providers owns the Postgres-Merkle LedgerProvider reference impl.
# Declare the Repo so `mix ecto.migrate` + `mix ecto.create` find it without
# needing `--repo Recurse.Providers.Repo` on every invocation.
config :recurse_providers, ecto_repos: [Recurse.Providers.Repo]

# Dev default connection. Overridable via DATABASE_URL in config/runtime.exs.
# Schema is migration-managed under apps/recurse_providers/priv/repo/migrations.
config :recurse_providers, Recurse.Providers.Repo,
  username: System.get_env("POSTGRES_USER", "recurse"),
  password: System.get_env("POSTGRES_PASSWORD", "recurse"),
  hostname: System.get_env("POSTGRES_HOST", "localhost"),
  port: String.to_integer(System.get_env("POSTGRES_PORT", "5432")),
  database: System.get_env("POSTGRES_DB", "recurse_dev"),
  pool_size: 10,
  migration_timestamps: [type: :utc_datetime_usec]

config :logger, :default_formatter,
  format: "$time $metadata[$level] $message\n",
  metadata: [:correlation_id, :tenant_id, :run_id]

# ---------------------------------------------------------------------------
# The fold (`apps/recurse_fold`) — configuration for the r5e kernel, which is
# a path dependency outside this umbrella.
#
# The kernel's own config/*.exs are NOT loaded when it is consumed as a
# dependency, so every `:r5e` key it reads has to be set here. Defaults kept
# deliberately distinct from a local kernel checkout's own (`.r5e`, port 4545)
# so that running the fold can never touch the kernel's real genesis state.
config :r5e,
  # Relative to the working directory — i.e. `apps/recurse_fold/.r5e-fold`
  # when running the fold's own mix tasks. Gitignored. A prod release
  # NEVER inherits this: config/runtime.exs sets `/data/kernel` there.
  data_dir: ".r5e-fold",
  http_port: 4546,
  start_server: true,
  # Enterprise's Cedar engine decides inside the kernel's admission pipeline.
  policy: Recurse.Fold.Policy.Cedar

# Spec 012 S9a — whether the fold starts its kernel at all. Always `true`:
# the fold's own suite needs a kernel under mix, and config/runtime.exs sets
# `enabled?: true` unconditionally in every environment, refusing to boot at
# all when `R5E_FOLD_ENABLED` asks for `false`. There is no fold-less mode in
# this release: the quickstart image boots the fold, and `R5E_FOLD_ENABLED`
# can only fail the boot, never disable it.
config :recurse_fold, enabled?: true

# Default: use per-env config file if present. Real provider selection
# is driven by `R5E_PROVIDER_<ROLE>_IMPL` env vars consumed by
# `Recurse.Gateway.Config.EnvProviderRegistry` at boot.
if File.exists?(Path.expand("#{config_env()}.exs", __DIR__)) do
  import_config "#{config_env()}.exs"
end
