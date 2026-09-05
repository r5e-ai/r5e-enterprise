# Test-env shared config.
#
# Owns the cross-app test defaults — most importantly the Ecto SQL Sandbox
# pool for `Recurse.Providers.Repo` so every integration test can share a
# single manual-mode checkout pattern (F002 T032 and onward).
#
# Per `elixir:ecto-thinking`: Sandbox requires `pool: Ecto.Adapters.SQL.Sandbox`
# and MUST be in manual mode at boot — tests call `SQL.Sandbox.checkout/1`
# explicitly, which keeps async-safe isolation per-test. The pool here
# intentionally does NOT use `async: false` at the ExUnit level: that call
# lives on each test module that legitimately needs global state (Bandit
# port binding, Bypass, etc.). `pool_size` stays higher than dev so parallel
# test checkouts don't starve.
#
# Real connection parameters come from environment variables so CI can
# point at its own Postgres without editing this file. Defaults match the
# `docker-compose.yaml` Postgres service from F002 T007 (user/pass/db all
# `recurse`, host `localhost` for out-of-compose dev runs).

import Config

config :recurse_providers, Recurse.Providers.Repo,
  username: System.get_env("POSTGRES_USER", "recurse"),
  password: System.get_env("POSTGRES_PASSWORD", "recurse"),
  hostname: System.get_env("POSTGRES_HOST", "localhost"),
  port: String.to_integer(System.get_env("POSTGRES_PORT", "5432")),
  database: System.get_env("POSTGRES_DB", "recurse_test"),
  pool: Ecto.Adapters.SQL.Sandbox,
  pool_size: 20,
  migration_timestamps: [type: :utc_datetime_usec]

# Gateway HTTP server is off in :test — integration tests boot components
# explicitly in their own test supervisor. This mirrors the
# `config/config.exs` umbrella default.
config :recurse_gateway, start_http?: false

# T090 — the OutboxReconciler is NOT started by the application
# supervisor in :test. The dedicated unit test starts per-test
# reconcilers with injected stubs. The config value below sets the
# default poll interval to a large value so any test that DOES start
# the reconciler without overriding options doesn't flood Telemetry
# with ticks.
config :recurse_gateway, :outbox_reconciler, poll_interval_ms: 60_000

# T091 — observability children are enabled by default (the
# MetricsRegistry is a safe dependency for every env). The telemetry
# poller, however, calls into Ecto from a non-test pid which the
# sandbox cannot serve; keep it disabled in :test.
config :recurse_gateway,
  telemetry_poller_enabled?: false,
  rate_limit_enabled?: false,
  outbox_reconciler_enabled?: false

# Spec 012 S6b — the bundle archive writes to `policy_bundles` from the
# loader process; most tests start a loader without a shared sandbox
# connection. The archive test enables it explicitly.
config :recurse_gateway, policy_bundle_archive_enabled?: false

# Broker HTTP server is off in :test for the same reason (avoid binding
# port 4001 during umbrella `mix test`). KeyRing runs in ephemeral mode
# so umbrella `mix test` can boot the :recurse_broker application without
# a real PEM on disk — matching the "Test-only ephemeral mode" section of
# `RecurseBroker.JWT.KeyRing`'s moduledoc.
config :recurse_broker,
  start_http?: false,
  keyring: [generate_ephemeral?: true]

# Silence application-level `:logger` noise in the suite. Individual tests
# can opt back in with `Logger.put_module_level/2`.
config :logger, level: :warning

# The fold's kernel state: a throwaway directory per `mix test` run, and no
# HTTP listener (nothing binds port 4546 during the suite). Mirrors the
# kernel's own config/test.exs, which is not loaded when :r5e is a dependency.
config :r5e,
  data_dir:
    Path.join(
      System.tmp_dir!(),
      "r5e-fold-test-#{System.os_time(:millisecond)}-#{:rand.uniform(100_000)}"
    ),
  start_server: false
