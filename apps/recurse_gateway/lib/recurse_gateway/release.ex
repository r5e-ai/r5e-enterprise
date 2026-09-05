defmodule Recurse.Gateway.Release do
  @moduledoc """
  Release tasks invokable from a built `mix release` artifact without
  booting the full application supervision tree.

  ## Why this module exists

  The audit-dev deploy pipeline (`.gitlab-ci.yml deploy:audit-dev`)
  drops a CI-built release tarball onto the EC2 box, atomically swaps
  it into `/opt/r5e/audit/current/`, and restarts
  `r5e-audit-audit.service`. Until F15, Ecto migrations were NOT
  applied to the live RDS database as part of that flow; new
  migrations only landed on the box if a human operator ran them
  manually via `bin/audit_console rpc` (post-restart, against the
  running BEAM).

  Caught 2026-04-30: codex's MR !6 added migration
  `20260428000000_f002_add_tool_call_event_kind.exs` (widens the
  `attestations.event_kind` CHECK constraint to include
  `tool_call`). The migration shipped to main and the deploy
  pipeline ran successfully — but the BEAM crashed on first
  `tool_call` event because the live DB still rejected the kind.
  The orchestrator unblocked the demo manually via:

      sudo -u beam bash -c 'set -a; source /etc/r5e-audit-audit.env; \\
        set +a; /opt/r5e/audit/current/bin/audit_console rpc \\
        "{:ok, _, _} = Ecto.Migrator.with_repo(Recurse.Providers.Repo, \\
          fn repo -> Ecto.Migrator.run(repo, :up, all: true) end); \\
          IO.puts(\\"migrations done\\")"'

  This module is the production-grade form of that one-liner. The
  deploy script now invokes `bin/audit_console eval
  'Recurse.Gateway.Release.migrate()'` AFTER the new release is
  staged but BEFORE the BEAM is restarted, against the new release's
  bytecode (so any new migrations packaged in the release apply
  against the live database).

  ## Standard Phoenix/Ecto release-task shape

  This is the canonical shape documented in `mix help phx.gen.release`
  and the Ecto README's "Releases" section: an `Application.load/1`
  per app whose ecto_repos are interesting, then
  `Ecto.Migrator.with_repo/2` per repo. `with_repo/2` starts the Repo
  + the minimum supervision required for migrations, runs the
  callback, and shuts everything down — no full app boot, no Bandit,
  no Cedar NIF init, no KMS rotation watcher.

  ## Module location rationale

  Lives in `:recurse_gateway` (alongside the gateway-supervised
  systemd unit) rather than `:recurse_providers` (which owns the
  Repo). Two reasons:

  * The `audit_console` release ships with `:recurse_gateway` as
    the umbrella app most closely identified with the deployed
    artifact (its OTP application is what the systemd unit hosts).
  * `mix release` invokes `bin/audit_console eval` against the
    release's BEAM; the entry-point module needs to be reachable
    from the application loader. Locating it in `:recurse_gateway`
    keeps the deploy script path (`bin/audit_console eval
    'Recurse.Gateway.Release.migrate()'`) short and discoverable
    next to the rest of the gateway's runtime surface.

  Repos are still discovered via
  `Application.fetch_env!(:recurse_providers, :ecto_repos)` —
  Repo ownership stays in `:recurse_providers` per Constitution
  Principle V.

  ## What we deliberately do NOT do here

  * No `down/0` or `rollback/2` — this module is `:up, all: true`
    only. Manual rollback of a bad migration is a deliberate human
    decision and stays out of automation. (See F15 brief.)
  * No `seed/0` — fixture loading is not a deploy-time concern.
  * No `:ecto_repos` for `:recurse_gateway` itself — that app
    declares no repos.
  """

  @doc """
  Run all pending migrations across every Repo in the release, `:up`.

  Loads each app whose `ecto_repos` we depend on (without starting
  it), then iterates the repos and runs `Ecto.Migrator.with_repo/2`
  for each. `with_repo/2` brings up the Repo's minimum supervision
  tree, runs the callback, and shuts it down again.

  Failure mode: if any migration raises, this function raises. The
  deploy script catches the non-zero exit and aborts the deploy
  before restarting the BEAM (see `.gitlab-ci.yml deploy:audit-dev`).
  Old release stays staged at `/opt/r5e/audit/previous`; current
  swap is reverted; service stays stopped pending operator
  intervention.
  """
  @spec migrate() :: :ok
  def migrate do
    load_app()

    for repo <- repos() do
      {:ok, _, _} = Ecto.Migrator.with_repo(repo, &Ecto.Migrator.run(&1, :up, all: true))
    end

    :ok
  end

  @doc """
  List the repos this release will migrate.

  Pure read of `:recurse_providers` `:ecto_repos` config; useful for
  smoke-testing the release task wiring without actually running
  migrations.
  """
  @spec repos() :: [module()]
  def repos do
    Application.fetch_env!(:recurse_providers, :ecto_repos)
  end

  # The `eval` entrypoint of a `mix release` does NOT start the app;
  # it loads the .app files and evaluates the expression. Ecto's
  # `:ecto_repos` config is set in `config/config.exs` and compiled
  # into `:recurse_providers`'s sys.config, but reading it requires
  # the app to be loaded first (Application.fetch_env!/2 fails with
  # ArgumentError otherwise). `Application.load/1` is idempotent + is
  # the documented way to make compiled config available without
  # starting children.
  defp load_app do
    Application.load(:recurse_providers)
  end
end
