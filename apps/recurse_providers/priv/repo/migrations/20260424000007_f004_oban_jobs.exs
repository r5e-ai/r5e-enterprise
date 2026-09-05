defmodule Recurse.Providers.Repo.Migrations.F004ObanJobs do
  @moduledoc """
  F004 Audit Console — Oban job-runner schema.

  Provisions the `oban_jobs` table + companion structures required by Oban
  2.18+ to persist scheduled cron entries and worker state. Anchors:

    * specs/004-audit-console/research.md D7 — single Postgres instance for
      Oban (Constitution Principle I Air-Gap Native; no new external services).
    * specs/004-audit-console/tasks.md T044 — wires the Oban supervisor.

  We use Oban's bundled migration helper at version 12 (the latest stable for
  2.18.x), which provisions the standard `oban_jobs` table, `oban_peers`
  (cluster-leader registry; safe in single-node mode), `oban_pruning`, and the
  notification triggers. Adding our own table by hand is an anti-pattern —
  Oban evolves the schema across versions and the helper carries the upgrade
  path forward.

  Single-tenant per-deployment in F004 (per spec Cross-tenant out-of-scope),
  so the default `prefix: "public"` is fine; we do NOT segregate Oban into a
  per-tenant schema.
  """
  use Ecto.Migration

  def up, do: Oban.Migration.up(version: 12)

  # Down to 1 (not 0) preserves the table shell so future migrations have
  # something to roll forward against. Per Oban's docs the recommended
  # rollback for full removal is `version: 1` rather than `:down`.
  def down, do: Oban.Migration.down(version: 1)
end
