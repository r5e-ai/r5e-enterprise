defmodule Mix.Tasks.R5e.Audit.CleanseDevData do
  @moduledoc """
  Wipe receipt/attestation tables in the dev database.

  Used to reset audit-dev so a fresh JSONL session can be re-imported
  through the new tool-call extractor pipeline. Deletes all rows in:

    * `attestations` — every receipt
    * `sessions` — every session record
    * `session_epochs` — per-session Merkle epochs
    * `merkle_nodes` — global Merkle leaves/internals
    * `global_ledger_entries` — global ledger checkpoint entries
    * `payload_outbox` — pending payload commits
    * `audit_exports` — saved evidence-export receipts

  Foreign-key-referenced tables (`tenants`, `signing_keys`,
  `policy_bundles`, etc.) are LEFT INTACT — those are configuration,
  not receipt data.

  ## Safety

  This task REFUSES to run unless `RECURSE_ENV` is `development`,
  `dev`, or `dogfood`, OR `--i-understand-this-is-destructive` is
  passed. The intent is "edge cases now beat edge cases at demo" —
  in dev only.

  Production paths must NEVER invoke this — receipts are immutable
  evidence; deleting them violates Constitution Principle II
  (Cryptographically Verifiable Receipts) and III (Tamper-Evident
  Ledger).

  ## Usage

      # Local dev (no env set defaults to refusal)
      RECURSE_ENV=development mix r5e.audit.cleanse_dev_data

      # audit-dev via SSM rpc against the running BEAM:
      sudo -u beam bash -c 'set -a; source /etc/r5e-audit-audit.env; \\
        RECURSE_ENV=dogfood /opt/r5e/audit/current/bin/audit_console rpc \\
        "Mix.Tasks.R5e.Audit.CleanseDevData.cleanse!()"'

  After cleansing, re-import via:

      mix r5e.import.claude_code_session \\
        --tenant-id org_01KQ5T2EH9NP3AWE54AB2APWNH \\
        --principal operator@example.com \\
        path/to/session.jsonl
  """

  use Mix.Task

  @shortdoc "Truncate receipt/attestation tables for dev re-import"

  @receipt_tables [
    # Order matters — dependents first so foreign keys don't trip.
    "audit_exports",
    "payload_outbox",
    "global_ledger_entries",
    "merkle_nodes",
    "attestations",
    "session_epochs",
    "sessions"
  ]

  @allowed_envs ["development", "dev", "dogfood", "test"]

  @impl Mix.Task
  def run(argv) do
    Mix.Task.run("app.start")

    {opts, _args, _invalid} =
      OptionParser.parse(argv,
        strict: [
          force: :boolean,
          # OptionParser converts hyphens to underscores in keyword names —
          # `--i-understand-this-is-destructive` arrives as
          # `:i_understand_this_is_destructive`.
          i_understand_this_is_destructive: :boolean
        ]
      )

    force? = Keyword.get(opts, :force, false)
    bypass? = Keyword.get(opts, :i_understand_this_is_destructive, false) or force?

    case ensure_safe(bypass?) do
      :ok ->
        cleanse!()

      {:error, env} ->
        Mix.raise("""
        Refusing to cleanse audit data: RECURSE_ENV=#{inspect(env)} is not
        in the allowed-list #{inspect(@allowed_envs)}. This task TRUNCATES
        every receipt in the database; it is dev-only.

        If you are SURE you want to run it on this environment, pass
        --i-understand-this-is-destructive (NOT recommended; production
        receipts are immutable evidence per Constitution Principle II).
        """)
    end
  end

  @doc """
  Public entrypoint suitable for `release rpc`. Truncates the receipt
  tables; ignores the env-var safety check (rpc-callers are assumed to
  have asserted safety themselves; the Mix task wraps this with the
  env check).
  """
  @spec cleanse!() :: :ok
  def cleanse! do
    repo = Recurse.Providers.Repo

    Mix.shell().info("[cleanse] truncating #{length(@receipt_tables)} receipt tables")

    {:ok, _} =
      repo.transaction(fn ->
        Enum.each(@receipt_tables, fn table ->
          # CASCADE handles referencing rows in tables we don't enumerate
          # (e.g. policy_drafts → policy_suggestion_runs); RESTART IDENTITY
          # resets the bigserial counters used by `global_ledger_entries.id`
          # and `merkle_nodes.id`.
          {:ok, _result} =
            Ecto.Adapters.SQL.query(
              repo,
              ~s(TRUNCATE TABLE "#{table}" RESTART IDENTITY CASCADE),
              []
            )

          Mix.shell().info("  truncated #{table}")
        end)
      end)

    Mix.shell().info("[cleanse] done — re-import via mix r5e.import.claude_code_session")
    :ok
  end

  defp ensure_safe(true), do: :ok

  defp ensure_safe(false) do
    env = current_env()

    if env in @allowed_envs do
      :ok
    else
      {:error, env}
    end
  end

  # Resolution layered so the operator can override at any layer:
  #   1. `RECURSE_ENV` env var (most specific, dev/dogfood path)
  #   2. `MIX_ENV` env var (mix shell convention)
  #   3. final-fallback default of `"prod"` (fail-closed: an unconfigured
  #      env is treated as prod and refused — credo flags Mix.env in
  #      application code so we resolve via env vars only).
  defp current_env do
    System.get_env("RECURSE_ENV") ||
      System.get_env("MIX_ENV") ||
      "prod"
  end
end
