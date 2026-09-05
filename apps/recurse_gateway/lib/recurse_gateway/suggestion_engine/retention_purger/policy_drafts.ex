defmodule Recurse.Gateway.SuggestionEngine.RetentionPurger.PolicyDrafts do
  @moduledoc """
  Daily retention purger for the `policy_drafts` table — F004 T045.

  ## Anchors

    * `specs/004-audit-console/contracts/retention_lifecycle.md` §"Lifecycle
      states / Policy Drafts" + §"Oban.Cron job schedule".
    * `specs/004-audit-console/research.md` D7 (Oban.Cron rationale).
    * `specs/004-audit-console/data-model.md` §0 — `:ui_retention_purge`
      event_kind in the canonical action matrix (one receipt per cycle).

  ## Iron Law check (`elixir:oban-thinking`)

    * Job args are JSON; no atoms-as-strings sharp edge here because cron
      entries pass `%{}` (no operator-supplied args). The `data_class`
      identity is hardcoded in the module — there's no need to thread it
      through args.
    * Errors propagate. We do NOT catch DB connection failures or query
      errors — they bubble up to Oban which will retry per `max_attempts`
      and surface in `oban_jobs.errors`. Swallowing into `{:ok, :failed}`
      would silently mask retention drift (Principle III: "everything
      attestable").
    * The hard-delete path uses `Repo.transaction + Repo.stream` to batch
      rows in chunks of 1,000 per `contracts/retention_lifecycle.md` §
      "Soft-delete column" — this prevents long-running transactions from
      blocking the row-level locks the data-plane Cedar evaluator may hold.

  ## Two-stage lifecycle

  Per `retention_lifecycle.md` §"Lifecycle states / Policy Drafts":

    1. **Soft-delete** rows where `inserted_at < now - policy_drafts_days`,
       `status NOT IN [:adopted_as_draft]` (chained-exemption guard), AND
       `deleted_at IS NULL`. Sets `deleted_at = now`. The grace window
       starts here — operators have `grace_window_days` to recover via
       DB-level intervention before hard-delete.
    2. **Hard-delete** rows where `deleted_at < now - grace_window_days`.
       Cedar source content is unrecoverable post-purge, but receipts
       referencing the draft (via `source_receipt_run_id` soft-FK) are
       NOT affected — they live in F002's 7-year audit retention.

  ## Configuration

  Reads from `Application.get_env(:recurse_gateway, :console_retention, [])`
  with the FR-029a defaults baked in:

    * `policy_drafts_days` — default 365.
    * `grace_window_days` — default 30 (operator-configurable 7-90 per
      `retention_lifecycle.md`; bounds-check happens in the future
      tier-config validator, not here).

  ## Receipt emission (T055a — wired)

  ONE `:ui_retention_purge` receipt per cycle with the aggregate counts in
  the predicate, committed through
  `Recurse.Gateway.SuggestionEngine.RetentionPurger.Receipt.emit/1` which
  builds + DSSE-signs + ledger-commits the system envelope via
  `EnvelopeBuilder.build_system/4` + `PostgresMerkleLedger.commit_attestation/2`.
  The shared helper also fires `[:recurse, :ui_retention_purge, :cycle]`
  telemetry so existing dashboards / SIEM tails continue to observe the
  same shape.
  """

  use Oban.Worker, queue: :retention, max_attempts: 3

  alias Recurse.Gateway.Admin.PolicyDrafts.PolicyDraft
  alias Recurse.Gateway.SuggestionEngine.RetentionPurger.Receipt
  alias Recurse.Providers.Repo

  import Ecto.Query

  require Logger

  @data_class "policy_drafts"

  @impl Oban.Worker
  def perform(%Oban.Job{} = _job) do
    cfg = retention_config()
    started_at = DateTime.utc_now()

    soft_count = soft_delete_expired(cfg, started_at)
    hard_count = hard_delete_purgeable(cfg, started_at)

    completed_at = DateTime.utc_now()
    duration_ms = DateTime.diff(completed_at, started_at, :millisecond)

    metrics = %{
      data_class: @data_class,
      soft_deleted_count: soft_count,
      hard_deleted_count: hard_count,
      started_at: started_at,
      completed_at: completed_at,
      duration_ms: duration_ms
    }

    Receipt.emit(metrics)

    Logger.info(fn ->
      "retention_purge cycle complete data_class=#{@data_class} " <>
        "soft=#{soft_count} hard=#{hard_count} duration_ms=#{duration_ms}"
    end)

    :ok
  end

  # `Repo.update_all/3` returns `{count, _returning}`. Soft-delete is a
  # single UPDATE — the grace-window hard-delete is the loop that follows.
  # We deliberately do NOT batch the soft-delete: even the 365-day default
  # window across thousands of drafts is a single small UPDATE locking
  # only the soft-deleted rows (no FK cascade).
  defp soft_delete_expired(cfg, now) do
    cutoff = DateTime.add(now, -cfg.policy_drafts_days, :day)

    {count, _} =
      from(d in PolicyDraft,
        where:
          d.inserted_at < ^cutoff and
            d.status != :adopted_as_draft and
            is_nil(d.deleted_at),
        update: [set: [deleted_at: ^now]]
      )
      |> Repo.update_all([])

    count
  end

  # Hard-delete in batches of 1,000 per `retention_lifecycle.md`. We stream
  # the purgeable IDs inside a transaction (Repo.stream/2 requires a tx),
  # collect each chunk, and run a single `delete_all` per chunk. The
  # serialized inner-transaction stream is fine because `:retention` queue
  # concurrency is 1 — no sibling job competes for these rows.
  defp hard_delete_purgeable(cfg, now) do
    cutoff = DateTime.add(now, -cfg.grace_window_days, :day)

    purgeable_ids_query =
      from(d in PolicyDraft,
        where: not is_nil(d.deleted_at) and d.deleted_at < ^cutoff,
        select: d.id
      )

    {:ok, total} =
      Repo.transaction(
        fn ->
          purgeable_ids_query
          |> Repo.stream(max_rows: 1_000)
          |> Stream.chunk_every(1_000)
          |> Enum.reduce(0, fn id_chunk, acc ->
            {n, _} =
              Repo.delete_all(from(d in PolicyDraft, where: d.id in ^id_chunk))

            acc + n
          end)
        end,
        timeout: 60_000
      )

    total
  end

  defp retention_config do
    cfg = Application.get_env(:recurse_gateway, :console_retention, [])

    %{
      policy_drafts_days: Keyword.get(cfg, :policy_drafts_days, 365),
      grace_window_days: Keyword.get(cfg, :grace_window_days, 30)
    }
  end
end
