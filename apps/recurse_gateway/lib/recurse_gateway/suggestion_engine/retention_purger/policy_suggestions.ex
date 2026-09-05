defmodule Recurse.Gateway.SuggestionEngine.RetentionPurger.PolicySuggestions do
  @moduledoc """
  Daily retention purger for the `policy_suggestions` table — F004 T046.

  ## Anchors

    * `specs/004-audit-console/contracts/retention_lifecycle.md` §"Lifecycle
      states / Policy Suggestions" + §"Oban.Cron job schedule".
    * Glossary cluster — **Policy** (entries: *Policy Suggestion*, *Source
      Label*, *Confidence Score*).

  ## Chained-exemption invariant

  Per `retention_lifecycle.md`: a suggestion with `status = :adopted_as_draft`
  is exempt from retention "for as long as the resulting draft is exempt."
  We translate that into the simpler stable check at this layer:

    * Soft-delete clause: `status NOT IN [:adopted_as_draft]`.
    * The chained exemption (suggestion stays visible because the
      generated draft is itself adopted as a deployed policy) is
      maintained transitively: an adopted suggestion never gets soft-
      deleted here, so it cannot reach the hard-delete grace window.

  Dismissed suggestions ARE eligible for purge once `now > generated_at +
  policy_suggestions_days` — the `dismissed_at` timestamp doesn't reset
  the retention clock; the spec is explicit that retention is anchored
  to `generated_at`.

  ## Two-stage lifecycle

    1. **Soft-delete** rows where `generated_at < now - policy_suggestions_days`
       AND `status NOT IN [:adopted_as_draft]` AND `deleted_at IS NULL`.
    2. **Hard-delete** rows where `deleted_at < now - grace_window_days`.

  ## Configuration

    * `policy_suggestions_days` — default 180 (FR-035a).
    * `grace_window_days` — default 30.

  ## Receipt emission (T055a — wired)

  ONE `:ui_retention_purge` receipt per cycle with `data_class:
  "policy_suggestions"`, committed via the shared
  `Recurse.Gateway.SuggestionEngine.RetentionPurger.Receipt.emit/1`
  helper. The same telemetry event continues to fire alongside the
  ledger commit for dashboard backwards compatibility.
  """

  use Oban.Worker, queue: :retention, max_attempts: 3

  alias Recurse.Gateway.Admin.PolicySuggestions.PolicySuggestion
  alias Recurse.Gateway.SuggestionEngine.RetentionPurger.Receipt
  alias Recurse.Providers.Repo

  import Ecto.Query

  require Logger

  @data_class "policy_suggestions"

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

  defp soft_delete_expired(cfg, now) do
    cutoff = DateTime.add(now, -cfg.policy_suggestions_days, :day)

    {count, _} =
      from(s in PolicySuggestion,
        where:
          s.generated_at < ^cutoff and
            s.status != :adopted_as_draft and
            is_nil(s.deleted_at),
        update: [set: [deleted_at: ^now]]
      )
      |> Repo.update_all([])

    count
  end

  defp hard_delete_purgeable(cfg, now) do
    cutoff = DateTime.add(now, -cfg.grace_window_days, :day)

    purgeable_ids_query =
      from(s in PolicySuggestion,
        where: not is_nil(s.deleted_at) and s.deleted_at < ^cutoff,
        select: s.id
      )

    {:ok, total} =
      Repo.transaction(
        fn ->
          purgeable_ids_query
          |> Repo.stream(max_rows: 1_000)
          |> Stream.chunk_every(1_000)
          |> Enum.reduce(0, fn id_chunk, acc ->
            {n, _} =
              Repo.delete_all(from(s in PolicySuggestion, where: s.id in ^id_chunk))

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
      policy_suggestions_days: Keyword.get(cfg, :policy_suggestions_days, 180),
      grace_window_days: Keyword.get(cfg, :grace_window_days, 30)
    }
  end
end
