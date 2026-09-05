defmodule Recurse.Gateway.Admin.BlastRadius.AsyncEscalation do
  @moduledoc """
  Oban worker for >10K-receipt Blast Radius computations — F004 T087 / US3.

  Per `contracts/blast_radius_algorithm.md` §6: when an estimated window
  exceeds 10K receipts the sync path returns `{:async_required, count}`
  + `202 Accepted` + `job_id`. This worker picks up the queued job,
  runs the streaming algorithm with the full 10-minute timeout, persists
  the result onto `policy_drafts.last_blast_radius_summary`, and
  broadcasts a Phoenix.PubSub message on `recurse:blast_radius_jobs`
  so the SPA's open-WebSocket listener can refresh.

  ## Iron Law check (`elixir:oban-thinking` + `elixir:otp-thinking`)

    * **Job args are JSON; atoms become strings.** The `perform/1` clause
      pattern-matches on string keys (`"draft_id"`, `"tenant_id"`, ...).
    * **Errors propagate.** A `{:error, reason}` from the underlying
      compute is returned verbatim so Oban marks the job failed and
      retries per `:max_attempts`. We do NOT catch + return `{:ok, _}` —
      that would silently mask blast-radius drift (Principle III).
    * **Timeout is 10 min** per algorithm §6's hard cap. Oban's default
      30s would kill long-running scans on populated 1M-receipt windows.

  ## PubSub topic

  On completion the worker broadcasts to `"recurse:blast_radius_jobs"` with
  the message `{:job_completed, draft_id, summary}` (success) or
  `{:job_failed, draft_id, reason}` (error). The SPA subscribes via the
  Live-tail WebSocket and re-fetches the draft on this event.

  ## Cron exclusion

  The blast-radius queue is configured in `config/config.exs` with
  concurrency=2; this worker is **on-demand only** (enqueued from
  `PolicyDraftsDryRunHandler`). It is NOT included in
  `oban_cron_crontab/0` because the work is operator-driven, not periodic.

  ## Cross-references

    * `specs/004-audit-console/contracts/blast_radius_algorithm.md` §6
    * `apps/recurse_gateway/lib/recurse_gateway/admin/blast_radius.ex` (T086)
    * `apps/recurse_gateway/lib/recurse_gateway/admin/policy_drafts_dry_run_handler.ex` (T091 — enqueuer)
  """

  use Oban.Worker,
    queue: :blast_radius,
    max_attempts: 3,
    unique: [
      period: 60,
      keys: [:draft_id, :since_iso, :until_iso],
      states: [:available, :scheduled, :executing, :retryable]
    ]

  alias Recurse.Gateway.Admin.BlastRadius
  alias Recurse.Gateway.Admin.PolicyDrafts

  require Logger

  @pubsub_topic "recurse:blast_radius_jobs"
  @timeout_ms 600_000

  @impl Oban.Worker
  def timeout(_job), do: @timeout_ms

  @impl Oban.Worker
  def perform(%Oban.Job{args: args}) do
    # GAN-review fix (PR-readiness #5, 2026-04-25): scope the draft fetch
    # by tenant_id to mirror the synchronous path's tenant guard (#1).
    # The enqueue site (`policy_drafts_dry_run_handler.ex`) records the
    # caller's tenant_id in the job args so the deferred compute cannot
    # cross tenant boundaries between enqueue + execute.
    with {:ok, draft_id} <- fetch_string(args, "draft_id"),
         {:ok, tenant_id} <- fetch_string(args, "tenant_id"),
         {:ok, since} <- parse_iso8601(args["since_iso"]),
         {:ok, until_dt} <- parse_iso8601(args["until_iso"]),
         {:ok, draft} <-
           PolicyDrafts.get(draft_id, tenant_scope: tenant_id, include_archived: true) do
      input = %{
        draft_id: draft.id,
        draft_cedar_source: draft.cedar_source,
        tenant_id: draft.tenant_id,
        window: %{since: since, until: until_dt},
        sample_size: Map.get(args, "sample_size", 20),
        force: true,
        force_sync?: true,
        persist?: true
      }

      case BlastRadius.compute_sync(input) do
        {:ok, summary} ->
          broadcast_completed(draft.id, summary)
          {:ok, summary}

        {:error, reason} = err ->
          broadcast_failed(draft.id, reason)
          err
      end
    else
      {:error, :not_found} ->
        # Draft was archived/hard-deleted between enqueue and execute — cancel
        # the job rather than retrying. Per oban-thinking: this is the
        # `:cancel` branch — not an unexpected error.
        Logger.info(fn -> "blast_radius async job: draft missing, cancelling args=#{inspect(args)}" end)
        {:cancel, :draft_not_found}

      {:error, reason} ->
        Logger.error(fn ->
          "blast_radius async job: invalid args reason=#{inspect(reason)} args=#{inspect(args)}"
        end)

        {:cancel, reason}
    end
  end

  @doc """
  Enqueue a fresh async blast-radius computation. Returns the inserted
  Oban job — the caller renders `job.id` into the 202 response body.

  Args carry only string-coerce-safe values (UUIDs + ISO8601 timestamps +
  integer sample_size) per the JSON-serialization rule.

  GAN-review fix (PR-readiness #5, 2026-04-25): `tenant_id` is now
  REQUIRED in the args. The deferred worker uses it to scope the
  draft fetch (`PolicyDrafts.get/2` with `:tenant_scope`) so the
  async path matches the sync path's tenant guard from blocker #1.
  """
  @spec enqueue(String.t(), String.t(), DateTime.t(), DateTime.t(), pos_integer()) ::
          {:ok, Oban.Job.t()} | {:error, term()}
  def enqueue(draft_id, tenant_id, %DateTime{} = since, %DateTime{} = until_dt, sample_size \\ 20)
      when is_binary(draft_id) and is_binary(tenant_id) and is_integer(sample_size) do
    %{
      "draft_id" => draft_id,
      "tenant_id" => tenant_id,
      "since_iso" => DateTime.to_iso8601(since),
      "until_iso" => DateTime.to_iso8601(until_dt),
      "sample_size" => sample_size
    }
    |> __MODULE__.new()
    |> Oban.insert()
  end

  @doc """
  PubSub topic name. Exposed so handlers + tests can subscribe without
  hard-coding the string.
  """
  @spec pubsub_topic() :: String.t()
  def pubsub_topic, do: @pubsub_topic

  # ---------------------------------------------------------------------------
  # Private
  # ---------------------------------------------------------------------------

  defp fetch_string(args, key) do
    case Map.get(args, key) do
      val when is_binary(val) and val != "" -> {:ok, val}
      _ -> {:error, {:missing_arg, key}}
    end
  end

  defp parse_iso8601(nil), do: {:error, :missing_iso8601}

  defp parse_iso8601(iso) when is_binary(iso) do
    case DateTime.from_iso8601(iso) do
      {:ok, dt, _offset} -> {:ok, dt}
      {:error, reason} -> {:error, {:invalid_iso8601, reason}}
    end
  end

  defp broadcast_completed(draft_id, summary) do
    safe_broadcast({:job_completed, draft_id, summary})
  end

  defp broadcast_failed(draft_id, reason) do
    safe_broadcast({:job_failed, draft_id, reason})
  end

  defp safe_broadcast(message) do
    pubsub = Application.get_env(:recurse_gateway, :pubsub_name, Recurse.Gateway.PubSub)

    if Code.ensure_loaded?(Phoenix.PubSub) do
      Phoenix.PubSub.broadcast(pubsub, @pubsub_topic, message)
    else
      :ok
    end
  rescue
    error ->
      Logger.warning(fn ->
        "blast_radius PubSub broadcast failed: #{inspect(error)} message=#{inspect(message)}"
      end)

      :ok
  end
end
