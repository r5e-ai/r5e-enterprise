defmodule Recurse.Gateway.SuggestionEngine.RetentionPurger.ChatHistory do
  @moduledoc """
  Daily retention purger for `chat_messages` + `chat_conversations` —
  F004 T047.

  ## Anchors

    * `specs/004-audit-console/contracts/retention_lifecycle.md` §"Lifecycle
      states / Chat Conversations + Chat Messages".
    * Spec FR-041a (per-message retention default 30 days) and FR-041b
      ("conversation transcript MUST be archived (soft-delete with last-N-
      messages preserved on read-only basis) and eventually purged").

  ## Three-stage lifecycle

  Per `retention_lifecycle.md`:

    1. **Per-message soft-delete**: messages where `created_at < now -
       chat_history_days` AND `deleted_at IS NULL` AND the message is
       NOT among the most-recent-N for its conversation (last-N
       preservation, default 5 per FR-041b). Sets `deleted_at = now`.
    2. **Conversation auto-archive**: conversations whose ALL messages
       are now soft-deleted (or hard-deleted) AND that aren't already
       archived get `archived_at = now`. The "ALL messages soft-
       deleted" check is a `NOT EXISTS` against the active
       `chat_messages` rows for that conversation.
    3. **Conversation hard-delete**: conversations where `archived_at <
       now - 90 days` (the 90-day post-archive grace per
       `retention_lifecycle.md`). Cascades to any remaining (pinned-
       archive) messages via the FK. Per the migration's
       `:delete_all` reference action, we don't need to chase rows by
       hand.

  ## Last-N preservation

  Per FR-041b + `retention_lifecycle.md`: "the most recent 5 messages
  of an archived conversation (configurable via
  `console.retention.chat_history_preserved_messages`, default 5) are
  retained as read-only past the per-message expiry." Concretely, the
  soft-delete UPDATE excludes any message whose `id` appears in the
  per-conversation `ORDER BY sequence DESC LIMIT N` window. We compute
  the window via a correlated subquery using `:dense_rank()`.

  Note: Postgres can't do `WHERE id NOT IN (correlated subquery)`
  efficiently at scale, but the chat_messages workload is bounded
  (per-conversation row counts are typically <10K and tenant-scoped).
  Per `retention_lifecycle.md` §"Failure modes", the job runs as a
  best-effort daily sweep — partial work is idempotent so a slow
  cycle that times out simply resumes next day.

  ## Configuration

    * `chat_history_days` — default 30 (FR-041a).
    * `chat_history_preserved_messages` — default 5 (FR-041b).
    * `chat_conversation_grace_days` — default 90 (D7 spec).
    * `grace_window_days` — default 30 (per-message hard-delete grace,
      symmetric with the other purgers).

  ## Receipt emission (T055a — wired)

  ONE `:ui_retention_purge` receipt per cycle with `data_class:
  "chat_history"`, committed via the shared
  `Recurse.Gateway.SuggestionEngine.RetentionPurger.Receipt.emit/1`
  helper. Counts roll up message-level + conversation-level operations
  into the single `soft_deleted_count` / `hard_deleted_count` tuple;
  the per-stage `breakdown` map flows into the predicate verbatim.
  """

  use Oban.Worker, queue: :retention, max_attempts: 3

  alias Recurse.Gateway.Admin.ChatHistory.{ChatConversation, ChatMessage}
  alias Recurse.Gateway.SuggestionEngine.RetentionPurger.Receipt
  alias Recurse.Providers.Repo

  import Ecto.Query

  require Logger

  @data_class "chat_history"

  @impl Oban.Worker
  def perform(%Oban.Job{} = _job) do
    cfg = retention_config()
    started_at = DateTime.utc_now()

    msg_soft = soft_delete_expired_messages(cfg, started_at)
    conv_archived = auto_archive_empty_conversations(started_at)
    msg_hard = hard_delete_purgeable_messages(cfg, started_at)
    conv_hard = hard_delete_purgeable_conversations(cfg, started_at)

    completed_at = DateTime.utc_now()
    duration_ms = DateTime.diff(completed_at, started_at, :millisecond)

    metrics = %{
      data_class: @data_class,
      soft_deleted_count: msg_soft + conv_archived,
      hard_deleted_count: msg_hard + conv_hard,
      started_at: started_at,
      completed_at: completed_at,
      duration_ms: duration_ms,
      breakdown: %{
        messages_soft: msg_soft,
        conversations_archived: conv_archived,
        messages_hard: msg_hard,
        conversations_hard: conv_hard
      }
    }

    Receipt.emit(metrics)

    Logger.info(fn ->
      "retention_purge cycle complete data_class=#{@data_class} " <>
        "msg_soft=#{msg_soft} conv_archived=#{conv_archived} " <>
        "msg_hard=#{msg_hard} conv_hard=#{conv_hard} " <>
        "duration_ms=#{duration_ms}"
    end)

    :ok
  end

  # Per-message soft-delete with last-N exclusion. The exclusion subquery
  # uses `dense_rank() OVER (PARTITION BY conversation_id ORDER BY sequence
  # DESC)` to identify the N newest active messages per conversation; any
  # message whose rank is ≤ N is preserved.
  #
  # We assemble the preserved-id set as a CTE-style subquery embedded in
  # the UPDATE's WHERE NOT IN. For F004's bounded chat workload this is
  # acceptable; if/when chat volume balloons (Day-2+) we'll revisit with
  # a partial-index strategy.
  defp soft_delete_expired_messages(cfg, now) do
    cutoff = DateTime.add(now, -cfg.chat_history_days, :day)
    preserve_n = cfg.chat_history_preserved_messages

    preserved_ids_subquery =
      from(m in ChatMessage,
        where: is_nil(m.deleted_at),
        select: %{
          id: m.id,
          rank: fragment("dense_rank() OVER (PARTITION BY ? ORDER BY ? DESC)", m.conversation_id, m.sequence)
        }
      )

    preserved_ids =
      from(p in subquery(preserved_ids_subquery),
        where: p.rank <= ^preserve_n,
        select: p.id
      )

    {count, _} =
      from(m in ChatMessage,
        where:
          m.inserted_at < ^cutoff and
            is_nil(m.deleted_at) and
            m.id not in subquery(preserved_ids),
        update: [set: [deleted_at: ^now]]
      )
      |> Repo.update_all([])

    count
  end

  # Auto-archive conversations whose every message is soft-deleted (or has
  # already been hard-deleted). `NOT EXISTS` against active messages is the
  # cleanest expression — Postgres short-circuits on the first hit.
  defp auto_archive_empty_conversations(now) do
    has_active_messages =
      from(m in ChatMessage,
        where: parent_as(:conv).id == m.conversation_id and is_nil(m.deleted_at),
        select: 1
      )

    {count, _} =
      from(c in ChatConversation, as: :conv,
        where: is_nil(c.archived_at) and not exists(has_active_messages),
        update: [set: [archived_at: ^now]]
      )
      |> Repo.update_all([])

    count
  end

  defp hard_delete_purgeable_messages(cfg, now) do
    cutoff = DateTime.add(now, -cfg.grace_window_days, :day)

    purgeable_ids_query =
      from(m in ChatMessage,
        where: not is_nil(m.deleted_at) and m.deleted_at < ^cutoff,
        select: m.id
      )

    {:ok, total} =
      Repo.transaction(
        fn ->
          purgeable_ids_query
          |> Repo.stream(max_rows: 1_000)
          |> Stream.chunk_every(1_000)
          |> Enum.reduce(0, fn id_chunk, acc ->
            {n, _} =
              Repo.delete_all(from(m in ChatMessage, where: m.id in ^id_chunk))

            acc + n
          end)
        end,
        timeout: 60_000
      )

    total
  end

  defp hard_delete_purgeable_conversations(cfg, now) do
    cutoff = DateTime.add(now, -cfg.chat_conversation_grace_days, :day)

    purgeable_ids_query =
      from(c in ChatConversation,
        where: not is_nil(c.archived_at) and c.archived_at < ^cutoff,
        select: c.id
      )

    {:ok, total} =
      Repo.transaction(
        fn ->
          purgeable_ids_query
          |> Repo.stream(max_rows: 1_000)
          |> Stream.chunk_every(1_000)
          |> Enum.reduce(0, fn id_chunk, acc ->
            {n, _} =
              Repo.delete_all(from(c in ChatConversation, where: c.id in ^id_chunk))

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
      chat_history_days: Keyword.get(cfg, :chat_history_days, 30),
      chat_history_preserved_messages:
        Keyword.get(cfg, :chat_history_preserved_messages, 5),
      grace_window_days: Keyword.get(cfg, :grace_window_days, 30),
      chat_conversation_grace_days:
        Keyword.get(cfg, :chat_conversation_grace_days, 90)
    }
  end

end
