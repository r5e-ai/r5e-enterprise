defmodule Recurse.Gateway.Admin.ChatHistory do
  @moduledoc """
  Admin context for the `chat_conversations` + `chat_messages` tables —
  F004 T105.

  Public CRUD + lifecycle API for the Audit Agent's per-principal
  conversation history. Talks directly to `Recurse.Providers.Repo` (the
  F002 Postgres Repo), NOT through the `LedgerProvider` behaviour. This
  is the load-bearing AD-001 c' compliance: UI state is owned by the
  Gateway admin context; the cryptographic ledger impl gets no new
  public methods.

  Cross-references:
    * `specs/004-audit-console/data-model.md` §1.3, §1.4 (schemas).
    * `specs/004-audit-console/data-model.md` §3.3 (public-API signatures).
    * `specs/004-audit-console/contracts/audit_api_extensions.md`
      §"Chat (Audit Agent)" (HTTP-side surface served by `ChatHandler`).
    * `apps/recurse_gateway/lib/recurse_gateway/admin/chat_history/chat_conversation.ex`
    * `apps/recurse_gateway/lib/recurse_gateway/admin/chat_history/chat_message.ex`

  ## Iron Law check (`elixir:elixir-thinking`)

    1. Mutable state across calls? No — every call is a pure function of
       args + Repo state.
    2. Concurrent execution? No — runs synchronously on the request
       process. Repo connection pool handles its own concurrency.
    3. Fault isolation? No — failures bubble through `{:ok, _} | {:error,
       _}` tuples; nothing rescued.

  All three NO → plain functions. No GenServer.

  ## Sequence-allocation invariant (`elixir:ecto-thinking`)

  Per `data-model.md` §1.4, `chat_messages.sequence` is per-conversation
  monotonic with a `UNIQUE(conversation_id, sequence)` constraint that
  doubles as a concurrency guard. Two writers racing to insert
  `sequence = N` → second one's INSERT raises a unique-violation. The
  `create_message/2` path catches that violation and retries with
  `sequence = N+1`. Three retries max before giving up — three concurrent
  agent turns into a single conversation is a pathological client
  behaviour; the tests assert single-writer determinism.

  ## Anti-pattern guards (`elixir:elixir-antipatterns`)

    * Multi-row writes (create conversation + first message; bump
      last_message_at + insert next message) wrapped in
      `Repo.transact/1` — atomic per Ecto-thinking sharp edge.
    * No `nil` returns from `get_conversation/2`; explicit
      `{:error, :not_found}`.
    * No `_ -> nil` catch-all on `Repo.get/2` results.
  """

  import Ecto.Query

  alias Recurse.Gateway.Admin.ChatHistory.ChatConversation
  alias Recurse.Gateway.Admin.ChatHistory.ChatMessage
  alias Recurse.Providers.Repo

  @max_sequence_retries 3

  # Truncation cap for the per-conversation `last_user_message_excerpt`
  # surfaced by `list_conversations/1` and the
  # `GET /v1/chat/conversations` payload (per `audit_api_extensions.md`
  # §"GET /v1/chat/conversations"). The contract example uses ~24 chars
  # ("Why was Alice's...") but the dropdown UI line-clamps to one line at
  # ~60-char column-width; 120 leaves comfortable headroom for non-Latin
  # scripts whose grapheme clusters render wider per code point.
  @excerpt_max_chars 120

  @typedoc """
  `attrs` accepted by `create_message/2`. Either string- or atom-keyed;
  the changeset normalizes to atoms via Ecto's cast pipeline.

  Required:
    * `:role` — one of `[:user, :agent, :tool_call, :tool_result]`.
    * `:content` — string ≤64 KB.

  Optional:
    * `:tool_calls` — list of tool-call maps (see ChatMessage moduledoc).
    * `:attested_run_id` — UUID of the receipt emitted for this message.

  And for the `:new` path of `create_message/2`:
    * `:tenant_id` — required.
    * `:principal_subject` — required.
  """
  @type message_attrs :: map()

  @doc """
  Append a message to a conversation. The `:new` path creates a
  conversation in the same transaction; the existing-id path bumps
  `last_message_at`.

  Sequence allocation is atomic via `UNIQUE(conversation_id, sequence)` +
  conflict-and-retry (max 3 attempts).

  Returns `{:ok, {conversation, message}}` so callers see the
  conversation_id (especially relevant for the `:new` path) without a
  follow-up read.
  """
  @spec create_message(:new | String.t(), message_attrs()) ::
          {:ok, {ChatConversation.t(), ChatMessage.t()}}
          | {:error, Ecto.Changeset.t() | :conversation_not_found}
  def create_message(:new, attrs) when is_map(attrs) do
    Repo.transact(fn ->
      with {:ok, tenant_id, principal_subject} <- fetch_new_conversation_keys(attrs),
           {:ok, conv} <- do_create_conversation(tenant_id, principal_subject),
           {:ok, msg} <- insert_message_with_sequence(conv, attrs, 1) do
        {:ok, {conv, msg}}
      end
    end)
  end

  def create_message(conversation_id, attrs)
      when is_binary(conversation_id) and is_map(attrs) do
    Repo.transact(fn ->
      with {:ok, conv} <- fetch_live_conversation(conversation_id),
           next_seq <- next_sequence(conv.id),
           {:ok, msg} <- insert_message_with_sequence(conv, attrs, next_seq),
           {:ok, conv2} <- bump_last_message_at(conv) do
        {:ok, {conv2, msg}}
      end
    end)
  end

  @doc """
  Explicitly create a conversation without an initial message.

  Used by F005+ chat-resume flows; `create_message(:new, _)` is the
  Day-1 path.
  """
  @spec create_conversation(String.t(), map()) ::
          {:ok, ChatConversation.t()} | {:error, Ecto.Changeset.t()}
  def create_conversation(tenant_id, attrs)
      when is_binary(tenant_id) and is_map(attrs) do
    principal_subject = attrs[:principal_subject] || attrs["principal_subject"]
    do_create_conversation(tenant_id, principal_subject)
  end

  defp do_create_conversation(_tenant_id, nil) do
    {:error,
     ChatConversation.changeset(%ChatConversation{}, %{}) |> Ecto.Changeset.add_error(:principal_subject, "required")}
  end

  defp do_create_conversation(tenant_id, principal_subject) do
    now = DateTime.utc_now()

    %ChatConversation{}
    |> ChatConversation.changeset(%{
      "tenant_id" => tenant_id,
      "principal_subject" => principal_subject,
      "started_at" => now,
      "last_message_at" => now
    })
    |> Repo.insert()
  end

  @doc """
  Fetch a conversation + its messages (sequence ascending). Returns
  `{:error, :not_found}` for missing or soft-deleted conversations
  (unless `:include_deleted` is set).

  Options:
    * `:limit` — message page size (default 100).
    * `:sequence_gt` — return messages with `sequence > N` (cursor).
    * `:include_archived` — boolean, default false.
    * `:include_deleted` — boolean, default false.
    * `:tenant_scope` — string; if set, returns `:not_found` when the
      conversation's tenant doesn't match (cross-tenant isolation).
    * `:principal_scope` — string; if set, returns `:not_found` when the
      conversation's `principal_subject` doesn't match (cross-principal
      isolation).
  """
  @spec get_conversation(String.t(), keyword()) ::
          {:ok, {ChatConversation.t(), [ChatMessage.t()]}}
          | {:error, :not_found}
  def get_conversation(conversation_id, opts \\ []) when is_binary(conversation_id) do
    include_archived? = Keyword.get(opts, :include_archived, false)
    include_deleted? = Keyword.get(opts, :include_deleted, false)
    tenant_scope = Keyword.get(opts, :tenant_scope)
    principal_scope = Keyword.get(opts, :principal_scope)
    limit = Keyword.get(opts, :limit, 100)
    sequence_gt = Keyword.get(opts, :sequence_gt)

    query =
      ChatConversation
      |> where([c], c.id == ^conversation_id)
      |> apply_deleted_filter(include_deleted?)
      |> apply_archived_filter(include_archived?)
      |> apply_scope(:tenant_id, tenant_scope)
      |> apply_scope(:principal_subject, principal_scope)

    case safe_one(query) do
      nil ->
        {:error, :not_found}

      %ChatConversation{} = conv ->
        messages = list_messages(conv.id, limit, sequence_gt)
        {:ok, {conv, messages}}
    end
  end

  @doc """
  List conversations for a principal-scoped query. Filters:

    * `:tenant_id` — required for cross-tenant isolation.
    * `:principal_subject` — required for cross-principal isolation
      (per `audit_api_extensions.md` §"GET /v1/chat/conversations" —
      conversations are per-principal, not per-tenant-shared).
    * `:limit` — default 50.
    * `:cursor` — opaque, not yet implemented (F005 task).
    * `:include_archived` — boolean, default false.
    * `:include_deleted` — boolean, default false.

  Returns a list of `{conversation, last_user_message_excerpt}` tuples
  where the excerpt is the most-recent user-role message body for the
  conversation, truncated to ~#{@excerpt_max_chars} chars (or `nil` if
  the conversation has no user message yet — e.g. a freshly-created
  agent-initiated conversation). The excerpt is what the standalone
  history dropdown's per-row label reads (`audit_api_extensions.md`
  §"GET /v1/chat/conversations"); without it every row falls through to
  the UI's `(untitled conversation)` placeholder (F007 from MR !93
  fix-pass-2 GAN).

  Returns `[]` (never raises) on empty filters or empty result.
  """
  @spec list_conversations(map()) :: [{ChatConversation.t(), String.t() | nil}]
  def list_conversations(filter) when is_map(filter) do
    include_archived? = Map.get(filter, :include_archived, false)
    include_deleted? = Map.get(filter, :include_deleted, false)
    limit = Map.get(filter, :limit, 50)

    # Single SQL round-trip: LEFT JOIN LATERAL the most-recent user message
    # for each conversation. We preserve the existing per-tenant +
    # per-principal scoping; the LATERAL subquery is bounded by
    # `LIMIT 1 ORDER BY sequence DESC` so even a long-running conversation
    # doesn't fan out the row count.
    user_msg_subq =
      from(m in ChatMessage,
        where:
          m.conversation_id == parent_as(:conv).id and
            m.role == ^:user and
            is_nil(m.deleted_at),
        order_by: [desc: m.sequence],
        limit: 1,
        select: m.content
      )

    ChatConversation
    |> from(as: :conv)
    |> apply_deleted_filter(include_deleted?)
    |> apply_archived_filter(include_archived?)
    |> filter_eq(:tenant_id, Map.get(filter, :tenant_id))
    |> filter_eq(:principal_subject, Map.get(filter, :principal_subject))
    |> order_by([conv: c], desc: c.last_message_at)
    |> limit(^limit)
    |> select([conv: c], {c, subquery(user_msg_subq)})
    |> Repo.all()
    |> Enum.map(fn {conv, content} -> {conv, excerpt_of(content)} end)
  end

  # Truncate a user-message body to the contract's excerpt shape.
  # `nil` (no user message in the conversation yet) round-trips as `nil`
  # so the UI can still show a sensible fallback (e.g. formatted started_at).
  defp excerpt_of(nil), do: nil

  defp excerpt_of(content) when is_binary(content) do
    case String.replace(content, ~r/\s+/u, " ") |> String.trim() do
      "" ->
        nil

      flat ->
        if String.length(flat) <= @excerpt_max_chars do
          flat
        else
          String.slice(flat, 0, @excerpt_max_chars - 1) <> "…"
        end
    end
  end

  @doc """
  Soft-archive a conversation. Idempotent; returns
  `{:error, :already_archived}` if `archived_at` is already set.

  Hard-delete happens 90 days later via the retention purge worker
  (D7 / `retention_lifecycle.md`).
  """
  @spec archive_conversation(String.t()) ::
          {:ok, ChatConversation.t()} | {:error, :not_found | :already_archived}
  def archive_conversation(conversation_id) when is_binary(conversation_id) do
    Repo.transact(fn ->
      with {:ok, conv} <- fetch_live_conversation(conversation_id, include_archived: true) do
        do_archive(conv)
      end
    end)
  end

  defp do_archive(%ChatConversation{archived_at: nil} = conv) do
    conv
    |> ChatConversation.changeset(%{"archived_at" => DateTime.utc_now()})
    |> Repo.update()
  end

  defp do_archive(%ChatConversation{}), do: {:error, :already_archived}

  # ---------------------------------------------------------------------------
  # Internal helpers
  # ---------------------------------------------------------------------------

  defp fetch_new_conversation_keys(attrs) do
    tenant_id = attrs[:tenant_id] || attrs["tenant_id"]
    principal_subject = attrs[:principal_subject] || attrs["principal_subject"]

    case {tenant_id, principal_subject} do
      {t, p} when is_binary(t) and is_binary(p) -> {:ok, t, p}
      _ -> {:error, :missing_conversation_keys}
    end
  end

  defp fetch_live_conversation(conversation_id, opts \\ []) do
    include_archived? = Keyword.get(opts, :include_archived, false)

    query =
      ChatConversation
      |> where([c], c.id == ^conversation_id)
      |> apply_deleted_filter(false)
      |> apply_archived_filter(include_archived?)

    case safe_one(query) do
      nil -> {:error, :conversation_not_found}
      conv -> {:ok, conv}
    end
  end

  defp insert_message_with_sequence(conv, attrs, starting_seq, attempt \\ 0) do
    cs_attrs =
      attrs
      |> stringify_atom_keys_shallow()
      |> Map.put("conversation_id", conv.id)
      |> Map.put("sequence", starting_seq)

    case %ChatMessage{} |> ChatMessage.changeset(cs_attrs) |> Repo.insert() do
      {:ok, msg} ->
        {:ok, msg}

      {:error, %Ecto.Changeset{errors: errors} = cs} ->
        if sequence_collision?(errors) and attempt < @max_sequence_retries do
          insert_message_with_sequence(conv, attrs, starting_seq + 1, attempt + 1)
        else
          {:error, cs}
        end
    end
  end

  defp sequence_collision?(errors) do
    Enum.any?(errors, fn
      {:sequence, {_msg, opts}} -> opts[:constraint] == :unique
      {[:conversation_id, :sequence], _} -> true
      _ -> false
    end)
  end

  defp next_sequence(conversation_id) do
    query =
      from(m in ChatMessage,
        where: m.conversation_id == ^conversation_id,
        select: max(m.sequence)
      )

    case Repo.one(query) do
      nil -> 1
      n when is_integer(n) -> n + 1
    end
  end

  defp bump_last_message_at(%ChatConversation{} = conv) do
    conv
    |> ChatConversation.changeset(%{"last_message_at" => DateTime.utc_now()})
    |> Repo.update()
  end

  defp list_messages(conversation_id, limit, sequence_gt) do
    base =
      from(m in ChatMessage,
        where: m.conversation_id == ^conversation_id and is_nil(m.deleted_at),
        order_by: [asc: m.sequence],
        limit: ^limit
      )

    case sequence_gt do
      nil -> Repo.all(base)
      seq when is_integer(seq) -> Repo.all(from(m in base, where: m.sequence > ^seq))
    end
  end

  defp apply_deleted_filter(query, true), do: query
  defp apply_deleted_filter(query, false), do: where(query, [c], is_nil(c.deleted_at))

  defp apply_archived_filter(query, true), do: query
  defp apply_archived_filter(query, false), do: where(query, [c], is_nil(c.archived_at))

  defp apply_scope(query, _field, nil), do: query

  defp apply_scope(query, :tenant_id, tid) when is_binary(tid),
    do: where(query, [c], c.tenant_id == ^tid)

  defp apply_scope(query, :principal_subject, sub) when is_binary(sub),
    do: where(query, [c], c.principal_subject == ^sub)

  defp filter_eq(query, _field, nil), do: query
  defp filter_eq(query, :tenant_id, v), do: where(query, [c], c.tenant_id == ^v)

  defp filter_eq(query, :principal_subject, v),
    do: where(query, [c], c.principal_subject == ^v)

  defp safe_one(query) do
    Repo.one(query)
  rescue
    Ecto.Query.CastError -> nil
  end

  defp stringify_atom_keys_shallow(map) when is_map(map) do
    Map.new(map, fn
      {k, v} when is_atom(k) -> {Atom.to_string(k), v}
      {k, v} -> {k, v}
    end)
  end
end
