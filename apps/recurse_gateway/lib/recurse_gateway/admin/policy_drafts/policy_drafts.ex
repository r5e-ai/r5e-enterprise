defmodule Recurse.Gateway.Admin.PolicyDrafts do
  @moduledoc """
  Admin context for the `policy_drafts` table — F004 T085.

  Public CRUD + lifecycle API for operator-authored Cedar drafts. Talks
  directly to `Recurse.Providers.Repo` (the F002 Postgres Repo), NOT
  through the `LedgerProvider` behaviour. This is the load-bearing
  AD-001 c' compliance: UI state is owned by the Gateway admin context;
  the cryptographic ledger impl gets no new public methods.

  Cross-references:
    * `specs/004-audit-console/data-model.md` §1.1 (PolicyDraft schema +
      lifecycle: `:draft → :draft | :adopted_as_draft | :archived`).
    * `specs/004-audit-console/data-model.md` §3.1 (public-API signatures).
    * `specs/004-audit-console/contracts/blast_radius_algorithm.md` §7
      (cache-invalidation hook fired from `update/3`).
    * `specs/004-audit-console/contracts/audit_api_extensions.md`
      §"Policy drafts" (HTTP-side surface served by
      `PolicyDraftsHandler`).

  ## Iron Law check (`elixir:elixir-thinking`)

    1. Mutable state across calls? No — every call is a pure function of
       its arguments + the Repo state. The cache invalidation in
       `update/3` is a single SQL `UPDATE`, not in-memory state.
    2. Concurrent execution? No — runs synchronously on the request
       process. Repo calls handle their own concurrency (connection pool).
    3. Fault isolation? No — failures bubble through `{:ok, _} | {:error, _}`
       tuples; nothing rescued.

  All three NO → plain functions. No GenServer.

  ## Anti-pattern guards (`elixir:elixir-antipatterns`)

    * No `_ -> nil` catch-all on `Repo.get/2` results — every miss is
      explicit `{:error, :not_found}`.
    * No primitive obsession on lifecycle transitions: `update/3`
      enforces the state machine documented in §1.1, not the call site.
    * No bypassing the changeset by hand-writing `Repo.update/2`
      attribute maps — every write goes through `PolicyDraft.changeset/2`.

  ## Lifecycle transitions

  Per `data-model.md` §1.1, the only legal transitions are:

      :draft           → :draft              (edit)
      :draft           → :adopted_as_draft   (suggestion-driven; via
                                              PolicySuggestions.adopt/2,
                                              not via this module's update)
      :draft           → :archived           (operator dismiss / retention)
      :adopted_as_draft → :archived          (operator-initiated)

  No transition out of `:archived`. The `update/3` function rejects
  illegal transitions with `{:error, %Ecto.Changeset{}}` carrying a
  `status: "invalid transition from X to Y"` error.
  """

  import Ecto.Query

  alias Ecto.Changeset
  alias Recurse.Gateway.Admin.PolicyDrafts.PolicyDraft
  alias Recurse.Providers.Repo

  @cache_invalidating_fields ~w(cedar_source scope_metadata condition_metadata)a

  @typedoc "Filter map accepted by `list/1`."
  @type list_filter :: %{
          optional(:tenant_id) => String.t(),
          optional(:status) => :draft | :adopted_as_draft | :archived,
          optional(:author_principal_subject) => String.t(),
          optional(:source_receipt_run_id) => String.t() | nil,
          optional(:inserted_at_before) => DateTime.t(),
          optional(:inserted_at_after) => DateTime.t(),
          optional(:limit) => pos_integer(),
          optional(:cursor) => String.t() | nil,
          optional(:include_deleted) => boolean()
        }

  @doc """
  Create a new draft. The `tenant_id` is the caller's authenticated tenant
  (Phase-1 single-tenant per BEAM); attrs carries the operator-supplied
  Cedar source + scope/condition metadata + optional `:source_receipt_run_id`
  back-link.

  Status defaults to `:draft`. Author principal subject is mandatory in attrs.
  """
  @spec create(String.t(), map()) ::
          {:ok, PolicyDraft.t()} | {:error, Ecto.Changeset.t()}
  def create(tenant_id, attrs) when is_binary(tenant_id) and is_map(attrs) do
    attrs_with_tenant =
      attrs
      |> stringify_atom_keys_shallow()
      |> Map.put("tenant_id", tenant_id)
      |> Map.put_new("status", :draft)

    %PolicyDraft{}
    |> PolicyDraft.changeset(attrs_with_tenant)
    |> Repo.insert()
  end

  @doc """
  Fetch a draft by ID. Returns `{:error, :not_found}` if the row is
  missing or soft-deleted (unless `:include_archived` / `:include_deleted`
  is set in `opts`).

  Options:
    * `:include_archived` — boolean (default false). If false, archived
      drafts are returned as `:not_found`.
    * `:include_deleted` — boolean (default false). Bypass soft-delete filter.
    * `:tenant_scope` — string. If set, `{:error, :not_found}` is returned
      when the row's `tenant_id` does not match.
  """
  @spec get(String.t(), keyword()) :: {:ok, PolicyDraft.t()} | {:error, :not_found}
  def get(draft_id, opts \\ []) when is_binary(draft_id) do
    include_archived? = Keyword.get(opts, :include_archived, false)
    include_deleted? = Keyword.get(opts, :include_deleted, false)
    tenant_scope = Keyword.get(opts, :tenant_scope)

    query =
      PolicyDraft
      |> where([d], d.id == ^draft_id)
      |> apply_deleted_filter(include_deleted?)
      |> apply_archived_filter(include_archived?)
      |> apply_tenant_scope(tenant_scope)

    case safe_one(query) do
      nil -> {:error, :not_found}
      %PolicyDraft{} = draft -> {:ok, draft}
    end
  end

  @doc """
  List drafts matching `filter`. Returns rows ordered by `inserted_at DESC`.
  Soft-deleted rows are excluded by default.

  Supported filter keys: see `t:list_filter/0`.
  """
  @spec list(list_filter()) :: [PolicyDraft.t()]
  def list(filter) when is_map(filter) do
    include_deleted? = Map.get(filter, :include_deleted, false)
    limit = Map.get(filter, :limit, 50)

    PolicyDraft
    |> apply_deleted_filter(include_deleted?)
    |> filter_tenant(Map.get(filter, :tenant_id))
    |> filter_status(Map.get(filter, :status))
    |> filter_author(Map.get(filter, :author_principal_subject))
    |> filter_source_receipt(Map.get(filter, :source_receipt_run_id))
    |> filter_inserted_before(Map.get(filter, :inserted_at_before))
    |> filter_inserted_after(Map.get(filter, :inserted_at_after))
    |> order_by([d], desc: d.inserted_at)
    |> limit(^limit)
    |> Repo.all()
  end

  @doc """
  Edit a draft's body / scope / conditions / status.

  Lifecycle is enforced inline: only the transitions documented in
  `data-model.md` §1.1 succeed; everything else returns
  `{:error, %Ecto.Changeset{}}`.

  ## Tenant scoping (defense-in-depth)

  Per FR-006 + Constitution Principle V, the row is fetched with a
  `tenant_id` predicate enforced in the SQL `WHERE` clause; cross-tenant
  IDs return `{:error, :not_found}` (NOT `{:error, :forbidden}`) so we
  leak nothing about the existence of the resource. Mirrors the
  `:tenant_scope` option already enforced on `get/2`.

  ## Cache invalidation (per blast_radius_algorithm.md §7)

  When `:cedar_source`, `:scope_metadata`, or `:condition_metadata` change,
  `last_blast_radius_summary` and `last_blast_radius_at` are cleared in
  the same transaction so the next dry-run recomputes against the new shape.
  """
  @spec update(String.t(), String.t(), map(), String.t()) ::
          {:ok, PolicyDraft.t()} | {:error, Ecto.Changeset.t() | :not_found}
  def update(draft_id, tenant_id, attrs, _actor)
      when is_binary(draft_id) and is_binary(tenant_id) and is_map(attrs) do
    Repo.transact(fn ->
      with {:ok, draft} <-
             get(draft_id, include_archived: true, tenant_scope: tenant_id),
           :ok <- check_lifecycle_transition(draft, attrs) do
        do_update(draft, attrs)
      end
    end)
  end

  defp do_update(%PolicyDraft{} = draft, attrs) do
    sanitized = stringify_atom_keys_shallow(attrs)
    changeset = PolicyDraft.changeset(draft, sanitized)

    changeset =
      if cache_invalidating_change?(changeset) do
        # Per §7: clear cached blast-radius summary on cedar_source/scope/condition change.
        changeset
        |> Changeset.put_change(:last_blast_radius_summary, nil)
        |> Changeset.put_change(:last_blast_radius_at, nil)
      else
        changeset
      end

    Repo.update(changeset)
  end

  @doc """
  Archive a draft (soft transition `status → :archived`; sets `archived_at`).
  Idempotent for already-archived rows (returns `{:error, :already_archived}`).

  Tenant-scoped: cross-tenant `draft_id` returns `{:error, :not_found}`
  (defense-in-depth per FR-006; SQL-level guard mirrors `update/4`).
  """
  @spec archive(String.t(), String.t(), String.t()) ::
          {:ok, PolicyDraft.t()} | {:error, :not_found | :already_archived}
  def archive(draft_id, tenant_id, _actor)
      when is_binary(draft_id) and is_binary(tenant_id) do
    Repo.transact(fn ->
      with {:ok, draft} <-
             get(draft_id, include_archived: true, tenant_scope: tenant_id) do
        do_archive(draft)
      end
    end)
  end

  defp do_archive(%PolicyDraft{status: :archived}), do: {:error, :already_archived}

  defp do_archive(%PolicyDraft{} = draft) do
    draft
    |> PolicyDraft.changeset(%{
      "status" => :archived,
      "archived_at" => DateTime.utc_now()
    })
    |> Repo.update()
  end

  @doc """
  Compute (or fetch cached) Blast Radius summary for a draft. Delegates
  to `Recurse.Gateway.Admin.BlastRadius.compute/1` for the streaming
  algorithm; persists the result on `policy_drafts.last_blast_radius_summary`
  on success.

  Options forwarded to `BlastRadius.compute/1`: `:window`, `:sample_size`,
  `:force` (bypass cache).
  """
  @spec dry_run(String.t(), String.t(), keyword()) ::
          {:ok, map()} | {:error, term()}
  def dry_run(draft_id, _actor, opts \\ []) when is_binary(draft_id) do
    with {:ok, draft} <- get(draft_id, include_archived: true) do
      input = build_blast_radius_input(draft, opts)
      Recurse.Gateway.Admin.BlastRadius.compute(input)
    end
  end

  @doc """
  Persist a freshly-computed Blast Radius summary onto the draft row.
  Called from `BlastRadius.compute/1` (sync) and the AsyncEscalation
  Oban worker (>10K). Always succeeds (no lifecycle check); idempotent.
  """
  @spec persist_blast_radius_summary(String.t(), map()) ::
          {:ok, PolicyDraft.t()} | {:error, :not_found | Ecto.Changeset.t()}
  def persist_blast_radius_summary(draft_id, summary)
      when is_binary(draft_id) and is_map(summary) do
    with {:ok, draft} <- get(draft_id, include_archived: true) do
      draft
      |> PolicyDraft.changeset(%{
        "last_blast_radius_summary" => summary,
        "last_blast_radius_at" => DateTime.utc_now()
      })
      |> Repo.update()
    end
  end

  # ---------------------------------------------------------------------------
  # Lifecycle enforcement
  # ---------------------------------------------------------------------------

  # No status change requested → always allowed (regular field edits).
  defp check_lifecycle_transition(_draft, attrs)
       when not is_map_key(attrs, :status) and
              not is_map_key(attrs, "status"),
       do: :ok

  defp check_lifecycle_transition(%PolicyDraft{status: current}, attrs) do
    requested = attrs[:status] || attrs["status"]

    case {current, requested} do
      # Same status — always OK (no-op).
      {same, same} ->
        :ok

      # :draft → :draft | :archived (suggestion adoption is via PolicySuggestions.adopt/2,
      # not via this module's update/3, so :adopted_as_draft is intentionally rejected here).
      {:draft, :archived} ->
        :ok

      # :adopted_as_draft → :archived (operator-initiated)
      {:adopted_as_draft, :archived} ->
        :ok

      # Anything else is an illegal transition.
      {from, to} ->
        message = "invalid transition from #{inspect(from)} to #{inspect(to)}"

        changeset = %Changeset{
          data: %PolicyDraft{},
          errors: [status: {message, []}],
          valid?: false,
          types: %{status: {:parameterized, Ecto.Enum, %{}}}
        }

        {:error, changeset}
    end
  end

  # ---------------------------------------------------------------------------
  # Filter helpers
  # ---------------------------------------------------------------------------

  defp apply_deleted_filter(query, true), do: query
  defp apply_deleted_filter(query, false), do: where(query, [d], is_nil(d.deleted_at))

  defp apply_archived_filter(query, true), do: query

  defp apply_archived_filter(query, false),
    do: where(query, [d], d.status != ^:archived)

  defp apply_tenant_scope(query, nil), do: query

  defp apply_tenant_scope(query, tid) when is_binary(tid),
    do: where(query, [d], d.tenant_id == ^tid)

  defp filter_tenant(query, nil), do: query
  defp filter_tenant(query, tid), do: where(query, [d], d.tenant_id == ^tid)

  defp filter_status(query, nil), do: query
  defp filter_status(query, status), do: where(query, [d], d.status == ^status)

  defp filter_author(query, nil), do: query

  defp filter_author(query, sub),
    do: where(query, [d], d.author_principal_subject == ^sub)

  defp filter_source_receipt(query, nil), do: query

  defp filter_source_receipt(query, run_id),
    do: where(query, [d], d.source_receipt_run_id == ^run_id)

  defp filter_inserted_before(query, nil), do: query
  defp filter_inserted_before(query, dt), do: where(query, [d], d.inserted_at < ^dt)

  defp filter_inserted_after(query, nil), do: query
  defp filter_inserted_after(query, dt), do: where(query, [d], d.inserted_at > ^dt)

  # ---------------------------------------------------------------------------
  # Cache invalidation
  # ---------------------------------------------------------------------------

  defp cache_invalidating_change?(%Changeset{changes: changes}) do
    Enum.any?(@cache_invalidating_fields, &Map.has_key?(changes, &1))
  end

  # ---------------------------------------------------------------------------
  # Blast Radius input construction
  # ---------------------------------------------------------------------------

  defp build_blast_radius_input(%PolicyDraft{} = draft, opts) do
    window = Keyword.get(opts, :window) || default_window()
    sample_size = Keyword.get(opts, :sample_size, 20)

    %{
      draft_id: draft.id,
      draft_cedar_source: draft.cedar_source,
      tenant_id: draft.tenant_id,
      window: window,
      sample_size: sample_size,
      force: Keyword.get(opts, :force, false),
      cached_summary: draft.last_blast_radius_summary,
      cached_at: draft.last_blast_radius_at
    }
  end

  defp default_window do
    until = DateTime.utc_now()
    since = DateTime.add(until, -30, :day)
    %{since: since, until: until}
  end

  # ---------------------------------------------------------------------------
  # Misc
  # ---------------------------------------------------------------------------

  # `Ecto.UUID` cast errors raise `Ecto.Query.CastError` on get/1 when the
  # path param is not a UUID. Map to nil so external callers don't learn
  # whether the malformed value happened to collide with a real draft.
  defp safe_one(query) do
    Repo.one(query)
  rescue
    Ecto.Query.CastError -> nil
  end

  # Accept either string-keyed or atom-keyed attrs from callers — handlers
  # tend to pass string keys (JSON), tests tend to pass atom keys. Convert
  # top-level keys to strings so the changeset cast/2 cast accepts them
  # uniformly. Nested values (scope_metadata, condition_metadata) are NOT
  # touched — JSONB round-trips both atoms and strings.
  defp stringify_atom_keys_shallow(map) when is_map(map) do
    Map.new(map, fn
      {k, v} when is_atom(k) -> {Atom.to_string(k), v}
      {k, v} -> {k, v}
    end)
  end
end
