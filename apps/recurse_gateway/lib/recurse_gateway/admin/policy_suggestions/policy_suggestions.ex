defmodule Recurse.Gateway.Admin.PolicySuggestions do
  @moduledoc """
  Admin context for the `policy_suggestions` table — F004 T125.

  Public CRUD + lifecycle API for auto-generated policy suggestions
  (heuristic + LLM sources). Talks directly to `Recurse.Providers.Repo`,
  NOT through `LedgerProvider` — same AD-001 c' compliance pattern as
  `Recurse.Gateway.Admin.PolicyDrafts` (T085).

  Cross-references:
    * `specs/004-audit-console/data-model.md` §1.2 (PolicySuggestion schema +
      lifecycle: `:active → :adopted_as_draft | :dismissed`).
    * `specs/004-audit-console/data-model.md` §3.2 (public-API signatures).
    * `specs/004-audit-console/contracts/audit_api_extensions.md`
      §"Policy suggestions" (HTTP-side surface served by
      `PolicySuggestionsHandler`, T134).

  ## Iron Law check (`elixir:elixir-thinking`)

    1. Mutable state across calls? No — Repo is the only state.
    2. Concurrent execution? No — runs synchronously on the request
       process; concurrent adopters race through `Repo.transact/1` which
       gives us the SQL-level serialization we need (single-row UPDATE).
    3. Fault isolation? No — failures bubble through `{:ok, _} | {:error, _}`.

  All three NO → plain functions. No GenServer.

  ## Anti-pattern guards (`elixir:elixir-antipatterns`)

    * No `_ -> nil` catch-all on `Repo.get/2` — every miss is explicit
      `{:error, :not_found}`.
    * No primitive obsession on lifecycle: `dismiss/2` and `adopt/2` enforce
      the state machine, not the caller.
    * No bypassing changesets — every write goes through
      `PolicySuggestion.changeset/2`.
    * No bare `Ecto.Multi` for the two-row adopt pipeline — we use
      `Repo.transact/1` (Ecto 3.12+) since neither row branches on the
      other's intermediate result; the transactional semantic is the only
      thing we need.

  ## Lifecycle transitions

  Per `data-model.md` §1.2:

      :active ──→ :adopted_as_draft   (operator clicks "Adopt as draft")
      :active ──→ :dismissed          (operator clicks dismiss)

  No transition out of `:adopted_as_draft` or `:dismissed`. The
  application-layer guards in `dismiss/2` and `adopt/2` reject
  illegal transitions with `{:error, :already_dismissed | :already_adopted}`.

  ## Manual refresh rate-limiting (FR-030a, Q5)

  `refresh/1` is rate-limited per-tenant via the F002 RateLimit Backend
  (Hammer ETS). The cap is 6 invocations/hour/tenant; the 7th call in a
  rolling 1-hour window returns `{:error, :rate_limited}`. The
  PolicySuggestionsHandler maps this to HTTP 429 + `Retry-After` per
  `audit_api_extensions.md` §"POST /v1/policy/suggestions/refresh".
  """

  import Ecto.Query

  alias Recurse.Gateway.Admin.PolicyDrafts
  alias Recurse.Gateway.Admin.PolicyDrafts.PolicyDraft
  alias Recurse.Gateway.Admin.PolicySuggestions.PolicySuggestion
  alias Recurse.Gateway.Admin.PolicySuggestions.PolicySuggestionRun
  alias Recurse.Providers.Repo

  @typedoc "Filter map accepted by `list/1`."
  @type list_filter :: %{
          optional(:tenant_id) => String.t(),
          optional(:status) => :active | :adopted_as_draft | :dismissed,
          optional(:source) => :heuristic | :llm,
          optional(:generation_run_id) => String.t(),
          optional(:limit) => pos_integer(),
          optional(:cursor) => String.t() | nil,
          optional(:include_deleted) => boolean()
        }

  # Rate-limit defaults per FR-030a / Q5: 6 calls / 1-hour rolling
  # window per tenant. Overridable via the `:console_refresh_rate_limit`
  # application env so the test suite (and operator deployments) can
  # adjust without code edits.
  @default_refresh_limit 6
  @default_refresh_scale_ms 3_600_000
  @rate_limit_key_prefix "ratelimit:console_refresh:"

  @doc """
  Create a fresh suggestion. `tenant_id` is the deployment tenant; attrs
  carries the engine-supplied source / pattern / Cedar / confidence
  payload. Status defaults to `:active`.
  """
  @spec create(String.t(), map()) ::
          {:ok, PolicySuggestion.t()} | {:error, Ecto.Changeset.t()}
  def create(tenant_id, attrs) when is_binary(tenant_id) and is_map(attrs) do
    attrs_with_tenant =
      attrs
      |> stringify_atom_keys_shallow()
      |> Map.put("tenant_id", tenant_id)
      |> Map.put_new("status", :active)

    %PolicySuggestion{}
    |> PolicySuggestion.changeset(attrs_with_tenant)
    |> Repo.insert()
  end

  @doc """
  Fetch a suggestion by ID. Soft-deleted rows return `:not_found`
  unless `:include_deleted` is set.

  Options:
    * `:include_deleted` — boolean (default false). Bypass soft-delete filter.
    * `:tenant_scope` — string. If set, `{:error, :not_found}` is returned
      when the row's `tenant_id` does not match (mirrors PolicyDrafts.get/2;
      cross-tenant access leaks nothing about existence).
  """
  @spec get(String.t(), keyword()) ::
          {:ok, PolicySuggestion.t()} | {:error, :not_found}
  def get(suggestion_id, opts \\ []) when is_binary(suggestion_id) do
    include_deleted? = Keyword.get(opts, :include_deleted, false)
    tenant_scope = Keyword.get(opts, :tenant_scope)

    query =
      PolicySuggestion
      |> where([s], s.id == ^suggestion_id)
      |> apply_deleted_filter(include_deleted?)
      |> apply_tenant_scope(tenant_scope)

    case safe_one(query) do
      nil -> {:error, :not_found}
      %PolicySuggestion{} = suggestion -> {:ok, suggestion}
    end
  end

  @doc """
  List suggestions matching `filter`. Returns rows ordered by
  `generated_at DESC`. Soft-deleted rows are excluded by default.
  """
  @spec list(list_filter()) :: [PolicySuggestion.t()]
  def list(filter) when is_map(filter) do
    include_deleted? = Map.get(filter, :include_deleted, false)
    limit = Map.get(filter, :limit, 50)

    PolicySuggestion
    |> apply_deleted_filter(include_deleted?)
    |> filter_tenant(Map.get(filter, :tenant_id))
    |> filter_status(Map.get(filter, :status))
    |> filter_source(Map.get(filter, :source))
    |> filter_generation_run(Map.get(filter, :generation_run_id))
    |> order_by([s], desc: s.generated_at)
    |> limit(^limit)
    |> Repo.all()
  end

  @doc """
  Dismiss a suggestion (operator action). Sets `dismissed_by` +
  `dismissed_at` and flips `status = :dismissed`. Idempotent against
  already-dismissed suggestions (`{:error, :already_dismissed}`); rejects
  the transition for `:adopted_as_draft` rows (`{:error, :already_adopted}`).

  Tenant-scoped: cross-tenant `suggestion_id` returns `{:error, :not_found}`
  (defense-in-depth per FR-006; SQL-level guard via the `:tenant_scope`
  option on `get/2`).
  """
  @spec dismiss(String.t(), String.t(), String.t()) ::
          {:ok, PolicySuggestion.t()}
          | {:error, :not_found | :already_dismissed | :already_adopted | Ecto.Changeset.t()}
  def dismiss(suggestion_id, tenant_id, dismissed_by)
      when is_binary(suggestion_id) and is_binary(tenant_id) and is_binary(dismissed_by) do
    Repo.transact(fn ->
      with {:ok, suggestion} <- get(suggestion_id, tenant_scope: tenant_id) do
        do_dismiss(suggestion, dismissed_by)
      end
    end)
  end

  defp do_dismiss(%PolicySuggestion{status: :dismissed}, _dismissed_by),
    do: {:error, :already_dismissed}

  defp do_dismiss(%PolicySuggestion{status: :adopted_as_draft}, _dismissed_by),
    do: {:error, :already_adopted}

  defp do_dismiss(%PolicySuggestion{} = suggestion, dismissed_by) do
    suggestion
    |> PolicySuggestion.changeset(%{
      "status" => :dismissed,
      "dismissed_by" => dismissed_by,
      "dismissed_at" => DateTime.utc_now()
    })
    |> Repo.update()
  end

  @doc """
  Atomic two-row write: seeds a new `policy_drafts` row with the
  suggestion's `proposed_cedar` AND flips the suggestion's status to
  `:adopted_as_draft` with `adopted_as_draft_id` populated.

  Wrapped in `Repo.transact/1` so a downstream failure (draft validation,
  unique violation) rolls back BOTH writes.

  Idempotent against already-adopted (`{:error, :already_adopted}`) and
  rejects dismissed suggestions (`{:error, :already_dismissed}`).

  ## Tenant scoping

  Cross-tenant `suggestion_id` returns `{:error, :not_found}` (mirrors
  `dismiss/3`; SQL-level guard via `:tenant_scope` on `get/2`). The new
  draft created by `do_adopt/2` inherits the suggestion's `tenant_id`,
  so adoption never crosses a tenant boundary even on the write side.
  """
  @spec adopt(String.t(), String.t(), String.t()) ::
          {:ok, {PolicySuggestion.t(), PolicyDraft.t()}}
          | {:error, :not_found | :already_adopted | :already_dismissed | Ecto.Changeset.t()}
  def adopt(suggestion_id, tenant_id, author_principal_subject)
      when is_binary(suggestion_id) and is_binary(tenant_id) and
             is_binary(author_principal_subject) do
    Repo.transact(fn ->
      with {:ok, suggestion} <- get(suggestion_id, tenant_scope: tenant_id) do
        do_adopt(suggestion, author_principal_subject)
      end
    end)
  end

  defp do_adopt(%PolicySuggestion{status: :adopted_as_draft}, _author),
    do: {:error, :already_adopted}

  defp do_adopt(%PolicySuggestion{status: :dismissed}, _author),
    do: {:error, :already_dismissed}

  defp do_adopt(%PolicySuggestion{} = suggestion, author_principal_subject) do
    draft_attrs = %{
      "cedar_source" => suggestion.proposed_cedar,
      "scope_metadata" => %{"scope_kind" => "tenant", "scope_value" => suggestion.tenant_id},
      "condition_metadata" => [],
      "author_principal_subject" => author_principal_subject,
      "status" => :draft
    }

    with {:ok, %PolicyDraft{} = draft} <- PolicyDrafts.create(suggestion.tenant_id, draft_attrs),
         {:ok, updated_suggestion} <- mark_adopted(suggestion, draft.id) do
      {:ok, {updated_suggestion, draft}}
    end
  end

  defp mark_adopted(%PolicySuggestion{} = suggestion, draft_id) do
    suggestion
    |> PolicySuggestion.changeset(%{
      "status" => :adopted_as_draft,
      "adopted_as_draft_id" => draft_id
    })
    |> Repo.update()
  end

  @doc """
  Trigger a manual refresh of the suggestion engines outside the
  regular cron cadence. Rate-limited per FR-030a (default 6/hour/tenant).

  Returns `{:ok, %PolicySuggestionRun{}}` carrying the queued run row;
  the caller (PolicySuggestionsHandler T134) is responsible for
  enqueueing the actual heuristic + LLM Oban jobs against it.

  Returns `{:error, :rate_limited}` past the per-tenant cap.

  Caller passes the requesting principal's subject so the run row
  carries `requested_by_principal_subject` for the operator-visible job
  log (FR-030a traceability).
  """
  @spec refresh(String.t(), String.t(), keyword()) ::
          {:ok, PolicySuggestionRun.t()} | {:error, :rate_limited | Ecto.Changeset.t()}
  def refresh(tenant_id, requested_by, opts \\ [])
      when is_binary(tenant_id) and is_binary(requested_by) do
    case check_refresh_rate(tenant_id, opts) do
      :ok -> create_refresh_run(tenant_id, requested_by, opts)
      {:error, :rate_limited} = err -> err
    end
  end

  # Hit the per-tenant Hammer bucket. The backend module is configurable
  # to keep the rate-limit pluggable (tests can swap in a stub backend).
  defp check_refresh_rate(tenant_id, opts) do
    backend = Keyword.get(opts, :backend, default_backend())
    limit = Keyword.get(opts, :limit, refresh_limit())
    scale_ms = Keyword.get(opts, :scale_ms, refresh_scale_ms())

    if is_nil(backend) do
      # No backend installed — the rate limit is effectively disabled
      # (test ergonomics: `:rate_limit_enabled?` defaults to `false`).
      :ok
    else
      case backend.hit(@rate_limit_key_prefix <> tenant_id, scale_ms, limit, 1) do
        {:allow, _count} -> :ok
        {:deny, _retry_after_ms} -> {:error, :rate_limited}
      end
    end
  end

  defp create_refresh_run(tenant_id, requested_by, opts) do
    source = Keyword.get(opts, :source, :heuristic)
    now = DateTime.utc_now()

    attrs = %{
      tenant_id: tenant_id,
      source: source,
      requested_by_principal_subject: requested_by,
      scheduled_at: now
    }

    %PolicySuggestionRun{}
    |> PolicySuggestionRun.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Configure-able default backend. Returns nil if rate limiting is not
  enabled in the application env (test default), so refresh proceeds
  uncapped during unit tests.
  """
  @spec default_backend() :: module() | nil
  def default_backend do
    if Application.get_env(:recurse_gateway, :rate_limit_enabled?, false) do
      Recurse.Gateway.RateLimit.Backend
    else
      nil
    end
  end

  @doc """
  Effective per-tenant limit for refresh calls (default 6/hour). Override
  via `:console_refresh_rate_limit` keyword in app env.
  """
  @spec refresh_limit() :: pos_integer()
  def refresh_limit do
    Application.get_env(:recurse_gateway, :console_refresh_rate_limit, [])
    |> Keyword.get(:limit, @default_refresh_limit)
  end

  @doc """
  Effective rolling-window size in ms (default 3_600_000 = 1 hour).
  """
  @spec refresh_scale_ms() :: pos_integer()
  def refresh_scale_ms do
    Application.get_env(:recurse_gateway, :console_refresh_rate_limit, [])
    |> Keyword.get(:scale_ms, @default_refresh_scale_ms)
  end

  # ---------------------------------------------------------------------------
  # Job-log helpers — used by HeuristicRunner / LlmRunner workers
  # ---------------------------------------------------------------------------

  @doc """
  Insert a fresh job-log row for a suggestion-engine run. Used by both
  the cron-scheduled and manual-refresh paths.
  """
  @spec start_run(map()) ::
          {:ok, PolicySuggestionRun.t()} | {:error, Ecto.Changeset.t()}
  def start_run(attrs) when is_map(attrs) do
    %PolicySuggestionRun{}
    |> PolicySuggestionRun.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Update a run row mid-flight. Common patterns:

    * `update_run(run, %{started_at: now})` — transition queued → running.
    * `update_run(run, %{completed_at: now, suggestions_generated_count: n})`
      — transition running → completed-ok.
    * `update_run(run, %{completed_at: now, error: msg})` — failed.
  """
  @spec update_run(PolicySuggestionRun.t(), map()) ::
          {:ok, PolicySuggestionRun.t()} | {:error, Ecto.Changeset.t()}
  def update_run(%PolicySuggestionRun{} = run, attrs) when is_map(attrs) do
    run
    |> PolicySuggestionRun.changeset(stringify_atom_keys_shallow(attrs))
    |> Repo.update()
  end

  @doc """
  Fetch a run row by ID — used by the operator job-log view + the
  manual-refresh handler to return the run row to the SPA.
  """
  @spec get_run(String.t()) ::
          {:ok, PolicySuggestionRun.t()} | {:error, :not_found}
  def get_run(run_id) when is_binary(run_id) do
    case safe_one(where(PolicySuggestionRun, [r], r.id == ^run_id)) do
      nil -> {:error, :not_found}
      %PolicySuggestionRun{} = run -> {:ok, run}
    end
  end

  # ---------------------------------------------------------------------------
  # Filter helpers
  # ---------------------------------------------------------------------------

  defp apply_deleted_filter(query, true), do: query
  defp apply_deleted_filter(query, false), do: where(query, [s], is_nil(s.deleted_at))

  defp apply_tenant_scope(query, nil), do: query

  defp apply_tenant_scope(query, tid) when is_binary(tid),
    do: where(query, [s], s.tenant_id == ^tid)

  defp filter_tenant(query, nil), do: query
  defp filter_tenant(query, tid), do: where(query, [s], s.tenant_id == ^tid)

  defp filter_status(query, nil), do: query
  defp filter_status(query, status), do: where(query, [s], s.status == ^status)

  defp filter_source(query, nil), do: query
  defp filter_source(query, source), do: where(query, [s], s.source == ^source)

  defp filter_generation_run(query, nil), do: query

  defp filter_generation_run(query, run_id),
    do: where(query, [s], s.generation_run_id == ^run_id)

  # ---------------------------------------------------------------------------
  # Misc
  # ---------------------------------------------------------------------------

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
