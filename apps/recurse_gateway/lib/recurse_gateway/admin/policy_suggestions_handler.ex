defmodule Recurse.Gateway.Admin.PolicySuggestionsHandler do
  @moduledoc """
  HTTP handler for the F004 policy-suggestions surface (T134).

  Per `contracts/audit_api_extensions.md` §"Policy suggestions":

      GET    /v1/policy/suggestions             → list (DashboardQuery / :ui_query)
      GET    /v1/policy/suggestions/{id}        → fetch single (PolicySuggestionView / :ui_policy_suggestion_viewed)
      POST   /v1/policy/suggestions/{id}/adopt  → adopt as draft (PolicySuggestionAdopt / :ui_policy_suggestion_adopted)
      POST   /v1/policy/suggestions/{id}/dismiss → dismiss (PolicySuggestionDismiss / :ui_policy_suggestion_dismissed)
      POST   /v1/policy/suggestions/refresh     → manual refresh (PolicySuggestionRefresh / :ui_policy_suggestion_refresh_requested)

  ## Auth pipeline

  Each request lands here AFTER `BrowserSessionPlug` has lifted the
  cookie envelope into `Authorization: Bearer <jwt>`. We then thread
  through `AuditPlane.Authz.gate/4` for the per-route Cedar action +
  resource — same pattern as `PolicyDraftsHandler`.

  ## Receipt emission

  Every successful (and Cedar-denied — handled inside `gate/4`) request
  emits exactly one canonical `event_kind` per `data-model.md` §0. The
  emission seam is `Recurse.Gateway.Admin.BrowserAuth.UiReceipts.emit/2`.

  ## Manual-refresh rate-limit

  `POST /v1/policy/suggestions/refresh` is rate-limited per FR-030a
  (default 6/hour/tenant). The `PolicySuggestions.refresh/3` context
  function returns `{:error, :rate_limited}` past the cap; we map that
  to HTTP 429 + `Retry-After` per the contract.

  ## Iron Law check (`elixir:phoenix-thinking`)

  Pure module — no GenServer. Runs on the Bandit-spawned request
  process. Every per-route function is a pure dispatch + render +
  receipt-emit chain.

  ## Cross-references

    * `specs/004-audit-console/contracts/audit_api_extensions.md`
      §"Policy suggestions"
    * `specs/004-audit-console/data-model.md` §0 (canonical matrix)
    * `apps/recurse_gateway/lib/recurse_gateway/admin/policy_suggestions/policy_suggestions.ex`
      (T125 — context)
  """

  alias Recurse.Gateway.Admin.BrowserAuth.UiReceipts
  alias Recurse.Gateway.Admin.PolicyDrafts.PolicyDraft
  alias Recurse.Gateway.Admin.PolicySuggestions
  alias Recurse.Gateway.Admin.PolicySuggestions.PolicySuggestion
  alias Recurse.Gateway.Admin.PolicySuggestions.PolicySuggestionRun
  alias Recurse.Gateway.AuditPlane.Authz
  alias Recurse.Shared.IdentityContext

  require Logger

  @action_dashboard_query "Recurse::Action::\"DashboardQuery\""
  @action_view "Recurse::Action::\"PolicySuggestionView\""
  @action_adopt "Recurse::Action::\"PolicySuggestionAdopt\""
  @action_dismiss "Recurse::Action::\"PolicySuggestionDismiss\""
  @action_refresh "Recurse::Action::\"PolicySuggestionRefresh\""

  @default_limit 50
  @max_limit 200

  # ---------------------------------------------------------------------------
  # GET /v1/policy/suggestions — list
  # ---------------------------------------------------------------------------

  @doc "List active suggestions. Cedar `DashboardQuery`; emits `:ui_query`."
  @spec list(Plug.Conn.t()) :: Plug.Conn.t()
  def list(%Plug.Conn{} = conn) do
    resource = %{
      type: "Recurse::Resource::ConsoleSurface",
      id: "policy_suggestions_list",
      attrs: %{"endpoint" => "/v1/policy/suggestions"}
    }

    case Authz.gate(conn, @action_dashboard_query, resource) do
      {:ok, conn_after, ctx, _bundle_ref} -> do_list(conn_after, ctx)
      err -> Authz.dispatch_gate_error(conn, err)
    end
  end

  defp do_list(conn, %IdentityContext{} = ctx) do
    conn = Plug.Conn.fetch_query_params(conn)
    params = parse_list_params(conn.query_params)

    filter = %{
      tenant_id: ctx.tenant_id,
      status: params.status,
      source: params.source,
      limit: params.limit,
      include_deleted: forensic_read_requested?(conn, ctx)
    }

    suggestions = PolicySuggestions.list(filter)

    body =
      JSON.encode!(%{
        "suggestions" => Enum.map(suggestions, &render_excerpt/1),
        "next_cursor" => nil
      })

    conn_after =
      conn
      |> Plug.Conn.put_resp_content_type("application/json")
      |> Plug.Conn.send_resp(200, body)

    emit_query_receipt(ctx, length(suggestions))
    conn_after
  end

  # ---------------------------------------------------------------------------
  # GET /v1/policy/suggestions/{id} — fetch single (operator opens in UI)
  # ---------------------------------------------------------------------------

  @doc "Fetch one suggestion. Cedar `PolicySuggestionView`; emits `:ui_policy_suggestion_viewed`."
  @spec get_one(Plug.Conn.t()) :: Plug.Conn.t()
  def get_one(%Plug.Conn{path_params: %{"id" => suggestion_id}} = conn)
      when is_binary(suggestion_id) do
    resource = %{
      type: "Recurse::Resource::ConsoleSurface",
      id: "policy_suggestions_get",
      attrs: %{"endpoint" => "/v1/policy/suggestions/#{suggestion_id}"}
    }

    case Authz.gate(conn, @action_view, resource) do
      {:ok, conn_after, ctx, _bundle_ref} -> do_get_one(conn_after, ctx, suggestion_id)
      err -> Authz.dispatch_gate_error(conn, err)
    end
  end

  def get_one(%Plug.Conn{} = conn) do
    Authz.send_bad_request(conn, "id path parameter is required")
  end

  defp do_get_one(conn, %IdentityContext{} = ctx, suggestion_id) do
    case PolicySuggestions.get(suggestion_id) do
      {:ok, %PolicySuggestion{tenant_id: tid} = suggestion} when tid == ctx.tenant_id ->
        emit_view_receipt(ctx, suggestion)

        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.send_resp(200, JSON.encode!(render_full(suggestion)))

      {:ok, _wrong_tenant} ->
        Authz.send_not_found(conn, "policy suggestion not found")

      {:error, :not_found} ->
        Authz.send_not_found(conn, "policy suggestion not found")
    end
  end

  # ---------------------------------------------------------------------------
  # POST /v1/policy/suggestions/{id}/adopt — adopt as draft
  # ---------------------------------------------------------------------------

  @doc """
  Adopt a suggestion as a draft. Cedar `PolicySuggestionAdopt`;
  emits `:ui_policy_suggestion_adopted` AND (transitively, via
  PolicyDrafts.create/2 → PolicyDraftsHandler doesn't fire here, the
  context module doesn't emit) we explicitly emit `:ui_policy_draft_created`
  here so the audit trail records BOTH atoms per the canonical matrix.
  """
  @spec adopt(Plug.Conn.t()) :: Plug.Conn.t()
  def adopt(%Plug.Conn{path_params: %{"id" => suggestion_id}} = conn)
      when is_binary(suggestion_id) do
    resource = %{
      type: "Recurse::Resource::ConsoleSurface",
      id: "policy_suggestions_adopt",
      attrs: %{"endpoint" => "/v1/policy/suggestions/#{suggestion_id}/adopt"}
    }

    case Authz.gate(conn, @action_adopt, resource) do
      {:ok, conn_after, ctx, _bundle_ref} -> do_adopt(conn_after, ctx, suggestion_id)
      err -> Authz.dispatch_gate_error(conn, err)
    end
  end

  def adopt(%Plug.Conn{} = conn) do
    Authz.send_bad_request(conn, "id path parameter is required")
  end

  defp do_adopt(conn, %IdentityContext{} = ctx, suggestion_id) do
    actor = principal_subject_from_ctx(ctx)

    case PolicySuggestions.adopt(suggestion_id, ctx.tenant_id, actor) do
      {:ok, {%PolicySuggestion{} = suggestion, %PolicyDraft{} = draft}} ->
        emit_adopted(ctx, suggestion, draft)
        emit_draft_created(ctx, draft)

        body =
          JSON.encode!(%{
            "draft_id" => draft.id,
            "suggestion_id" => suggestion.id
          })

        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.send_resp(201, body)

      {:error, :not_found} ->
        Authz.send_not_found(conn, "policy suggestion not found")

      {:error, :already_adopted} ->
        Authz.send_bad_request(conn, "suggestion already adopted")

      {:error, :already_dismissed} ->
        Authz.send_bad_request(conn, "suggestion already dismissed")

      {:error, %Ecto.Changeset{} = cs} ->
        Authz.send_bad_request(conn, "validation failed: #{inspect(changeset_errors(cs))}")
    end
  end

  # ---------------------------------------------------------------------------
  # POST /v1/policy/suggestions/{id}/dismiss — dismiss
  # ---------------------------------------------------------------------------

  @doc "Dismiss a suggestion. Cedar `PolicySuggestionDismiss`; emits `:ui_policy_suggestion_dismissed`. 204 on success."
  @spec dismiss(Plug.Conn.t()) :: Plug.Conn.t()
  def dismiss(%Plug.Conn{path_params: %{"id" => suggestion_id}} = conn)
      when is_binary(suggestion_id) do
    resource = %{
      type: "Recurse::Resource::ConsoleSurface",
      id: "policy_suggestions_dismiss",
      attrs: %{"endpoint" => "/v1/policy/suggestions/#{suggestion_id}/dismiss"}
    }

    case Authz.gate(conn, @action_dismiss, resource) do
      {:ok, conn_after, ctx, _bundle_ref} -> do_dismiss(conn_after, ctx, suggestion_id)
      err -> Authz.dispatch_gate_error(conn, err)
    end
  end

  def dismiss(%Plug.Conn{} = conn) do
    Authz.send_bad_request(conn, "id path parameter is required")
  end

  defp do_dismiss(conn, %IdentityContext{} = ctx, suggestion_id) do
    actor = principal_subject_from_ctx(ctx)

    case PolicySuggestions.dismiss(suggestion_id, ctx.tenant_id, actor) do
      {:ok, %PolicySuggestion{} = suggestion} ->
        emit_dismissed(ctx, suggestion)
        Plug.Conn.send_resp(conn, 204, "")

      {:error, :not_found} ->
        Authz.send_not_found(conn, "policy suggestion not found")

      {:error, :already_dismissed} ->
        Plug.Conn.send_resp(conn, 204, "")

      {:error, :already_adopted} ->
        Authz.send_bad_request(conn, "suggestion already adopted as draft; cannot dismiss")

      {:error, %Ecto.Changeset{} = cs} ->
        Authz.send_bad_request(conn, "validation failed: #{inspect(changeset_errors(cs))}")
    end
  end

  # ---------------------------------------------------------------------------
  # POST /v1/policy/suggestions/refresh — manual refresh
  # ---------------------------------------------------------------------------

  @doc """
  Manual refresh trigger. Cedar `PolicySuggestionRefresh`; emits
  `:ui_policy_suggestion_refresh_requested`. Rate-limited to 6/hour/tenant
  per FR-030a; over-cap returns 429 + Retry-After.
  """
  @spec refresh(Plug.Conn.t()) :: Plug.Conn.t()
  def refresh(%Plug.Conn{} = conn) do
    resource = %{
      type: "Recurse::Resource::ConsoleSurface",
      id: "policy_suggestions_refresh",
      attrs: %{"endpoint" => "/v1/policy/suggestions/refresh"}
    }

    case Authz.gate(conn, @action_refresh, resource) do
      {:ok, conn_after, ctx, _bundle_ref} -> do_refresh(conn_after, ctx)
      err -> Authz.dispatch_gate_error(conn, err)
    end
  end

  defp do_refresh(conn, %IdentityContext{} = ctx) do
    body = conn.body_params || %{}
    sources = parse_sources(Map.get(body, "sources"))

    if :llm in sources and not Recurse.Gateway.ReleaseSurface.llm_suggestions_available?() do
      Authz.send_service_unavailable(conn, "LLM suggestions are unavailable in this release")
    else
      refresh_available(conn, ctx, sources)
    end
  end

  defp refresh_available(conn, ctx, sources) do
    actor = principal_subject_from_ctx(ctx)
    backend_opt = Map.get(conn.private, :policy_suggestions_refresh_backend)

    refresh_opts =
      [source: List.first(sources)]
      |> maybe_with_backend(backend_opt)

    case PolicySuggestions.refresh(ctx.tenant_id, actor, refresh_opts) do
      {:ok, %PolicySuggestionRun{} = run} ->
        emit_refresh(ctx, run)

        body =
          JSON.encode!(%{
            "run_id" => run.id,
            "sources_triggered" => Enum.map(sources, &Atom.to_string/1)
          })

        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.send_resp(202, body)

      {:error, :rate_limited} ->
        scale_seconds = div(PolicySuggestions.refresh_scale_ms(), 1_000)

        body =
          JSON.encode!(%{
            "error" => %{
              "code" => "ERR_RATE_LIMITED",
              "message" =>
                "Refresh rate limit exceeded for this tenant " <>
                  "(#{PolicySuggestions.refresh_limit()}/#{scale_seconds}s)"
            }
          })

        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.put_resp_header("retry-after", Integer.to_string(scale_seconds))
        |> Plug.Conn.send_resp(429, body)

      {:error, %Ecto.Changeset{} = cs} ->
        Authz.send_bad_request(conn, "validation failed: #{inspect(changeset_errors(cs))}")
    end
  end

  defp maybe_with_backend(opts, nil), do: opts
  defp maybe_with_backend(opts, backend), do: Keyword.put(opts, :backend, backend)

  # ---------------------------------------------------------------------------
  # Receipt emission helpers
  # ---------------------------------------------------------------------------

  defp emit_query_receipt(%IdentityContext{} = ctx, row_count) do
    UiReceipts.emit(:ui_query, %{
      query_kind: "policy_suggestions",
      row_count: row_count,
      principal_subject: principal_subject_from_ctx(ctx),
      tenant_id: ctx.tenant_id,
      correlation_id: ctx.correlation_id
    })
  end

  defp emit_view_receipt(%IdentityContext{} = ctx, %PolicySuggestion{} = suggestion) do
    UiReceipts.emit(:ui_policy_suggestion_viewed, %{
      suggestion_id: suggestion.id,
      principal_subject: principal_subject_from_ctx(ctx),
      tenant_id: ctx.tenant_id,
      correlation_id: ctx.correlation_id
    })
  end

  defp emit_adopted(
         %IdentityContext{} = ctx,
         %PolicySuggestion{} = suggestion,
         %PolicyDraft{} = draft
       ) do
    UiReceipts.emit(:ui_policy_suggestion_adopted, %{
      suggestion_id: suggestion.id,
      draft_id: draft.id,
      principal_subject: principal_subject_from_ctx(ctx),
      tenant_id: ctx.tenant_id,
      correlation_id: ctx.correlation_id
    })
  end

  defp emit_draft_created(%IdentityContext{} = ctx, %PolicyDraft{} = draft) do
    UiReceipts.emit(:ui_policy_draft_created, %{
      draft_id: draft.id,
      source_receipt_run_id: draft.source_receipt_run_id,
      principal_subject: principal_subject_from_ctx(ctx),
      tenant_id: ctx.tenant_id,
      correlation_id: ctx.correlation_id
    })
  end

  defp emit_dismissed(%IdentityContext{} = ctx, %PolicySuggestion{} = suggestion) do
    UiReceipts.emit(:ui_policy_suggestion_dismissed, %{
      suggestion_id: suggestion.id,
      principal_subject: principal_subject_from_ctx(ctx),
      tenant_id: ctx.tenant_id,
      correlation_id: ctx.correlation_id
    })
  end

  defp emit_refresh(%IdentityContext{} = ctx, %PolicySuggestionRun{} = run) do
    UiReceipts.emit(:ui_policy_suggestion_refresh_requested, %{
      run_id: run.id,
      principal_subject: principal_subject_from_ctx(ctx),
      tenant_id: ctx.tenant_id,
      correlation_id: ctx.correlation_id
    })
  end

  # ---------------------------------------------------------------------------
  # Render helpers
  # ---------------------------------------------------------------------------

  defp render_excerpt(%PolicySuggestion{} = s) do
    %{
      "id" => s.id,
      "source" => Atom.to_string(s.source || :heuristic),
      "confidence" => s.confidence_score,
      "pattern_summary" => s.pattern_summary,
      "proposed_cedar" => s.proposed_cedar,
      "blast_radius_snapshot" => s.blast_radius_snapshot,
      "status" => Atom.to_string(s.status || :active),
      "generated_at" => dt_or_nil(s.generated_at)
    }
  end

  defp render_full(%PolicySuggestion{} = s) do
    %{
      "id" => s.id,
      "tenant_id" => s.tenant_id,
      "source" => Atom.to_string(s.source || :heuristic),
      "confidence" => s.confidence_score,
      "pattern_summary" => s.pattern_summary,
      "proposed_cedar" => s.proposed_cedar,
      "blast_radius_snapshot" => s.blast_radius_snapshot,
      "generation_run_id" => s.generation_run_id,
      "status" => Atom.to_string(s.status || :active),
      "dismissed_by" => s.dismissed_by,
      "dismissed_at" => dt_or_nil(s.dismissed_at),
      "adopted_as_draft_id" => s.adopted_as_draft_id,
      "generated_at" => dt_or_nil(s.generated_at),
      "created_at" => dt_or_nil(s.inserted_at),
      "updated_at" => dt_or_nil(s.updated_at)
    }
  end

  defp dt_or_nil(nil), do: nil
  defp dt_or_nil(%DateTime{} = dt), do: DateTime.to_iso8601(dt)
  defp dt_or_nil(s) when is_binary(s), do: s

  # ---------------------------------------------------------------------------
  # Param parsing
  # ---------------------------------------------------------------------------

  defp parse_list_params(query_params) do
    %{
      status: parse_status(Map.get(query_params, "status", "active")),
      source: parse_source(Map.get(query_params, "source")),
      limit: parse_limit(Map.get(query_params, "limit"))
    }
  end

  defp parse_status("active"), do: :active
  defp parse_status("adopted_as_draft"), do: :adopted_as_draft
  defp parse_status("dismissed"), do: :dismissed
  defp parse_status(_), do: :active

  defp parse_source("heuristic"), do: :heuristic
  defp parse_source("llm"), do: :llm
  defp parse_source(_), do: nil

  defp parse_limit(nil), do: @default_limit

  defp parse_limit(value) when is_binary(value) do
    case Integer.parse(value) do
      {n, ""} when n >= 1 -> min(n, @max_limit)
      _ -> @default_limit
    end
  end

  defp parse_limit(_), do: @default_limit

  defp parse_sources(nil), do: [:heuristic]
  defp parse_sources([]), do: [:heuristic]

  defp parse_sources(sources) when is_list(sources) do
    sources
    |> Enum.map(&parse_source/1)
    |> Enum.reject(&is_nil/1)
    |> case do
      [] -> [:heuristic]
      list -> Enum.uniq(list)
    end
  end

  defp parse_sources(_), do: [:heuristic]

  # ---------------------------------------------------------------------------
  # Misc
  # ---------------------------------------------------------------------------

  defp principal_subject_from_ctx(%IdentityContext{principal: %{subject: sub}})
       when is_binary(sub),
       do: sub

  defp principal_subject_from_ctx(%IdentityContext{principal: %{account_id: id}})
       when is_binary(id),
       do: id

  defp principal_subject_from_ctx(_), do: "unknown"

  # T143 — forensic-read flag (`?include_deleted=true`) is operator-only per
  # `contracts/retention_lifecycle.md`.
  defp forensic_read_requested?(conn, %IdentityContext{principal: %{recurse_role: role}}) do
    case {Map.get(conn.query_params, "include_deleted"), role} do
      {"true", "platform_operator"} -> true
      _ -> false
    end
  end

  defp forensic_read_requested?(_conn, _ctx), do: false

  defp changeset_errors(%Ecto.Changeset{} = changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Enum.reduce(opts, msg, fn {key, value}, acc ->
        String.replace(acc, "%{#{key}}", to_string(value))
      end)
    end)
  end
end
