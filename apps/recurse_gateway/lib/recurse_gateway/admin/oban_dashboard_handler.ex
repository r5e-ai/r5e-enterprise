defmodule Recurse.Gateway.Admin.ObanDashboardHandler do
  @moduledoc """
  Operator-visible Oban-job-log dashboard at `GET /admin/oban` (T148,
  Phase-9 polish).

  Returns the last 100 `policy_suggestion_runs` rows + the last 100 generic
  Oban jobs from `oban_jobs` as a single JSON envelope. Cedar-gated to
  `platform_operator` only via `AuditPlane.Authz.gate/4` (action
  `DashboardQuery`); emits `:ui_query` per the canonical
  `data-model.md` §0 matrix.

  ## Implementation choice

  We deliberately do NOT pull in `Oban.Web` (an OSS dependency that adds
  several megabytes, a Phoenix LiveView surface we don't control, and an
  authn pipeline that doesn't compose with the F004 Cedar gate). Instead
  this handler is a 200-line custom JSON renderer that the SPA's
  Operations page consumes directly. Operators wanting a richer UI can
  add Oban.Web in their own deployment without changing this file.

  ## Response shape

      {
        "policy_suggestion_runs": [
          {
            "id": "...",
            "source": "heuristic" | "llm",
            "status": "queued" | "running" | "completed" | "failed",
            "tenant_id": "...",
            "scheduled_at": "...",
            "started_at": "...",
            "completed_at": "...",
            "suggestions_generated_count": 5,
            "llm_token_spend": 1234,
            "error": null | "..."
          },
          ...
        ],
        "oban_jobs": [
          {
            "id": 12345,
            "worker": "Recurse.Gateway.SuggestionEngine.HeuristicRunner",
            "queue": "suggestion_engine",
            "state": "completed",
            "inserted_at": "...",
            "attempted_at": "...",
            "completed_at": "...",
            "attempt": 1,
            "max_attempts": 3,
            "first_error": null | "..."
          },
          ...
        ],
        "queues": {
          "suggestion_engine": 2,
          "retention": 1,
          "blast_radius": 2
        }
      }

  ## Iron Law check (`elixir:phoenix-thinking` + `elixir:oban-thinking`)

  Pure module — no GenServer state. Two parallel `Repo.all/1` queries on
  the request process; both bounded to 100 rows. `oban_jobs` query
  gracefully handles the case where the Oban table doesn't exist (test
  envs without Oban migrations applied) by returning `[]`.

  ## Cross-references

    * `specs/004-audit-console/tasks.md` T148
    * `specs/004-audit-console/data-model.md` §0 (`:ui_query`)
    * `apps/recurse_gateway/lib/recurse_gateway/admin/policy_suggestions/policy_suggestion_run.ex`
  """

  import Ecto.Query

  alias Recurse.Gateway.Admin.BrowserAuth.UiReceipts
  alias Recurse.Gateway.Admin.PolicySuggestions.PolicySuggestionRun
  alias Recurse.Gateway.AuditPlane.Authz
  alias Recurse.Providers.Repo
  alias Recurse.Shared.IdentityContext

  require Logger

  @action ~s|Recurse::Action::"DashboardQuery"|
  @max_rows 100

  @doc """
  Plug-shaped entry point. Cedar-gated `DashboardQuery` (operator-only via
  the role-allowlist policy bundle); emits `:ui_query` with
  `query_kind: "oban_dashboard"`.
  """
  @spec handle(Plug.Conn.t()) :: Plug.Conn.t()
  def handle(%Plug.Conn{} = conn) do
    resource = %{
      type: "Recurse::Resource::ConsoleSurface",
      id: "oban_dashboard",
      attrs: %{"endpoint" => "/admin/oban"}
    }

    case Authz.gate(conn, @action, resource) do
      {:ok, conn_after, ctx, _bundle_ref} -> do_handle(conn_after, ctx)
      err -> Authz.dispatch_gate_error(conn, err)
    end
  end

  defp do_handle(conn, %IdentityContext{} = ctx) do
    runs = list_recent_runs()
    jobs = list_recent_oban_jobs()

    body = %{
      "policy_suggestion_runs" => Enum.map(runs, &render_run/1),
      "oban_jobs" => Enum.map(jobs, &render_job/1),
      "queues" => render_queues()
    }

    emit_query_receipt(ctx, length(runs) + length(jobs))

    conn
    |> Plug.Conn.put_resp_content_type("application/json")
    |> Plug.Conn.send_resp(200, JSON.encode!(body))
  end

  # ---------------------------------------------------------------------------
  # Queries
  # ---------------------------------------------------------------------------

  defp list_recent_runs do
    PolicySuggestionRun
    |> where([r], is_nil(r.deleted_at))
    |> order_by([r], desc: r.inserted_at)
    |> limit(^@max_rows)
    |> Repo.all()
  end

  # `oban_jobs` is created by the Oban migration. In test envs without
  # Oban configured, the table may not exist; rescue the cast/exec error
  # and return an empty list so the dashboard still renders.
  defp list_recent_oban_jobs do
    sql = """
    SELECT id, worker, queue, state, inserted_at, attempted_at, completed_at,
           attempt, max_attempts, errors
      FROM oban_jobs
     ORDER BY inserted_at DESC
     LIMIT $1
    """

    case Ecto.Adapters.SQL.query(Repo, sql, [@max_rows]) do
      {:ok, %{rows: rows, columns: cols}} ->
        Enum.map(rows, &row_to_map(&1, cols))

      {:error, _reason} ->
        []
    end
  rescue
    _ -> []
  end

  defp row_to_map(row, cols) do
    cols
    |> Enum.zip(row)
    |> Map.new()
  end

  # ---------------------------------------------------------------------------
  # Render helpers
  # ---------------------------------------------------------------------------

  defp render_run(%PolicySuggestionRun{} = r) do
    %{
      "id" => r.id,
      "tenant_id" => r.tenant_id,
      "source" => r.source && Atom.to_string(r.source),
      "status" => derive_status(r),
      "requested_by" => r.requested_by_principal_subject,
      "scheduled_at" => dt_or_nil(r.scheduled_at),
      "started_at" => dt_or_nil(r.started_at),
      "completed_at" => dt_or_nil(r.completed_at),
      "suggestions_generated_count" => r.suggestions_generated_count,
      "llm_token_spend" => r.llm_token_spend,
      "error" => r.error,
      "inserted_at" => dt_or_nil(r.inserted_at)
    }
  end

  defp derive_status(%PolicySuggestionRun{completed_at: %DateTime{}, error: e}) when is_binary(e),
    do: "failed"

  defp derive_status(%PolicySuggestionRun{completed_at: %DateTime{}}), do: "completed"
  defp derive_status(%PolicySuggestionRun{started_at: %DateTime{}}), do: "running"
  defp derive_status(%PolicySuggestionRun{}), do: "queued"

  defp render_job(row) when is_map(row) do
    errors = Map.get(row, "errors") || []
    first_error = first_error_message(errors)

    %{
      "id" => Map.get(row, "id"),
      "worker" => Map.get(row, "worker"),
      "queue" => Map.get(row, "queue"),
      "state" => Map.get(row, "state"),
      "inserted_at" => dt_or_nil(Map.get(row, "inserted_at")),
      "attempted_at" => dt_or_nil(Map.get(row, "attempted_at")),
      "completed_at" => dt_or_nil(Map.get(row, "completed_at")),
      "attempt" => Map.get(row, "attempt"),
      "max_attempts" => Map.get(row, "max_attempts"),
      "first_error" => first_error
    }
  end

  defp first_error_message([]), do: nil
  defp first_error_message([first | _]) when is_map(first), do: Map.get(first, "error")
  defp first_error_message(_), do: nil

  defp render_queues do
    case Application.get_env(:recurse_gateway, Oban) do
      nil ->
        %{}

      cfg when is_list(cfg) ->
        cfg
        |> Keyword.get(:queues, [])
        |> Map.new(fn {q, n} -> {Atom.to_string(q), n} end)
    end
  end

  defp dt_or_nil(nil), do: nil
  defp dt_or_nil(%DateTime{} = dt), do: DateTime.to_iso8601(dt)
  defp dt_or_nil(%NaiveDateTime{} = ndt), do: NaiveDateTime.to_iso8601(ndt)
  defp dt_or_nil(s) when is_binary(s), do: s
  defp dt_or_nil(_), do: nil

  # ---------------------------------------------------------------------------
  # Receipt emission
  # ---------------------------------------------------------------------------

  defp emit_query_receipt(%IdentityContext{} = ctx, row_count) do
    UiReceipts.emit(:ui_query, %{
      query_kind: "oban_dashboard",
      row_count: row_count,
      principal_subject: principal_subject(ctx),
      tenant_id: ctx.tenant_id,
      correlation_id: ctx.correlation_id
    })
  end

  defp principal_subject(%IdentityContext{principal: %{subject: sub}}) when is_binary(sub),
    do: sub

  defp principal_subject(%IdentityContext{principal: %{account_id: id}}) when is_binary(id),
    do: id

  defp principal_subject(_), do: "unknown"
end
