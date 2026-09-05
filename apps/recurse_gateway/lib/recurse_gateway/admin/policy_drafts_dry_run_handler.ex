defmodule Recurse.Gateway.Admin.PolicyDraftsDryRunHandler do
  @moduledoc """
  `POST /v1/policy/drafts/{id}/dry-run` (F004 T091).

  The Wiz-pattern Blast Radius computation entry point. Per
  `contracts/audit_api_extensions.md` and
  `contracts/blast_radius_algorithm.md`:

    * Sync if estimated window ≤ 10K receipts → 200 + full summary.
    * Async if estimated > 10K → 202 + `job_id` + `poll_url`.

  ## Response shape (sync, per audit_api_extensions.md §"Policy drafts")

      {
        "draft_id": "uuid",
        "window_days": 30,
        "total_receipts_in_window": 8552,
        "total_affected": 120,
        "matches_intent": 115,
        "unintended": 5,
        "would_have_allowed": 0,         # **load-bearing 4-cell field**
        "no_change": 8432,
        "sample_receipts": [...],
        "computed_at": "...",
        "attested_run_id": "uuid"
      }

  ## Response shape (async)

      {"draft_id": "uuid", "job_id": "...", "poll_url": "/v1/policy/drafts/.../dry-run/..."}

  ## Cedar action + receipt

  Cedar action `PolicyDraftDryRun`; emits `:ui_policy_draft_dry_run`. The
  receipt's predicate carries `cedar_source_hash`, `window_since`,
  `window_until`, the 4-cell counts, `mode: "sync" | "async"`, `duration_ms`
  per algorithm contract §"Observability".

  ## Iron Law check (`elixir:phoenix-thinking`)

  Pure module — no GenServer. Sync path runs the streaming algorithm
  in-process; async path enqueues an Oban job and returns immediately.
  Neither path holds state across requests.

  ## Cross-references

    * `specs/004-audit-console/contracts/blast_radius_algorithm.md`
      (full algorithm + §6 async escalation + §7 cache + §"Observability")
    * `specs/004-audit-console/contracts/audit_api_extensions.md`
      §"Policy drafts" — dry-run endpoint contract
    * `apps/recurse_gateway/lib/recurse_gateway/admin/blast_radius.ex` (T086)
    * `apps/recurse_gateway/lib/recurse_gateway/admin/blast_radius/async_escalation.ex` (T087)
  """

  alias Recurse.Gateway.Admin.BlastRadius
  alias Recurse.Gateway.Admin.BlastRadius.AsyncEscalation
  alias Recurse.Gateway.Admin.BrowserAuth.UiReceipts
  alias Recurse.Gateway.Admin.PolicyDrafts
  alias Recurse.Gateway.Admin.PolicyDrafts.PolicyDraft
  alias Recurse.Gateway.AuditPlane.Authz
  alias Recurse.Shared.IdentityContext

  require Logger

  @action "Recurse::Action::\"PolicyDraftDryRun\""
  @default_window_days 30

  @doc """
  Plug-shaped entry point. Returns 200 (sync), 202 (async), 400 (Cedar
  parse), 404 (draft missing), or 500 (compute failure).
  """
  @spec handle(Plug.Conn.t()) :: Plug.Conn.t()
  def handle(%Plug.Conn{path_params: %{"id" => draft_id}} = conn) when is_binary(draft_id) do
    resource = %{
      type: "Recurse::Resource::ConsoleSurface",
      id: "policy_drafts_dry_run",
      attrs: %{"endpoint" => "/v1/policy/drafts/#{draft_id}/dry-run"}
    }

    case Authz.gate(conn, @action, resource) do
      {:ok, conn_after, ctx, _bundle_ref} -> do_handle(conn_after, ctx, draft_id)
      err -> Authz.dispatch_gate_error(conn, err)
    end
  end

  def handle(%Plug.Conn{} = conn) do
    Authz.send_bad_request(conn, "id path parameter is required")
  end

  defp do_handle(conn, %IdentityContext{} = ctx, draft_id) do
    body = conn.body_params || %{}
    window_days = parse_window_days(body)
    force_async? = Map.get(body, "async", false) == true

    case PolicyDrafts.get(draft_id, include_archived: true, tenant_scope: ctx.tenant_id) do
      {:ok, %PolicyDraft{} = draft} ->
        run_or_enqueue(conn, ctx, draft, window_days, force_async?)

      {:error, :not_found} ->
        Authz.send_not_found(conn, "policy draft not found")
    end
  end

  defp run_or_enqueue(conn, ctx, %PolicyDraft{} = draft, window_days, force_async?) do
    until_dt = DateTime.utc_now()
    since = DateTime.add(until_dt, -window_days, :day)

    if force_async? do
      enqueue_async(conn, ctx, draft, since, until_dt, window_days)
    else
      compute_and_dispatch(conn, ctx, draft, since, until_dt, window_days)
    end
  end

  defp compute_and_dispatch(conn, ctx, %PolicyDraft{} = draft, since, until_dt, window_days) do
    input = %{
      draft_id: draft.id,
      draft_cedar_source: draft.cedar_source,
      tenant_id: draft.tenant_id,
      window: %{since: since, until: until_dt},
      sample_size: 20,
      cached_summary: draft.last_blast_radius_summary,
      cached_at: draft.last_blast_radius_at,
      persist?: true,
      force: false
    }

    case BlastRadius.compute(input) do
      {:ok, summary} ->
        respond_sync(conn, ctx, draft, summary, window_days)

      {:cached, summary} ->
        respond_sync(conn, ctx, draft, summary, window_days)

      {:async_required, _estimated} ->
        enqueue_async(conn, ctx, draft, since, until_dt, window_days)

      {:error, {:cedar_parse_error, message}} ->
        Authz.send_bad_request(conn, "cedar parse error: #{message}")

      {:error, reason} ->
        Logger.error(fn ->
          "policy_draft dry_run sync failed: #{inspect(reason)} draft_id=#{draft.id}"
        end)

        Authz.send_internal_error(conn, reason)
    end
  end

  defp respond_sync(conn, %IdentityContext{} = ctx, %PolicyDraft{} = draft, summary, window_days) do
    body = %{
      "draft_id" => draft.id,
      "window_days" => window_days,
      "total_receipts_in_window" => Map.get(summary, "total_scanned", 0),
      "total_affected" => Map.get(summary, "total_affected", 0),
      "matches_intent" => Map.get(summary, "matches_intent", 0),
      "unintended" => Map.get(summary, "unintended", 0),
      # **load-bearing 4-cell field per §5a — MUST be top-level integer**
      "would_have_allowed" => Map.get(summary, "would_have_allowed", 0),
      "no_change" => Map.get(summary, "no_change", 0),
      "sample_receipts" => Map.get(summary, "sample_receipts", []),
      "computed_at" => Map.get(summary, "computed_at"),
      "cedar_source_hash" => Map.get(summary, "cedar_source_hash"),
      "duration_ms" => Map.get(summary, "duration_ms", 0),
      "mode" => Map.get(summary, "mode", "sync")
    }

    emit_dry_run(ctx, draft, summary, "sync", window_days)

    conn
    |> Plug.Conn.put_resp_content_type("application/json")
    |> Plug.Conn.send_resp(200, JSON.encode!(body))
  end

  defp enqueue_async(
         conn,
         %IdentityContext{} = ctx,
         %PolicyDraft{} = draft,
         since,
         until_dt,
         window_days
       ) do
    # GAN-review fix #5: thread the caller's tenant_id into the job
    # args so the deferred worker scopes its draft fetch by tenant.
    case AsyncEscalation.enqueue(draft.id, ctx.tenant_id, since, until_dt) do
      {:ok, job} ->
        body = %{
          "draft_id" => draft.id,
          "job_id" => Integer.to_string(job.id),
          "poll_url" => "/v1/policy/drafts/#{draft.id}/dry-run/#{job.id}",
          "mode" => "async",
          "window_days" => window_days
        }

        emit_dry_run(ctx, draft, %{}, "async", window_days)

        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.send_resp(202, JSON.encode!(body))

      {:error, reason} ->
        Logger.error(fn ->
          "policy_draft dry_run async enqueue failed: #{inspect(reason)} draft_id=#{draft.id}"
        end)

        Authz.send_internal_error(conn, reason)
    end
  end

  # ---------------------------------------------------------------------------
  # Receipt emission
  # ---------------------------------------------------------------------------

  defp emit_dry_run(%IdentityContext{} = ctx, %PolicyDraft{} = draft, summary, mode, window_days) do
    UiReceipts.emit(:ui_policy_draft_dry_run, %{
      draft_id: draft.id,
      cedar_source_hash: Map.get(summary, "cedar_source_hash"),
      window_days: window_days,
      total_scanned: Map.get(summary, "total_scanned", 0),
      total_affected: Map.get(summary, "total_affected", 0),
      matches_intent: Map.get(summary, "matches_intent", 0),
      unintended: Map.get(summary, "unintended", 0),
      would_have_allowed: Map.get(summary, "would_have_allowed", 0),
      mode: mode,
      duration_ms: Map.get(summary, "duration_ms", 0),
      principal_subject: principal_subject_from_ctx(ctx),
      tenant_id: ctx.tenant_id,
      correlation_id: ctx.correlation_id
    })
  end

  # ---------------------------------------------------------------------------
  # Param parsing
  # ---------------------------------------------------------------------------

  defp parse_window_days(%{"window_days" => n}) when is_integer(n) and n > 0 and n <= 365, do: n

  defp parse_window_days(%{"window_days" => s}) when is_binary(s) do
    case Integer.parse(s) do
      {n, ""} when n > 0 and n <= 365 -> n
      _ -> @default_window_days
    end
  end

  defp parse_window_days(_), do: @default_window_days

  defp principal_subject_from_ctx(%IdentityContext{principal: %{subject: sub}})
       when is_binary(sub),
       do: sub

  defp principal_subject_from_ctx(%IdentityContext{principal: %{account_id: id}})
       when is_binary(id),
       do: id

  defp principal_subject_from_ctx(_), do: "unknown"
end
