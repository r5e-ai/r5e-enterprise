defmodule Recurse.Gateway.Admin.PolicyDraftsHandler do
  @moduledoc """
  HTTP handler for the F004 policy-drafts CRUD surface (T089).

  Per `contracts/audit_api_extensions.md` §"Policy drafts":

      GET    /v1/policy/drafts              → list (DashboardQuery / :ui_query)
      POST   /v1/policy/drafts              → create (PolicyDraftCreate / :ui_policy_draft_created)
      GET    /v1/policy/drafts/{id}         → fetch single (DashboardQuery / :ui_query)
      PATCH  /v1/policy/drafts/{id}         → edit (PolicyDraftEdit / :ui_policy_draft_edited)
      DELETE /v1/policy/drafts/{id}         → archive (PolicyDraftArchive / :ui_policy_draft_archived)

  ## Auth pipeline

  Each request lands here AFTER `BrowserSessionPlug` has lifted the
  cookie envelope into `Authorization: Bearer <jwt>`. We then thread
  through `AuditPlane.Authz.gate/4` for the per-route Cedar action +
  resource — same pattern as `SessionTimelineHandler` and
  `LocalVerifyHandler`.

  ## Receipt emission

  Every successful (and Cedar-denied — handled inside `gate/4`) request
  emits exactly one canonical `event_kind` per `data-model.md` §0. The
  emission seam is `Recurse.Gateway.Admin.BrowserAuth.UiReceipts.emit/2`.

  ## Iron Law check (`elixir:phoenix-thinking`)

  Pure module — no GenServer. Runs on the Bandit-spawned request
  process. Every per-route function is a pure dispatch + render +
  receipt-emit chain.

  ## Cross-references

    * `specs/004-audit-console/contracts/audit_api_extensions.md` §"Policy drafts"
    * `specs/004-audit-console/data-model.md` §0 (canonical event_kind ↔ Cedar action matrix)
    * `apps/recurse_gateway/lib/recurse_gateway/admin/policy_drafts/policy_drafts.ex` (T085)
  """

  alias Recurse.Gateway.Admin.BrowserAuth.UiReceipts
  alias Recurse.Gateway.Admin.PolicyDrafts
  alias Recurse.Gateway.Admin.PolicyDrafts.PolicyDraft
  alias Recurse.Gateway.AuditPlane.Authz
  alias Recurse.Shared.IdentityContext

  require Logger

  @action_dashboard_query "Recurse::Action::\"DashboardQuery\""
  @action_create "Recurse::Action::\"PolicyDraftCreate\""
  @action_edit "Recurse::Action::\"PolicyDraftEdit\""
  @action_archive "Recurse::Action::\"PolicyDraftArchive\""

  @default_limit 50
  @max_limit 200

  # ---------------------------------------------------------------------------
  # GET /v1/policy/drafts — list
  # ---------------------------------------------------------------------------

  @doc """
  Handle `GET /v1/policy/drafts`. Cedar action `DashboardQuery`; emits
  `:ui_query` (`query_kind: "policy_drafts"`).
  """
  @spec list(Plug.Conn.t()) :: Plug.Conn.t()
  def list(%Plug.Conn{} = conn) do
    resource = %{
      type: "Recurse::Resource::ConsoleSurface",
      id: "policy_drafts_list",
      attrs: %{"endpoint" => "/v1/policy/drafts"}
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
      author_principal_subject: params.author_principal_subject,
      limit: params.limit,
      include_deleted: forensic_read_requested?(conn, ctx)
    }

    drafts = PolicyDrafts.list(filter)

    body =
      JSON.encode!(%{
        "drafts" => Enum.map(drafts, &render_excerpt/1),
        "next_cursor" => nil
      })

    conn_after =
      conn
      |> Plug.Conn.put_resp_content_type("application/json")
      |> Plug.Conn.send_resp(200, body)

    emit_query_receipt(ctx, "policy_drafts", length(drafts))
    conn_after
  end

  # ---------------------------------------------------------------------------
  # POST /v1/policy/drafts — create
  # ---------------------------------------------------------------------------

  @doc """
  Handle `POST /v1/policy/drafts`. Cedar action `PolicyDraftCreate`;
  emits `:ui_policy_draft_created`.
  """
  @spec create(Plug.Conn.t()) :: Plug.Conn.t()
  def create(%Plug.Conn{} = conn) do
    resource = %{
      type: "Recurse::Resource::ConsoleSurface",
      id: "policy_drafts",
      attrs: %{"endpoint" => "/v1/policy/drafts"}
    }

    case Authz.gate(conn, @action_create, resource) do
      {:ok, conn_after, ctx, _bundle_ref} -> do_create(conn_after, ctx)
      err -> Authz.dispatch_gate_error(conn, err)
    end
  end

  defp do_create(conn, %IdentityContext{} = ctx) do
    body = conn.body_params || %{}

    attrs = %{
      "cedar_source" => Map.get(body, "cedar_source", ""),
      "scope_metadata" => Map.get(body, "scope_metadata", %{}),
      "condition_metadata" => Map.get(body, "condition_metadata", []),
      "source_receipt_run_id" => Map.get(body, "source_receipt_run_id"),
      "author_principal_subject" => principal_subject_from_ctx(ctx),
      "status" => :draft
    }

    case PolicyDrafts.create(ctx.tenant_id, attrs) do
      {:ok, %PolicyDraft{} = draft} ->
        emit_draft_created(ctx, draft)

        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.send_resp(201, JSON.encode!(render_full(draft)))

      {:error, %Ecto.Changeset{} = changeset} ->
        Authz.send_bad_request(conn, format_changeset_errors(changeset))
    end
  end

  # ---------------------------------------------------------------------------
  # GET /v1/policy/drafts/{id} — fetch
  # ---------------------------------------------------------------------------

  @doc """
  Handle `GET /v1/policy/drafts/{id}`. Cedar action `DashboardQuery`;
  emits `:ui_query` (`query_kind: "policy_drafts"`).
  """
  @spec get(Plug.Conn.t()) :: Plug.Conn.t()
  def get(%Plug.Conn{path_params: %{"id" => draft_id}} = conn) when is_binary(draft_id) do
    resource = %{
      type: "Recurse::Resource::ConsoleSurface",
      id: "policy_drafts_get",
      attrs: %{"endpoint" => "/v1/policy/drafts/#{draft_id}"}
    }

    case Authz.gate(conn, @action_dashboard_query, resource) do
      {:ok, conn_after, ctx, _bundle_ref} -> do_get(conn_after, ctx, draft_id)
      err -> Authz.dispatch_gate_error(conn, err)
    end
  end

  def get(%Plug.Conn{} = conn) do
    Authz.send_bad_request(conn, "id path parameter is required")
  end

  defp do_get(conn, %IdentityContext{} = ctx, draft_id) do
    case PolicyDrafts.get(draft_id, include_archived: true, tenant_scope: ctx.tenant_id) do
      {:ok, %PolicyDraft{} = draft} ->
        emit_query_receipt(ctx, "policy_drafts", 1)

        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.send_resp(200, JSON.encode!(render_full(draft)))

      {:error, :not_found} ->
        Authz.send_not_found(conn, "policy draft not found")
    end
  end

  # ---------------------------------------------------------------------------
  # PATCH /v1/policy/drafts/{id} — edit
  # ---------------------------------------------------------------------------

  @doc """
  Handle `PATCH /v1/policy/drafts/{id}`. Cedar action `PolicyDraftEdit`;
  emits `:ui_policy_draft_edited`.
  """
  @spec update(Plug.Conn.t()) :: Plug.Conn.t()
  def update(%Plug.Conn{path_params: %{"id" => draft_id}} = conn) when is_binary(draft_id) do
    resource = %{
      type: "Recurse::Resource::ConsoleSurface",
      id: "policy_drafts_edit",
      attrs: %{"endpoint" => "/v1/policy/drafts/#{draft_id}"}
    }

    case Authz.gate(conn, @action_edit, resource) do
      {:ok, conn_after, ctx, _bundle_ref} -> do_update(conn_after, ctx, draft_id)
      err -> Authz.dispatch_gate_error(conn, err)
    end
  end

  def update(%Plug.Conn{} = conn) do
    Authz.send_bad_request(conn, "id path parameter is required")
  end

  defp do_update(conn, %IdentityContext{} = ctx, draft_id) do
    body = conn.body_params || %{}
    actor = principal_subject_from_ctx(ctx)

    # Only allow editing the body / scope / conditions per the contract.
    attrs =
      body
      |> Map.take(["cedar_source", "scope_metadata", "condition_metadata"])

    case PolicyDrafts.update(draft_id, ctx.tenant_id, attrs, actor) do
      {:ok, %PolicyDraft{} = draft} ->
        emit_draft_edited(ctx, draft)

        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.send_resp(200, JSON.encode!(render_full(draft)))

      {:error, :not_found} ->
        Authz.send_not_found(conn, "policy draft not found")

      {:error, %Ecto.Changeset{} = changeset} ->
        Authz.send_bad_request(conn, format_changeset_errors(changeset))
    end
  end

  # ---------------------------------------------------------------------------
  # DELETE /v1/policy/drafts/{id} — archive (soft)
  # ---------------------------------------------------------------------------

  @doc """
  Handle `DELETE /v1/policy/drafts/{id}`. Cedar action `PolicyDraftArchive`;
  emits `:ui_policy_draft_archived`. Returns 204 No Content on success.
  """
  @spec archive(Plug.Conn.t()) :: Plug.Conn.t()
  def archive(%Plug.Conn{path_params: %{"id" => draft_id}} = conn) when is_binary(draft_id) do
    resource = %{
      type: "Recurse::Resource::ConsoleSurface",
      id: "policy_drafts_archive",
      attrs: %{"endpoint" => "/v1/policy/drafts/#{draft_id}"}
    }

    case Authz.gate(conn, @action_archive, resource) do
      {:ok, conn_after, ctx, _bundle_ref} -> do_archive(conn_after, ctx, draft_id)
      err -> Authz.dispatch_gate_error(conn, err)
    end
  end

  def archive(%Plug.Conn{} = conn) do
    Authz.send_bad_request(conn, "id path parameter is required")
  end

  defp do_archive(conn, %IdentityContext{} = ctx, draft_id) do
    actor = principal_subject_from_ctx(ctx)

    case PolicyDrafts.archive(draft_id, ctx.tenant_id, actor) do
      {:ok, %PolicyDraft{} = draft} ->
        emit_draft_archived(ctx, draft)
        Plug.Conn.send_resp(conn, 204, "")

      {:error, :already_archived} ->
        # Idempotent — already archived returns 204 too per REST convention.
        Plug.Conn.send_resp(conn, 204, "")

      {:error, :not_found} ->
        Authz.send_not_found(conn, "policy draft not found")
    end
  end

  # ---------------------------------------------------------------------------
  # Receipt emission helpers
  # ---------------------------------------------------------------------------

  defp emit_query_receipt(%IdentityContext{} = ctx, query_kind, row_count) do
    UiReceipts.emit(:ui_query, %{
      query_kind: query_kind,
      row_count: row_count,
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

  defp emit_draft_edited(%IdentityContext{} = ctx, %PolicyDraft{} = draft) do
    UiReceipts.emit(:ui_policy_draft_edited, %{
      draft_id: draft.id,
      principal_subject: principal_subject_from_ctx(ctx),
      tenant_id: ctx.tenant_id,
      correlation_id: ctx.correlation_id
    })
  end

  defp emit_draft_archived(%IdentityContext{} = ctx, %PolicyDraft{} = draft) do
    UiReceipts.emit(:ui_policy_draft_archived, %{
      draft_id: draft.id,
      principal_subject: principal_subject_from_ctx(ctx),
      tenant_id: ctx.tenant_id,
      correlation_id: ctx.correlation_id
    })
  end

  # ---------------------------------------------------------------------------
  # Render helpers
  # ---------------------------------------------------------------------------

  defp render_excerpt(%PolicyDraft{} = draft) do
    %{
      "id" => draft.id,
      "tenant_id" => draft.tenant_id,
      "author_principal_subject" => draft.author_principal_subject,
      "source_receipt_run_id" => draft.source_receipt_run_id,
      "cedar_source_excerpt" => excerpt(draft.cedar_source, 120),
      "status" => Atom.to_string(draft.status || :draft),
      "created_at" => dt_or_nil(draft.inserted_at),
      "updated_at" => dt_or_nil(draft.updated_at),
      "last_blast_radius_summary" => draft.last_blast_radius_summary
    }
  end

  defp render_full(%PolicyDraft{} = draft) do
    %{
      "id" => draft.id,
      "tenant_id" => draft.tenant_id,
      "author_principal_subject" => draft.author_principal_subject,
      "source_receipt_run_id" => draft.source_receipt_run_id,
      "cedar_source" => draft.cedar_source,
      "scope_metadata" => draft.scope_metadata,
      "condition_metadata" => draft.condition_metadata,
      "status" => Atom.to_string(draft.status || :draft),
      "archived_at" => dt_or_nil(draft.archived_at),
      "last_blast_radius_at" => dt_or_nil(draft.last_blast_radius_at),
      "last_blast_radius_summary" => draft.last_blast_radius_summary,
      "created_at" => dt_or_nil(draft.inserted_at),
      "updated_at" => dt_or_nil(draft.updated_at)
    }
  end

  defp excerpt(nil, _len), do: ""
  defp excerpt(s, len) when is_binary(s) and byte_size(s) <= len, do: s
  defp excerpt(s, len) when is_binary(s), do: binary_part(s, 0, len) <> "..."

  defp dt_or_nil(nil), do: nil
  defp dt_or_nil(%DateTime{} = dt), do: DateTime.to_iso8601(dt)
  defp dt_or_nil(s) when is_binary(s), do: s

  # ---------------------------------------------------------------------------
  # Param parsing
  # ---------------------------------------------------------------------------

  defp parse_list_params(query_params) do
    %{
      status: parse_status(Map.get(query_params, "status", "draft")),
      author_principal_subject: blank_to_nil(Map.get(query_params, "author_principal_subject")),
      limit: parse_limit(Map.get(query_params, "limit"))
    }
  end

  defp parse_status("draft"), do: :draft
  defp parse_status("adopted_as_draft"), do: :adopted_as_draft
  defp parse_status("archived"), do: :archived
  # Any other value (or missing) defaults to :draft per the contract default.
  defp parse_status(_), do: :draft

  defp parse_limit(nil), do: @default_limit

  defp parse_limit(value) when is_binary(value) do
    case Integer.parse(value) do
      {n, ""} when n >= 1 -> min(n, @max_limit)
      _ -> @default_limit
    end
  end

  defp parse_limit(_), do: @default_limit

  defp blank_to_nil(nil), do: nil
  defp blank_to_nil(""), do: nil
  defp blank_to_nil(s) when is_binary(s), do: s

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
  # `contracts/retention_lifecycle.md`. Auditors get a silent `false`.
  defp forensic_read_requested?(conn, %IdentityContext{principal: %{recurse_role: role}}) do
    case {Map.get(conn.query_params, "include_deleted"), role} do
      {"true", "platform_operator"} -> true
      _ -> false
    end
  end

  defp forensic_read_requested?(_conn, _ctx), do: false

  defp format_changeset_errors(%Ecto.Changeset{} = changeset) do
    errors =
      Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
        Enum.reduce(opts, msg, fn {key, value}, acc ->
          String.replace(acc, "%{#{key}}", to_string(value))
        end)
      end)

    "validation failed: #{inspect(errors)}"
  end
end
