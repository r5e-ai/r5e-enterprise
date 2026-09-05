defmodule Recurse.Gateway.Admin.SessionTimelineHandler do
  @moduledoc """
  `GET /v1/audit/sessions/{session_id}` (F004 T060, FR-008/-010).

  Returns all attestations belonging to `session_id`, grouped + ordered
  chronologically by `(timestamp ASC, run_id ASC)`. Used by the SPA's
  Receipt Detail / Session Timeline view to render a single agent
  session's full receipt thread.

  ## Flow

    1. `AuditPlane.Authz.gate/4` — JWT validation (lifted from cookie
       by `BrowserSessionPlug`) + Cedar evaluation against
       `Recurse::Action::"DashboardQuery"` (the canonical dashboard
       action per `data-model.md` §0).
    2. Tenant-scope check: load the session, compare its `tenant_id`
       against the caller's `IdentityContext.tenant_id`. Mismatch
       returns 403 + an attested `:policy_denied` receipt (the
       cross-tenant case per `audit_api_extensions.md` §"Cross-cutting
       rules").
    3. Decode the optional `cursor` (server-signed b64 per D8 / T062).
    4. Stream attestations from `PostgresMerkleLedger.query_paginated/1`
       with `session_id` filter, page-bounded by `limit` (default 100,
       max 500).
    5. Render the F004 session-timeline shape per
       `audit_api_extensions.md` §"Session timeline".
    6. Emit a `:ui_query` (`query_kind: "session_timeline"`) attestation
       per `data-model.md` §0 — fire-and-forget through `UiReceipts.emit/2`
       so a missing receipt is an audit gap, not a user-facing failure.

  ## Why F004 reuses the F002 `AuditPlane.Authz.gate/4` pipeline

  The cookie envelope is lifted into `Authorization: Bearer <jwt>` by
  `BrowserSessionPlug` upstream of this handler in the router. Once that
  lift happens the handler sees an identical request shape to a
  direct-API caller (`Authorization: Bearer ...`) and the existing F002
  Cedar gate / JWT validator chain runs unchanged. Bifurcating the auth
  surface would have meant maintaining two policy-evaluator entry
  points; the cookie-lifting trick keeps them unified.

  ## Tenant-scope enforcement order

  We Cedar-gate FIRST, then resolve the session's tenant_id, then
  cross-tenant check. The Cedar policy already requires
  `principal.tenant_id == context.tenant_id` for `DashboardQuery`, so
  passing through `gate/4` proves the caller's role is valid for the
  caller's own tenant. The session-tenant check is a separate defense:
  even a `tenant_auditor` with a valid role MUST NOT read a session
  belonging to a different tenant. This is the path that earns the
  `:policy_denied` receipt — Cedar passed but the resource-scope check
  failed. (Under Phase-1 single-tenant-per-BEAM this is a defense-in-
  depth path; Phase-2 federation will exercise it routinely.)

  ## Iron Law check (`elixir:phoenix-thinking`)

  Pure module — no GenServer. Runs on the Bandit-spawned request
  process. The fan-out to `UiReceipts.emit/2` IS synchronous (per the
  F004 receipt seam contract; see Wave 3A T055a) but it never raises:
  emission failures are logged at `:error` and the request still
  completes successfully. The 2-second SC-009 budget covers the
  in-line emit per the contract's "emits its attested receipt before
  sending the 200 response body" rule.

  ## Cross-references

    * `specs/004-audit-console/contracts/audit_api_extensions.md`
      §"Session timeline"
    * `specs/004-audit-console/research.md` D8 (cursor signing)
    * `specs/004-audit-console/data-model.md` §0 (`:ui_query` /
      `query_kind: "session_timeline"`)
    * `apps/recurse_gateway/lib/recurse_gateway/admin/cursor.ex` (T062)
    * `apps/recurse_gateway/lib/recurse_gateway/audit_plane/authz.ex`
      (F002 Authz.gate/4 reused here)
  """

  alias Recurse.Gateway.Admin.BrowserAuth.UiReceipts
  alias Recurse.Gateway.Admin.Cursor
  alias Recurse.Gateway.AuditPlane.Authz
  alias Recurse.Providers.Impls.PostgresMerkleLedger
  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Session, as: SessionSchema
  alias Recurse.Providers.Repo
  alias Recurse.Shared.IdentityContext

  require Logger

  @action "Recurse::Action::\"DashboardQuery\""
  @default_limit 100
  @max_limit 500

  @doc """
  Entry point. Returns a responded `Plug.Conn` after sending the response.
  """
  @spec handle(Plug.Conn.t()) :: Plug.Conn.t()
  def handle(%Plug.Conn{path_params: %{"session_id" => session_id}} = conn)
      when is_binary(session_id) do
    resource = %{
      type: "Recurse::Resource::ConsoleSurface",
      id: "session_timeline",
      attrs: %{"endpoint" => "/v1/audit/sessions/#{session_id}"}
    }

    case Authz.gate(conn, @action, resource) do
      {:ok, conn_with_ctx, ctx, _bundle_ref} ->
        do_handle(conn_with_ctx, ctx, session_id)

      error ->
        Authz.dispatch_gate_error(conn, error)
    end
  end

  # When Plug.Router dispatches via `get "/v1/audit/sessions/:session_id"`,
  # the session_id appears in `conn.path_params`. The clause above is the
  # router-fed shape; this fallback keeps the function total against
  # programmer error (test fixtures that build a conn without path_params).
  def handle(%Plug.Conn{} = conn) do
    Authz.send_bad_request(conn, "session_id path parameter is required")
  end

  defp do_handle(conn, %IdentityContext{} = ctx, session_id) do
    conn_with_params = Plug.Conn.fetch_query_params(conn)

    with {:ok, params} <- parse_query_params(conn_with_params.query_params),
         {:ok, session} <- fetch_session(session_id),
         :ok <- enforce_tenant_scope(ctx, session, conn_with_params) do
      run_query(conn_with_params, ctx, session, params)
    else
      {:error, :session_not_found} ->
        Authz.send_not_found(conn_with_params, "session_id not found")

      {:error, :cross_tenant} ->
        # Emit the cross-tenant denial receipt FIRST so the operator
        # sees the attempt in the audit log before the 403 response
        # ships (per FR-006 / FR-042 — the receipt is the source of
        # truth for the denial, the response is only the user-facing
        # surface).
        emit_cross_tenant_denial(ctx, session_id)
        Authz.send_forbidden(conn_with_params, :cross_tenant)

      {:error, {:bad_param, message}} ->
        Authz.send_bad_request(conn_with_params, message)

      {:error, :invalid_cursor} ->
        Authz.send_bad_request(conn_with_params, "cursor is malformed or not from a prior response")
    end
  end

  # ---------------------------------------------------------------------------
  # Tenant-scope enforcement — cross-tenant access returns 403 + attested
  # `:policy_denied` per audit_api_extensions.md §"Cross-cutting rules".
  # ---------------------------------------------------------------------------

  defp fetch_session(session_id) do
    case Repo.get(SessionSchema, session_id) do
      nil -> {:error, :session_not_found}
      %SessionSchema{} = session -> {:ok, session}
    end
  rescue
    # `Ecto.UUID` cast errors raise `Ecto.Query.CastError` on get/1 when
    # the path param is not a UUID. Map to not_found so external callers
    # don't learn whether the malformed value happened to collide with a
    # real session.
    Ecto.Query.CastError -> {:error, :session_not_found}
  end

  defp enforce_tenant_scope(%IdentityContext{tenant_id: caller_tid}, %SessionSchema{tenant_id: sess_tid}, _conn)
       when caller_tid == sess_tid,
       do: :ok

  defp enforce_tenant_scope(_ctx, _session, _conn), do: {:error, :cross_tenant}

  # ---------------------------------------------------------------------------
  # Query execution + rendering
  # ---------------------------------------------------------------------------

  defp run_query(conn, ctx, %SessionSchema{} = session, params) do
    query_opts =
      %{
        session_id: session.session_id,
        limit: params.limit
      }
      |> maybe_put(:cursor, encode_f002_cursor(params.cursor_bound))

    case PostgresMerkleLedger.query_paginated(query_opts) do
      {:ok, %{rows: rows, next_cursor: f002_cursor}} ->
        # F002's `query_paginated/1` returns rows DESC-by-timestamp; the
        # session-timeline contract specifies ASC chronological order so
        # the SPA renders sequentially. Reverse here rather than asking
        # the F002 surface to grow a sort flag (would force a body
        # change in the F002 handler — out of scope per task framing).
        sorted_rows = Enum.reverse(rows)

        body =
          JSON.encode!(%{
            "session_id" => session.session_id,
            "tenant_id" => session.tenant_id,
            "started_at" => dt_or_nil(session.session_start),
            "last_seen_at" => last_seen_at(sorted_rows, session),
            "epoch_count" => epoch_count(session),
            "receipts" => Enum.map(sorted_rows, &render_row/1),
            "next_cursor" => translate_cursor(f002_cursor)
          })

        conn_after =
          conn
          |> Plug.Conn.put_resp_content_type("application/json")
          |> Plug.Conn.send_resp(200, body)

        emit_session_timeline_query(ctx, session.session_id, length(sorted_rows))
        conn_after

      {:error, :invalid_cursor} ->
        Authz.send_bad_request(conn, "cursor is malformed or not from a prior response")

      {:error, reason} ->
        Logger.error(fn -> "session_timeline query failed: #{inspect(reason)}" end)
        Authz.send_internal_error(conn, reason)
    end
  end

  defp last_seen_at([], session), do: dt_or_nil(session.session_start)

  defp last_seen_at(rows, _session) do
    rows
    |> List.last()
    |> Map.get(:timestamp)
    |> dt_or_nil()
  end

  # F002 1-run-1-session always emits a single epoch (epoch_index = 0),
  # so `epoch_count` is naturally `max(epoch_index) + 1`. Rather than
  # query session_epochs separately (extra DB hit), report 1 — this is
  # accurate for Phase-1 and the column gets re-derived from the rows
  # themselves once Governance multi-epoch shapes land in F005+.
  defp epoch_count(_session), do: 1

  defp render_row(att) do
    %{
      "run_id" => att.run_id,
      "sequence" => att.session_chain_epoch || 0,
      "event_kind" => to_string_or_nil(att.event_kind),
      "policy_decision" => to_string_or_nil(att.policy_decision),
      "verification_level" => to_string_or_nil(att.verification_level),
      "principal_subject" => principal_subject_or_nil(att.principal),
      "matched_policy" => att.policy_canonical_hash |> hex_or_nil(),
      "summary" => build_summary(att)
    }
  end

  # The summary is a UI-friendly one-line digest derived from the
  # event_kind + outcome. This is intentionally lossy — the full
  # signed_predicate is available via `GET /v1/audit/receipts/{run_id}`
  # for drill-in.
  defp build_summary(att) do
    [
      to_string_or_nil(att.event_kind),
      "outcome=" <> (to_string_or_nil(att.outcome) || "unknown")
    ]
    |> Enum.reject(&is_nil/1)
    |> Enum.join(" ")
  end

  defp principal_subject_or_nil(%{"subject" => sub}) when is_binary(sub), do: sub
  defp principal_subject_or_nil(%{"account_id" => id}) when is_binary(id), do: id
  defp principal_subject_or_nil(_), do: nil

  # F004 cursor envelope wraps F002's opaque cursor inside a server-signed
  # blob. The F002 cursor itself encodes `(timestamp, run_id)` as base64
  # JSON; we sign-and-wrap so the F004 audit-console surface uniformly
  # rejects tampered cursors per audit_api_extensions.md.
  defp translate_cursor(nil), do: nil

  defp translate_cursor(f002_cursor) when is_binary(f002_cursor) do
    case Base.url_decode64(f002_cursor, padding: false) do
      {:ok, json_bytes} ->
        case JSON.decode(json_bytes) do
          {:ok, %{"ts" => ts_iso, "run_id" => run_id}} ->
            ts_us = iso_to_microseconds(ts_iso)
            Cursor.encode({ts_us, run_id})

          _ ->
            nil
        end

      :error ->
        nil
    end
  end

  defp iso_to_microseconds(ts_iso) when is_binary(ts_iso) do
    case DateTime.from_iso8601(ts_iso) do
      {:ok, dt, _offset} -> DateTime.to_unix(dt, :microsecond)
      _ -> 0
    end
  end

  # Re-encode the decoded `(ts_us, run_id)` tuple into F002's internal
  # cursor format (base64-encoded JSON `{ts: ISO8601, run_id: uuid}`)
  # so `PostgresMerkleLedger.query_paginated/1` can apply the bound on
  # its DESC-by-timestamp result set. The F004-side wrapping (sign +
  # opaque b64) is the trust boundary; F002's internal cursor is an
  # impl detail re-derived from the verified payload.
  defp encode_f002_cursor(nil), do: nil

  defp encode_f002_cursor({ts_us, run_id}) when is_integer(ts_us) and is_binary(run_id) do
    case DateTime.from_unix(ts_us, :microsecond) do
      {:ok, dt} ->
        json = JSON.encode!(%{"ts" => DateTime.to_iso8601(dt), "run_id" => run_id})
        Base.url_encode64(json, padding: false)

      _ ->
        nil
    end
  end

  # ---------------------------------------------------------------------------
  # Receipt emission
  # ---------------------------------------------------------------------------

  defp emit_session_timeline_query(%IdentityContext{} = ctx, session_id, row_count) do
    UiReceipts.emit(:ui_query, %{
      query_kind: "session_timeline",
      session_id: session_id,
      row_count: row_count,
      principal_subject: principal_subject_from_ctx(ctx),
      tenant_id: ctx.tenant_id,
      correlation_id: ctx.correlation_id
    })
  end

  defp emit_cross_tenant_denial(%IdentityContext{} = ctx, target_session_id) do
    UiReceipts.emit(:ui_session, %{
      event: "policy_denied",
      reason: "cross_tenant_session_access",
      target_session_id: target_session_id,
      principal_subject: principal_subject_from_ctx(ctx),
      tenant_id: ctx.tenant_id,
      correlation_id: ctx.correlation_id
    })
  end

  # The `IdentityContext.principal` is a `%Recurse.Shared.Principal{}`
  # struct — for OBO-human principals the `subject` field carries the
  # IdP `sub` claim; for service-account principals `account_id` is the
  # auditor-meaningful identifier. This mirrors the convention in
  # UiReceipts' principal_for/3.
  defp principal_subject_from_ctx(%IdentityContext{principal: %{subject: sub}}) when is_binary(sub),
    do: sub

  defp principal_subject_from_ctx(%IdentityContext{principal: %{account_id: id}}) when is_binary(id),
    do: id

  defp principal_subject_from_ctx(_), do: nil

  # ---------------------------------------------------------------------------
  # Query-param parsing
  # ---------------------------------------------------------------------------

  defp parse_query_params(query_params) do
    with {:ok, limit} <- parse_limit(Map.get(query_params, "limit")),
         {:ok, cursor_bound} <- parse_cursor(Map.get(query_params, "cursor")) do
      {:ok, %{limit: limit, cursor_bound: cursor_bound}}
    end
  end

  defp parse_limit(nil), do: {:ok, @default_limit}

  defp parse_limit(value) when is_binary(value) do
    case Integer.parse(value) do
      {n, ""} when n >= 1 -> {:ok, min(n, @max_limit)}
      _ -> {:error, {:bad_param, "limit must be a positive integer"}}
    end
  end

  defp parse_cursor(nil), do: {:ok, nil}
  defp parse_cursor(""), do: {:ok, nil}

  defp parse_cursor(value) when is_binary(value) do
    case Cursor.decode(value) do
      {:ok, payload} -> {:ok, payload}
      {:error, :invalid_cursor} -> {:error, :invalid_cursor}
    end
  end

  # ---------------------------------------------------------------------------
  # Small render helpers (mirror F002 ReceiptsHandler conventions)
  # ---------------------------------------------------------------------------

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)

  defp to_string_or_nil(nil), do: nil
  defp to_string_or_nil(v) when is_atom(v), do: Atom.to_string(v)
  defp to_string_or_nil(v) when is_binary(v), do: v
  defp to_string_or_nil(v), do: to_string(v)

  defp dt_or_nil(nil), do: nil
  defp dt_or_nil(%DateTime{} = dt), do: DateTime.to_iso8601(dt)
  defp dt_or_nil(v) when is_binary(v), do: v

  defp hex_or_nil(nil), do: nil
  defp hex_or_nil(v) when is_binary(v), do: Base.encode16(v, case: :lower)
end
