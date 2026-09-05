defmodule Recurse.Gateway.Admin.ParserDriftHandler do
  @moduledoc """
  `GET /v1/audit/parser-drift` (spec 012 S4, plan §10 "parser drift is a
  product surface").

  Lists the `parser_drift_events` rows for the session's tenant — the
  event / block / delta types an LLM-proxy parser could not classify,
  with a keys-only sample, first/last seen and a count — plus the
  node's `new_since_boot` counter (the same number `/readyz` reports).
  The SPA renders a "Parser drift" panel from it, shown only when the
  list is non-empty.

  Cookie-gated like the other console reads: `BrowserSessionPipe` lifts
  the cookie, `Authz.gate/3` evaluates Cedar action `DashboardQuery`,
  and a `:ui_query` receipt (`query_kind: "parser_drift"`) is emitted per
  call, mirroring `PolicyDraftsHandler.list/1`.

  ## Response

      {
        "events": [
          {"id": 1, "api_format": "anthropic_messages", "event_type": "block:widget",
           "sample_redacted": "keys=payload,type", "first_seen": "...", "last_seen": "...",
           "count": 3}
        ],
        "new_since_boot": 1
      }
  """

  alias Recurse.Gateway.Admin.BrowserAuth.UiReceipts
  alias Recurse.Gateway.AuditPlane.Authz
  alias Recurse.Gateway.LlmProxy.ParserDrift
  alias Recurse.Providers.ParserDrift, as: Store
  alias Recurse.Shared.IdentityContext

  @action "Recurse::Action::\"DashboardQuery\""
  @max_limit 500

  @spec handle(Plug.Conn.t()) :: Plug.Conn.t()
  def handle(%Plug.Conn{} = conn) do
    resource = %{
      type: "Recurse::Resource::AuditEndpoint",
      id: "v1_audit_parser_drift",
      attrs: %{"endpoint" => "/v1/audit/parser-drift"}
    }

    case Authz.gate(conn, @action, resource) do
      {:ok, conn_with_ctx, ctx, _bundle_ref} -> do_list(conn_with_ctx, ctx)
      error -> Authz.dispatch_gate_error(conn, error)
    end
  end

  defp do_list(conn, %IdentityContext{} = ctx) do
    conn = Plug.Conn.fetch_query_params(conn)
    limit = parse_limit(Map.get(conn.query_params, "limit"))
    api_format = nonempty(Map.get(conn.query_params, "api_format"))

    rows = Store.list(ctx.tenant_id, limit: limit, api_format: api_format)

    body =
      JSON.encode!(%{
        "events" => Enum.map(rows, &render/1),
        "new_since_boot" => ParserDrift.new_since_boot()
      })

    conn_after =
      conn
      |> Plug.Conn.put_resp_content_type("application/json")
      |> Plug.Conn.send_resp(200, body)

    UiReceipts.emit(:ui_query, %{
      query_kind: "parser_drift",
      row_count: length(rows),
      principal_subject: principal_subject(ctx),
      tenant_id: ctx.tenant_id,
      correlation_id: ctx.correlation_id
    })

    conn_after
  end

  defp render(row) do
    %{
      "id" => row.id,
      "api_format" => row.api_format,
      "event_type" => row.event_type,
      "sample_redacted" => row.sample_redacted,
      "first_seen" => DateTime.to_iso8601(row.first_seen),
      "last_seen" => DateTime.to_iso8601(row.last_seen),
      "count" => row.count
    }
  end

  defp parse_limit(nil), do: 100

  defp parse_limit(value) when is_binary(value) do
    case Integer.parse(value) do
      {n, ""} when n > 0 -> min(n, @max_limit)
      _ -> 100
    end
  end

  defp nonempty(s) when is_binary(s) and s != "", do: s
  defp nonempty(_), do: nil

  defp principal_subject(%IdentityContext{principal: %{subject: subject}})
       when is_binary(subject),
       do: subject

  defp principal_subject(_), do: "unknown"
end
