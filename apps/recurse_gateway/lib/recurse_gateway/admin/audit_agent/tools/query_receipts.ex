defmodule Recurse.Gateway.Admin.AuditAgent.Tools.QueryReceipts do
  @moduledoc """
  Audit Agent Tool 1 — `query_receipts` (F004 T109).

  Pure-SQL faceted query over `attestations`. Agent-callable equivalent
  of the dashboard's structured query bar.

  Cost: zero LLM tokens. Cedar action:
  `Recurse::Action::"AuditAgentToolQueryReceipts"`. Required roles:
  `tenant_auditor` or `platform_operator`.

  Cross-references:
    * `specs/004-audit-console/contracts/audit_agent_tools.md` §"Tool 1"
    * `specs/004-audit-console/data-model.md` §0 (event_kind matrix).
  """

  @behaviour Recurse.Gateway.Admin.AuditAgent.Tool

  import Ecto.Query

  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Attestation
  alias Recurse.Providers.Repo

  @input_schema %{
    "type" => "object",
    "additionalProperties" => false,
    "properties" => %{
      "filters" => %{
        "type" => "object",
        "properties" => %{
          "event_kind" => %{"type" => "array", "items" => %{"type" => "string"}},
          "policy_decision" => %{"type" => "string", "enum" => ["allow", "deny"]},
          "principal_subject" => %{"type" => "string"},
          "tool_name" => %{"type" => "string"},
          "since" => %{"type" => "string", "format" => "date-time"},
          "until" => %{"type" => "string", "format" => "date-time"}
        }
      },
      "limit" => %{"type" => "integer", "minimum" => 1, "maximum" => 100, "default" => 20}
    }
  }

  @output_schema %{
    "type" => "object",
    "required" => ["receipts", "total_match_count_estimate"],
    "properties" => %{
      "receipts" => %{
        "type" => "array",
        "items" => %{
          "type" => "object",
          "required" => [
            "run_id",
            "event_kind",
            "policy_decision",
            "timestamp",
            "principal_subject",
            "summary"
          ]
        }
      },
      "total_match_count_estimate" => %{"type" => "integer"}
    }
  }

  @impl true
  def name, do: "query_receipts"

  @impl true
  def cedar_action, do: ~s|Recurse::Action::"AuditAgentToolQueryReceipts"|

  @impl true
  def event_kind, do: :ui_chat_skill_invoked_query_receipts

  @impl true
  def input_schema, do: @input_schema

  @impl true
  def output_schema, do: @output_schema

  @impl true
  def call(input, %{tenant_id: tenant_id}) when is_map(input) and is_binary(tenant_id) do
    filters = Map.get(input, "filters", %{}) |> normalize_keys()
    limit = Map.get(input, "limit", 20) |> clamp_limit()

    query =
      Attestation
      |> where([a], a.tenant_id == ^tenant_id)
      |> apply_event_kind(Map.get(filters, "event_kind"))
      |> apply_policy_decision(Map.get(filters, "policy_decision"))
      |> apply_principal_subject(Map.get(filters, "principal_subject"))
      |> apply_since(Map.get(filters, "since"))
      |> apply_until(Map.get(filters, "until"))
      |> order_by([a], desc: a.timestamp)
      |> limit(^limit)

    receipts =
      query
      |> Repo.all()
      |> Enum.map(&to_summary/1)

    {:ok,
     %{
       "receipts" => receipts,
       "total_match_count_estimate" => length(receipts)
     }}
  end

  defp normalize_keys(map) when is_map(map) do
    Map.new(map, fn
      {k, v} when is_atom(k) -> {Atom.to_string(k), v}
      {k, v} -> {k, v}
    end)
  end

  defp clamp_limit(n) when is_integer(n) and n > 0 and n <= 100, do: n
  defp clamp_limit(_), do: 20

  defp apply_event_kind(query, nil), do: query

  defp apply_event_kind(query, kinds) when is_list(kinds) and kinds != [] do
    atoms =
      kinds
      |> Enum.map(&safe_to_existing_atom/1)
      |> Enum.reject(&is_nil/1)

    case atoms do
      [] -> query
      list -> where(query, [a], a.event_kind in ^list)
    end
  end

  defp apply_event_kind(query, _), do: query

  defp apply_policy_decision(query, nil), do: query

  defp apply_policy_decision(query, "allow"),
    do: where(query, [a], a.policy_decision == ^:allow)

  defp apply_policy_decision(query, "deny"),
    do: where(query, [a], a.policy_decision == ^:deny)

  defp apply_policy_decision(query, _), do: query

  defp apply_principal_subject(query, nil), do: query

  defp apply_principal_subject(query, sub) when is_binary(sub) do
    # principal is stored as JSONB; use Ecto fragment to compare
    where(query, [a], fragment("?->>'subject' = ?", a.principal, ^sub))
  end

  defp apply_principal_subject(query, _), do: query

  defp apply_since(query, nil), do: query

  defp apply_since(query, ts) when is_binary(ts) do
    case DateTime.from_iso8601(ts) do
      {:ok, dt, _offset} -> where(query, [a], a.timestamp >= ^dt)
      _ -> query
    end
  end

  defp apply_since(query, _), do: query

  defp apply_until(query, nil), do: query

  defp apply_until(query, ts) when is_binary(ts) do
    case DateTime.from_iso8601(ts) do
      {:ok, dt, _offset} -> where(query, [a], a.timestamp <= ^dt)
      _ -> query
    end
  end

  defp apply_until(query, _), do: query

  defp safe_to_existing_atom(s) when is_binary(s) do
    String.to_existing_atom(s)
  rescue
    ArgumentError -> nil
  end

  defp safe_to_existing_atom(_), do: nil

  defp to_summary(%Attestation{} = att) do
    %{
      "run_id" => att.run_id,
      "event_kind" => att.event_kind |> to_string(),
      "policy_decision" => att.policy_decision |> to_string(),
      "timestamp" => att.timestamp |> DateTime.to_iso8601(),
      "principal_subject" => principal_subject(att.principal),
      "summary" => build_summary(att)
    }
  end

  defp principal_subject(%{"subject" => s}) when is_binary(s), do: s
  defp principal_subject(%{"account_id" => s}) when is_binary(s), do: s
  defp principal_subject(_), do: "unknown"

  defp build_summary(%Attestation{event_kind: ek, policy_decision: pd}) do
    "#{pd} #{ek}" |> String.slice(0, 200)
  end
end
