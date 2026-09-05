defmodule Recurse.Gateway.Admin.AuditAgent.Tools.FindSimilarReceipts do
  @moduledoc """
  Audit Agent Tool 4 — `find_similar_receipts` (F004 T112).

  Pure-SQL similarity over `(principal_subject, event_kind, resource_kind,
  tool_name)` axes. Returns receipts that share one or more of these
  dimensions with the seed receipt, scored by the count of matching
  dimensions / total dimensions considered.

  Cost: zero LLM tokens. Cedar action:
  `Recurse::Action::"AuditAgentToolFindSimilarReceipts"`. Required roles:
  `tenant_auditor` or `platform_operator`.

  Cross-references:
    * `specs/004-audit-console/contracts/audit_agent_tools.md` §"Tool 4"
  """

  @behaviour Recurse.Gateway.Admin.AuditAgent.Tool

  import Ecto.Query

  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Attestation
  alias Recurse.Providers.Repo

  @input_schema %{
    "type" => "object",
    "additionalProperties" => false,
    "required" => ["run_id"],
    "properties" => %{
      "run_id" => %{"type" => "string", "format" => "uuid"},
      "limit" => %{"type" => "integer", "minimum" => 1, "maximum" => 50, "default" => 10},
      "since" => %{"type" => "string", "format" => "date-time"}
    }
  }

  @output_schema %{
    "type" => "object",
    "required" => ["seed_run_id", "similar_receipts", "match_dimensions"],
    "properties" => %{
      "seed_run_id" => %{"type" => "string"},
      "match_dimensions" => %{"type" => "array", "items" => %{"type" => "string"}},
      "similar_receipts" => %{"type" => "array"}
    }
  }

  @impl true
  def name, do: "find_similar_receipts"

  @impl true
  def cedar_action, do: ~s|Recurse::Action::"AuditAgentToolFindSimilarReceipts"|

  @impl true
  def event_kind, do: :ui_chat_skill_invoked_find_similar_receipts

  @impl true
  def input_schema, do: @input_schema

  @impl true
  def output_schema, do: @output_schema

  @impl true
  def call(input, %{tenant_id: tenant_id}) when is_map(input) and is_binary(tenant_id) do
    run_id = Map.fetch!(input, "run_id")
    limit = Map.get(input, "limit", 10) |> clamp_limit()
    since = parse_since(Map.get(input, "since"))

    case safe_get(run_id) do
      nil ->
        {:error, :not_found}

      %Attestation{tenant_id: tid} when tid != tenant_id ->
        {:error, :not_found}

      %Attestation{} = seed ->
        seed_subject = principal_subject(seed.principal)
        seed_event_kind = seed.event_kind

        match_dimensions = ["principal_subject", "event_kind"]

        candidates =
          Attestation
          |> where([a], a.tenant_id == ^tenant_id)
          |> where([a], a.run_id != ^run_id)
          |> apply_since(since)
          |> where(
            [a],
            fragment("?->>'subject' = ?", a.principal, ^seed_subject) or
              a.event_kind == ^seed_event_kind
          )
          |> order_by([a], desc: a.timestamp)
          |> limit(^limit)
          |> Repo.all()

        similar =
          Enum.map(candidates, fn att ->
            score = compute_score(seed, att, seed_subject, seed_event_kind)

            %{
              "run_id" => att.run_id,
              "timestamp" => att.timestamp |> DateTime.to_iso8601(),
              "summary" => "#{att.policy_decision} #{att.event_kind}",
              "match_score" => score
            }
          end)

        {:ok,
         %{
           "seed_run_id" => run_id,
           "match_dimensions" => match_dimensions,
           "similar_receipts" => similar,
           "attested_run_ids" => [run_id]
         }}
    end
  end

  defp clamp_limit(n) when is_integer(n) and n > 0 and n <= 50, do: n
  defp clamp_limit(_), do: 10

  defp parse_since(nil), do: nil

  defp parse_since(ts) when is_binary(ts) do
    case DateTime.from_iso8601(ts) do
      {:ok, dt, _offset} -> dt
      _ -> nil
    end
  end

  defp apply_since(query, nil), do: query
  defp apply_since(query, dt), do: where(query, [a], a.timestamp >= ^dt)

  defp safe_get(run_id) do
    Repo.get(Attestation, run_id)
  rescue
    Ecto.Query.CastError -> nil
  end

  defp principal_subject(%{"subject" => s}) when is_binary(s), do: s
  defp principal_subject(%{"account_id" => s}) when is_binary(s), do: s
  defp principal_subject(_), do: "unknown"

  defp compute_score(_seed, att, seed_subject, seed_event_kind) do
    matches = 0
    matches = if principal_subject(att.principal) == seed_subject, do: matches + 1, else: matches
    matches = if att.event_kind == seed_event_kind, do: matches + 1, else: matches
    # Two dimensions considered (principal_subject, event_kind); scale to [0, 1].
    matches / 2
  end
end
