defmodule Recurse.Gateway.SuggestionEngine.Heuristic.RecurringDeny do
  @moduledoc """
  Heuristic pattern 2 of 5 — **`recurring_deny`** (research D3 §2).

  > For any (principal, action, resource_kind) tuple with ≥10 receipts
  > where 100% are denied by the same matched_policy, suggest narrowing
  > or removing the deny so legitimate-looking-now-blocked traffic gets
  > reconsidered. Surfaces over-broad rules.

  Deterministic, pure-function detector. One suggestion per
  `(principal, action, resource_kind)` tuple per cycle. The
  `matched_policy` field on the receipt drives the "same policy"
  criterion; receipts whose `matched_policy` differs across the group
  are excluded.

  ## Confidence scoring

  Confidence = `min(95, 60 + count_of_denies)`. Higher than
  recurring_allow because a unanimous over-broad-deny pattern is a
  strong actionable signal even at small counts.
  """

  alias Recurse.Gateway.SuggestionEngine.Heuristic

  @threshold 10

  @spec detect([Heuristic.receipt()]) :: [Heuristic.suggestion()]
  def detect(receipts) when is_list(receipts) do
    receipts
    |> Heuristic.chronological()
    |> Enum.group_by(fn r -> {r.principal_subject, r.action_label, r.resource_kind} end)
    |> Enum.flat_map(fn {{subject, action, resource_kind}, group} ->
      build_for_group(subject, action, resource_kind, group)
    end)
    |> Heuristic.sort()
  end

  defp build_for_group(subject, action, resource_kind, group) do
    deny_count = length(group)

    cond do
      deny_count < @threshold ->
        []

      not Enum.all?(group, &(&1.policy_decision == :deny)) ->
        []

      not unanimous_matched_policy?(group) ->
        []

      true ->
        matched = Map.get(hd(group), :matched_policy) || "unknown"
        [build_suggestion(subject, action, resource_kind, deny_count, matched)]
    end
  end

  defp unanimous_matched_policy?(group) do
    case Enum.uniq_by(group, &Map.get(&1, :matched_policy)) do
      [%{matched_policy: mp}] when not is_nil(mp) -> true
      _ -> false
    end
  end

  defp build_suggestion(subject, action, resource_kind, deny_count, matched) do
    summary =
      Heuristic.trim(
        "#{Heuristic.subject_excerpt(subject)} denied #{deny_count} times by " <>
          "#{matched} for #{action} — consider narrowing the rule.",
        200
      )

    # The proposed change is a narrower forbid that scopes the existing
    # deny only to a specific principal so an operator can review the
    # over-broad parent rule. We do NOT auto-emit a permit — that is the
    # operator's call.
    cedar =
      Heuristic.trim(
        ~s|// review the over-broad deny "#{matched}" — it currently blocks #{action}\n| <>
          ~s|forbid (principal == Recurse::Principal::Human::"#{subject}", | <>
          ~s|action == Recurse::Action::"#{action}", | <>
          ~s|resource is #{resource_kind});|,
        500
      )

    %{
      pattern_name: :recurring_deny,
      principal_subject_hash: Heuristic.subject_hash(subject),
      action_hash: Heuristic.action_hash(action),
      principal_subject_excerpt: Heuristic.subject_excerpt(subject),
      action_label: action,
      confidence_score: min(95, 60 + deny_count),
      pattern_summary: summary,
      proposed_cedar: cedar
    }
  end
end
