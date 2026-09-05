defmodule Recurse.Gateway.SuggestionEngine.Heuristic.RecurringAllow do
  @moduledoc """
  Heuristic pattern 1 of 5 — **`recurring_allow`** (research D3 §1).

  > For any (principal, action, resource_kind) tuple with ≥50 receipts and
  > 0 denies in the window, suggest an explicit allow rule. Captures the
  > "alice@corp uses search_kb 423 times — codify it" case.

  Deterministic, pure-function detector. Pattern surfaces *codify-existing-
  behavior* opportunities (vs the deny-class patterns which surface
  *security regressions*). One suggestion per `(principal, action,
  resource_kind)` tuple per cycle.

  ## Confidence scoring

  Confidence = `min(99, 50 + count_of_allows / 10)`. A tuple with 50
  allows scores 55; 200 allows scores 70; 500 allows scores 99 (capped).
  Linear-ish; reflects the fact that the bar (≥50) already cut out
  low-volume noise so the marginal confidence-per-receipt is small.
  """

  alias Recurse.Gateway.SuggestionEngine.Heuristic

  @threshold 50

  @doc """
  Scan `receipts` for `(principal, action, resource_kind)` tuples meeting
  the `recurring_allow` rule. Returns a list of suggestion maps in the
  shape documented in `Heuristic`.
  """
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
    {allows, denies} = Enum.split_with(group, &(&1.policy_decision == :allow))
    allow_count = length(allows)

    if allow_count >= @threshold and denies == [] do
      [build_suggestion(subject, action, resource_kind, allow_count)]
    else
      []
    end
  end

  defp build_suggestion(subject, action, resource_kind, allow_count) do
    summary =
      Heuristic.trim(
        "#{Heuristic.subject_excerpt(subject)} invoked #{action} #{allow_count} times " <>
          "with 0 denies — consider an explicit allow rule.",
        200
      )

    cedar =
      Heuristic.trim(
        ~s|permit (principal == Recurse::Principal::Human::"#{subject}", | <>
          ~s|action == Recurse::Action::"#{action}", | <>
          ~s|resource is #{resource_kind});|,
        500
      )

    %{
      pattern_name: :recurring_allow,
      principal_subject_hash: Heuristic.subject_hash(subject),
      action_hash: Heuristic.action_hash(action),
      principal_subject_excerpt: Heuristic.subject_excerpt(subject),
      action_label: action,
      confidence_score: min(99, 50 + div(allow_count, 10)),
      pattern_summary: summary,
      proposed_cedar: cedar
    }
  end
end
