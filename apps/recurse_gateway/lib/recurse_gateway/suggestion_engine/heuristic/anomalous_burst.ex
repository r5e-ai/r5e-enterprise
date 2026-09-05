defmodule Recurse.Gateway.SuggestionEngine.Heuristic.AnomalousBurst do
  @moduledoc """
  Heuristic pattern 3 of 5 — **`anomalous_burst`** (research D3 §3).

  > Any (principal, tool) tuple with ≥3 receipts in the last 24h after
  > 0 in the prior 30 days, where principal isn't a service account —
  > suggest explicit deny pending review. Surfaces novel agent
  > behaviors.

  Deterministic, pure-function detector. The "last 24h" window is
  computed relative to the **maximum committed_at** across the input
  receipts (NOT `DateTime.utc_now/0`) — this keeps the detector
  reproducible across two invocations on the same window even if
  wall-clock time advances between calls.

  Service accounts are excluded (`principal_kind == :service_account`)
  because automated workloads are expected to burst.

  ## Confidence scoring

  Confidence = `min(90, 70 + count_in_24h * 2)`. Higher base than
  recurring_allow because a no-history-then-burst pattern is
  intrinsically suspicious.
  """

  alias Recurse.Gateway.SuggestionEngine.Heuristic

  @recent_threshold 3

  @spec detect([Heuristic.receipt()]) :: [Heuristic.suggestion()]
  def detect([]), do: []

  def detect(receipts) when is_list(receipts) do
    sorted = Heuristic.chronological(receipts)
    {recent_window_end, recent_window_start} = recent_window(sorted)

    sorted
    |> Enum.group_by(fn r -> {r.principal_subject, r.action_label} end)
    |> Enum.flat_map(fn {{subject, action}, group} ->
      build_for_group(subject, action, group, recent_window_start, recent_window_end)
    end)
    |> Heuristic.sort()
  end

  defp recent_window(sorted) do
    %{committed_at: latest} = List.last(sorted)
    {latest, DateTime.add(latest, -24, :hour)}
  end

  defp build_for_group(subject, action, group, recent_start, recent_end) do
    {recent, prior} =
      Enum.split_with(group, fn r ->
        DateTime.compare(r.committed_at, recent_start) != :lt and
          DateTime.compare(r.committed_at, recent_end) != :gt
      end)

    recent_count = length(recent)

    cond do
      recent_count < @recent_threshold ->
        []

      prior != [] ->
        []

      service_account?(group) ->
        []

      true ->
        [build_suggestion(subject, action, recent_count)]
    end
  end

  defp service_account?(group) do
    Enum.all?(group, fn r ->
      Map.get(r, :principal_kind, :obo_human) == :service_account
    end)
  end

  defp build_suggestion(subject, action, recent_count) do
    summary =
      Heuristic.trim(
        "#{Heuristic.subject_excerpt(subject)} invoked #{action} #{recent_count} times " <>
          "in the last 24h with no prior history — review for anomalous activity.",
        200
      )

    cedar =
      Heuristic.trim(
        ~s|// novel pattern detected — pending operator review\n| <>
          ~s|forbid (principal == Recurse::Principal::Human::"#{subject}", | <>
          ~s|action == Recurse::Action::"#{action}", | <>
          ~s|resource);|,
        500
      )

    %{
      pattern_name: :anomalous_burst,
      principal_subject_hash: Heuristic.subject_hash(subject),
      action_hash: Heuristic.action_hash(action),
      principal_subject_excerpt: Heuristic.subject_excerpt(subject),
      action_label: action,
      confidence_score: min(90, 70 + recent_count * 2),
      pattern_summary: summary,
      proposed_cedar: cedar
    }
  end
end
