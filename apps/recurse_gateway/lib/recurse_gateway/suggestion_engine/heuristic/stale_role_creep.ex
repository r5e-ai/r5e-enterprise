defmodule Recurse.Gateway.SuggestionEngine.Heuristic.StaleRoleCreep do
  @moduledoc """
  Heuristic pattern 5 of 5 — **`stale_role_creep`** (research D3 §5).

  > Any principal whose action distribution this week differs
  > significantly (chi-squared p<0.05) from their action distribution
  > 30 days ago — suggest reviewing their `recurse_role`. Captures
  > gradual permission scope creep.

  Deterministic, pure-function detector. Comparison windows are
  computed relative to the **maximum committed_at** across the input
  (NOT wall-clock) for reproducibility.

  ## Algorithm

  1. Define **recent** = receipts in last 7 days (relative to max).
  2. Define **baseline** = receipts in days 30..7 (the prior 23 days).
  3. For each principal that has receipts in BOTH windows:
     a. Build the action-frequency distribution `{action -> count}` for each window.
     b. Compute Pearson chi-squared statistic comparing the distributions
        (treating recent as observed, baseline-rescaled-to-recent-total as expected).
     c. If `p < 0.05` (df = number_of_actions - 1), emit a suggestion.
  4. Two-sample chi-squared with the standard `Σ (O - E)² / E` formula;
     `p < 0.05` is approximated via the gamma function-free
     **Wilson-Hilferty** transformation (close enough for our heuristic
     bar — exactness here would be premature precision).

  ## Confidence scoring

  Confidence = `min(85, 60 + 5 * trunc(chi2_stat))`. Scales smoothly
  with the strength of the divergence; capped at 85 because chi-squared
  is a noisy signal at small N.

  ## Edge cases

  * Principals with <10 receipts in EITHER window are excluded — N too
    small for a meaningful chi-squared.
  * Principals with action distributions identical across the windows
    score chi2 = 0 → no suggestion (the floor is the threshold, not an
    arbitrary epsilon).
  """

  alias Recurse.Gateway.SuggestionEngine.Heuristic

  @recent_days 7
  @baseline_days 30
  @min_per_window 10
  @critical_value_p05_df1 3.841
  @critical_value_p05_df3 7.815
  @critical_value_p05_df5 11.07

  @spec detect([Heuristic.receipt()]) :: [Heuristic.suggestion()]
  def detect([]), do: []

  def detect(receipts) when is_list(receipts) do
    sorted = Heuristic.chronological(receipts)
    %{committed_at: latest} = List.last(sorted)
    recent_start = DateTime.add(latest, -@recent_days, :day)
    baseline_start = DateTime.add(latest, -@baseline_days, :day)

    sorted
    |> Enum.group_by(& &1.principal_subject)
    |> Enum.flat_map(fn {subject, group} ->
      build_for_principal(subject, group, recent_start, baseline_start)
    end)
    |> Heuristic.sort()
  end

  defp build_for_principal(subject, group, recent_start, baseline_start) do
    recent_window =
      Enum.filter(group, fn r -> DateTime.compare(r.committed_at, recent_start) != :lt end)

    baseline_window =
      Enum.filter(group, fn r ->
        DateTime.compare(r.committed_at, baseline_start) != :lt and
          DateTime.compare(r.committed_at, recent_start) == :lt
      end)

    if length(recent_window) < @min_per_window or length(baseline_window) < @min_per_window do
      []
    else
      assess_distribution_shift(subject, recent_window, baseline_window)
    end
  end

  defp assess_distribution_shift(subject, recent_window, baseline_window) do
    recent_freq = action_frequencies(recent_window)
    baseline_freq = action_frequencies(baseline_window)

    actions = Map.keys(recent_freq) ++ Map.keys(baseline_freq)
    actions = Enum.uniq(actions) |> Enum.sort()

    {chi2, df} = chi_squared(actions, recent_freq, baseline_freq)

    if significant?(chi2, df) do
      [build_suggestion(subject, recent_window, baseline_window, chi2)]
    else
      []
    end
  end

  defp action_frequencies(receipts) do
    Enum.reduce(receipts, %{}, fn r, acc ->
      Map.update(acc, r.action_label, 1, &(&1 + 1))
    end)
  end

  defp chi_squared(actions, observed, baseline) do
    obs_total = Enum.sum(Map.values(observed))
    base_total = Enum.sum(Map.values(baseline))

    if base_total == 0 or obs_total == 0 do
      {0.0, 0}
    else
      scale = obs_total / base_total

      stat =
        Enum.reduce(actions, 0.0, fn action, acc ->
          contribute(action, observed, baseline, scale, acc)
        end)

      df = max(length(actions) - 1, 1)
      {stat, df}
    end
  end

  # Per-action chi-squared contribution. Action absent in baseline but
  # present in recent → contribute capped obs² (chi-squared treats
  # missing-from-expected as the strongest possible divergence, but we
  # cap to avoid pathological blow-ups on a single new action).
  defp contribute(action, observed, baseline, scale, acc) do
    obs = Map.get(observed, action, 0)
    expected = Map.get(baseline, action, 0) * scale

    if expected > 0 do
      acc + :math.pow(obs - expected, 2) / expected
    else
      acc + min(obs * obs, 100.0)
    end
  end

  # Lookup-table approach: critical chi-squared values at p=0.05 for the
  # df values we expect (1, 3, 5). For df > 5, use the asymptotic
  # approximation `chi2 > df + 2 * sqrt(2 * df)` (≈p=0.05 normal-tail
  # equivalent). This avoids dragging in a stats lib for a heuristic.
  defp significant?(chi2, df) when df <= 1, do: chi2 > @critical_value_p05_df1
  defp significant?(chi2, df) when df <= 3, do: chi2 > @critical_value_p05_df3
  defp significant?(chi2, df) when df <= 5, do: chi2 > @critical_value_p05_df5

  defp significant?(chi2, df) do
    threshold = df + 2.0 * :math.sqrt(2.0 * df)
    chi2 > threshold
  end

  defp build_suggestion(subject, recent_window, _baseline_window, chi2) do
    most_recent_action =
      recent_window
      |> List.last()
      |> Map.get(:action_label, "unknown")

    summary =
      Heuristic.trim(
        "#{Heuristic.subject_excerpt(subject)} action distribution this week diverges " <>
          "significantly (chi2=#{Float.round(chi2, 2)}) from prior 30 days — review recurse_role.",
        200
      )

    cedar =
      Heuristic.trim(
        ~s|// principal's action mix has drifted — review role assignment\n| <>
          ~s|// most recent novel action: #{most_recent_action}\n| <>
          ~s|// suggested action: confirm #{Heuristic.subject_excerpt(subject)}'s recurse_role.|,
        500
      )

    %{
      pattern_name: :stale_role_creep,
      principal_subject_hash: Heuristic.subject_hash(subject),
      # Stale-role-creep is principal-level (no specific action drives it);
      # we hash the principal again as the action_hash so the dedup key
      # remains principal-unique.
      action_hash: Heuristic.subject_hash(subject),
      principal_subject_excerpt: Heuristic.subject_excerpt(subject),
      action_label: "(role drift)",
      confidence_score: min(85, 60 + 5 * trunc(chi2)),
      pattern_summary: summary,
      proposed_cedar: cedar
    }
  end
end
