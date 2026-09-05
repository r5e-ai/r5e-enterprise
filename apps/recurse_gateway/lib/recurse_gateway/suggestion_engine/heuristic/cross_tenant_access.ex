defmodule Recurse.Gateway.SuggestionEngine.Heuristic.CrossTenantAccess do
  @moduledoc """
  Heuristic pattern 4 of 5 — **`cross_tenant_access`** (research D3 §4).

  > Any principal accessing resources tagged with a tenant attribute
  > different from their home tenant — suggest scope restriction. (For
  > F004 single-tenant: this fires only on resources with explicit
  > `tenant_attribute` mismatches; uncommon but worth surfacing.)

  Deterministic, pure-function detector. The detector compares the
  receipt's `tenant_attribute` (resource side) against the principal's
  home tenant (`Map.get(receipt, :principal_tenant_id)`); when they
  differ, the (principal, action, resource_kind) tuple emits a
  suggestion. Receipts whose `tenant_attribute` is nil (the common case
  in single-tenant deployments) are skipped silently.

  ## Confidence scoring

  Confidence = `min(95, 70 + count_of_mismatches * 5)`. High base
  because cross-tenant access is a security-class signal; the
  per-mismatch step is steeper than recurring_allow because each one
  is independently meaningful.
  """

  alias Recurse.Gateway.SuggestionEngine.Heuristic

  @spec detect([Heuristic.receipt()]) :: [Heuristic.suggestion()]
  def detect(receipts) when is_list(receipts) do
    receipts
    |> Heuristic.chronological()
    |> Enum.filter(&mismatch?/1)
    |> Enum.group_by(fn r -> {r.principal_subject, r.action_label, r.resource_kind} end)
    |> Enum.map(fn {{subject, action, resource_kind}, group} ->
      build_suggestion(subject, action, resource_kind, length(group), group)
    end)
    |> Heuristic.sort()
  end

  defp mismatch?(receipt) do
    home = Map.get(receipt, :principal_tenant_id)
    resource = Map.get(receipt, :tenant_attribute)
    is_binary(home) and is_binary(resource) and home != resource
  end

  defp build_suggestion(subject, action, resource_kind, count, group) do
    foreign_tenant = Map.get(hd(group), :tenant_attribute, "<unknown>")

    summary =
      Heuristic.trim(
        "#{Heuristic.subject_excerpt(subject)} accessed #{resource_kind} in tenant " <>
          "#{foreign_tenant} (not their home tenant) #{count} times — restrict scope.",
        200
      )

    cedar =
      Heuristic.trim(
        ~s|// cross-tenant access detected — restrict to home tenant\n| <>
          ~s|forbid (principal == Recurse::Principal::Human::"#{subject}", | <>
          ~s|action == Recurse::Action::"#{action}", | <>
          ~s|resource is #{resource_kind})\n| <>
          ~s|when { resource.tenant_id != principal.tenant_id };|,
        500
      )

    %{
      pattern_name: :cross_tenant_access,
      principal_subject_hash: Heuristic.subject_hash(subject),
      action_hash: Heuristic.action_hash(action),
      principal_subject_excerpt: Heuristic.subject_excerpt(subject),
      action_label: action,
      confidence_score: min(95, 70 + count * 5),
      pattern_summary: summary,
      proposed_cedar: cedar
    }
  end
end
