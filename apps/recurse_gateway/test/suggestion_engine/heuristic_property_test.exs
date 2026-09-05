defmodule Recurse.Gateway.SuggestionEngine.HeuristicPropertyTest do
  @moduledoc """
  Surface U — Heuristic suggestion engine determinism (F004 T121).

  Per `specs/004-audit-console/contracts/property_test_surface_catalog_f004.md`
  §"Surface U":

    1. **Byte-equality** of two engine runs over the same window.
    2. **Reordering invariance** — running the engine on a shuffled
       copy of the same fixtures (then sorted by committed_at) produces
       the same suggestion set.
    3. **Per-pattern triggering** — each of the 5 patterns produces the
       expected suggestion shape against a hand-crafted fixture window.
    4. **Deduplication invariant** — two principals matching the same
       pattern produce two suggestions (one per principal), never one
       merged or three duplicates.
    5. **Deduplication key shape** — `(pattern_name,
       principal_subject_hash, action_hash)` is byte-stable; SHA-256-prefix
       16 bytes per pattern module.

  ## Iterations

  200 per the surface catalog. DB-free; pure-function patterns; cheap
  enough to run in default `mix test` without `--include property`.

  ## stream-data-thinking discipline

    * No `filter/2`. All generators construct receipts directly from
      typed components (principal subject, action label, decision,
      committed_at).
    * `bind/2` chains keep timestamp drift bounded so windows remain
      chronologically valid.
    * Shrinking shrinks scalar fields cleanly — minimal failure cases
      reveal which pattern fires (or fails to dedup) on the smallest
      possible window.

  ## Cross-references

    * `apps/recurse_gateway/lib/recurse_gateway/suggestion_engine/heuristic.ex`
    * `apps/recurse_gateway/lib/recurse_gateway/suggestion_engine/heuristic/*.ex`
    * `specs/004-audit-console/research.md` D3 (5-pattern set)
  """

  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Recurse.Gateway.SuggestionEngine.Heuristic
  alias Recurse.Gateway.SuggestionEngine.Heuristic.AnomalousBurst
  alias Recurse.Gateway.SuggestionEngine.Heuristic.CrossTenantAccess
  alias Recurse.Gateway.SuggestionEngine.Heuristic.RecurringAllow
  alias Recurse.Gateway.SuggestionEngine.Heuristic.RecurringDeny
  alias Recurse.Gateway.SuggestionEngine.Heuristic.StaleRoleCreep

  @principals ~w(alice@corp bob@corp carol@corp dan@corp eve@corp)
  @actions ~w(search_kb chat_completion bash_exec http_get tool_call)
  @resources ~w(LLMEndpoint ToolCall Document)
  @patterns [RecurringAllow, RecurringDeny, AnomalousBurst, CrossTenantAccess, StaleRoleCreep]

  describe "Surface U property #1 — byte-equality across two runs" do
    property "same window produces same suggestions twice over" do
      check all(
              receipts <- receipt_window_gen(min: 50, max: 250),
              max_runs: 200
            ) do
        first = run_all_patterns(receipts)
        second = run_all_patterns(receipts)

        assert first == second
      end
    end
  end

  describe "Surface U property #2 — reordering invariance" do
    property "shuffling fixtures (then re-sort) produces same suggestion set" do
      check all(
              receipts <- receipt_window_gen(min: 50, max: 250),
              max_runs: 200
            ) do
        original = run_all_patterns(receipts)
        shuffled = Enum.shuffle(receipts)
        # Note: shuffled is reordered; pattern detectors call
        # `Heuristic.chronological/1` internally to re-sort, so the
        # shuffled fixture window MUST yield byte-identical output.
        reshuffled = run_all_patterns(shuffled)

        assert original == reshuffled
      end
    end
  end

  describe "Surface U property #3 — per-pattern triggering" do
    test "RecurringAllow triggers on ≥50 allows + 0 denies" do
      receipts = build_recurring_allow_window("alice@corp", "search_kb", 60)

      [suggestion] = RecurringAllow.detect(receipts)

      assert suggestion.pattern_name == :recurring_allow
      assert suggestion.principal_subject_excerpt == "alice@corp"
      assert suggestion.action_label == "search_kb"
      assert byte_size(suggestion.principal_subject_hash) == 16
      assert byte_size(suggestion.action_hash) == 16
      assert suggestion.confidence_score >= 50 and suggestion.confidence_score <= 99
    end

    test "RecurringDeny triggers on ≥10 unanimous denies by same matched_policy" do
      receipts = build_recurring_deny_window("bob@corp", "bash_exec", 12)

      [suggestion] = RecurringDeny.detect(receipts)

      assert suggestion.pattern_name == :recurring_deny
      assert suggestion.principal_subject_excerpt == "bob@corp"
      assert suggestion.action_label == "bash_exec"
      assert byte_size(suggestion.principal_subject_hash) == 16
      assert byte_size(suggestion.action_hash) == 16
      assert suggestion.confidence_score >= 60
    end

    test "AnomalousBurst triggers on ≥3 in-24h after 0-prior-30d (non-service-account)" do
      receipts = build_burst_window("carol@corp", "http_get", 4)

      [suggestion] = AnomalousBurst.detect(receipts)

      assert suggestion.pattern_name == :anomalous_burst
      assert suggestion.principal_subject_excerpt == "carol@corp"
      assert suggestion.action_label == "http_get"
    end

    test "AnomalousBurst suppresses service accounts" do
      receipts =
        "svc-bot"
        |> build_burst_window("http_get", 4)
        |> Enum.map(&Map.put(&1, :principal_kind, :service_account))

      assert [] = AnomalousBurst.detect(receipts)
    end

    test "CrossTenantAccess triggers on tenant_attribute mismatch" do
      receipts = build_cross_tenant_window("dan@corp", "search_kb", 3)

      [suggestion] = CrossTenantAccess.detect(receipts)

      assert suggestion.pattern_name == :cross_tenant_access
      assert suggestion.principal_subject_excerpt == "dan@corp"
      assert suggestion.action_label == "search_kb"
      assert suggestion.confidence_score >= 75
    end

    test "StaleRoleCreep triggers on chi-squared distribution drift" do
      receipts = build_role_creep_window("eve@corp")

      suggestions = StaleRoleCreep.detect(receipts)

      assert length(suggestions) == 1
      [suggestion] = suggestions
      assert suggestion.pattern_name == :stale_role_creep
      assert suggestion.principal_subject_excerpt == "eve@corp"
    end
  end

  describe "Surface U property #4 — deduplication" do
    test "two principals matching the same pattern produce two suggestions" do
      window =
        build_recurring_allow_window("alice@corp", "search_kb", 60) ++
          build_recurring_allow_window("bob@corp", "search_kb", 55)

      suggestions = RecurringAllow.detect(window)

      assert length(suggestions) == 2

      assert Enum.map(suggestions, & &1.principal_subject_excerpt)
             |> Enum.sort() == ["alice@corp", "bob@corp"]
    end

    test "same principal in same pattern emits exactly one suggestion (no triplication)" do
      # 100 receipts for one principal — should yield exactly one
      # suggestion (one per (principal, action, resource_kind) tuple).
      window = build_recurring_allow_window("alice@corp", "search_kb", 100)

      assert [_one] = RecurringAllow.detect(window)
    end
  end

  describe "Surface U property #5 — dedup key shape" do
    test "principal_subject_hash and action_hash are 16-byte SHA-256 prefixes" do
      sha256_prefix_alice = :crypto.hash(:sha256, "alice@corp") |> binary_part(0, 16)
      sha256_prefix_action = :crypto.hash(:sha256, "search_kb") |> binary_part(0, 16)

      assert Heuristic.subject_hash("alice@corp") == sha256_prefix_alice
      assert Heuristic.action_hash("search_kb") == sha256_prefix_action
    end

    test "Heuristic.sort/1 ordering is by (pattern_name, subject_hash, action_hash)" do
      window =
        build_recurring_allow_window("zeta@corp", "search_kb", 60) ++
          build_recurring_allow_window("alpha@corp", "search_kb", 60)

      [first, second] = RecurringAllow.detect(window)

      # Sorted by principal_subject_hash (binary order); not by subject string.
      assert first.principal_subject_hash <= second.principal_subject_hash
    end

    property "dedup key components are deterministic across calls" do
      check all(
              subject <- StreamData.member_of(@principals),
              action <- StreamData.member_of(@actions),
              max_runs: 200
            ) do
        assert Heuristic.subject_hash(subject) == Heuristic.subject_hash(subject)
        assert Heuristic.action_hash(action) == Heuristic.action_hash(action)
      end
    end
  end

  # ---------------------------------------------------------------------------
  # Generators
  # ---------------------------------------------------------------------------

  # `committed_at` is bounded to the trailing 30 days so the
  # AnomalousBurst pattern's "no prior 30 days" check works correctly
  # (otherwise the property would silently never trigger that pattern).
  defp receipt_window_gen(opts) do
    min_count = Keyword.fetch!(opts, :min)
    max_count = Keyword.fetch!(opts, :max)

    StreamData.bind(
      StreamData.integer(min_count..max_count),
      fn count ->
        StreamData.list_of(receipt_gen(), length: count)
      end
    )
  end

  defp receipt_gen do
    gen all(
          principal <- StreamData.member_of(@principals),
          action <- StreamData.member_of(@actions),
          resource <- StreamData.member_of(@resources),
          decision <- decision_gen(),
          committed_at <- committed_at_gen()
        ) do
      %{
        principal_subject: principal,
        action_label: action,
        resource_kind: resource,
        policy_decision: decision,
        committed_at: committed_at,
        principal_kind: :obo_human,
        principal_tenant_id: "tenant-a",
        tenant_attribute: nil,
        matched_policy: nil
      }
    end
  end

  # 4:1 allow:deny weighting per the surface catalog spec.
  defp decision_gen do
    StreamData.frequency([
      {4, StreamData.constant(:allow)},
      {1, StreamData.constant(:deny)}
    ])
  end

  defp committed_at_gen do
    # Bounded to the trailing 30 days. We anchor on a fixed reference
    # time so two property runs that produce "the same" generator output
    # actually produce identical timestamps (no wall-clock drift across
    # the StreamData seed).
    reference = ~U[2026-04-24 00:00:00.000000Z]
    seconds_back = StreamData.integer(0..(30 * 86_400))

    StreamData.bind(seconds_back, fn s ->
      StreamData.constant(DateTime.add(reference, -s, :second))
    end)
  end

  # ---------------------------------------------------------------------------
  # Hand-crafted pattern-specific fixtures
  # ---------------------------------------------------------------------------

  defp build_recurring_allow_window(subject, action, count) do
    base = ~U[2026-04-24 00:00:00.000000Z]

    Enum.map(1..count, fn i ->
      %{
        principal_subject: subject,
        action_label: action,
        resource_kind: "LLMEndpoint",
        policy_decision: :allow,
        committed_at: DateTime.add(base, -i * 60, :second),
        principal_kind: :obo_human,
        principal_tenant_id: "tenant-a",
        tenant_attribute: nil,
        matched_policy: nil
      }
    end)
  end

  defp build_recurring_deny_window(subject, action, count) do
    base = ~U[2026-04-24 00:00:00.000000Z]

    Enum.map(1..count, fn i ->
      %{
        principal_subject: subject,
        action_label: action,
        resource_kind: "ToolCall",
        policy_decision: :deny,
        committed_at: DateTime.add(base, -i * 60, :second),
        principal_kind: :obo_human,
        principal_tenant_id: "tenant-a",
        tenant_attribute: nil,
        matched_policy: "platform_roles.cedar:line:42"
      }
    end)
  end

  defp build_burst_window(subject, action, recent_count) do
    # Anchor at a reference timestamp; recent burst lands 1 hour ago,
    # zero prior receipts in the window.
    base = ~U[2026-04-24 00:00:00.000000Z]

    Enum.map(1..recent_count, fn i ->
      %{
        principal_subject: subject,
        action_label: action,
        resource_kind: "LLMEndpoint",
        policy_decision: :allow,
        committed_at: DateTime.add(base, -i * 600, :second),
        principal_kind: :obo_human,
        principal_tenant_id: "tenant-a",
        tenant_attribute: nil,
        matched_policy: nil
      }
    end)
  end

  defp build_cross_tenant_window(subject, action, count) do
    base = ~U[2026-04-24 00:00:00.000000Z]

    Enum.map(1..count, fn i ->
      %{
        principal_subject: subject,
        action_label: action,
        resource_kind: "Document",
        policy_decision: :allow,
        committed_at: DateTime.add(base, -i * 60, :second),
        principal_kind: :obo_human,
        principal_tenant_id: "tenant-a",
        tenant_attribute: "tenant-foreign",
        matched_policy: nil
      }
    end)
  end

  # Crafted to trigger StaleRoleCreep:
  # - Recent 7 days: 100% one new action
  # - Prior 23 days (within 30): mostly different actions
  defp build_role_creep_window(subject) do
    base = ~U[2026-04-24 00:00:00.000000Z]

    recent =
      Enum.map(1..15, fn i ->
        receipt(subject, "bash_exec", DateTime.add(base, -i * 3600, :second))
      end)

    baseline =
      for offset <- 1..15, action <- ["search_kb", "chat_completion", "http_get"] do
        # Place baseline in days 8..30 (inclusive of 8th-day boundary)
        seconds_back = (8 + offset) * 86_400 + 3600
        receipt(subject, action, DateTime.add(base, -seconds_back, :second))
      end

    recent ++ baseline
  end

  defp receipt(subject, action, committed_at) do
    %{
      principal_subject: subject,
      action_label: action,
      resource_kind: "LLMEndpoint",
      policy_decision: :allow,
      committed_at: committed_at,
      principal_kind: :obo_human,
      principal_tenant_id: "tenant-a",
      tenant_attribute: nil,
      matched_policy: nil
    }
  end

  defp run_all_patterns(receipts) do
    @patterns
    |> Enum.flat_map(& &1.detect(receipts))
    |> Heuristic.sort()
  end
end
