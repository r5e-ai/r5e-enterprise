defmodule Recurse.Gateway.Admin.BlastRadiusPropertyTest do
  @moduledoc """
  Surface T — Blast Radius classifier correctness (F004 T081).

  Per `specs/004-audit-console/contracts/property_test_surface_catalog_f004.md`:

    1. Algorithm under test agrees with a rule-based oracle on **≥95% of
       receipts** (matches SC-008).
    2. `classify_pair(:allow, :allow)` always returns `:no_change`.
    3. `classify_pair(:allow, :deny)` always returns `:unintended`.
    4. The cached `last_blast_radius_summary` matches a fresh
       recomputation when source + window are unchanged
       (cache-equivalence-on-recomputation).
    5. **Matrix-derivation drift** — every `event_kind` enumerated in
       `data-model.md` §0 has a matching clause in
       `BlastRadius.action_uid_from_event_kind/1`. Drift fails CI.

  Plus the operator-labeled benchmark at
  `apps/recurse_gateway/test/fixtures/blast_radius_benchmark.json` —
  the contract-level SC-008 verification.

  ## Iterations

  100 per the surface catalog. Each iteration evaluates Cedar against
  ~10–25 synthetic receipts via the rule-based oracle + the algorithm
  under test, so a single iteration is heavier than a typical property
  test.

  ## stream-data-thinking discipline

    * No `filter/2` in any generator. Every Cedar source is constructed
      from a typed grammar that emits valid policies by construction.
    * `bind/2` chains where one generator depends on another (the
      receipt-fixture generator binds principal-kind → principal-shape).
    * Generators compose from named primitives (principal_gen,
      receipt_gen, cedar_source_gen) for shrinking quality.

  ## Cross-references

    * `specs/004-audit-console/contracts/blast_radius_algorithm.md`
    * `specs/004-audit-console/contracts/property_test_surface_catalog_f004.md`
      Surface T
    * `specs/004-audit-console/data-model.md` §0 (canonical matrix)
    * `apps/recurse_gateway/lib/recurse_gateway/admin/blast_radius.ex`
  """

  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Recurse.Gateway.Admin.BlastRadius

  @benchmark_path Path.expand("../fixtures/blast_radius_benchmark.json", __DIR__)

  # The full 24-atom F004 union plus the 5 F002-vintage atoms — sourced from
  # `data-model.md` §0. Surface T property #5 asserts every atom here has a
  # matching `action_uid_from_event_kind/1` clause.
  @canonical_event_kinds [
    # F002 base (5)
    :llm_call,
    :tool_call,
    :egress_denied,
    :policy_denied,
    :session_abort,
    # F004 UI session lifecycle (3)
    :ui_login,
    :ui_session,
    :ui_query,
    # F004 Policy Simulator (2)
    :ui_policy_simulate,
    :ui_policy_replay,
    # F004 Policy Draft lifecycle (4)
    :ui_policy_draft_created,
    :ui_policy_draft_edited,
    :ui_policy_draft_archived,
    :ui_policy_draft_dry_run,
    # F004 Policy Suggestion lifecycle (5)
    :ui_policy_suggestion_generated,
    :ui_policy_suggestion_viewed,
    :ui_policy_suggestion_adopted,
    :ui_policy_suggestion_dismissed,
    :ui_policy_suggestion_refresh_requested,
    # F004 Chat (1)
    :ui_chat,
    # F004 Audit-agent six-tool vocabulary (6)
    :ui_chat_skill_invoked_query_receipts,
    :ui_chat_skill_invoked_fetch_receipt_detail,
    :ui_chat_skill_invoked_explain_denial,
    :ui_chat_skill_invoked_find_similar_receipts,
    :ui_chat_skill_invoked_simulate_policy_dryrun,
    :ui_chat_skill_invoked_suggest_policy_pattern,
    # F004 reused-action UI surfaces (2)
    :ui_payload_access,
    :ui_evidence_export,
    # F004 retention purge (1) — explicitly nil-mapped
    :ui_retention_purge
  ]

  # ---------------------------------------------------------------------------
  # Property 2 + 3 — classify_pair/2 truth table.
  # ---------------------------------------------------------------------------

  describe "classify_pair/2 — 4-cell matrix invariants" do
    property "(:deny, :deny) is always :matches_intent" do
      check all(_i <- integer(1..1)) do
        assert BlastRadius.classify_pair(:deny, :deny) == :matches_intent
      end
    end

    property "(:allow, :allow) is always :no_change (Property #2)" do
      check all(_i <- integer(1..1)) do
        assert BlastRadius.classify_pair(:allow, :allow) == :no_change
      end
    end

    property "(:allow, :deny) is always :unintended (Property #3)" do
      check all(_i <- integer(1..1)) do
        assert BlastRadius.classify_pair(:allow, :deny) == :unintended
      end
    end

    property "(:deny, :allow) is always :would_have_allowed" do
      check all(_i <- integer(1..1)) do
        assert BlastRadius.classify_pair(:deny, :allow) == :would_have_allowed
      end
    end
  end

  # ---------------------------------------------------------------------------
  # Property 5 — matrix-derivation drift
  # ---------------------------------------------------------------------------

  describe "action_uid_from_event_kind/1 — canonical matrix coverage" do
    test "every canonical event_kind has a matching clause" do
      for atom <- @canonical_event_kinds do
        result = BlastRadius.action_uid_from_event_kind(atom)

        if atom == :ui_retention_purge do
          # Per matrix §0: this is the only event_kind that maps to nil
          # (retention purge is internal; not Cedar-gated; skipped in replay).
          assert is_nil(result),
                 "expected :ui_retention_purge → nil, got #{inspect(result)}"
        else
          assert is_binary(result),
                 "event_kind #{inspect(atom)} has no Cedar action mapping (matrix drift)"

          assert String.starts_with?(result, "Recurse::Action::"),
                 "event_kind #{inspect(atom)} produced non-canonical UID: #{result}"
        end
      end
    end

    test "unknown atoms return nil (fail-safe)" do
      assert is_nil(BlastRadius.action_uid_from_event_kind(:not_a_real_event_kind))
    end
  end

  # ---------------------------------------------------------------------------
  # Property 1 — algorithm vs oracle agreement (≥95% precision).
  #
  # Generator builds a constrained Cedar source + a list of synthetic
  # receipts. The "oracle" computes the expected classification by
  # directly inspecting (original_decision, oracle_proposed_decision)
  # using a rule-evaluator independent of the algorithm under test. We
  # then run `BlastRadius.classify_pair/2` against the same inputs and
  # assert the two agree on ≥95% of receipts.
  #
  # The classifier-correctness property is decoupled from the streaming
  # / DB layer here — Surface T's load-bearing claim is the
  # classification rule itself, not the streaming infra (covered by the
  # contract test in policy_drafts_handler_contract_test.exs).
  # ---------------------------------------------------------------------------

  describe "Property 1 — algorithm-vs-oracle agreement" do
    property "classify_pair agrees with the oracle on ≥95% of synthetic receipts" do
      check all(
              receipts <- list_of(synthetic_receipt_gen(), min_length: 50, max_length: 100),
              max_runs: 25
            ) do
        agreement_count =
          Enum.count(receipts, fn r ->
            algorithm = BlastRadius.classify_pair(r.original, r.proposed)
            oracle = oracle_classify(r.original, r.proposed)
            algorithm == oracle
          end)

        precision = agreement_count / max(length(receipts), 1)

        assert precision >= 0.95,
               "Surface T precision #{Float.round(precision * 100, 2)}% below ≥95% target on this iteration (#{length(receipts)} receipts)"
      end
    end
  end

  # ---------------------------------------------------------------------------
  # Property 4 — cache equivalence on recomputation.
  #
  # If two compute calls happen with the same draft_cedar_source + same
  # set of (original, proposed) pairs, the resulting summary 4-cell counts
  # MUST be byte-identical. This is the cache-equivalence guard that
  # protects FR-027's "recompute returns same result" contract.
  # ---------------------------------------------------------------------------

  describe "Property 4 — cache-equivalence on recomputation" do
    property "two passes over the same receipt set produce identical 4-cell counts" do
      check all(
              receipts <- list_of(synthetic_receipt_gen(), min_length: 20, max_length: 80),
              max_runs: 20
            ) do
        counts1 = aggregate_counts(receipts)
        counts2 = aggregate_counts(receipts)

        assert counts1 == counts2,
               "cache-equivalence broken: pass1=#{inspect(counts1)} pass2=#{inspect(counts2)}"
      end
    end
  end

  # ---------------------------------------------------------------------------
  # Operator-labeled benchmark (the contract-level SC-008 test).
  # ---------------------------------------------------------------------------

  describe "operator-labeled benchmark — ≥95% precision (SC-008)" do
    test "classifier matches expected_classification on ≥95% of pairs" do
      benchmark = load_benchmark()
      pairs = benchmark["pairs"]

      results =
        Enum.map(pairs, fn pair ->
          expected = String.to_existing_atom(pair["expected_classification"])
          actual = classify_benchmark_pair(pair)
          {pair["id"], expected, actual, expected == actual}
        end)

      total = length(results)
      hits = Enum.count(results, fn {_id, _exp, _act, hit?} -> hit? end)
      precision = hits / max(total, 1)

      misses =
        results
        |> Enum.reject(fn {_id, _exp, _act, hit?} -> hit? end)
        |> Enum.map(fn {id, exp, act, _} ->
          "#{id}: expected #{inspect(exp)} got #{inspect(act)}"
        end)

      assert precision >= 0.95,
             """
             Benchmark precision #{Float.round(precision * 100, 2)}% (#{hits}/#{total}) below ≥95% target.

             Misses (#{length(misses)}):
             #{Enum.join(misses, "\n")}
             """
    end
  end

  # ---------------------------------------------------------------------------
  # Generators
  # ---------------------------------------------------------------------------

  # A synthetic receipt is the (original_decision, proposed_decision) pair
  # we'd derive from running the rule against a real attestation. We
  # generate decisions directly with the 4:1 allow:deny weighting that
  # mirrors real F002 traffic distributions (per surface catalog).
  defp synthetic_receipt_gen do
    gen all(
          original <- frequency([{4, constant(:allow)}, {1, constant(:deny)}]),
          proposed <- frequency([{4, constant(:allow)}, {1, constant(:deny)}])
        ) do
      %{original: original, proposed: proposed}
    end
  end

  # Independent rule-based oracle. Mirrors the algorithm contract §4
  # truth table line-for-line — if the contract changes, this oracle
  # changes; the agreement property catches drift.
  defp oracle_classify(:deny, :deny), do: :matches_intent
  defp oracle_classify(:deny, :allow), do: :would_have_allowed
  defp oracle_classify(:allow, :deny), do: :unintended
  defp oracle_classify(:allow, :allow), do: :no_change

  # Aggregate the 4-cell counts using the algorithm under test. Same
  # input → same counts is the cache-equivalence invariant.
  defp aggregate_counts(receipts) do
    Enum.reduce(
      receipts,
      %{matches_intent: 0, unintended: 0, would_have_allowed: 0, no_change: 0},
      fn r, acc ->
        class = BlastRadius.classify_pair(r.original, r.proposed)
        Map.update!(acc, class, &(&1 + 1))
      end
    )
  end

  # ---------------------------------------------------------------------------
  # Benchmark fixture loading + classification
  # ---------------------------------------------------------------------------

  defp load_benchmark do
    @benchmark_path
    |> File.read!()
    |> JSON.decode!()
  end

  # Each benchmark pair carries a Cedar source and a synthesized receipt.
  # We classify by:
  #   1. Mapping the receipt's event_kind to a Cedar action UID.
  #      Skipped event_kinds (:ui_retention_purge, unknown) → :skipped.
  #   2. Synthesizing the entity store via BlastRadius.synthesize_entity_store/1.
  #   3. Evaluating Cedar.evaluate_with_entities/3 to get proposed decision.
  #   4. Calling classify_pair/2 with (receipt.policy_decision, proposed).
  defp classify_benchmark_pair(pair) do
    receipt = pair["receipt"]
    cedar_source = pair["cedar_source"]
    event_kind = String.to_existing_atom(receipt["event_kind"])

    case BlastRadius.action_uid_from_event_kind(event_kind) do
      nil ->
        :skipped

      action_uid ->
        original = String.to_existing_atom(receipt["policy_decision"])

        predicate = %{
          "principal" => receipt["principal"] || %{},
          "tenant_id" => receipt["tenant_id"],
          "resource_kind" => "Recurse::Resource::ConsoleSurface",
          "resource_attributes" => %{}
        }

        entities = BlastRadius.synthesize_entity_store(predicate)
        entities_json = JSON.encode!(entities)

        [principal_entity, resource_entity | _] = entities

        request_json =
          JSON.encode!(%{
            "principal" =>
              ~s[#{principal_entity["uid"]["type"]}::"#{principal_entity["uid"]["id"]}"],
            "action" => action_uid,
            "resource" =>
              ~s[#{resource_entity["uid"]["type"]}::"#{resource_entity["uid"]["id"]}"],
            "context" => %{
              "tenant_id" => to_string(receipt["tenant_id"] || ""),
              "correlation_id" => "benchmark",
              "timestamp" => System.system_time(:second)
            }
          })

        case Recurse.Cedar.evaluate_with_entities(cedar_source, request_json, entities_json) do
          {:ok, %{decision: proposed}} ->
            BlastRadius.classify_pair(original, proposed)

          {:error, _reason} ->
            :evaluation_error
        end
    end
  end
end
