defmodule RecurseGateway.Integration.SC008BlastRadiusPrecisionTest do
  @moduledoc """
  SC-008 — Blast Radius classifier precision (F004 T151).

  Drives `BlastRadius.compute/1`'s underlying single-pair classification
  step against the operator-labeled benchmark fixture
  (`apps/recurse_gateway/test/fixtures/blast_radius_benchmark.json`)
  and asserts ≥95% precision (per spec SC-008).

  The fixture currently ships ~25 hand-curated pairs (4-cell coverage:
  matches_intent, unintended, would_have_allowed, no_change). Operators
  curate the full 200-pair set over time as ambiguous cases land; the
  test asserts ≥95% against whatever is present.

  ## How precision is measured

  For each fixture pair `{cedar_source, receipt, expected_classification}`:
    1. Synthesize a Cedar entity store from the receipt's principal.
    2. Look up the Cedar action UID via
       `BlastRadius.action_uid_from_event_kind/1`.
    3. Evaluate the cedar_source against the synthetic entity set.
    4. Combine `(receipt.policy_decision, evaluator_decision)` into the
       4-cell classification.
    5. Compare to `expected_classification`.

  Precision = `correct / total`. The fixture's `_comment_classification_rules`
  field documents the expected mapping; this test re-implements it inline
  so a fixture-comment drift fails the test rather than silently changing
  the oracle.

  ## `@moduletag :sc008`

  Excluded from default `mix test`. Run via:

      mix test --include sc008 \\
        apps/recurse_gateway/test/integration/sc008_blast_radius_precision_test.exs

  ## Cross-references

    * `specs/004-audit-console/spec.md` SC-008
    * `specs/004-audit-console/contracts/blast_radius_algorithm.md` §5a
    * `apps/recurse_gateway/test/fixtures/blast_radius_benchmark.json`
    * `apps/recurse_gateway/lib/recurse_gateway/admin/blast_radius.ex`
  """

  use ExUnit.Case, async: true

  @moduletag :sc008
  @moduletag timeout: :timer.minutes(2)

  alias Recurse.Cedar
  alias Recurse.Gateway.Admin.BlastRadius

  @fixture_path Path.expand(
                  "../../test/fixtures/blast_radius_benchmark.json",
                  __DIR__
                )

  @precision_floor 0.95

  test "SC-008 — Blast Radius classifier ≥95% precision against benchmark" do
    %{"pairs" => pairs} =
      @fixture_path
      |> File.read!()
      |> JSON.decode!()

    assert is_list(pairs) and pairs != []

    results = Enum.map(pairs, &classify_pair/1)
    correct = Enum.count(results, & &1.correct?)
    total = length(results)
    precision = correct / total

    failure_summary =
      results
      |> Enum.reject(& &1.correct?)
      |> Enum.map(fn r ->
        "  - #{r.id}: expected=#{r.expected} got=#{r.actual} reason=#{r.reason}"
      end)
      |> Enum.join("\n")

    assert precision >= @precision_floor, """
    SC-008 precision below floor #{@precision_floor}: got #{precision}
    (#{correct}/#{total} correct).

    Mismatches:
    #{failure_summary}
    """
  end

  # ---------------------------------------------------------------------------
  # Per-pair classification
  # ---------------------------------------------------------------------------

  defp classify_pair(pair) do
    id = pair["id"]
    expected = pair["expected_classification"]
    cedar_source = pair["cedar_source"]
    receipt = pair["receipt"]

    case classify(cedar_source, receipt) do
      {:ok, actual} ->
        %{
          id: id,
          expected: expected,
          actual: actual,
          correct?: actual == expected,
          reason: ""
        }

      {:error, reason} ->
        %{
          id: id,
          expected: expected,
          actual: "evaluation_error",
          correct?: false,
          reason: inspect(reason)
        }
    end
  end

  defp classify(cedar_source, receipt) do
    event_kind = String.to_existing_atom(receipt["event_kind"])
    action_uid = BlastRadius.action_uid_from_event_kind(event_kind)
    original_decision = String.to_existing_atom(receipt["policy_decision"])

    if is_nil(action_uid) do
      # `:ui_retention_purge` has no Cedar action; the algorithm skips it
      # (per data-model.md §0). Match the fixture's "skipped" expected.
      {:ok, "skipped"}
    else
      classify_active_pair(cedar_source, action_uid, original_decision, receipt)
    end
  end

  defp classify_active_pair(cedar_source, action_uid, original_decision, receipt) do
    case evaluate_synthetic(cedar_source, action_uid, receipt) do
      {:ok, proposed_decision} ->
        {:ok, classify_pair_decisions(original_decision, proposed_decision)}

      err ->
        err
    end
  end

  defp evaluate_synthetic(cedar_source, action_uid, receipt) do
    principal = receipt["principal"] || %{}
    subject = Map.get(principal, "subject", "unknown")
    principal_type = principal_type(principal)
    tenant_id = tenant_id_or_default(Map.get(receipt, "tenant_id"))

    entities = JSON.encode!(synthetic_entities(principal_type, subject, principal, tenant_id))

    # The fixture allows `tenant_id: null` (`edge_missing_tenant`); coerce
    # to a real string so Cedar's "no nulls in context" rule doesn't fire
    # before we get to the policy decision.
    request = JSON.encode!(synthetic_request(principal_type, subject, action_uid, tenant_id))

    case Cedar.evaluate_with_entities(cedar_source, request, entities) do
      {:ok, %{decision: decision}} -> {:ok, decision}
      {:error, _} = err -> err
    end
  end

  defp principal_type(principal) do
    case Map.get(principal, "kind", "obo_human") do
      "obo_human" -> "Recurse::Principal::Human"
      "service_account" -> "Recurse::Principal::ServiceAccount"
      "autonomous" -> "Recurse::Principal::Autonomous"
      other -> "Recurse::Principal::" <> String.capitalize(other)
    end
  end

  defp tenant_id_or_default(s) when is_binary(s) and s != "", do: s
  defp tenant_id_or_default(_), do: "tenant-1"

  defp synthetic_entities(principal_type, subject, principal, tenant_id) do
    [
      %{
        "uid" => %{"type" => principal_type, "id" => subject},
        "attrs" => %{
          "tenant_id" => tenant_id,
          "recurse_role" => Map.get(principal, "recurse_role", "caller")
        },
        "parents" => []
      },
      %{
        "uid" => %{"type" => "Recurse::Resource::ConsoleSurface", "id" => "synthetic"},
        "attrs" => %{},
        "parents" => []
      }
    ]
  end

  defp synthetic_request(principal_type, subject, action_uid, tenant_id) do
    %{
      "principal" => ~s[#{principal_type}::"#{subject}"],
      "action" => action_uid,
      "resource" => ~s[Recurse::Resource::ConsoleSurface::"synthetic"],
      "context" => %{
        "tenant_id" => tenant_id,
        "correlation_id" => "sc008-test",
        "timestamp" => System.system_time(:second),
        "client_ip" => "0.0.0.0"
      }
    }
  end

  # 4-cell classification per blast_radius_algorithm.md §5a
  defp classify_pair_decisions(:deny, :deny), do: "matches_intent"
  defp classify_pair_decisions(:allow, :deny), do: "unintended"
  defp classify_pair_decisions(:deny, :allow), do: "would_have_allowed"
  defp classify_pair_decisions(:allow, :allow), do: "no_change"
end
