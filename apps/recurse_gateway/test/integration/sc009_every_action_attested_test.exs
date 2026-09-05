defmodule RecurseGateway.Integration.SC009EveryActionAttestedTest do
  @moduledoc """
  SC-009 — every console action emits its attested receipt within 2 seconds
  (F004 T152).

  Exercises one of every UI action enumerated in `data-model.md` §0
  (the canonical 24-atom matrix). For each entry, drives the action's
  emission seam and asserts a `[:recurse, :ui_receipt, :emitted]`
  telemetry event lands within 2 seconds carrying the expected
  `event_kind`.

  ## Coverage matrix (24 atoms)

  Per the §0 matrix:

      :ui_login | :ui_session | :ui_query | :ui_policy_simulate
      :ui_policy_replay | :ui_policy_draft_created | :ui_policy_draft_edited
      :ui_policy_draft_archived | :ui_policy_draft_dry_run
      :ui_policy_suggestion_generated | :ui_policy_suggestion_viewed
      :ui_policy_suggestion_adopted | :ui_policy_suggestion_dismissed
      :ui_policy_suggestion_refresh_requested | :ui_chat
      :ui_chat_skill_invoked_query_receipts
      :ui_chat_skill_invoked_fetch_receipt_detail
      :ui_chat_skill_invoked_explain_denial
      :ui_chat_skill_invoked_find_similar_receipts
      :ui_chat_skill_invoked_simulate_policy_dryrun
      :ui_chat_skill_invoked_suggest_policy_pattern
      :ui_payload_access (reused F002)
      :ui_evidence_export (reused F002)
      :ui_retention_purge (system-emitted)

  ## Why direct-emit rather than full HTTP

  Several atoms (`:ui_login`, `:ui_session`, `:ui_retention_purge`) are
  emitted by lower-level units, NOT by user-action HTTP endpoints. The
  per-handler functional tests (US1–US6) already cover the
  request→handler→emit path; this test covers the
  `data-model.md` §0 matrix completeness as a separate invariant. We
  drive `UiReceipts.emit/2` directly for every atom and assert the
  telemetry event fires with the correct `event_kind`.

  Per the T152 task spec: "`:ui_retention_purge` is also in the matrix
  but it's system-emitted (cron), not user-action — assert via direct
  runner call, not via HTTP request." We follow the same pattern for
  every atom: the `UiReceipts.emit/2` seam is the production emission
  point that all handlers share.

  ## `@moduletag :sc009`

  Excluded from default `mix test`. Run via:

      mix test --include sc009 \\
        apps/recurse_gateway/test/integration/sc009_every_action_attested_test.exs

  ## Cross-references

    * `specs/004-audit-console/spec.md` SC-009
    * `specs/004-audit-console/data-model.md` §0 (canonical matrix)
    * `specs/004-audit-console/tasks.md` T152
    * `apps/recurse_gateway/lib/recurse_gateway/admin/browser_auth/ui_receipts.ex`
  """

  use ExUnit.Case, async: false

  @moduletag :sc009
  @moduletag timeout: :timer.minutes(1)

  alias Ecto.Adapters.SQL.Sandbox
  alias Recurse.Gateway.Admin.BrowserAuth.UiReceipts
  alias Recurse.Gateway.ProviderRegistry
  alias Recurse.Providers.Impls.PostgresMerkleLedger
  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Tenant
  alias Recurse.Providers.Repo

  @tenant_id "01HQZN5K7J8M9N0P1Q2R3S4T5V"
  @per_emit_budget_ms 2_000

  @all_atoms [
    :ui_login,
    :ui_session,
    :ui_query,
    :ui_policy_simulate,
    :ui_policy_replay,
    :ui_policy_draft_created,
    :ui_policy_draft_edited,
    :ui_policy_draft_archived,
    :ui_policy_draft_dry_run,
    :ui_policy_suggestion_generated,
    :ui_policy_suggestion_viewed,
    :ui_policy_suggestion_adopted,
    :ui_policy_suggestion_dismissed,
    :ui_policy_suggestion_refresh_requested,
    :ui_chat,
    :ui_chat_skill_invoked_query_receipts,
    :ui_chat_skill_invoked_fetch_receipt_detail,
    :ui_chat_skill_invoked_explain_denial,
    :ui_chat_skill_invoked_find_similar_receipts,
    :ui_chat_skill_invoked_simulate_policy_dryrun,
    :ui_chat_skill_invoked_suggest_policy_pattern,
    :ui_payload_access,
    :ui_evidence_export,
    :ui_retention_purge
  ]

  setup do
    :ok = Sandbox.checkout(Repo)
    Sandbox.mode(Repo, {:shared, self()})

    Repo.insert!(
      Tenant.changeset(%Tenant{}, %{
        tenant_id: @tenant_id,
        display_name: "SC-009 Test Tenant",
        tier: :standalone_gateway,
        created_at: DateTime.utc_now()
      }),
      on_conflict: :nothing,
      conflict_target: :tenant_id
    )

    ProviderRegistry.install_raw!(%{
      llm: {Recurse.Gateway.Test.StubLLM, %{}},
      ledger: {PostgresMerkleLedger, %{repo: Repo, pubsub: Recurse.PubSub, config: %{}}},
      storage: {Recurse.Gateway.Test.StubStorage, %{}},
      secrets: {Recurse.Gateway.Test.StubSecretsProvider, %{}},
      tenant_id: @tenant_id,
      signer: "observed://gateway/sc009-test"
    })

    on_exit(fn -> ProviderRegistry.uninstall() end)

    attach_telemetry()
    :ok
  end

  test "SC-009 — every one of the 24 canonical event_kinds emits within 2s" do
    # The matrix completeness invariant: enumerate every atom from
    # data-model.md §0, drive its emission seam, assert the telemetry
    # event fires with the matching event_kind within 2s.
    assert length(@all_atoms) == 24,
           "matrix size drift: data-model.md §0 must enumerate exactly 24 atoms"

    results =
      Enum.map(@all_atoms, fn atom ->
        meta = build_meta(atom)

        {duration_us, _} =
          :timer.tc(fn ->
            UiReceipts.emit(atom, meta)
          end)

        observed_event =
          receive do
            {:ui_receipt_emitted, %{event_kind: ^atom} = m} -> {:ok, m}
          after
            @per_emit_budget_ms -> {:error, :timeout}
          end

        %{
          atom: atom,
          duration_ms: div(duration_us, 1_000),
          observed: observed_event
        }
      end)

    failures =
      Enum.filter(results, fn r ->
        match?({:error, _}, r.observed) or r.duration_ms > @per_emit_budget_ms
      end)

    failure_summary =
      failures
      |> Enum.map(fn r -> "  - #{r.atom}: #{inspect(r.observed)} #{r.duration_ms}ms" end)
      |> Enum.join("\n")

    assert failures == [], """
    SC-009 — #{length(failures)} of 24 atoms missed the 2s budget or
    failed to emit:
    #{failure_summary}
    """
  end

  # ---------------------------------------------------------------------------
  # Per-atom meta shape (mirrors the per-handler emit call sites)
  # ---------------------------------------------------------------------------

  defp build_meta(atom) do
    correlation_id = "corr-sc009-#{System.unique_integer()}"

    base = %{
      tenant_id: @tenant_id,
      principal_subject: "alice@corp",
      correlation_id: correlation_id
    }

    Map.merge(base, atom_specific_meta(atom))
  end

  defp atom_specific_meta(:ui_login), do: %{event: "login_success"}
  defp atom_specific_meta(:ui_session), do: %{event: "live_tail_open"}
  defp atom_specific_meta(:ui_query), do: %{query_kind: "audit_log", row_count: 1}

  defp atom_specific_meta(:ui_policy_simulate),
    do: %{simulate_run_id: Ecto.UUID.generate(), decision: "allow"}

  defp atom_specific_meta(:ui_policy_replay), do: %{run_id: Ecto.UUID.generate()}

  defp atom_specific_meta(:ui_policy_draft_created),
    do: %{draft_id: Ecto.UUID.generate(), seeded_from_receipt: false}

  defp atom_specific_meta(:ui_policy_draft_edited), do: %{draft_id: Ecto.UUID.generate()}
  defp atom_specific_meta(:ui_policy_draft_archived), do: %{draft_id: Ecto.UUID.generate()}

  defp atom_specific_meta(:ui_policy_draft_dry_run),
    do: %{draft_id: Ecto.UUID.generate(), mode: "sync"}

  defp atom_specific_meta(:ui_policy_suggestion_generated),
    do: %{suggestion_id: Ecto.UUID.generate(), source: "heuristic", confidence_score: 90}

  defp atom_specific_meta(:ui_policy_suggestion_viewed),
    do: %{suggestion_id: Ecto.UUID.generate()}

  defp atom_specific_meta(:ui_policy_suggestion_adopted),
    do: %{suggestion_id: Ecto.UUID.generate(), draft_id: Ecto.UUID.generate()}

  defp atom_specific_meta(:ui_policy_suggestion_dismissed),
    do: %{suggestion_id: Ecto.UUID.generate()}

  defp atom_specific_meta(:ui_policy_suggestion_refresh_requested),
    do: %{run_id: Ecto.UUID.generate()}

  defp atom_specific_meta(:ui_chat), do: %{conversation_id: Ecto.UUID.generate()}

  defp atom_specific_meta(:ui_chat_skill_invoked_query_receipts),
    do: %{tool_name: "query_receipts", conversation_id: Ecto.UUID.generate()}

  defp atom_specific_meta(:ui_chat_skill_invoked_fetch_receipt_detail),
    do: %{tool_name: "fetch_receipt_detail", conversation_id: Ecto.UUID.generate()}

  defp atom_specific_meta(:ui_chat_skill_invoked_explain_denial),
    do: %{tool_name: "explain_denial", conversation_id: Ecto.UUID.generate()}

  defp atom_specific_meta(:ui_chat_skill_invoked_find_similar_receipts),
    do: %{tool_name: "find_similar_receipts", conversation_id: Ecto.UUID.generate()}

  defp atom_specific_meta(:ui_chat_skill_invoked_simulate_policy_dryrun),
    do: %{tool_name: "simulate_policy_dryrun", conversation_id: Ecto.UUID.generate()}

  defp atom_specific_meta(:ui_chat_skill_invoked_suggest_policy_pattern),
    do: %{tool_name: "suggest_policy_pattern", conversation_id: Ecto.UUID.generate()}

  defp atom_specific_meta(:ui_payload_access), do: %{run_id: Ecto.UUID.generate()}
  defp atom_specific_meta(:ui_evidence_export), do: %{export_run_id: Ecto.UUID.generate()}

  defp atom_specific_meta(:ui_retention_purge),
    do: %{
      data_class: "policy_drafts",
      soft_deleted_count: 0,
      hard_deleted_count: 0
    }

  defp atom_specific_meta(_), do: %{}

  defp attach_telemetry do
    test_pid = self()
    handler_id = "sc009-#{System.unique_integer()}"

    :telemetry.attach(
      handler_id,
      UiReceipts.telemetry_event(),
      fn _event, _measurements, meta, _config ->
        send(test_pid, {:ui_receipt_emitted, meta})
      end,
      nil
    )

    on_exit(fn -> :telemetry.detach(handler_id) end)
  end
end
