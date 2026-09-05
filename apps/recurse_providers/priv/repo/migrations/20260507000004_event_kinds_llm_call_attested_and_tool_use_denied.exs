defmodule Recurse.Providers.Repo.Migrations.EventKindsLlmCallAttestedAndToolUseDenied do
  @moduledoc """
  Add the persisted `:llm_call_attested` and `:tool_use_denied` attestation
  event kinds for Spec 009 (LLM API Proxy) Phase 3 Sub-3.7.

  ## Why two atoms

    * `:llm_call_attested` — exactly one per LLM call (Cedar-traversed
      request → final response chunk). Carries full call metadata + the
      per-tool-intent decisions array. DSSE-signed by
      `Recurse.Gateway.LlmProxy.AttestationEmitter.emit_call_attestation/1`
      via the existing `EnvelopeBuilder.build_system/4` path.

    * `:tool_use_denied` — exactly one per `decision == :deny` intent.
      Each such predicate references the parent `:llm_call_attested`
      receipt by `parent_llm_call_run_id` so blast-radius queries can
      pivot from a denial to the call that surfaced it.

  ## Lockstep (Constitution Principle VII — single MR)

  This migration MUST land in the same commit as:
    * `apps/recurse_shared/lib/recurse_shared/attestation/signed_predicate.ex`
      `@event_kinds` extension
    * `apps/recurse_gateway/lib/recurse_gateway/admin/browser_auth/ui_receipts.ex`
      `@allowed_event_kinds` + `ui_event_kind` typespec extension
    * `apps/recurse_providers/lib/recurse_providers/impls/postgres_merkle_ledger/schemas/attestation.ex`
      `@event_kind_values` Ecto.Enum extension

  ## NOT VALID + VALIDATE pattern

  Same per-row online widening pattern as
  `20260506000000_oci_add_policy_bundle_activated_event_kind.exs`. Drops
  the existing CHECK, adds the widened CHECK as `NOT VALID` (so existing
  rows are not re-scanned at ADD time), then immediately runs `VALIDATE
  CONSTRAINT` to confirm every existing row passes — both DDL statements
  hold short locks, no long table lock.
  """

  use Ecto.Migration

  @persisted_f002_values ~w(llm_call tool_call policy_denied)

  @f004_values ~w(
    ui_login
    ui_session
    ui_query
    ui_policy_simulate
    ui_policy_replay
    ui_policy_draft_created
    ui_policy_draft_edited
    ui_policy_draft_archived
    ui_policy_draft_dry_run
    ui_policy_suggestion_generated
    ui_policy_suggestion_viewed
    ui_policy_suggestion_adopted
    ui_policy_suggestion_dismissed
    ui_policy_suggestion_refresh_requested
    ui_chat
    ui_chat_skill_invoked_query_receipts
    ui_chat_skill_invoked_fetch_receipt_detail
    ui_chat_skill_invoked_explain_denial
    ui_chat_skill_invoked_find_similar_receipts
    ui_chat_skill_invoked_simulate_policy_dryrun
    ui_chat_skill_invoked_suggest_policy_pattern
    ui_payload_access
    ui_evidence_export
    ui_retention_purge
  )

  @mcp_values ~w(mcp_tool_call ui_mcp_quarantine)

  @oci_policy_values ~w(policy_bundle_activated)

  @spec_009_values ~w(llm_call_attested tool_use_denied)

  defp check_clause(values) do
    "event_kind IN (" <> Enum.map_join(values, ", ", &"'#{&1}'") <> ")"
  end

  def up do
    execute("ALTER TABLE attestations DROP CONSTRAINT IF EXISTS attestations_event_kind_check")

    widened =
      @persisted_f002_values ++
        @f004_values ++
        @mcp_values ++
        @oci_policy_values ++
        @spec_009_values

    execute("""
    ALTER TABLE attestations
      ADD CONSTRAINT attestations_event_kind_check
      CHECK (#{check_clause(widened)})
      NOT VALID
    """)

    execute("ALTER TABLE attestations VALIDATE CONSTRAINT attestations_event_kind_check")
  end

  def down do
    execute("ALTER TABLE attestations DROP CONSTRAINT IF EXISTS attestations_event_kind_check")

    pre_009 =
      @persisted_f002_values ++ @f004_values ++ @mcp_values ++ @oci_policy_values

    execute("""
    ALTER TABLE attestations
      ADD CONSTRAINT attestations_event_kind_check
      CHECK (#{check_clause(pre_009)})
      NOT VALID
    """)

    execute("ALTER TABLE attestations VALIDATE CONSTRAINT attestations_event_kind_check")
  end
end
