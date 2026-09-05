defmodule Recurse.Providers.Repo.Migrations.F002AddToolCallEventKind do
  @moduledoc """
  Add the persisted F002 `tool_call` attestation event kind.

  `SignedPredicate.event_kinds/0` has broader F002 vocabulary, but this
  migration intentionally widens the persisted Postgres CHECK only for the
  production emitter added by the importer: `tool_call`. At this point
  `egress_denied` and `session_abort` remain contract-level vocabulary, not
  database-accepted values.

  Uses the same NOT VALID + VALIDATE pattern as the F004 widening to keep the
  catalog update brief and avoid a long DML-blocking validation lock.
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

  defp check_clause(values) do
    "event_kind IN (" <> Enum.map_join(values, ", ", &"'#{&1}'") <> ")"
  end

  def up do
    execute("ALTER TABLE attestations DROP CONSTRAINT IF EXISTS attestations_event_kind_check")

    execute("""
    ALTER TABLE attestations
      ADD CONSTRAINT attestations_event_kind_check
      CHECK (#{check_clause(@persisted_f002_values ++ @f004_values)})
      NOT VALID
    """)

    execute("ALTER TABLE attestations VALIDATE CONSTRAINT attestations_event_kind_check")
  end

  def down do
    execute("ALTER TABLE attestations DROP CONSTRAINT IF EXISTS attestations_event_kind_check")

    execute("""
    ALTER TABLE attestations
      ADD CONSTRAINT attestations_event_kind_check
      CHECK (#{check_clause(["llm_call", "policy_denied"] ++ @f004_values)})
      NOT VALID
    """)

    execute("ALTER TABLE attestations VALIDATE CONSTRAINT attestations_event_kind_check")
  end
end
