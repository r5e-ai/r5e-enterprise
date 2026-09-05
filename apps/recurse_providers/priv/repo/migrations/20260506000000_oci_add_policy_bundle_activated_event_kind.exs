defmodule Recurse.Providers.Repo.Migrations.OciAddPolicyBundleActivatedEventKind do
  @moduledoc """
  Add the persisted `:policy_bundle_activated` attestation event kind
  for the OciPolicyProvider hot-reload workflow
  (`POST /v1/admin/cedar-bundle/activate`). Each successful
  `OciBundleManager.activate/2` emits an attestation receipt carrying
  old_digest → new_digest + source_ref + operator principal_subject
  so policy-state replay can reconstruct which bundle was active at
  any past evaluation.

  Same NOT VALID + VALIDATE pattern as
  `20260501000000_mcp_add_ui_mcp_quarantine_event_kind.exs`. Lockstep
  between this constraint, `SignedPredicate.@event_kinds`, and the
  Ecto schema's `@event_kind_values` is documented in the
  SignedPredicate module attribute.
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

  defp check_clause(values) do
    "event_kind IN (" <> Enum.map_join(values, ", ", &"'#{&1}'") <> ")"
  end

  def up do
    execute("ALTER TABLE attestations DROP CONSTRAINT IF EXISTS attestations_event_kind_check")

    execute("""
    ALTER TABLE attestations
      ADD CONSTRAINT attestations_event_kind_check
      CHECK (#{check_clause(@persisted_f002_values ++ @f004_values ++ @mcp_values ++ @oci_policy_values)})
      NOT VALID
    """)

    execute("ALTER TABLE attestations VALIDATE CONSTRAINT attestations_event_kind_check")
  end

  def down do
    execute("ALTER TABLE attestations DROP CONSTRAINT IF EXISTS attestations_event_kind_check")

    execute("""
    ALTER TABLE attestations
      ADD CONSTRAINT attestations_event_kind_check
      CHECK (#{check_clause(@persisted_f002_values ++ @f004_values ++ @mcp_values)})
      NOT VALID
    """)

    execute("ALTER TABLE attestations VALIDATE CONSTRAINT attestations_event_kind_check")
  end
end
