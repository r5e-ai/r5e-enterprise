defmodule Recurse.Providers.Repo.Migrations.F004WidenEventKindCheck do
  @moduledoc """
  Extend the `attestations.event_kind` CHECK constraint to accept the
  UI-emitted event_kind values introduced by F004 (Audit Console).

  Uses the NOT VALID + VALIDATE CONSTRAINT pattern (§2.0 of F004 data-model.md)
  to avoid the AccessExclusiveLock that a naive `ALTER TABLE ... ADD CONSTRAINT`
  would acquire against the (projected 1B-row) attestations table:

    1. DROP the existing constraint (catalog-only update; brief
       AccessExclusiveLock).
    2. ADD the wider constraint with NOT VALID — Postgres records the
       constraint without scanning existing rows; the `AccessExclusiveLock` is
       held only for the catalog update (milliseconds). New INSERTs are gated
       immediately.
    3. VALIDATE CONSTRAINT — takes only `ShareUpdateExclusiveLock` (blocks DDL
       on the table but NOT DML reads/writes). Existing F002-vintage rows pass
       trivially because (`llm_call`, `policy_denied`) ⊂ wider union.

  This is the FIRST F004 migration to touch an F002-owned table. All future
  widenings of any `attestations` CHECK constraint MUST use this pattern. The
  F002 Wave R1 migration (`20260424100000_f002_us2_event_kind_policy_denied`)
  used the unsafe drop-then-recreate pattern, but ran before any
  `:policy_denied` rows existed, so its implicit validation scan was
  inexpensive. F004 widening runs against a populated attestations table that
  already contains `:policy_denied` rows from F002 production traffic; the
  Wave R1 pattern would block DML for the duration. See data-model.md §2.0
  for the cross-reference.

  Schema-side, `Attestation.@event_kind_values` in
  `apps/recurse_providers/lib/recurse_providers/impls/postgres_merkle_ledger/schemas/attestation.ex`
  is updated in lockstep (Wave 1B; tracked by separate task).

  Cross-ref: specs/004-audit-console/data-model.md §0 (canonical UI-action
  matrix — the 24 new F004 atoms below MUST match §0 verbatim) and §2.1
  (the migration-detail subsection).
  """
  use Ecto.Migration

  # F002-vintage values (preserved unchanged). The Wave R1 widening landed
  # `:policy_denied`; F002 has not landed any further widenings.
  @f002_values ~w(llm_call policy_denied)

  # F004 values — must match §0 of data-model.md verbatim. 24 new atoms.
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

  defp check_clause do
    "event_kind IN (" <>
      Enum.map_join(@f002_values ++ @f004_values, ", ", &"'#{&1}'") <>
      ")"
  end

  def up do
    # Drop the existing constraint (it was added by F002; recreating with
    # NOT VALID requires removing the old shape first). The DROP itself takes
    # a brief AccessExclusiveLock (catalog-only update); the heavy lifting is
    # the VALIDATE CONSTRAINT step below.
    execute("ALTER TABLE attestations DROP CONSTRAINT IF EXISTS attestations_event_kind_check")

    # Add the wider constraint as NOT VALID. Postgres records the constraint
    # without scanning existing rows; new INSERTs are gated by the constraint
    # immediately, but pre-existing rows are not rescanned.
    execute("""
    ALTER TABLE attestations
      ADD CONSTRAINT attestations_event_kind_check
      CHECK (#{check_clause()})
      NOT VALID
    """)

    # VALIDATE — takes ShareUpdateExclusiveLock (blocks DDL on the table but
    # NOT DML reads/writes). All existing F002-vintage rows pass trivially
    # because (`llm_call`, `policy_denied`) ⊂ wider union. After this completes
    # the constraint is fully valid and indistinguishable from a regular CHECK.
    execute("ALTER TABLE attestations VALIDATE CONSTRAINT attestations_event_kind_check")
  end

  def down do
    # Forward-only migration. Once any receipt with a new (F004-introduced)
    # event_kind has been committed to the attestations table, dropping back
    # to the F002 CHECK union would require destroying those rows, which
    # violates Constitution Principle III (append-only invariant).
    #
    # If F004 must be backed out, the rollback strategy is:
    #   1. Stop emitting new event_kinds (revert F004 application code).
    #   2. Leave the wider CHECK in place — existing F002 receipts remain
    #      valid because the wider CHECK is a strict superset of the F002 CHECK.
    #   3. F002-emitting traffic continues to satisfy the wider constraint
    #      with no behavior change.
    #
    # No DDL is run on `down/0`. This is the most honest representation of
    # "you can't safely back this out at the schema level."
    :ok
  end
end
