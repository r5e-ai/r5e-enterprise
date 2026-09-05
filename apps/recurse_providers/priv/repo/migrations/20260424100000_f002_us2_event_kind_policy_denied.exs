defmodule Recurse.Providers.Repo.Migrations.F002Us2EventKindPolicyDenied do
  @moduledoc """
  Extend the `attestations.event_kind` CHECK constraint to accept the
  `'policy_denied'` value emitted by the Gateway's deny branch
  (F002 FR-005 / FR-016a / US2 / tasks.md T057).

  The Wave 3E-2 `EnvelopeBuilder` stamps `event_kind: :policy_denied`
  for Cedar-deny traversals so auditors can filter on `event_kind`
  directly without parsing `policy_decision`. The initial F002 migration
  (`20260423100000`) locked the CHECK to `('llm_call')` only; this
  migration widens it to `('llm_call', 'policy_denied')`.

  Schema-side the Ecto field's `@event_kind_values` is updated in
  `apps/recurse_providers/lib/recurse_providers/impls/postgres_merkle_ledger/schemas/attestation.ex`
  in lockstep.
  """
  use Ecto.Migration

  def up do
    drop constraint(:attestations, :attestations_event_kind_check)

    create constraint(
             :attestations,
             :attestations_event_kind_check,
             check: "event_kind IN ('llm_call', 'policy_denied')"
           )
  end

  def down do
    drop constraint(:attestations, :attestations_event_kind_check)

    create constraint(
             :attestations,
             :attestations_event_kind_check,
             check: "event_kind IN ('llm_call')"
           )
  end
end
