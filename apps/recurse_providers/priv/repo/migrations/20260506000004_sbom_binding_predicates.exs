defmodule Recurse.Providers.Repo.Migrations.SbomBindingPredicates do
  @moduledoc """
  Spec B (007-sbom-supply-chain-attestation) — Phase 1 migration #4 of 4.

  Creates `sbom_binding_predicates` — the "binary X has SBOM Y, attested
  by source Z" attestation rows. Phase 5 will populate via
  `Recurse.Gateway.Sbom.BindingEmitter`.

  Source of truth: `specs/007-sbom-supply-chain-attestation/data-model.md`
  section "SbomBindingPredicate" (R-004).

  ## Deviation from data-model.md (documented)

  data-model.md describes `signed_predicate_id` as a `BIGINT` FK to
  `recurse_signed_predicates.id`. The actual existing table in this
  repo today is `attestations` (created by F002 migration
  `20260423100000_f002_initial_schemas.exs`) with primary key
  `run_id` of type `:binary_id`. There is no `recurse_signed_predicates`
  table; the spec uses that name as an aspirational alias for the
  existing attestations table.

  Decision: target the actual existing table. The FK column is named
  `signed_predicate_run_id` (rather than the spec's `signed_predicate_id`)
  so the type mismatch is obvious at the schema level and downstream
  Ecto code can't accidentally treat it as an integer. If/when the
  table is renamed to `recurse_signed_predicates`, this column can be
  renamed in the same migration.

  Notes on shape:
    * `tenant_id` uses the F002 `:string` ULID convention.
    * `sbom_publication_id` FK to `sbom_publications` is `ON DELETE
      RESTRICT` — bindings keep publications alive (you can't purge a
      publication that something is attesting to).
    * `signed_predicate_run_id` FK to `attestations` is `ON DELETE
      RESTRICT` for the same reason — the binding row is downstream
      of the predicate.
    * `attestation_envelope` is the raw DSSE envelope bytes (customer +
      recurse_managed) OR the Sigstore Bundle bytes (vendor) — opaque
      to the DB.
    * `verification_status` defaults to `'unverified'` so newly-inserted
      rows are explicit about the not-yet-verified state.
  """

  use Ecto.Migration

  def up do
    create table(:sbom_binding_predicates) do
      add :tenant_id,
          references(:tenants, column: :tenant_id, type: :string, on_delete: :restrict),
          null: false

      add :sbom_publication_id,
          references(:sbom_publications, on_delete: :restrict),
          null: false

      add :binary_identity, :string, null: false
      add :sbom_digest, :binary, null: false
      add :attested_by, :string, null: false
      add :attested_by_subject, :string, null: false
      add :attestation_envelope, :binary, null: false

      # See moduledoc "Deviation from data-model.md" — FK targets the
      # actual `attestations.run_id` (binary_id), not the spec's
      # aspirational `recurse_signed_predicates.id` (integer).
      add :signed_predicate_run_id,
          references(:attestations,
            column: :run_id,
            type: :binary_id,
            on_delete: :restrict
          ),
          null: false

      add :verified_at, :utc_datetime_usec
      add :verification_status, :string, null: false, default: "unverified"
      add :verification_failure_reason, :string

      timestamps(type: :utc_datetime_usec)
    end

    # One binding per (sbom, source, signer).
    create unique_index(
             :sbom_binding_predicates,
             [:sbom_publication_id, :attested_by, :attested_by_subject],
             name: :sbom_binding_predicates_publication_source_signer_index
           )

    # "All bindings for this binary".
    create index(:sbom_binding_predicates, [:tenant_id, :binary_identity])

    # "All customer-attested SBOMs".
    create index(:sbom_binding_predicates, [:tenant_id, :attested_by])

    # Reverse lookup from the canonical predicate.
    create index(:sbom_binding_predicates, [:signed_predicate_run_id])

    # Hash-length invariant on the mirrored sbom_digest column.
    create constraint(
             :sbom_binding_predicates,
             :sbom_binding_predicates_sbom_digest_len,
             check: "octet_length(sbom_digest) = 32"
           )

    # Source-of-attestation enum (3 sources per R-004).
    create constraint(
             :sbom_binding_predicates,
             :sbom_binding_predicates_attested_by_check,
             check: "attested_by IN ('customer', 'recurse_managed', 'vendor')"
           )

    # Verification-status enum.
    create constraint(
             :sbom_binding_predicates,
             :sbom_binding_predicates_verification_status_check,
             check:
               "verification_status IN ('verified', 'unverified', 'verification_failed')"
           )

    # Failure reason populated only on failure.
    create constraint(
             :sbom_binding_predicates,
             :sbom_binding_predicates_failure_reason_consistency_check,
             check:
               "(verification_status = 'verification_failed' AND " <>
                 "verification_failure_reason IS NOT NULL) OR " <>
                 "(verification_status <> 'verification_failed' AND " <>
                 "verification_failure_reason IS NULL)"
           )
  end

  def down do
    drop table(:sbom_binding_predicates)
  end
end
