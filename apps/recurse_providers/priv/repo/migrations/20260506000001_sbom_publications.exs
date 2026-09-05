defmodule Recurse.Providers.Repo.Migrations.SbomPublications do
  @moduledoc """
  Spec B (007-sbom-supply-chain-attestation) — Phase 1 migration #1 of 4.

  Creates `sbom_publications` — the canonical CAS-referenced ingested
  CycloneDX SBOM document. One row per `(tenant_id, digest, arch)`.

  Source of truth: `specs/007-sbom-supply-chain-attestation/data-model.md`
  section "SbomPublication" (R-002 / R-006 / R-009).

  Notes on shape:
    * `tenant_id` is `:string` (matches the F002 `tenants.tenant_id`
      ULID-string convention from `20260423100000_f002_initial_schemas.exs`),
      not `:integer` as the data-model.md draft pseudocode shows. The spec
      narrative says "tenant_id BIGINT NOT NULL" but every existing table
      in this repo uses the F002 `:string` convention. Picking the
      established convention preserves cross-table FK shape.
    * `digest` is the SHA-256 of canonical JSON (32 bytes); enforced
      by an `octet_length = 32` CHECK to match the F002 hash-column
      pattern.
    * `document_cas_ref` is the StorageProvider CAS-ref (e.g.,
      `s3://recurse-cas/sha256/<hex_digest>`); body is fetched on demand.
    * Soft size cap defaults to 100 MB; tenant config can override at
      ingest time (the cap is enforced pre-INSERT in the ingest pipeline,
      not just at the DB layer).
  """

  use Ecto.Migration

  def up do
    create table(:sbom_publications) do
      add :tenant_id,
          references(:tenants, column: :tenant_id, type: :string, on_delete: :restrict),
          null: false

      add :digest, :binary, null: false
      add :spec_version, :string, null: false
      add :serial_number, :string
      add :document_cas_ref, :string, null: false
      add :size_bytes, :integer, null: false
      add :component_count, :integer, null: false, default: 0
      add :edge_count, :integer, null: false, default: 0
      add :max_depth, :integer, null: false, default: 0
      add :has_cycles, :boolean, null: false, default: false
      add :ingest_warnings, {:array, :map}, null: false, default: []
      add :binary_identity, :string, null: false
      add :arch, :string, null: false

      timestamps(type: :utc_datetime_usec)
    end

    # R-006 idempotence; multi-arch keyed (R-009).
    create unique_index(:sbom_publications, [:tenant_id, :digest, :arch],
             name: :sbom_publications_tenant_digest_arch_index
           )

    # "All SBOMs for this binary across archs"
    create index(:sbom_publications, [:tenant_id, :binary_identity])

    # Chronological listing.
    create index(:sbom_publications, [:tenant_id, :inserted_at],
             name: :sbom_publications_tenant_inserted_at_desc_index
           )

    # Partial index for the "cyclic SBOMs" diagnostic page.
    create index(:sbom_publications, [:tenant_id],
             name: :sbom_publications_cyclic_index,
             where: "has_cycles = true"
           )

    # Hash-length invariant (I-001).
    create constraint(
             :sbom_publications,
             :sbom_publications_digest_len,
             check: "octet_length(digest) = 32"
           )

    # Soft size cap (R-005). Tenant config can override pre-INSERT;
    # the DB-level cap is a sanity bound (100 MB).
    create constraint(
             :sbom_publications,
             :sbom_publications_size_bytes_check,
             check: "size_bytes > 0 AND size_bytes <= 104857600"
           )

    create constraint(
             :sbom_publications,
             :sbom_publications_spec_version_check,
             check: "spec_version IN ('1.4', '1.5', '1.6')"
           )

    # Sanity bound on graph depth (R-003 traversal at 20).
    create constraint(
             :sbom_publications,
             :sbom_publications_max_depth_check,
             check: "max_depth >= 0 AND max_depth <= 30"
           )

    create constraint(
             :sbom_publications,
             :sbom_publications_component_count_check,
             check: "component_count >= 0"
           )

    create constraint(
             :sbom_publications,
             :sbom_publications_edge_count_check,
             check: "edge_count >= 0"
           )
  end

  def down do
    drop table(:sbom_publications)
  end
end
