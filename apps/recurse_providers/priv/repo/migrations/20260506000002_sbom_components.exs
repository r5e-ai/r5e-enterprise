defmodule Recurse.Providers.Repo.Migrations.SbomComponents do
  @moduledoc """
  Spec B (007-sbom-supply-chain-attestation) — Phase 1 migration #2 of 4.

  Creates `sbom_components` — the dedup-by-digest software component
  registry. `lodash@4.17.21` referenced by 100 SBOMs is ONE row in
  `sbom_components` referenced by 100 edges.

  Source of truth: `specs/007-sbom-supply-chain-attestation/data-model.md`
  section "SbomComponent".

  Notes on shape:
    * `tenant_id` uses the F002 `:string` ULID convention (see sibling
      `20260506000001_sbom_publications.exs` moduledoc for the
      type-pick rationale).
    * `digest` is computed deterministically from
      `(name, version, purl, sorted_upstream_hashes)` (32 bytes SHA-256).
    * `upstream_hashes` is a JSONB array of `%{algorithm, value}` maps.
    * `is_transitive` is a denormalized rollup; ingest writes it after
      the dep-edge graph is materialized (Phase 2).
    * License columns: `license_id` (SPDX) XOR `license_expression`
      (compound). At most one is populated per row; CHECK enforces the
      mutual exclusion.
  """

  use Ecto.Migration

  def up do
    create table(:sbom_components) do
      add :tenant_id,
          references(:tenants, column: :tenant_id, type: :string, on_delete: :restrict),
          null: false

      add :digest, :binary, null: false
      add :name, :string, null: false
      add :version, :string, null: false
      add :ecosystem, :string
      add :purl, :string
      add :cpe, :string
      add :license_id, :string
      add :license_expression, :string
      add :upstream_hashes, {:array, :map}, null: false, default: []
      add :is_transitive, :boolean, null: false, default: false

      timestamps(type: :utc_datetime_usec)
    end

    # Primary lookup + dedup.
    create unique_index(:sbom_components, [:tenant_id, :digest],
             name: :sbom_components_tenant_digest_index
           )

    # "Find all variants of `lodash`".
    create index(:sbom_components, [:tenant_id, :name, :version])

    # Ecosystem-filtered queries.
    create index(:sbom_components, [:tenant_id, :ecosystem, :name])

    # Purl-based blast-radius input — Spec A's CveAdvisoryProvider often
    # provides purl; this is the matching path on the consumer side.
    create index(:sbom_components, [:tenant_id, :purl])

    # Hash-length invariant (digest is SHA-256 → 32 bytes).
    create constraint(
             :sbom_components,
             :sbom_components_digest_len,
             check: "octet_length(digest) = 32"
           )

    # At least one identifier (ecosystem OR purl).
    create constraint(
             :sbom_components,
             :sbom_components_identifier_check,
             check: "ecosystem IS NOT NULL OR purl IS NOT NULL"
           )

    # License columns are mutually exclusive.
    create constraint(
             :sbom_components,
             :sbom_components_license_exclusive_check,
             check: "license_id IS NULL OR license_expression IS NULL"
           )
  end

  def down do
    drop table(:sbom_components)
  end
end
