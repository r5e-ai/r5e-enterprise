defmodule Recurse.Providers.Repo.Migrations.SbomDependencyEdges do
  @moduledoc """
  Spec B (007-sbom-supply-chain-attestation) — Phase 1 migration #3 of 4.

  Creates `sbom_dependency_edges` — the parent → child dep edges within
  a publication. THIS IS THE HOT PATH FOR PHASE 4 BLAST-RADIUS QUERIES.

  Source of truth: `specs/007-sbom-supply-chain-attestation/data-model.md`
  section "SbomDependencyEdge". Index strategy from R-003.

  Notes on shape:
    * `tenant_id` uses the F002 `:string` ULID convention.
    * Edges reference components by `digest` (NOT a hard FK) — the
      recursive CTE traverses by joining on digest, which lets component
      dedup happen at the digest level without per-publication FK
      maintenance overhead.
    * `sbom_publication_id` IS a hard FK with ON DELETE CASCADE — when
      a publication is purged, all its edges go with it.
    * Edges are immutable post-ingest; `timestamps(updated_at: false)`.
    * `(tenant_id, child_component_digest)` is the blast-radius hot
      lookup — keep it cheap and indexed.

  Index list rationale (R-003 perf path):
    * Primary uniqueness on `(sbom_publication_id, parent, child)`.
    * `(tenant_id, child_component_digest)` — "which graphs contain this
      component as a child?" — the headline blast-radius lookup.
    * `(tenant_id, parent_component_digest, child_component_digest)` —
      neighbor walk (recursive CTE step).
    * `(sbom_publication_id, depth_from_root)` — sbom-scoped depth
      queries for the UI.
    * `(tenant_id, child_component_digest, sbom_publication_id)` —
      multi-tenant blast-radius (which SBOMs use this component, scoped
      to one tenant).
  """

  use Ecto.Migration

  def up do
    create table(:sbom_dependency_edges) do
      add :tenant_id,
          references(:tenants, column: :tenant_id, type: :string, on_delete: :restrict),
          null: false

      add :sbom_publication_id,
          references(:sbom_publications, on_delete: :delete_all),
          null: false

      add :parent_component_digest, :binary, null: false
      add :child_component_digest, :binary, null: false
      add :depth_from_root, :integer, null: false
      add :is_dev_dependency, :boolean, null: false, default: false

      timestamps(type: :utc_datetime_usec, updated_at: false)
    end

    # Primary uniqueness within a publication.
    create unique_index(
             :sbom_dependency_edges,
             [:sbom_publication_id, :parent_component_digest, :child_component_digest],
             name: :sbom_dependency_edges_publication_parent_child_index
           )

    # The blast-radius hot path. R-003: this is the index that makes
    # the recursive CTE viable at scale.
    create index(:sbom_dependency_edges, [:tenant_id, :child_component_digest])

    # Neighbor walk (recursive CTE step). Explicit short index name
    # to avoid Postgres' 63-char identifier truncation.
    create index(
             :sbom_dependency_edges,
             [:tenant_id, :parent_component_digest, :child_component_digest],
             name: :sbom_dep_edges_tenant_parent_child_index
           )

    # Sbom-scoped depth queries for UI tree rendering.
    create index(:sbom_dependency_edges, [:sbom_publication_id, :depth_from_root])

    # Multi-tenant blast-radius — which SBOMs use this component, scoped
    # to a tenant — covers the per-tenant fanout query without a tenant
    # check on every row. Explicit short name (auto-generated would be
    # truncated by Postgres).
    create index(
             :sbom_dependency_edges,
             [:tenant_id, :child_component_digest, :sbom_publication_id],
             name: :sbom_dep_edges_tenant_child_publication_index
           )

    # Hash-length invariants on parent + child digests.
    create constraint(
             :sbom_dependency_edges,
             :sbom_dependency_edges_parent_digest_len,
             check: "octet_length(parent_component_digest) = 32"
           )

    create constraint(
             :sbom_dependency_edges,
             :sbom_dependency_edges_child_digest_len,
             check: "octet_length(child_component_digest) = 32"
           )

    # Sanity bound on depth.
    create constraint(
             :sbom_dependency_edges,
             :sbom_dependency_edges_depth_check,
             check: "depth_from_root >= 0 AND depth_from_root <= 30"
           )
  end

  def down do
    drop table(:sbom_dependency_edges)
  end
end
