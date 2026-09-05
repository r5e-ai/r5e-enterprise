# Contract: Dependency Graph Query

**Module**: `Recurse.Gateway.Sbom.GraphQuery`
**Owner phase**: Phase 3 (graph queries)
**Consumed by**: Phase 4 (blast-radius), Phase 6 (UI dep tree drill)

## Purpose

Read-side queries over the materialized dep graph (`sbom_dependency_edges`) using Postgres recursive CTEs. Cycle-safe (path array). Depth-bounded (default 20).

## Public API

```elixir
@spec component_subtree(
        tenant_id :: String.t()                       # ULID per F002 convention,
        sbom_publication_id :: integer(),
        root_component_digest :: binary(),
        opts :: [max_depth: pos_integer(), include_dev: boolean()]
      ) :: {:ok, [%{component_digest: binary(), depth: non_neg_integer(), path: [binary()]}]}

@spec sbom_components_at_depth(
        tenant_id :: String.t()                       # ULID per F002 convention,
        sbom_publication_id :: integer(),
        depth :: non_neg_integer()
      ) :: {:ok, [SbomComponent.t()]}

@spec sbom_full_tree(
        tenant_id :: String.t()                       # ULID per F002 convention,
        sbom_publication_id :: integer(),
        opts :: [max_depth: pos_integer(), include_dev: boolean()]
      ) :: {:ok, %{nodes: [%{...}], edges: [%{...}]}}

@spec components_using(
        tenant_id :: String.t()                       # ULID per F002 convention,
        target_component_digest :: binary(),
        opts :: [include_dev: boolean()]
      ) :: {:ok, [%{sbom_publication_id: integer(), depth: non_neg_integer()}]}

@spec shared_subgraph(
        tenant_id :: String.t()                       # ULID per F002 convention,
        sbom_publication_a_id :: integer(),
        sbom_publication_b_id :: integer()
      ) :: {:ok, %{shared_components: [binary()], a_only: integer(), b_only: integer()}}
```

## Recursive CTE shape (canonical)

The hot path is `components_using/2` (used by blast-radius). The CTE shape:

```sql
WITH RECURSIVE walk(component_digest, sbom_publication_id, depth, path) AS (
  -- base case: direct match
  SELECT child_component_digest, sbom_publication_id, 1, ARRAY[child_component_digest]
  FROM sbom_dependency_edges
  WHERE tenant_id = $1
    AND child_component_digest = $2
    AND ($3 OR is_dev_dependency = false)  -- include_dev flag
  
  UNION ALL
  
  -- recursive case: walk up to parents
  SELECT e.parent_component_digest, e.sbom_publication_id, w.depth + 1, w.path || e.parent_component_digest
  FROM sbom_dependency_edges e
  JOIN walk w
    ON e.tenant_id = $1
    AND e.child_component_digest = w.component_digest
    AND e.sbom_publication_id = w.sbom_publication_id
  WHERE w.depth < $4  -- max_depth
    AND NOT (e.parent_component_digest = ANY(w.path))  -- cycle-detect
)
SELECT DISTINCT sbom_publication_id, MIN(depth) AS depth_from_root
FROM walk
GROUP BY sbom_publication_id;
```

This walks UP from a target component to all SBOMs that contain it (transitive ancestors). Pairs with the indexes documented in data-model.md (`INDEX (tenant_id, child_component_digest)`).

## Invariants

- **I-001**: All recursive walks terminate within `max_depth` regardless of cycle presence (cycle-detect via `path` array)
- **I-002**: For acyclic graphs, `transitive_closure(component_digest)` equals BFS/DFS of the same component (closure correctness)
- **I-003**: All queries are tenant-scoped; cross-tenant leak is impossible by query construction
- **I-004**: `components_using/2` returns `(sbom_publication_id, depth)` pairs where depth is the SHORTEST path from the target component to the SBOM root (minimum-depth observation)
- **I-005**: `shared_subgraph/3` is commutative — `shared_subgraph(a, b)` returns the same `shared_components` set as `shared_subgraph(b, a)`

## Test contracts

- **CT-001**: For a known fixture graph (publication with components A → B → C, where C is a transitive of A via B), `component_subtree(_, _, A_digest)` returns `[{A, 0}, {B, 1}, {C, 2}]`.
- **CT-002**: For the same fixture, `components_using(_, C_digest)` returns one entry: `(publication_id, depth: 2)`.
- **CT-003**: For a cyclic fixture (A → B → A), `component_subtree(_, _, A_digest)` returns `[{A, 0}, {B, 1}]` and does NOT loop.
- **CT-004**: `sbom_components_at_depth/3` returns components at exactly the requested depth; depth=0 returns roots.

## Property tests

- **PT-001**: For any randomly-generated DAG of N components, `component_subtree(root)` returns a result that, when interpreted as a graph, equals the input DAG exactly.
- **PT-002**: For any randomly-generated cyclic graph of N components, `component_subtree(root)` terminates within `max_depth` and returns a finite result.
- **PT-003**: `transitive_closure` is the same regardless of edge insertion order (commutative property).

## Failure modes

- `:depth_exceeded` — query exceeded `max_depth`; result is partial. Returned as `{:ok, %{partial: true, results: [...]}}`. Caller decides whether to re-run with higher max_depth or accept the partial.
- `:no_such_publication` — `sbom_publication_id` does not exist for tenant. `{:error, :not_found}`.
- `:no_such_component` — Component digest doesn't exist anywhere in tenant's components. `{:ok, %{results: []}}` (not an error — empty result set).

## Performance contracts

- **P-001**: `components_using/2` over 1000 ingested SBOMs returns in <500ms p95 with the documented indexes.
- **P-002**: `sbom_full_tree/2` for a 1000-component SBOM returns in <2s p95.
- **P-003**: All queries use parameterized SQL via Ecto; no string concatenation; no SQL-injection surface.

## Dependencies

- `Ecto.Query` — query construction (existing)
- `Ecto.Adapters.SQL` — raw SQL for the recursive CTE (Ecto's query DSL doesn't natively support recursive CTEs; we use `Ecto.Adapters.SQL.query/4`)
- No new Hex deps
