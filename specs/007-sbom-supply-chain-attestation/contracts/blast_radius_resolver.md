# Contract: Blast-Radius Resolver

**Module**: `Recurse.Gateway.Sbom.BlastRadiusResolver`
**Owner phase**: Phase 4 (CVE blast-radius resolver)
**Consumed by**: Spec A's Hub CVE response (Phase 6 of Spec A); Phase 6 of Spec B (UI)

## Purpose

Given a CVE advisory shape (component name + ecosystem + affected version range, optional patched version), return the set of `SbomPublication`s whose dep tree contains a matching component, with depth + last-attested-action timestamp + 7-day action count + patched-version-resolution annotation.

This is the canonical "blast-radius" surface that customers and Spec A's Hub CVE response automation consume. Every call is recorded as a `CveBlastRadiusQuery` row (audit-only, immutable).

## Public API

```elixir
@spec resolve(
        tenant_id :: String.t()                       # ULID per F002 convention,
        advisory :: advisory_input(),
        opts :: [include_dev: boolean(), max_depth: pos_integer()]
      ) :: {:ok, blast_radius_result()} | {:error, atom()}

@type advisory_input :: %{
  cve_id: String.t(),                       # e.g. "CVE-2024-12345"
  component_name: String.t(),                # e.g. "lodash"
  ecosystem: String.t(),                     # "npm" | "pypi" | "maven" | ...
  affected_range: String.t(),                # ecosystem-specific range expression: "<4.17.21" | "[1.0,1.5)"
  patched_in: String.t() | nil,              # ecosystem-specific patched version: "4.17.21" | "1.5.0"
  severity: :critical | :high | :medium | :low | :unknown
}

@type blast_radius_result :: %{
  query_id: integer(),                       # CveBlastRadiusQuery.id (audit ref)
  affected: [affected_binary()],
  unaffected_count: non_neg_integer(),       # SBOMs that contain the component but NOT in the affected range
  total_sboms_scanned: non_neg_integer(),
  elapsed_ms: pos_integer()
}

@type affected_binary :: %{
  sbom_publication_id: integer(),
  binary_identity: String.t(),
  arch: String.t(),
  affected_components: [%{
    component_digest: binary(),
    component_version: String.t(),
    depth_from_root: non_neg_integer()
  }],
  has_patched_path?: boolean(),              # R-008
  last_action_at: DateTime.t() | nil,
  action_count_7d: non_neg_integer()
}
```

## Algorithm (high level)

1. **Match components**: query `sbom_components` for rows matching `(ecosystem, name)` with `version` falling within `affected_range`. Returns a set of component digests.
2. **Walk up from each matched component**: for each digest from step 1, run `Recurse.Gateway.Sbom.GraphQuery.components_using/2` to find the affected SBOMs with their min-depth.
3. **Annotate per-binary**: for each affected SBOM, look up `binary_identity` + `arch` from `sbom_publications`; query attestation history for `last_action_at` and `action_count_7d` (the existing `attestations` table — joined on `binary_identity`).
4. **Patched-path heuristic**: if `patched_in` is provided, check whether the SBOM contains a component matching `(ecosystem, name)` with version `≥ patched_in` ANYWHERE in the dep tree (R-008). If yes, `has_patched_path? = true`.
5. **Record query**: insert `CveBlastRadiusQuery` row with input + result + caller principal + elapsed_ms.
6. **Emit attestation**: a Recurse signed predicate is emitted for the query call itself (every blast-radius query is an attested action per FR-014).

## Invariants

- **I-001**: `resolve/2` is deterministic — same input + same DB state produces same output. Re-running yields a `result_digest` that matches.
- **I-002**: `resolve/2` is commutative w.r.t. SBOM ingest order — ingesting SBOMs A, B, C in any order before the query produces the same `affected` set.
- **I-003**: `affected` is sorted by `(severity desc, action_count_7d desc, depth_from_root asc)` — most-impactful binaries first.
- **I-004**: `total_sboms_scanned` ≥ `length(affected) + unaffected_count` (the scan covered at least the SBOMs that returned a result, but may scan more; the difference is SBOMs with no matching component at all).
- **I-005**: For an empty `affected_range` (advisory says "no version is affected" — rare but legal), `affected = []`.
- **I-006**: For the special wildcard `affected_range: "*"`, every SBOM containing the component is in `affected` (no version filter). 

## Version-range semantics

Version-range matching is ecosystem-specific. The resolver delegates to:

- **npm**: semver range parser (`Recurse.Shared.Sbom.Versioning.Semver.matches?/2`)
- **pypi**: PEP 440 specifier parser
- **maven**: Maven version-range syntax
- **go**: Go module version syntax
- **rubygems**: Bundler / gem requirement parser
- **cargo**: Cargo SemVer requirement
- **deb**: Debian version comparison (epoch + upstream + revision)
- **rpm**: RPM EVR comparison

For ecosystems we don't yet support (the parser returns `:unsupported_ecosystem`), we EXACT-MATCH on version string only — equivalent to `affected_range = "= <exact_version>"`. We log a `:warning` predicate noting the fallback.

The version-range parser modules live in `apps/recurse_shared/lib/recurse_shared/sbom/versioning/`.

## Test contracts

- **CT-001**: Known fixture: 100 SBOMs across two ecosystems, one shared deep transitive. CVE on the transitive returns 100 affected binaries with depth-of-transitivity matching the fixture.
- **CT-002**: For a CVE with `patched_in`, an SBOM that contains both `lodash@4.17.20` (affected) and `lodash@4.17.21` (patched, perhaps via a different dep) returns `has_patched_path?: true`.
- **CT-003**: For a CVE not present in any SBOM, `resolve/2` returns `affected: []`, `unaffected_count: 0`, `total_sboms_scanned: <count>`.
- **CT-004**: `CveBlastRadiusQuery` row is created on every call, including ones with empty `affected`.

## Property tests

- **PT-001**: Resolution is order-independent — for any random permutation of SBOM ingest order, `resolve/2` returns the same `affected` set.
- **PT-002**: For an advisory with `affected_range: "*"`, `resolve` returns every SBOM containing the named component.
- **PT-003**: For two equivalent advisories (same component, same range expressed differently — e.g. `"<4.17.21"` vs `"[0,4.17.21)"`), `resolve` returns the same affected set (semantic-equivalence test).

## Performance contracts

- **P-001**: `resolve/2` p95 < 5s across 1000 ingested SBOMs at any dep depth (per SC-003).
- **P-002**: `resolve/2` for a CVE matching ZERO components returns in < 200ms (early-return on empty match-set).

## Failure modes

- `:advisory_invalid` — advisory is missing required fields or has malformed `affected_range`.
- `:unsupported_ecosystem` — fall back to exact version match; emit warning, do NOT fail.
- `:max_depth_exceeded` — graph traversal hit max_depth; result is partial. Caller can re-run with higher max_depth.

## Audit predicate emission

Every successful `resolve/2` call emits one `cve_blast_radius_query_executed` event_kind predicate (added in Phase 4 migrations) containing:

- `caller_principal` (who ran it)
- `advisory_digest` (SHA-256 of canonicalized advisory_input)
- `result_digest` (SHA-256 of canonicalized result)
- `elapsed_ms`
- `affected_count`

This predicate is the audit trail referenced by FR-014.

## Dependencies

- `Recurse.Gateway.Sbom.GraphQuery` — Phase 3 graph traversal
- `Recurse.Shared.Sbom.Versioning.*` — per-ecosystem version-range parsers
- Existing predicate emission machinery
- No new Hex deps for the resolver itself; some ecosystem version-range parsers may pull in narrowly-scoped Hex deps (e.g., `version` for semver — already in deps)
