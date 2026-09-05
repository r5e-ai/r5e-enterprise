# Contract: CycloneDX Parser

**Module**: `Recurse.Shared.Sbom.Cyclonedx.Parser` + `Recurse.Shared.Sbom.Cyclonedx.Canonicalizer` + `Recurse.Shared.Sbom.Cyclonedx.VersionDetector`
**Owner phase**: Phase 1 (types + parser)
**Consumed by**: Phase 2 (ingest pipeline)

## Purpose

Parse CycloneDX 1.4 / 1.5 / 1.6 JSON documents into Recurse-internal Elixir structs. Produce a deterministic canonical JSON representation for SHA-256 digest computation. Detect version. Detect cycles in the dep graph at parse time (warn-not-fail per R-010).

## Public API

```elixir
@spec parse(binary()) ::
        {:ok, %{
          publication: Publication.t() (without :id, :inserted_at),
          components: [Component.t() (without :id)],
          edges: [DependencyEdge.t() (without :id)],
          warnings: [warning()]
        }}
        | {:error, parse_error()}

@spec canonicalize(parsed :: map()) :: {:ok, binary()} | {:error, atom()}

@type warning :: 
        {:cycle_detected, components: [String.t()]}      # R-010
      | {:unknown_field, path: String.t()}                # forward-compat
      | {:duplicate_bom_ref, ref: String.t()}             # CycloneDX-spec violation; we warn but accept
      | {:missing_optional_field, name: String.t()}

@type parse_error ::
        :malformed_json
      | :missing_bom_format
      | :unsupported_spec_version
      | :missing_components_key
      | %{reason: :invalid_purl, purl: String.t()}
      | %{reason: :duplicate_dependency_root, refs: [String.t()]}
```

`Recurse.Shared.Sbom.Cyclonedx.VersionDetector.detect/1`:

```elixir
@spec detect(parsed_json :: map()) :: 
        {:ok, "1.4" | "1.5" | "1.6"} | {:error, :unsupported_spec_version}
```

## Invariants

- **I-001**: `parse/1` is total over byte input (returns `{:error, _}` for any malformed input; never raises)
- **I-002**: `parse → canonicalize → SHA-256` is deterministic for any well-formed document
- **I-003**: Re-parsing canonicalized output produces the same internal struct
- **I-004**: Unknown fields (forward-compat) emit `{:unknown_field, ...}` warnings but do NOT fail parsing
- **I-005**: Cyclic dep graphs emit `{:cycle_detected, components: [...]}` warnings but do NOT fail parsing
- **I-006**: `Component.digest` is computed from `(name, version, purl, sorted_upstream_hashes)` — same component in two SBOMs MUST produce the same digest

## Test contracts

- **CT-001**: Parse the official CycloneDX 1.4 / 1.5 / 1.6 sample documents from the CycloneDX GitHub repo `examples/` directory. Each version's samples MUST round-trip through `parse → canonicalize → parse` to the same struct.
- **CT-002**: For a fixture document with a known dep cycle, parse emits `{:cycle_detected, ...}` warning and the result includes all edges (does NOT drop edges to break the cycle).
- **CT-003**: For a fixture with unknown `serviceProvider` field (CycloneDX 1.6 addition that we don't reason about), parse emits `{:unknown_field, "serviceProvider"}` warning and proceeds.
- **CT-004**: `VersionDetector.detect/1` returns `"1.4"` for `specVersion: "1.4"`, `"1.5"` for `"1.5"`, `"1.6"` for `"1.6"`, and `{:error, :unsupported_spec_version}` for `"1.3"` or absent.

## Property tests (StreamData)

- **PT-001**: For any binary input, `parse/1` returns `{:ok, _}` or `{:error, _}` — never raises.
- **PT-002**: For any randomly-generated `bomFormat: "CycloneDX"` JSON document with a valid `specVersion`, parse → canonicalize → SHA-256 is deterministic.
- **PT-003**: For two component generators that produce structurally-equal components but with different field orderings, the resulting `Component.digest` values are equal.
- **PT-004**: Parse rejects malformed JSON with `:malformed_json` (no exception); fuzz with random byte sequences.

## Failure modes (parse errors)

| Error | Trigger | Handling |
|-------|---------|----------|
| `:malformed_json` | Body is not valid JSON | Return `{:error, _}`; ingest pipeline emits `sbom_ingested` predicate with `outcome: :rejected, error: :malformed_json` |
| `:missing_bom_format` | JSON parses but no `bomFormat` field | Return `{:error, _}`; predicate emit |
| `:unsupported_spec_version` | `specVersion` is not 1.4/1.5/1.6 | Return `{:error, _}`; predicate emit |
| `:missing_components_key` | No `components` array (an SBOM with zero components is technically legal but useless to us) | Return `{:error, _}` |
| `:invalid_purl` | A component has a `purl` field that doesn't match Package URL spec | Return `{:error, _}` with the bad purl |
| `:duplicate_dependency_root` | Multiple components claim to be the SBOM root | Return `{:error, _}` with the conflicting refs |

## Canonicalization rules (R-002)

The canonicalizer MUST:
1. Sort all object keys lexicographically (recursive)
2. Use minimal numeric representation per JSON spec (no leading zeros, no trailing zeros after decimal, exponential notation only when necessary)
3. Escape strings per RFC 8259 (no escaping that's not strictly required; consistent escaping for control chars)
4. Use `\n` (not `\r\n`) for any embedded newlines
5. Drop fields that the parser reports as unknown — `unknown` fields don't affect digest computation (forward-compat).

This is RFC 8785 JCS modulo the unknown-field-drop rule (which is Spec B-specific because we don't validate the full schema).

## Dependencies

- `Jason` — JSON parsing (existing)
- `:crypto.hash(:sha256, _)` — digest computation (Erlang stdlib)
- No new Hex deps; small targeted parser per R-001
