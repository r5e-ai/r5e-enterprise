# Contract: SbomPublication

**Module**: `Recurse.Shared.Sbom.Publication`
**Owner phase**: Phase 1 (types + parser)
**Consumed by**: Phase 2 (ingest pipeline), Phase 3 (graph queries), Phase 4 (blast-radius), Phase 5 (binding emitter), Phase 6 (UI)

## Purpose

The canonical CAS-referenced ingested CycloneDX SBOM document. Every `SbomPublication` is uniquely identified by `(tenant_id, digest, arch)`; the `digest` is the SHA-256 of the RFC 8785 JCS-canonicalized JSON body.

## Struct shape

```elixir
%Recurse.Shared.Sbom.Publication{
  id: integer(),
  tenant_id: integer(),
  digest: <<binary, 32 bytes>>,
  spec_version: "1.4" | "1.5" | "1.6",
  serial_number: String.t() | nil,
  document_cas_ref: String.t(),       # e.g. "s3://recurse-cas/sha256/<hex_digest>"
  size_bytes: pos_integer(),
  component_count: non_neg_integer(),
  edge_count: non_neg_integer(),
  max_depth: non_neg_integer(),
  has_cycles: boolean(),
  ingest_warnings: [%{type: atom(), details: map()}],
  binary_identity: String.t(),
  arch: String.t(),
  inserted_at: DateTime.t(),
  updated_at: DateTime.t()
}
```

## Invariants

- **I-001**: `digest` is exactly 32 bytes (SHA-256 binary).
- **I-002**: `digest` is computed deterministically from canonical JSON: re-canonicalizing + re-hashing the document at `document_cas_ref` MUST yield the same `digest`.
- **I-003**: `(tenant_id, digest, arch)` is unique. Concurrent ingest of the same triple is a no-op (R-006).
- **I-004**: `size_bytes` ≤ tenant's configured size cap (default 100 MB, R-005).
- **I-005**: `component_count` and `edge_count` match the count of rows in `sbom_components` (after dedup) and `sbom_dependency_edges` for this publication respectively.
- **I-006**: `max_depth` ≤ 30 (sanity; depth-bounded traversal at 20).
- **I-007**: `binary_identity` is non-empty and one of: OCI digest (`sha256:<hex>`), purl (`pkg:<ecosystem>/<name>@<version>`), or `<ecosystem>:<name>@<version>` fallback.
- **I-008**: `arch` is one of: `"amd64"`, `"arm64"`, `"amd64+darwin"`, `"arm64+darwin"`, `"any"` (extensible — these are the launch values).

## Public API

```elixir
@spec by_digest(tenant_id :: integer(), digest :: binary(), arch :: String.t()) ::
        {:ok, t()} | {:error, :not_found}

@spec list_for_binary(tenant_id :: integer(), binary_identity :: String.t()) :: [t()]

@spec fetch_canonical_json(t()) ::
        {:ok, binary()} | {:error, :payload_unavailable}
```

`fetch_canonical_json/1` calls into the existing `StorageProvider` to retrieve the body from S3 (or MinIO in air-gapped). The body is cached in-process briefly via `:ets`-backed cache (TTL 5min) to amortize repeated fetches.

## Test contracts

- **CT-001**: For a known CycloneDX 1.5 fixture, `Publication.by_digest/3` returns the publication with the expected fields populated.
- **CT-002**: `Publication.list_for_binary/2` returns multi-arch SBOMs grouped by arch (e.g., `[%{arch: "amd64"}, %{arch: "arm64"}]` for a multi-arch binary).
- **CT-003**: `Publication.fetch_canonical_json/1` returns the same bytes that were CAS-stored at ingest time; re-hashing yields the same `digest`.

## Property tests

- **PT-001**: For any well-formed CycloneDX document, `parse → canonicalize → SHA-256` is deterministic across runs and across processes.
- **PT-002**: `Publication.by_digest/3` is idempotent — concurrent `INSERT ... ON CONFLICT DO NOTHING` against the same `(tenant_id, digest, arch)` always yields exactly one row.

## Failure modes

- `:size_exceeded` — body exceeds configured size cap; ingest rejects pre-parse
- `:invalid_spec_version` — document is not CycloneDX 1.4/1.5/1.6
- `:malformed_json` — body is not valid JSON
- `:malformed_cyclonedx` — JSON is valid but doesn't match minimal CycloneDX shape (missing `bomFormat`, etc.)
- `:cas_storage_failed` — S3 PUT failed (re-tried per `StorageProvider` retry policy first)

All failures are `{:error, atom()}` or `{:error, %{reason: atom(), details: map()}}` — no exceptions on hot ingest path.
