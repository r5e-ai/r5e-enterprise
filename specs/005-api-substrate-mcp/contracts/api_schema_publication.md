# Contract: ApiSchemaPublication (CAS-referenced schema artifacts)

**Module**: `Recurse.Shared.ApiSubstrate.SchemaPublication`
**Phase**: 1 (substrate machinery)

## Purpose

Every API capability's request/response/error schema is published as an immutable CAS-referenced artifact. The schema artifact is canonicalized JSON Schema (draft 2020-12); the canonical form is hashed (SHA-256); the hash is the immutable identifier; the artifact is stored in S3 via the existing `StorageProvider`; the introspection surface returns `(url, digest)` pairs.

This is the same pattern Recurse uses for the predicate envelope schema versioning (per `.specify/state-of-play.md`). One mechanism, multiple consumers (predicate schemas + capability schemas + future REST/GraphQL schema publication).

## API surface

```elixir
defmodule Recurse.Shared.ApiSubstrate.SchemaPublication do
  @doc """
  Canonicalize + hash + store a JSON Schema. Returns the publication
  record with stable digest. Idempotent: re-publishing identical
  content returns the existing record.
  """
  @spec publish(schema :: map(), schema_kind :: :request | :response | :error) ::
          {:ok, %{
            id: integer(),
            digest: String.t(),
            cas_uri: String.t(),
            schema_kind: atom(),
            published_at: DateTime.t()
          }}

  @doc """
  Fetch a published schema by its CAS digest. Returns the canonicalized
  body. Caches in-memory after first fetch.
  """
  @spec fetch(digest :: String.t()) :: {:ok, map()} | {:error, :not_found}

  @doc """
  Verify a candidate schema body matches a known digest. Used by
  consumers (e.g., MCP intercept) when schema-checking incoming traffic.
  """
  @spec verify(body :: map(), digest :: String.t()) :: :ok | {:error, :digest_mismatch}
end
```

## Canonicalization rules

1. JSON Schema body is encoded as UTF-8 JSON with:
   - Object keys sorted alphabetically (recursive)
   - No trailing whitespace
   - Numbers in canonical form (no `1.0` for integer 1)
   - Unicode normalized to NFC
2. The canonicalized bytes are hashed with SHA-256.
3. The hex-lowercase digest IS the publication identifier.

## Storage

- Backend: existing `StorageProvider` (S3 in connected; MinIO/local in air-gapped).
- Key: `s3://<bucket>/api-substrate/schemas/<digest_first_2_chars>/<digest>.json` — sharded by first 2 hex chars to avoid bucket key explosion at scale.
- Content-Type: `application/schema+json`
- Object metadata: `schema_kind`, `published_at` (also stored in `api_schema_publications` row for queryability)

## Tests required

**Contract**:
- `publish/2` is idempotent: same input → same digest → same row
- `fetch/1` returns the exact canonicalized body for a known digest
- `verify/2` succeeds for matching body, fails with `:digest_mismatch` for non-matching

**Property tests** (`StreamData`):
- Round-trip: arbitrary JSON Schema → publish → fetch by returned digest → bytes match
- Canonicalization is order-invariant: schema with keys in different order produces same digest
- Tamper detection: any single-byte mutation of the body → `verify/2` returns `:digest_mismatch`

## Constitution alignment

- **Principle III** (Cryptographic Provenance): the digest IS the integrity proof. The hash IS the signature when paired with a signed predicate that contains the hash.
- **Principle IV** (Detached Payloads / Privacy-First): schemas live in S3, ledger only references digests. Schema deletion does NOT invalidate predicates that reference deleted schemas (verifier presents the cached schema).
- **Principle V** (Provider-Interface Neutrality): uses existing `StorageProvider` PI; no new vendor abstraction.
