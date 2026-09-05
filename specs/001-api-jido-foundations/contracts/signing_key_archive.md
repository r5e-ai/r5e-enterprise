# Signing-Key Archive (Deliverable J — Part 2)

**Status**: Phase-1 contract. **Binding for Feature 002+ Gateway/Audit
Plane implementation.**

**Requirement**: FR-046 (KMS-backed long-lived Gateway document-signing
key).
**Related**: FR-003 (`SecretsProvider`), FR-021 (signed predicate's
`signer` field references archived key), FR-048 surface 2 (Export
Evidence zip carries key material), SC-020 (long-horizon verification
at T+1 year), Constitution Principle III (durability).

## Purpose

Transport SVIDs rotate hourly. Document-signing keys DON'T — they
must stay verifiable for the lifetime of a receipt, which is forever
(constitutional durability, Principle III). The **Signing-Key
Archive** is the Postgres row plus the `SecretsProvider`-released
public-key material that together let an auditor verify a receipt's
DSSE signature years after the Gateway that signed it has been torn
down.

An auditor running the CLI procedure does NOT query this archive
directly — the material they need is baked into each Export Evidence
zip (FR-048 surface 2). The archive is the authoritative source that
the zip pulls from at export time, and the online endpoint
(`GET /v1/audit/signing-keys/...`) is a convenience for customers
verifying live without a zip.

## Lifecycle

```
      ┌──────────────┐
      │  SecretsProvider │
      │  (KMS / HSM / Vault)
      └────┬─────────┘
           │  mint (new key, new version)
           ▼
    ┌──────────────┐      use      ┌────────────┐
    │    active    │──────────────▶│ Gateway    │──sign──▶ DSSE envelope
    │ (key_id, vN) │               │ signs      │         (signer_key_id, signer_key_version)
    └──────┬───────┘               └────────────┘
           │  quarterly rotation (default)
           │  — or — operator-initiated rotation
           ▼
    ┌──────────────┐
    │  retired     │  retired_at = now()
    │ (still read- │  row NEVER deleted (Principle III)
    │  only, still │
    │  verifiable) │
    └──────────────┘
```

**Mint.** On first Gateway boot per tenant, and on each rotation, the
Gateway authenticates to `SecretsProvider` using its short-lived
transport SVID and requests a new signing key. The provider returns
`{key_id, key_version, public_key_pem, key_algorithm, not_before,
not_after}`. Private material never leaves the KMS.

**Use.** Receipts reference the active key by
`signer_key_id:signer_key_version`. The DSSE envelope's
`signatures[].keyid` is the composite string `<key_id>:v<key_version>`
per FR-021.

**Rotate.** Default schedule: **quarterly** (every 90 days). An
operator may trigger early rotation (e.g., suspected key compromise).
Rotation:

1. Mint new `key_id:vN+1` via `SecretsProvider`.
2. Insert new `SigningKey` row (`retired_at = null`).
3. Mark prior row `retired_at = now()`. Row is retained; `public_key_pem`
   stays readable indefinitely.
4. New attestations emitted after step 2 reference `vN+1`.
5. In-flight attestations signed with `vN` remain verifiable against
   the retired row's `public_key_pem` forever.

**Archive.** Retirement is purely a flag; the row lives forever.

## KMS integration (`SecretsProvider`)

| Tier                   | `SecretsProvider` implementation                                                                 |
|------------------------|--------------------------------------------------------------------------------------------------|
| `managed_saas`         | AWS KMS via IRSA-attached IAM role on Gateway pod. Key policy pins access to Gateway's SPIFFE ID. |
| `standalone_gateway`   | AWS KMS (same as above) OR customer Vault (Transit engine) per tier config.                      |
| `vpc_runner`           | Customer AWS KMS in their VPC; IRSA or direct IAM.                                               |
| `appliance`            | Local HSM-equivalent (PKCS#11 device) OR bundled software HSM per FR-046; key never leaves appliance. |

The `SecretsProvider` contract (see
`provider_interfaces/secrets_provider.ex`) commits these callbacks:

- `sign(key_id, key_version, bytes_to_sign) :: {:ok, signature} | {:error, term}`
- `public_key(key_id, key_version) :: {:ok, {pem, key_algorithm}} | {:error, term}`
- `mint(tenant_id, key_algorithm) :: {:ok, key_id, key_version} | {:error, term}`
- `list_versions(key_id) :: {:ok, [key_version]} | {:error, term}`

The Gateway's signing critical path is a single `sign/3` call; no key
material enters BEAM memory.

## Public-key export format

The on-disk (and on-zip) representation of one signing-key row:

```
signing_keys/<key_id>/v<key_version>/
  ├── public.pem            PEM-encoded SubjectPublicKeyInfo
  └── metadata.json         see schema below
```

`metadata.json`:

```json
{
  "key_id": "rec-signing-2026q2",
  "key_version": 3,
  "tenant_id": "01HQXZ9RXK0000000000000T01",
  "key_algorithm": "ed25519",
  "signer_spiffe_id": "spiffe://tenant-001.recurse.ai/gateway/g-01",
  "not_before": "2026-04-01T00:00:00Z",
  "not_after":  "2026-07-01T00:00:00Z",
  "created_at": "2026-04-01T00:00:00Z",
  "retired_at": null,
  "source": "aws-kms",
  "source_key_arn": "arn:aws:kms:us-east-1:111122223333:key/abcd1234-..."
}
```

Field rules:

- `key_algorithm`: enum `ed25519` (preferred) | `ecdsa_p256` | `rsa_pss_2048`.
- `not_before` / `not_after`: advisory validity window. Expired keys
  remain verifiable (constitutional durability); the window is for
  operator rotation UX and does NOT gate verification.
- `signer_spiffe_id`: the Gateway instance that issued this key
  version. For multi-Gateway-instance tenants this identifies which
  instance minted the key; it is NOT the transport SVID.
- `source`: which `SecretsProvider` backend this key lives in
  (`aws-kms` | `vault-transit` | `pkcs11-hsm` | `software-hsm`).
- `source_key_arn` / `source_key_uri` (optional): provider-native
  identifier. Advisory only — the composite `(key_id, key_version)`
  is the Recurse-native primary key.

PEM format is RFC 7468-compliant `-----BEGIN PUBLIC KEY-----` blocks
containing a SubjectPublicKeyInfo DER per RFC 5280.

## Archive schema (Postgres)

Repeating `data-model.md` for the broker contract's self-containment:

```sql
CREATE TABLE signing_keys (
  id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
  key_id          TEXT         NOT NULL,
  key_version     INTEGER      NOT NULL,
  tenant_id       TEXT         NOT NULL REFERENCES tenants(id),
  spiffe_signer_id TEXT        NOT NULL,
  public_key_pem  TEXT         NOT NULL,
  key_algorithm   TEXT         NOT NULL
                               CHECK (key_algorithm IN ('ed25519','ecdsa_p256','rsa_pss_2048')),
  not_before      TIMESTAMPTZ  NOT NULL,
  not_after       TIMESTAMPTZ  NOT NULL,
  source          TEXT         NOT NULL,
  source_key_arn  TEXT,
  created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
  retired_at      TIMESTAMPTZ,                         -- NULL = active; NEVER UPDATE TO NULL after set
  UNIQUE (key_id, key_version),
  UNIQUE (tenant_id, key_id, key_version)
);

-- Constitutional durability: deletions are forbidden.
-- Enforced by a deny-DELETE trigger at the Gateway DB user level.
CREATE OR REPLACE FUNCTION signing_keys_forbid_delete()
RETURNS TRIGGER AS $$
BEGIN
  RAISE EXCEPTION 'signing_keys rows are retained forever (Constitution Principle III)';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER signing_keys_no_delete
  BEFORE DELETE ON signing_keys
  FOR EACH ROW EXECUTE FUNCTION signing_keys_forbid_delete();
```

Field `retired_at` is nullable: `NULL` ⇒ active, timestamp ⇒ retired.
Retirement transitions once, monotonically. No row is ever deleted.

## Query surface

### `GET /v1/audit/signing-keys/{key_id}/v{key_version}`

| Field           | Value                                                                                          |
|-----------------|------------------------------------------------------------------------------------------------|
| Method          | `GET`                                                                                          |
| Auth            | `Authorization: Bearer <SPIFFE JWT-SVID>` (FR-011), Cedar-authorized same pattern as payload broker (`audit_payload_broker.md`) |
| Response `Content-Type` | `application/json`                                                                     |
| Response body   | the `metadata.json` shape above, with `public_key_pem` embedded as a string.                   |

Response shape:

```json
{
  "key_id": "rec-signing-2026q2",
  "key_version": 3,
  "tenant_id": "01HQXZ9RXK0000000000000T01",
  "key_algorithm": "ed25519",
  "signer_spiffe_id": "spiffe://tenant-001.recurse.ai/gateway/g-01",
  "not_before": "2026-04-01T00:00:00Z",
  "not_after": "2026-07-01T00:00:00Z",
  "created_at": "2026-04-01T00:00:00Z",
  "retired_at": null,
  "public_key_pem": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAB...\n-----END PUBLIC KEY-----\n"
}
```

Cedar policy attributes on the `Resource::SigningKey` entity:
`tenant_id`, `key_id`, `key_version`, `retired` (bool). Baseline
policy template grants `tenant_auditor` read of all keys in their
tenant (retired or active) — retired keys MUST remain readable or
long-horizon verification breaks.

### `GET /v1/audit/signing-keys?tenant_id={t}`

List endpoint for admin/operator UIs. Returns all versions (active +
retired). Paginated per FR-019. Not used by the CLI verifier procedure.

## Export Evidence zip integration (cross-ref T087)

Every Export Evidence zip for `run_id = R` includes:

```
evidence/<run_id>/signing_key_archive/
  ├── <key_id_1>/
  │     ├── v<version>/
  │     │   ├── public.pem
  │     │   └── metadata.json
  │     └── v<version_next>/
  │         ├── public.pem
  │         └── metadata.json
  ├── <key_id_2>/
  │     └── v<version>/...
  └── INDEX.json         — enumerates every (key_id, key_version) referenced
                           by any attestation in this run_id
```

`INDEX.json`:

```json
{
  "run_id": "01HQXZ9RXKRUN000000000RU01",
  "exported_at": "2026-04-22T15:00:00Z",
  "keys": [
    { "key_id": "rec-signing-2026q2", "key_version": 3, "path": "rec-signing-2026q2/v3/" },
    { "key_id": "rec-signing-2026q1", "key_version": 7, "path": "rec-signing-2026q1/v7/" }
  ]
}
```

The Export Evidence exporter (T087) walks every attestation in the
run, collects the distinct `(signer_key_id, signer_key_version)`
tuples, and emits one directory per tuple. This makes the zip
**self-contained** for offline verification — the auditor never
needs the archive endpoint because every referenced public key
travels inside the zip.

This is the mechanism that makes SC-020 (T0+1 year verification)
concrete: even if the Gateway that signed is long gone, its public
keys rode out with every receipt it ever produced.

## Failure modes

All failures use the v1.0 Error Envelope per FR-010.

| `error.code`          | HTTP | Trigger                                                                                  |
|-----------------------|------|------------------------------------------------------------------------------------------|
| `ERR_AUTH_FAILED`     | 401  | SPIFFE JWT-SVID invalid / expired / untrusted                                            |
| `ERR_NOT_FOUND`       | 404  | `key_id:version` unknown within caller's tenant (no cross-tenant disclosure)             |
| `ERR_POLICY_DENIED`   | 403  | Cedar `Decision::Deny`                                                                    |
| `ERR_TENANT_ISOLATION`| 403  | Structural pre-check `principal.tenant_id != signing_key.tenant_id`                      |
| `ERR_KMS_UNAVAILABLE` | 502  | Online mint / sign path failed; `SecretsProvider` circuit-breaker open (verification-only read-path always succeeds because `public_key_pem` is cached in `signing_keys`) |

Note: **verification-path reads NEVER depend on KMS availability.** The
public key is materialized into `public_key_pem` at mint time and
stays in Postgres forever. KMS outages block new signing, not
verification. This is a core FR-046 property for SC-015 fail-closed
posture.

## Metrics

- `recurse_signing_key_archive_requests_total{tenant_id, decision}`
- `recurse_signing_key_rotations_total{tenant_id, key_id}`
- `recurse_signing_key_retire_latency_seconds{tenant_id}` — histogram,
  time from mint-new to retire-old during rotation.
- `recurse_signing_key_kms_sign_errors_total{tenant_id, key_id}` —
  alerts on non-zero (upstream KMS sign path unavailable).

## Cross-references

- `provider_interfaces/secrets_provider.ex` — the behaviour bound
  by every `SecretsProvider` impl.
- `audit_payload_broker.md` (Deliverable J part 1) — shares the
  Cedar-authorization + tenant-pre-check pattern.
- `cli_verifier_procedure.md` (Deliverable J part 3) — step 2 of
  the CLI flow consumes `public.pem` from the zip.
- `../data-model.md` §`SigningKey` — authoritative ERD row.
- T087 Export Evidence zip task — the exporter that bakes this
  archive material into each zip.

## HANDOFF notes

- **Public-key export format is fully specified** for `ed25519` /
  `ecdsa_p256` / `rsa_pss_2048`. For any fourth algorithm added in a
  future Phase (e.g., ML-DSA / post-quantum), the `metadata.json`
  `key_algorithm` enum bumps MINOR version of the
  `application/vnd.recurse.attestation+json` mediaType and the CLI
  verifier procedure is revised. No Phase-1 work needed.
- `source_key_arn` field is advisory; some `SecretsProvider`
  implementations (software HSM on air-gapped Appliance) have no
  external URI. Field is optional in `metadata.json`; auditors MUST
  NOT treat its absence as an error.
