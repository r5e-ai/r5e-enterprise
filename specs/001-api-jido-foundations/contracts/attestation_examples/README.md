# Attestation Examples (Deliverable E, SC-010)

Three worked attestation receipts — one per `principal.kind` — each
shown at all three `verification_level` states. Together they cover the
full matrix required by SC-010 and exercised by the CLI verifier
procedure (`../cli_verifier_procedure.md`).

Layout of each file:

```
{
  "_comment": "single JSON doc with three siblings keyed by verification_level",
  "signed":                     { "mediaType": ..., "dsseEnvelope": ..., "outer": ... },
  "local_inclusion_verified":   { "mediaType": ..., "dsseEnvelope": ..., "outer": ... },
  "global_inclusion_verified":  { "mediaType": ..., "dsseEnvelope": ..., "outer": ... }
}
```

The `dsseEnvelope` is identical across the three siblings for a given
principal — DSSE is signed once and the signed predicate never mutates.
Only the `outer` container advances:

| Level                          | `session_chain_epoch` present | `inclusion_proof_local` | `inclusion_proof_global` | `session_state`            |
|--------------------------------|-------------------------------|-------------------------|--------------------------|----------------------------|
| `signed`                       | yes (root may still be `null`)| `null`                  | `null`                   | `active`                   |
| `local_inclusion_verified`     | yes                           | RFC 9162 TransItem b64  | `null`                   | `active`                   |
| `global_inclusion_verified`    | yes                           | RFC 9162 TransItem b64  | RFC 9162 TransItem b64   | `interim_committed` or `committed` |

## Anchors (shared across all three files)

| Field                     | Value                                                                 |
|---------------------------|-----------------------------------------------------------------------|
| `policy_canonical_hash`   | `sha256:44ea666a2c953505b19b2f197d9128f9c4914149cd7a94f6db06833171cb5542` (Cedar stability fixture — see `../../../../apps/recurse_shared/priv/test_fixtures/cedar_stability/`) |
| `signer`                  | `spiffe://tenant-001.recurse.ai/gateway/g-01`                         |
| `tenant_id`               | `01HQXZ9RXK0000000000000T01` (ULID)                                   |
| `session_chain_root`      | `sha256:9f3c0b8aa1c6b4a5bde8e9b77f72e8b1c0d4a2f5e7d3b9a6c8d1e2f3a4b5c6d7` |

All `payload` fields are illustrative base64 of stand-in in-toto v1.0
Statements (`_type: https://in-toto.io/Statement/v1`, `predicateType:
https://recurse.ai/attestation/v1`). Real payloads would be produced by
the Gateway at emission time per FR-021. Signatures are placeholder
bytes — these fixtures are documentation, not live-verifiable crypto.
