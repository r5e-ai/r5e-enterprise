# Audit Payload Broker (Deliverable J — Part 1)

**Status**: Phase-1 contract. **Binding for Feature 002+ Gateway/Audit
Plane implementation.**

**Requirement**: FR-030.
**Related**: FR-011 (SPIFFE JWT-SVID auth), FR-021 (`payload_uri` in
signed predicate), FR-030a (Cedar-attributed authorization), FR-048
surface 2 (Export Evidence zip — broker retrieves the detached payload
bytes that land in the zip).

## Purpose

Attestation receipts carry only a `payload_hash` and a `payload_uri`
pointing at customer-owned storage (S3, GCS, Azure Blob, on-prem object
store). The **Audit Payload Broker** is the narrow, tenant-isolated
Recurse endpoint that resolves a `payload_uri` under a Cedar-attributed
authorization policy, streams the detached payload bytes back to a
permitted auditor, and guarantees cross-tenant isolation.

This is the ONLY Recurse-side surface that hands payload bytes to an
auditor. Everything else (DSSE verification, Merkle proof verification,
policy-hash verification) the auditor can do entirely off-platform
using the Export Evidence zip and `recurse-verify` per
`cli_verifier_procedure.md`.

## Endpoint

```
GET /v1/audit/broker/{payload_uri_hash}
```

| Field                 | Value                                                              |
|-----------------------|--------------------------------------------------------------------|
| Method                | `GET`                                                              |
| Auth                  | `Authorization: Bearer <SPIFFE JWT-SVID>` (FR-011)                 |
| `{payload_uri_hash}`  | `sha256` hex of the canonical `payload_uri` string from the receipt. The hash is used rather than the raw URI to keep customer storage paths out of URL logs. |
| Required headers      | `X-Correlation-ID` (ULID per FR-031), `Accept: application/octet-stream` |
| Response body         | Raw payload bytes — exactly the bytes whose SHA-256 equals `payload_hash` in the signed predicate. |
| Response `Content-Type` | `application/octet-stream`                                       |
| `Transfer-Encoding`   | `chunked` — broker streams bytes as they land from customer storage |

Rationale for path-by-hash: an auditor knows `payload_uri` from the
receipt but exposing it in URL paths leaks customer storage layout to
the broker's access logs. The broker maintains an internal
`payload_uri_hash → payload_uri` map keyed by tenant.

## Authorization model (Cedar-attributed, FR-030a)

Every broker call is authorized by evaluating the active Cedar policy
bundle (FR-039) against the tuple `(Principal, Action::GetPayload,
Resource::Payload, Context)`. No hardcoded roles; everything lives in
policy.

Baseline Cedar policy auditors configure (shipped as a template in the
Cedar Playground's policy library):

```cedar
// grant platform_operators and tenant_auditors access to payload
// bytes for receipts within their assigned tenant
permit(
    principal,
    action == Action::"GetPayload",
    resource
) when {
    principal.recurse_role in ["platform_operator", "tenant_auditor"]
    && principal.tenant_id == resource.tenant_id
};
```

Entity shapes passed to the Cedar authorizer:

```json
{
  "principal": {
    "uid": { "type": "RecurseUser", "id": "u-alice" },
    "attrs": {
      "recurse_role": "tenant_auditor",
      "tenant_id": "01HQXZ9RXK0000000000000T01",
      "principal_kind": "obo_human",
      "subject": "alice@audit.example.com"
    }
  },
  "action": { "uid": { "type": "Action", "id": "GetPayload" } },
  "resource": {
    "uid": { "type": "Payload", "id": "sha256:a2c4e680...9876" },
    "attrs": {
      "tenant_id": "01HQXZ9RXK0000000000000T01",
      "run_id": "01HQXZ9RXKRUN000000000RU01",
      "session_id": "01HQXZ9RXKSESS0000000000001",
      "event_kind": "tool_call",
      "payload_uri_scheme": "s3"
    }
  },
  "context": {
    "correlation_id": "01HQXZ9RXKCORR00000000000CC",
    "request_time": "2026-04-22T14:31:17Z",
    "jwt_svid_spiffe_id": "spiffe://tenant-001.recurse.ai/auditor/alice-laptop"
  }
}
```

The broker:

1. Authenticates the caller's SPIFFE JWT-SVID (`PrincipalProvider`
   resolves the carried claims to an `IdentityContext` per FR-011 /
   FR-026).
2. Resolves `payload_uri_hash` against the tenant-scoped URI map to
   recover the full `Payload` entity (`tenant_id`, `run_id`,
   `session_id`, `event_kind`, `payload_uri_scheme`).
3. Calls `Recurse.Cedar.evaluate(principal, action, resource, context)`.
4. Allows the stream only on `Decision::Allow`; otherwise returns
   `ERR_POLICY_DENIED` without revealing whether the payload exists.

## Never-out-of-scope guarantee (cross-tenant isolation)

The broker enforces tenant isolation in **two** independent layers; both
must pass for a stream to begin:

**Layer 1 — Structural pre-check (before Cedar).** On the decoded
`IdentityContext`, the broker asserts
`principal.tenant_id == payload.tenant_id`. If the hash-to-URI map lookup
requires cross-tenant fan-out to even find the `payload_uri`, the
lookup is scoped to the caller's tenant partition only — an auditor
from tenant A cannot hash-collide into tenant B's storage. Mismatch
returns `ERR_TENANT_ISOLATION` immediately with no Cedar evaluation.

**Layer 2 — Cedar policy check.** The baseline policy template above
REQUIRES `principal.tenant_id == resource.tenant_id` regardless of
role. Even if a customer mis-authors a Cedar policy that grants
`platform_operator` a global role, the broker's structural pre-check
in Layer 1 has already prevented any cross-tenant lookup. A Cedar
policy can widen access WITHIN a tenant but cannot widen it ACROSS
tenants.

This two-layer design is the concrete Principle-III-compliant
implementation of the constitutional "fail-closed on tenant isolation"
invariant. It is enforced by the Gateway code, not by operator vigilance.

## Streaming response

Payloads can be large (multi-MB LLM prompts/responses; tool-call JSON
blobs with attached binaries). The broker streams:

1. Opens the customer `StorageProvider` ranged read at offset 0.
2. Sends `HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\n\r\n`.
3. Streams bytes in chunks (`StorageProvider` drives chunk size;
   typical 64 KiB).
4. Emits trailing SHA-256 in response trailer `X-Payload-Hash: sha256:...`
   so the auditor's verifier MAY compare against the receipt's
   `payload_hash` inline. (The zip-based flow in
   `cli_verifier_procedure.md` compares without needing the trailer,
   but the trailer is a convenience for live-streaming auditors.)

The broker does NOT buffer the full payload in memory.

## Failure modes

All failures use the v1.0 Error Envelope per FR-010:

| `error.code`              | HTTP | Trigger                                                                                      | Log detail                                               |
|---------------------------|------|----------------------------------------------------------------------------------------------|----------------------------------------------------------|
| `ERR_AUTH_FAILED`         | 401  | SPIFFE JWT-SVID invalid, expired, untrusted issuer, missing                                  | Include `jwt_svid_spiffe_id` claim if parseable          |
| `ERR_NOT_FOUND`           | 404  | `payload_uri_hash` unknown within caller's tenant partition                                  | No disclosure whether hash exists in a different tenant  |
| `ERR_POLICY_DENIED`       | 403  | Cedar `Decision::Deny`; tenant match already verified                                        | Log the denying policy ID (not the policy body)          |
| `ERR_TENANT_ISOLATION`    | 403  | Structural pre-check failed: `principal.tenant_id != resource.tenant_id`                     | Log both tenant IDs plus the correlation ID for audit    |
| `ERR_STORAGE_UNAVAILABLE` | 502  | Customer `StorageProvider` rejected / timed out the ranged read                              | Do NOT leak underlying provider error text to auditor    |
| `ERR_PAYLOAD_CORRUPTED`   | 502  | Streaming-time SHA-256 of retrieved bytes ≠ receipt's `payload_hash`                         | Fire `recurse_audit_payload_hash_mismatch_total` metric  |

`ERR_NOT_FOUND` and `ERR_POLICY_DENIED` deliberately return the same
shape body to prevent probing. Only `ERR_TENANT_ISOLATION` is returned
instead of `ERR_POLICY_DENIED` when the pre-check failed — this is
loud-fail by design because a tenant-isolation mismatch is a
constitutional integrity event that MUST alert operators.

## Metrics

- `recurse_audit_broker_requests_total{tenant_id, decision}` — counter,
  label `decision` ∈ `{allow, deny_policy, deny_isolation, auth_failed,
  not_found}`.
- `recurse_audit_broker_bytes_streamed_total{tenant_id}` — counter.
- `recurse_audit_payload_hash_mismatch_total{tenant_id}` — counter;
  alerts on any non-zero increment.
- `recurse_audit_broker_latency_seconds_bucket{tenant_id, phase}` —
  histogram; `phase` ∈ `{auth, cedar, storage_first_byte, storage_total}`.

## Cross-references

- `signing_key_archive.md` (Deliverable J part 2) — the public signing
  key material an auditor uses to verify the DSSE envelope of the
  receipt whose `payload_uri` led them here.
- `cli_verifier_procedure.md` (Deliverable J part 3) — the end-to-end
  off-platform verification flow; step 5 reconciles the streamed bytes'
  SHA-256 against the receipt's `payload_hash`.
- `../data-model.md` — `Attestation` entity's `payload_hash` +
  `payload_uri` fields and the canonicalization rules that give
  `payload_uri_hash` its stable value.
- `openapi.yaml` — endpoint listing.

## Forward compatibility

- **Presigned-URL mode (Phase 2).** A future performance optimization may
  return a short-lived presigned URL to customer storage directly
  rather than proxying bytes. Any such mode will be an explicit
  opt-in per tenant; the proxy path stays the canonical Phase-1
  default because it preserves the two-layer isolation guarantee
  without relying on the storage provider's presigning semantics.
- **Range-request support (Phase 2).** The endpoint will accept
  `Range:` headers forwarded to the underlying `StorageProvider` for
  sampled audits of very-large payloads. Not Phase-1.
