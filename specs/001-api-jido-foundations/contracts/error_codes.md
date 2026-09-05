# Error Code Enum (Deliverable H — FR-010)

> **STATUS (2026-04-29, issue #30 Task M):** the original `Recurse.Shared.ErrorCodes`
> module enumerated below was **deleted** as a zero-caller aspirational shell. The
> v1.0 atom enum drifted away from what handlers actually emit on the wire (which
> the SPA's `ApiError` parser at `ui/src/lib/api.ts` is the canonical consumer of).
> Real consolidation now lives in three per-domain modules:
>
>   * `apps/recurse_gateway/lib/recurse_gateway/identity/auth_failure_reason.ex`
>     — JWT-validation reason → `ERR_UNAUTHORIZED_*` per-cause codes.
>   * `apps/recurse_gateway/lib/recurse_gateway/audit_plane/authz.ex`
>     `forbidden_code_and_message/1` — Cedar-deny reason → `ERR_FORBIDDEN`
>     / `ERR_FORBIDDEN_TENANT`.
>   * `apps/recurse_gateway/lib/recurse_gateway/admin/browser_session_plug.ex`
>     `unauthorized_envelope_for/1` — cookie failure cause → `ERR_SESSION_*`.
>
> The canonical wire envelope is now the flat shape pinned by
> `apps/recurse_gateway/priv/schemas/error_envelope.json` and built by
> `Recurse.Gateway.AuditPlane.ErrorEnvelope.build/3`. The 12-code v1.0 enum
> below is preserved as a historical reference for the original FR-010
> contract; the live wire codes are a superset and per-cause discriminated.

Canonical enumeration of the twelve v1.0 error codes used in the Recurse
uniform error envelope on the Control, Governance, and Audit Planes.
Data Plane errors are **never** rendered through this envelope — they follow
FR-016a–f (protocol-native).

**Historical authoritative source**: was the Elixir module
`apps/recurse_shared/lib/recurse_shared/error_codes.ex`
(`Recurse.Shared.ErrorCodes`) — deleted in MR #30/Task M. Live consolidation
is in the per-domain modules listed in the status banner above.

## Envelope shape

```json
{
  "code": "ERR_TIER_MISMATCH",
  "message": "endpoint not implemented in this deployment tier",
  "correlation_id": "01HXXXXXXXXXXXXXXXXXXXXXXX",
  "details": {
    "active_tier": "standalone_gateway",
    "endpoint_requires_tier": ["managed_saas", "vpc_runner", "appliance"]
  }
}
```

Every envelope carries `code`, `message`, and `correlation_id` (ULID per
FR-018). `details` is optional and carries structured context relevant to the
specific code — e.g., `{active_tier, endpoint_requires_tier}` for
`ERR_TIER_MISMATCH`, `{retry_after_seconds, limit, window}` for
`ERR_RATE_LIMITED`.

## Summary table

| Code                         | HTTP | When emitted                                                                                                                             |
|------------------------------|-----:|------------------------------------------------------------------------------------------------------------------------------------------|
| `ERR_AUTH_FAILED`            | 401  | Non-Data-Plane inbound SPIFFE-JWT-SVID (FR-011) or `X-Observed-Identity` JWT (FR-017) invalid / expired / not presented.                |
| `ERR_PRINCIPAL_FAILED`       | 401  | Machine identity passed; PrincipalProvider could not validate / resolve the principal claim (FR-026). Missing-principal fails closed.    |
| `ERR_VALIDATION`             | 400  | Malformed request body, missing required fields, missing or malformed `Idempotency-Key` on a required endpoint (FR-028).                |
| `ERR_TIER_MISMATCH`          | 501  | Client called a tier-inactive endpoint (e.g., `/v1/orchestrator/*` against a `standalone_gateway` deployment). 501, not 503, per FR-024. |
| `ERR_RATE_LIMITED`           | 429  | Per-tenant / per-plane QPS or payload-size limit exceeded (FR-023). Response carries `Retry-After` and `X-RateLimit-*` headers.         |
| `ERR_POLICY_DENIED`          | 403  | A Control / Governance / Audit Plane call was denied by Cedar policy. Data Plane denials are protocol-native (FR-016a), not this code.   |
| `ERR_TENANT_ISOLATION`       | 403  | Defense-in-depth check per FR-020 — structurally impossible in BEAM-per-customer Phase 1, but wired to catch any future-Phase-2 leak.    |
| `ERR_NOT_FOUND`              | 404  | Addressed resource does not exist (unknown `run_id`, `step_id`, `policy_bundle_digest`, etc.).                                           |
| `ERR_INTERNAL`               | 500  | Unexpected server-side failure; logged with correlation_id for operator follow-up. No sensitive details leaked in `message`.             |
| `ERR_LEDGER_COMMIT_FAILED`   | 500  | Global-ledger commit attempt failed after backoff exhaustion (FR-040). Affected session surfaces `commit_retry_exhausted: true` in outer.|
| `ERR_SESSION_UNKNOWN`        | 404  | Audit / Control plane call referenced a `session_id` the Runtime has no record of.                                                       |
| `ERR_TOKEN_EXCHANGE_FAILED`  | 500  | RFC 8693 Token Exchange (FR-047) to the IdP failed; propagated back to MCP server and then to the agent as a protocol-native error frame.|

All mappings are asserted by the test in
`apps/recurse_gateway/test/audit_plane/error_envelope_test.exs` and the per-handler contract tests under `apps/recurse_gateway/test/audit_plane/` and `apps/recurse_gateway/test/admin/`.

## Detailed reference

### `ERR_AUTH_FAILED` — HTTP 401

Inbound machine-identity validation failed. Common causes:

- Missing `Authorization: Bearer <SPIFFE-JWT-SVID>` on a Control / Governance /
  Audit Plane request.
- SVID signature invalid against the configured trust-domain CA.
- SVID `exp` in the past (no grace; FR-011 specifies reject-on-expiry).
- `X-Observed-Identity` JWT (Standalone Gateway) signed with a disallowed
  algorithm (HS256, `none`), missing a required claim, or `aud` mismatch.

Example:

```json
HTTP/1.1 401 Unauthorized
Content-Type: application/json

{
  "code": "ERR_AUTH_FAILED",
  "message": "SPIFFE SVID expired",
  "correlation_id": "01HXXXXXXXXXXXXXXXXXXXXXXX"
}
```

### `ERR_PRINCIPAL_FAILED` — HTTP 401

Machine identity passed but the PrincipalProvider could not produce a valid
principal claim. Examples:

- `PrincipalProvider.validate/2` returned `{:error, :upstream_idp_unreachable}`.
- Returned principal failed JCS canonicalization round-trip.
- `principal.kind` field missing or unrecognized.

Per FR-026 missing-principal fails closed.

```json
HTTP/1.1 401 Unauthorized

{
  "code": "ERR_PRINCIPAL_FAILED",
  "message": "PrincipalProvider returned no principal",
  "correlation_id": "01HXXXXXXXXXXXXXXXXXXXXXXX"
}
```

### `ERR_VALIDATION` — HTTP 400

Client-side malformed input. Always emitted on missing/invalid
`Idempotency-Key` for required endpoints (FR-028). Never rolls up or suppresses
field-level detail — `details.field_errors[]` is the convention.

```json
HTTP/1.1 400 Bad Request

{
  "code": "ERR_VALIDATION",
  "message": "request body failed schema validation",
  "correlation_id": "01HXXXXXXXXXXXXXXXXXXXXXXX",
  "details": {
    "field_errors": [
      {"field": "execution_mode", "error": "must be one of [byoc]"},
      {"field": "policy_bindings", "error": "must be a non-empty array"}
    ]
  }
}
```

### `ERR_TIER_MISMATCH` — HTTP 501

The only endpoint-inactive code. Per FR-024 the deliberate choice of 501
(vs 503) prevents LB / SDK retry storms. `details` always carries
`active_tier` and `endpoint_requires_tier[]`.

```json
HTTP/1.1 501 Not Implemented

{
  "code": "ERR_TIER_MISMATCH",
  "message": "endpoint not implemented in this deployment tier",
  "correlation_id": "01HXXXXXXXXXXXXXXXXXXXXXXX",
  "details": {
    "active_tier": "standalone_gateway",
    "endpoint_requires_tier": ["managed_saas", "vpc_runner", "appliance"]
  }
}
```

### `ERR_RATE_LIMITED` — HTTP 429

Per-tenant / per-plane limit breached. Non-Data-Plane path. Response includes
`Retry-After` and `X-RateLimit-Limit`, `X-RateLimit-Remaining`,
`X-RateLimit-Reset` headers per FR-023.

```json
HTTP/1.1 429 Too Many Requests
Retry-After: 5
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1714060800

{
  "code": "ERR_RATE_LIMITED",
  "message": "tenant QPS exceeded on control plane",
  "correlation_id": "01HXXXXXXXXXXXXXXXXXXXXXXX",
  "details": {
    "retry_after_seconds": 5,
    "limit": 60,
    "window": "1m"
  }
}
```

### `ERR_POLICY_DENIED` — HTTP 403

Cedar policy evaluation returned `Deny` on a Control / Governance / Audit
request (NOT on Data Plane — Data Plane denials are protocol-native per
FR-016a). `details.policy_canonical_hash` identifies the bundle that denied.

```json
HTTP/1.1 403 Forbidden

{
  "code": "ERR_POLICY_DENIED",
  "message": "caller principal not authorized for Audit Plane payload broker",
  "correlation_id": "01HXXXXXXXXXXXXXXXXXXXXXXX",
  "details": {
    "policy_canonical_hash": "c30a2d...",
    "matched_rules": ["deny_payload_access_without_auditor_role"]
  }
}
```

### `ERR_TENANT_ISOLATION` — HTTP 403

Defense-in-depth only. In Phase 1 (BEAM-per-customer) this is structurally
unreachable, but the check is wired per FR-020 so any future multi-tenant
regression fails loud. Any emission in production is treated as a P0 incident.

```json
HTTP/1.1 403 Forbidden

{
  "code": "ERR_TENANT_ISOLATION",
  "message": "cross-tenant access attempt detected (defense-in-depth)",
  "correlation_id": "01HXXXXXXXXXXXXXXXXXXXXXXX",
  "details": {
    "expected_tenant": "01HTENANTA00000000000000000",
    "observed_tenant": "01HTENANTB00000000000000000"
  }
}
```

### `ERR_NOT_FOUND` — HTTP 404

Addressed resource does not exist. Covers unknown `run_id` on
`/v1/audit/receipts/{run_id}/{step_id}`, unknown `policy_bundle_digest` on
`/v1/governance/policy/{digest}`, unknown `payload_uri_hash` on the audit
broker, etc.

```json
HTTP/1.1 404 Not Found

{
  "code": "ERR_NOT_FOUND",
  "message": "no receipt for run_id=01H... step_id=01H...",
  "correlation_id": "01HXXXXXXXXXXXXXXXXXXXXXXX"
}
```

### `ERR_INTERNAL` — HTTP 500

Catch-all for unexpected server-side failures. `message` is generic
("internal error; please retry"); detailed diagnostics are logged server-side
against `correlation_id`. Never leaks stack traces or provider-internal error
strings into the envelope.

```json
HTTP/1.1 500 Internal Server Error

{
  "code": "ERR_INTERNAL",
  "message": "internal error; please retry or contact support with correlation_id",
  "correlation_id": "01HXXXXXXXXXXXXXXXXXXXXXXX"
}
```

### `ERR_LEDGER_COMMIT_FAILED` — HTTP 500

Emitted on endpoints whose success semantics require a successful ledger
commit (future Control Plane / Governance Plane operations; Phase-1 the
primary user is internal, surfaced via `commit_retry_exhausted: true` on
affected receipts). Per FR-040, bounded exponential backoff exhausted; alerting
fires via `recurse_ledger_commit_backoff_exhausted_total` metric.

```json
HTTP/1.1 500 Internal Server Error

{
  "code": "ERR_LEDGER_COMMIT_FAILED",
  "message": "ledger commit retries exhausted; session remains at local_inclusion_verified",
  "correlation_id": "01HXXXXXXXXXXXXXXXXXXXXXXX",
  "details": {
    "session_id": "01HSESSION00000000000000000",
    "commit_retry_exhausted": true
  }
}
```

### `ERR_SESSION_UNKNOWN` — HTTP 404

Called with a `session_id` the Runtime has no record of. Distinct from
`ERR_NOT_FOUND` — this signals a specifically-shaped identifier; narrow error
code aids client-side handling.

```json
HTTP/1.1 404 Not Found

{
  "code": "ERR_SESSION_UNKNOWN",
  "message": "session not found",
  "correlation_id": "01HXXXXXXXXXXXXXXXXXXXXXXX",
  "details": {
    "session_id": "01HSESSION00000000000000000"
  }
}
```

### `ERR_TOKEN_EXCHANGE_FAILED` — HTTP 500

RFC 8693 OAuth Token Exchange (FR-047) to the configured IdP failed — e.g.,
IdP unreachable, `subject_token` invalid, `audience` not permitted by IdP
policy, IdP returned HTTP 4xx. Per FR-047 this is also propagated back to the
agent through the MCP server as a protocol-native MCP error frame (never the
Recurse envelope on the Data Plane); the envelope shape below is what the
Control / Governance operator sees if they query the audit trail for the
failed exchange.

```json
HTTP/1.1 500 Internal Server Error

{
  "code": "ERR_TOKEN_EXCHANGE_FAILED",
  "message": "IdP rejected token exchange for audience=https://jira.corp",
  "correlation_id": "01HXXXXXXXXXXXXXXXXXXXXXXX",
  "details": {
    "idp": "okta",
    "audience": "https://jira.corp",
    "idp_status_code": 400,
    "idp_error": "invalid_target"
  }
}
```

## Cross-references

- `apps/recurse_gateway/lib/recurse_gateway/audit_plane/error_envelope.ex` —
  canonical envelope builder; per-domain code-mapping modules listed in the
  status banner above. (The legacy `Recurse.Shared.ErrorCodes` enum was
  deleted in MR #30/Task M as zero-caller aspirational shell.)
- `openapi.yaml#/components/schemas/ErrorEnvelope` — machine-readable contract.
- `openapi.yaml#/components/responses/RecurseError` — referenced by every
  non-Data-Plane error response.
- `streaming_policy_matrix.md` — terminal frame shapes on SSE endpoints (which
  do NOT use this envelope).
- FR-010, FR-016, FR-023, FR-024, FR-028, FR-029, FR-040, FR-047 in
  `specs/001-api-jido-foundations/spec.md`.
