# X-Observed-Identity JWT — Flow & JWKS Rotation (Deliverable I, JWT half companion to T052)

Narrative companion to `x_observed_identity.schema.json` (FR-017). Covers:
  - worked example JWT (header + payload + signature);
  - JWKS rotation flow;
  - Gateway validation pipeline;
  - clock skew handling;
  - replay-protection cache semantics.

Applies **only** to the Standalone AI Gateway deployment shape. In Governance
shapes (managed_saas, vpc_runner, appliance) machine identity is established
via netns + SPIFFE mTLS per FR-025 — `X-Observed-Identity` is ignored (and, as
a defense-in-depth rule, stripped at ingress).

## Worked example

### Decoded header

```json
{
  "alg": "ES256",
  "typ": "JWT",
  "kid": "broker-key-2026-04-rotation-01"
}
```

Header `alg` MUST be one of `RS256`, `ES256`, `EdDSA`. `HS256` (HMAC, symmetric
secret) and `none` (unsigned) are rejected at validation with
`ERR_AUTH_FAILED` on non-Data-Plane, HTTP 401 protocol-native on Data Plane.

`kid` is REQUIRED when the issuer's JWKS contains more than one active key —
the Gateway indexes JWKS lookups by `kid`.

### Decoded payload

```json
{
  "iss": "https://broker.customer-ai.example.com",
  "sub": "agent:hr-bot-production",
  "aud": "https://gateway.customer-ai.example.com",
  "exp": 1713830400,
  "nbf": 1713829800,
  "iat": 1713829800,
  "jti": "01HXCS2JWT0000000000000000",
  "recurse_tenant_id": "01HTENANT00000000000000000A"
}
```

- `iss` is the Standalone Identity Broker URL (FR-053) or a customer-supplied
  JWT issuer URL.
- `sub` is the observed machine identifier. Appears in attestation receipts'
  `machine_identity.observed_jwt_subject` equivalent surface (for Standalone Gateway
  deployments the SPIFFE-shaped ID is synthesized from `sub`).
- `aud` MUST exactly match the Gateway's configured audience value
  (`auth.anchors.observed_identity_audience` in Tier Configuration).
- `exp - iat ≤ configured max_lifetime_seconds` (default: 15 minutes). Longer
  lifetimes require explicit `dev_mode`-guarded opt-in.
- `jti` is a ULID or UUIDv7; replay cache is keyed on `(iss, jti)`.
- `recurse_tenant_id` is optional but strongly recommended for defense-in-depth
  matching against the deployment's fixed tenant.

### Full compact JWS (illustrative, elided signature)

```
eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImJyb2tlci1rZXktMjAyNi0wNC0wMS0wMSJ9
.
eyJpc3MiOiJodHRwczovL2Jyb2tlci5jdXN0b21lci1haS5leGFtcGxlLmNvbSIsInN1YiI6ImFnZW50OmhyLWJvdC1wcm9kdWN0aW9uIiwiYXVkIjoiaHR0cHM6Ly9nYXRld2F5LmN1c3RvbWVyLWFpLmV4YW1wbGUuY29tIiwiZXhwIjoxNzEzODMwNDAwLCJuYmYiOjE3MTM4Mjk4MDAsImlhdCI6MTcxMzgyOTgwMCwianRpIjoiMDFIWENTMkpXVDAwMDAwMDAwMDAwMDAwMDAiLCJyZWN1cnNlX3RlbmFudF9pZCI6IjAxSFRFTkFOVDAwMDAwMDAwMDAwMDAwMDAwQSJ9
.
<ECDSA-P-256 signature over the first two segments>
```

## Validation pipeline (Gateway ingress)

On every Data Plane or non-Data-Plane request in Standalone Gateway tier:

1. **Extract header** `X-Observed-Identity`. If absent → reject
   (`ERR_AUTH_FAILED` non-Data-Plane; HTTP 401 protocol-native Data Plane).
2. **Parse compact JWS**. Malformed → reject.
3. **Inspect header `alg`**. Reject `HS256`, `none`, and any algorithm not in
   the allow-list (`RS256`, `ES256`, `EdDSA`).
4. **Look up JWKS**. Cache key = `iss`; JWKS fetched from
   `{iss}/.well-known/jwks.json` (or the explicitly-configured JWKS URL
   override in Tier Configuration). JWKS cache TTL: min of `Cache-Control:
   max-age`, server-configured max (default 10 minutes).
5. **Resolve key by `kid`**. If header has `kid`, look up the matching JWK; if
   absent, fall back to the single active JWK (reject if >1).
6. **Verify signature** against the resolved JWK.
7. **Validate temporal claims**: `now >= nbf - 60s`, `now <= exp + 60s`
   (±60s tolerance per FR-017).
8. **Validate `aud`**: MUST include the configured Gateway audience.
9. **Validate `iss`**: MUST be on the Gateway's allow-list of accepted issuers.
10. **Replay-check `jti`**: look up `(iss, jti)` in the bounded LRU cache; if
    present → reject. If absent → insert with TTL = `exp - now + 60s` (keep
    through skew window).
11. **Optional tenant check**: if `recurse_tenant_id` present, MUST equal the
    deployment's fixed `tenant_id`; otherwise reject with
    `ERR_TENANT_ISOLATION`.
12. **Strip header** `X-Observed-Identity` from the forwarded-upstream request
    (defense against downstream surfaces treating the JWT as authoritative).
13. **Attach `IdentityContext`** (FR-026) for the rest of request processing.

Any failure in steps 1–11 terminates the request with the documented code;
the validation order is NOT exposed to clients (no leak about which check
specifically failed beyond `ERR_AUTH_FAILED` / `ERR_TENANT_ISOLATION`).

## JWKS rotation flow

Standard OIDC-compatible key rotation. No Recurse-specific mechanism needed;
the broker (or customer issuer) MUST implement the well-known behavior:

```
t0:     Issuer has Key_A (active signer) and Key_B (pre-publish).
        JWKS contains [Key_A, Key_B]. JWTs are signed with Key_A.
        Gateway caches JWKS; `kid=A` lookups succeed.

t1:     Issuer starts signing new JWTs with Key_B. Key_A remains in JWKS
        (still resolvable for already-issued but still-valid Key_A-signed JWTs).
        Gateway's cached JWKS still contains both; both `kid=A` and `kid=B`
        validate.

t2:     Issuer's JWKS TTL elapses on the Gateway; Gateway re-fetches JWKS.
        (`max-age` from the broker's JWKS response governs this.) No JWT
        validation has ever failed — because Key_A was still present in JWKS
        through the transition.

t3:     After ≥ max-JWT-lifetime has passed since t1 (so no outstanding
        Key_A-signed JWTs can exist), the issuer removes Key_A from JWKS and
        publishes the new JWKS with [Key_B, Key_C] (Key_C is the next
        pre-publish). Gateway JWKS cache invalidates on next fetch.
```

This is the classic "overlap window" pattern from OIDC / JWKS best practice.
Rotation cadence is operator-determined — the Recurse-shipped broker rotates
signer keys every 90 days by default (configurable).

### Failure modes during rotation

- **Gateway JWKS cache stale past rotation**: a JWT signed with Key_B arrives
  before the Gateway has refreshed JWKS. Validation with the stale JWKS fails
  (unknown `kid`). The Gateway treats unknown-`kid` on a `200-ish` JWT shape
  as a **trigger-refresh** event: it force-fetches JWKS once per (iss, kid)
  pair within a bounded window, then re-validates. This keeps rotation
  latency bounded without opening a cache-bypass DoS vector (the
  force-refresh is rate-limited per-issuer).
- **Issuer JWKS endpoint unreachable**: the Gateway uses the last good cached
  JWKS until its TTL expires; after expiry, new requests fail with
  `ERR_AUTH_FAILED`. Existing in-flight connections continue against the old
  JWKS.
- **Issuer rotates AHEAD of schedule** (revokes Key_A with outstanding
  Key_A-signed JWTs in flight): affected JWTs get rejected; the JWTs' `exp`
  windows are the natural bound on impact. Operator alarm:
  `recurse_gateway_jwt_unknown_kid_rate` metric.

## Replay cache (FR-017 `jti` handling)

- **Default implementation**: bounded-size LRU cache keyed on `(iss, jti)`,
  valued with `exp` timestamp.
- **Default capacity**: 100k entries **per issuer** — sized for ≥ 3× the
  (JWT lifetime × peak QPS) product at the Gateway's configured rate limits.
- **Default entry TTL**: `max(configured_jwt_max_lifetime, 15 minutes)`.
  Entries auto-expire when `now > value + 60s`.
- **Cache eviction**: LRU on capacity breach; the evicted entry's `jti` would
  no longer prevent replay, but replay is bounded by `exp` — so the window of
  risk is ≤ remaining `exp`. Operators alarm on capacity evictions via
  `recurse_gateway_jti_cache_evicted_total`.
- **Cache is process-local** in Phase 1 (single-BEAM-per-customer; no
  federation). Phase-2 federation will require a shared replay store.

## Cross-references

- `x_observed_identity.schema.json` — machine-readable JWT payload contract.
- `standalone_identity_broker.md` — the broker that issues these JWTs
  (FR-053).
- `openapi.yaml#/components/securitySchemes/x_observed_identity` — OpenAPI
  security scheme consumed by Data Plane endpoints under this auth anchor.
- FR-017, FR-020, FR-025, FR-053 in `spec.md`.
