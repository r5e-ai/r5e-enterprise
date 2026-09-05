# Contract: Recurse Standalone Identity Broker API

**Feature**: F002 | **Spec**: FR-008 (rewrites F001 FR-053 mechanics) | **Research**: D2

This contract defines the wire-level HTTP API of the `:recurse_broker` OTP application as shipped in F002's `docker-compose.yaml`. Per AD-001 c' + F001 Constitution Principle V, the broker produces JWTs that the Gateway's `PrincipalProvider` implementation consumes — no vendor SDKs are imported by Gateway business logic.

---

## Endpoints

### `POST /token/exchange` — RFC 8693 OAuth 2.0 Token Exchange

**Request** (form-urlencoded body):

| Field | Required | Type | Notes |
|---|---|---|---|
| `grant_type` | ✓ | string | MUST equal `urn:ietf:params:oauth:grant-type:token-exchange`. |
| `subject_token` | ✓ | string | The customer IdP's token to exchange. OIDC `id_token` in F002 slice; SAML 2.0 `<Assertion>` base64-encoded in slice 1b. |
| `subject_token_type` | ✓ | string | `urn:ietf:params:oauth:token-type:id_token` (F002 slice) OR `urn:ietf:params:oauth:token-type:saml2` (slice 1b). |
| `audience` | ✓ | string | MUST equal the Gateway's configured audience (e.g., `recurse-gateway-prod`). |
| `requested_token_type` | optional | string | Default `urn:ietf:params:oauth:token-type:jwt` (only supported value in F002). |
| `scope` | optional | string | Ignored in F002 (reserved for future fine-grained role-within-role scoping). |

**Response (200)** — RFC 8693 conforming, `Content-Type: application/json`:

```json
{
  "access_token": "eyJhbGciOiJFUzI1NiIsImtpZCI6...",
  "issued_token_type": "urn:ietf:params:oauth:token-type:jwt",
  "token_type": "Bearer",
  "expires_in": 900
}
```

The `access_token` is a minted `X-Observed-Identity` JWT conforming to F001 FR-017 + F002 FR-007 with the `principal` custom claim populated per FR-009 + Clarifications Q3.

**Error responses** (RFC 6749 §5.2 shape with OAuth-standard error codes):

| HTTP | `error` | `error_description` | Cause |
|---|---|---|---|
| 400 | `invalid_request` | "missing grant_type" / "invalid audience" / etc. | Malformed form body or wrong `grant_type` / `audience`. |
| 400 | `unsupported_grant_type` | "only urn:ietf:params:oauth:grant-type:token-exchange supported" | Wrong `grant_type` value. |
| 400 | `invalid_subject_token_type` | "unknown subject_token_type" | Wrong `subject_token_type` value. |
| 401 | `invalid_subject_token` | "subject_token signature invalid" / "expired" / "issuer not trusted" | OIDC verification failed. |
| 403 | `unauthorized_client` | "principal has no role mapping and no default_recurse_role configured" | Role resolution produced no match + no default. |
| 503 | `temporarily_unavailable` | "customer IdP JWKS fetch failed" | OIDC discovery / JWKS fetch error; retryable. |

### `GET /oidc/jwks` — JWKS publication for Gateway discovery

**Response (200)** — `Content-Type: application/json`:

```json
{
  "keys": [
    {
      "kty": "EC",
      "crv": "P-256",
      "kid": "broker-2026-04-23-v1",
      "use": "sig",
      "alg": "ES256",
      "x": "...",
      "y": "..."
    },
    {
      "kty": "EC",
      "crv": "P-256",
      "kid": "broker-2026-01-23-v0",
      "use": "sig",
      "alg": "ES256",
      "x": "...",
      "y": "..."
    }
  ]
}
```

During rotation the broker publishes N keys: the active signing key + all non-expired prior keys (overlap window). Gateway MUST cache this endpoint (default TTL 5 min) and refresh on `kid`-miss per FR-007.

### `GET /healthz` — liveness

Returns `200 {"status": "ok", "version": "0.2.0"}` when the broker is accepting requests; `503` if OIDC discovery has failed for all configured issuers for ≥ 2 minutes.

---

## Minted X-Observed-Identity JWT shape

**Header**:
```json
{"alg": "ES256", "kid": "broker-2026-04-23-v1", "typ": "JWT"}
```

**Payload** — REQUIRED claims per F001 FR-017 + F002 FR-007:

| Claim | Type | Notes |
|---|---|---|
| `iss` | string | Broker's configured issuer URL (e.g., `https://recurse-broker.corp.example`). |
| `sub` | string | Principal subject — equals `subject_token.sub` for human principals; canonical per `principal.kind`. |
| `aud` | string | Gateway audience (e.g., `"recurse-gateway-prod"`). |
| `exp` | integer | Unix timestamp; `iat + 900` (15-min TTL default; configurable 5–60 min). |
| `nbf` | integer | Unix timestamp; equals `iat`. |
| `iat` | integer | Unix timestamp at mint. |
| `jti` | string | UUIDv4; unique per token; used for Gateway-side replay cache. |
| `principal` | object | Custom claim; see below. |

**`principal` custom claim** — F002 FR-009's authoritative shape:

```json
{
  "kind": "obo_human",
  "issuer": "https://your-tenant.okta.com",
  "subject": "auth0|507f1f77bcf86cd799439011",
  "display_name": "Alice Anderson",
  "groups": ["cn=recurse-operators,...", "cn=engineering,..."],
  "recurse_role": "platform_operator"
}
```

`kind` derivation (broker logic):
- `subject_token_type == "id_token"` AND `subject_token.aud` matches configured customer-IdP's "interactive" client ID → `obo_human`.
- `subject_token_type == "id_token"` AND `subject_token.azp` present AND resolves to a configured "service" client ID → `service_account` (with `account_id` = subject_token.sub, `scope` = subject_token.scope list).
- `subject_token_type == "id_token"` AND no human subject (service client + no `aud` for humans) AND broker's YAML opts into autonomous → `autonomous`.

If `kind` cannot be determined unambiguously, broker rejects with `401 invalid_subject_token` rather than guessing.

---

## `broker-role-mapping.yaml` schema

Operator-configured; loaded at broker boot + SIGHUP reload.

```yaml
# Highest-privilege matching group wins.
# Values MUST be one of: platform_operator | tenant_auditor | caller.
group_to_recurse_role:
  "cn=recurse-operators,ou=groups,dc=corp,dc=example": platform_operator
  "cn=recurse-auditors,ou=groups,dc=corp,dc=example": tenant_auditor
  "cn=recurse-users,ou=groups,dc=corp,dc=example": caller

# Fallback when no group matches (or groups claim absent). Null = reject.
default_recurse_role: caller

# Per-issuer OIDC config (for multi-IdP deployments; uncommon in F002).
issuers:
  - url: https://your-tenant.okta.com
    allowed_audiences: ["corp-sso-client"]
    alg_allowlist: [RS256, ES256]
```

Validation: `group_to_recurse_role` values constrained to the three role strings; any other value fails boot. Duplicate group keys fail boot.

---

## Security discipline

- **`alg: none` rejected** — JOSE `alg` allowlist per issuer (default `[RS256, ES256, EdDSA]` for `subject_token` verification; minted JWT always `ES256` per F002 FR-007).
- **5-segment tokens (JWE) rejected** — broker processes JWS only.
- **`exp`/`nbf`/`iat`** enforced with 60s clock skew tolerance.
- **`jti` NOT reused** — broker mints fresh `jti` per request (UUIDv4).
- **Clock-drift resistance**: broker's monotonic clock used for TTL math (wall-clock only for `iat`).
- **Customer IdP key format** — `JOSE.JWK.from_map/1` only (no `from_pem` on remote data per JOSE pitfall research).

---

## Property-test surfaces (Constitution Principle VI)

Under `contracts/property_test_surface_catalog_f002.md`:

- **Surface N**: JWT validation — generator emits `{valid | expired | wrong_aud | wrong_iss | alg_none | tampered_signature | reused_jti}` JWTs; Gateway's validator MUST accept only the first class and emit the correct error for each.
- **Surface O**: RFC 8693 Token Exchange round-trip — given a valid OIDC `id_token` + role mapping, the minted `X-Observed-Identity` JWT MUST validate at the Gateway, resolve to the expected `recurse_role`, and pass Cedar evaluation against `platform_roles.cedar`.
- **Surface P**: JWKS `kid`-miss refresh race — concurrent unknown-kid requests MUST coalesce behind one refresh and all eventually resolve (no spurious 401s).

---

## Out of scope (slice 1b + later)

- SAML 2.0 subject_token validation (libraries `samly`/`esaml` unmaintained + XSW risk — explicit deferral).
- DPoP / mTLS-bound tokens (RFC 8705 `cnf` claim reserved).
- Token-exchange refresh (`refresh_token` flow unused in this slice; 15-min TTL accepted; exchange again on expiry).
- Broker JWT signing-key storage in KMS/HSM (F002 ships PEM from disk via config; KMS integration deferred).
- Multi-issuer-policy routing (F002 assumes one primary customer IdP per deployment; multi-IdP deferred).
