# Standalone Identity Broker (Deliverable I, broker half — FR-053)

The Standalone Identity Broker is the lightweight identity component Recurse
ships alongside the Standalone AI Gateway (FR-050) so customers can stand up
the "zero-friction redirect" value proposition without rolling their own JWT
issuer. It exists to:

  1. **Transform** the customer's existing SSO assertion (OIDC /
     SAML-via-OIDC-federation-webhook) into a short-lived
     `X-Observed-Identity` JWT per FR-017.
  2. **Publish** a JWKS endpoint so the Gateway can verify those JWTs with
     standard OIDC key-rotation semantics.
  3. **Protect** against replays with a bounded `jti` cache.

The broker is **optional**. Customers with existing JWT issuer infrastructure
can point the Gateway at their own issuer and skip the broker entirely (BYO
path below). The broker and BYO paths are functionally identical from the
Gateway's perspective — both produce JWTs conforming to
`x_observed_identity.schema.json`.

## Deployment topology (Standalone AI Gateway)

```
                             ┌──────────────────────────────┐
 Customer SSO                │  Standalone AI Gateway host  │
 (Okta / Entra / Auth0 /     │                              │
  any OIDC IdP)              │  ┌─────────────────────┐     │
        │                    │  │ Identity Broker     │     │
        │   sso_webhook      │  │ :8082               │     │
        ├───────────────────►│  │  /sso/webhook       │     │
        │   {id_token}       │  │  /.well-known/      │     │
        │                    │  │    jwks.json        │     │
        │                    │  └─────────┬───────────┘     │
        │                    │            │ mints JWT       │
        │                    │            │                 │
        │                    │  ┌─────────▼───────────┐     │
 Customer's                  │  │ Recurse Gateway     │     │
 enterprise AI app ──────────┼─►│ :8443 (TLS)         │     │
 (e.g., Bedrock-backed       │  │  /v1/chat/…         │     │
  chatbot) with              │  │  /v1/mcp/…          │     │
  OPENAI_BASE_URL pointed    │  │                     │     │
  at Gateway + JWT attached  │  │  validates JWT via  │     │
                             │  │  Broker JWKS        │     │
                             │  └─────────────────────┘     │
                             └──────────────────────────────┘
```

The broker is colocated with the Gateway in the Standalone deployment shape.
It is a separate OS process (or container) sharing the host with the Gateway;
NOT part of the `:recurse_gateway` OTP application, to preserve the isolation
boundary between JWT issuance (a sensitive key-holding role) and traffic
handling.

## SSO Webhook contract

The customer's SSO IdP POSTs to the broker's `/sso/webhook` endpoint when an
end-user signs in to the enterprise AI application. Two flavors, both
supported:

### OIDC path (default)

Request (from customer IdP → broker):

```http
POST /sso/webhook HTTP/1.1
Host: broker.customer-ai.example.com
Content-Type: application/json
Authorization: Bearer <idp_webhook_shared_secret>

{
  "id_token": "<id_token JWT issued by customer IdP>",
  "agent_identifier": "hr-bot-production",
  "requested_audience": "https://gateway.customer-ai.example.com"
}
```

- `id_token` is the customer IdP's own OIDC ID token; the broker validates
  it against the customer IdP's JWKS (configured at deployment time).
- `agent_identifier` is a free-form machine-identity string the enterprise
  AI app supplies to identify which logical agent the user is acting through.
  Becomes the `sub` claim in the minted `X-Observed-Identity` JWT.
- `requested_audience` is optional; when absent the broker defaults to its
  configured `default_audience`.

Response (broker → customer IdP):

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "x_observed_identity": "<minted compact JWS>",
  "expires_at": 1713830400
}
```

The customer's enterprise AI app then attaches `x_observed_identity` as the
`X-Observed-Identity` header on every request to the Gateway.

### SAML-via-OIDC-federation webhook path

Customers on SAML-only IdPs (e.g., legacy ADFS) use an OIDC federation shim
(e.g., Keycloak, Dex) that turns SAML assertions into OIDC ID tokens; the
broker treats the shim as the customer IdP. No native SAML validation in the
broker itself — this keeps the broker focused on a single format.

## JWKS endpoint

The broker exposes `GET /.well-known/jwks.json` serving its current signer
public keys in standard JWKS format:

```json
{
  "keys": [
    {
      "kty": "EC",
      "crv": "P-256",
      "kid": "broker-key-2026-04-rotation-01",
      "use": "sig",
      "alg": "ES256",
      "x": "<base64url>",
      "y": "<base64url>"
    },
    {
      "kty": "EC",
      "crv": "P-256",
      "kid": "broker-key-2026-01-rotation-01",
      "use": "sig",
      "alg": "ES256",
      "x": "<base64url>",
      "y": "<base64url>"
    }
  ]
}
```

Response includes `Cache-Control: max-age=600` (10 minutes default). During
rotation, both outgoing and incoming key versions appear in the JWKS for at
least `max_jwt_lifetime` seconds so no valid JWT is left unverifiable.

**Rotation cadence**: every 90 days by default, configurable via
`broker.signing_key_rotation_days`. Rotation procedure is the standard
OIDC overlap-window pattern documented in `x_observed_identity_flow.md`.

## BYO JWT issuer (alternative path)

Customers who already operate a JWT issuer (e.g., their OIDC IdP itself, or a
home-grown service) can skip the Recurse broker and have the Gateway accept
JWTs directly from their issuer. Configuration lives in Tier Configuration:

```yaml
auth:
  anchors:
    observed_identity: true
  identity_broker:
    enabled: false                   # broker not deployed
    byo_jwt_issuer: true
    byo_issuers:
      - iss: "https://idp.customer.example.com"
        jwks_uri: "https://idp.customer.example.com/.well-known/jwks.json"
        expected_audience: "https://gateway.customer-ai.example.com"
```

The Gateway's `X-Observed-Identity` validator treats the configured
`byo_issuers[].iss` list as its allow-list of acceptable `iss` values and
fetches each issuer's JWKS independently. From the Gateway's perspective the
validation pipeline is identical; only the JWT source differs.

Operators choosing BYO assume the operational responsibility for:
  - issuing JWTs with the `x_observed_identity.schema.json` claim set;
  - signing with `RS256` / `ES256` / `EdDSA` (HS256 / `none` forbidden);
  - operating a JWKS endpoint with standard rotation semantics;
  - `jti` uniqueness across issued tokens (for the replay cache).

## Replay-protection cache (broker-side)

While the Gateway maintains its own `(iss, jti)` replay cache on the incoming
side, the **broker** ALSO enforces `jti` uniqueness on its MINT side — no two
minted JWTs can share a `jti`. The broker-side cache:

- **Implementation**: LRU keyed on `jti` (broker is single-issuer so `iss` is
  implicit).
- **Default capacity**: 100k entries — equivalent to ≥ 3× peak mint QPS ×
  JWT lifetime.
- **Default entry TTL**: JWT `exp - iat` + 60s skew window (default 15
  minutes + 60s = ~16 min).
- **Configuration**: `broker.jti_cache_capacity` and `broker.jti_cache_ttl`
  in Tier Configuration.
- **Eviction alarm**: `recurse_broker_jti_cache_evicted_total` metric.

This is belt-and-braces; the Gateway's cache is the authoritative replay
gate in the validation pipeline.

## Broker endpoints summary

| Method | Path                        | Purpose                                                         | Auth                                                   |
|--------|-----------------------------|-----------------------------------------------------------------|--------------------------------------------------------|
| POST   | `/sso/webhook`              | Customer IdP posts ID token + agent identifier; broker mints JWT | Shared-secret bearer (`idp_webhook_shared_secret`)    |
| GET    | `/.well-known/jwks.json`    | Gateway (and any verifier) fetches broker signer public keys    | Unauthenticated; public                                |
| GET    | `/healthz`                  | Liveness probe                                                  | Unauthenticated                                        |
| GET    | `/metrics`                  | Prometheus metrics scrape                                       | Scrape-credential bearer (separate from Gateway's)     |

The broker does NOT process any LLM / MCP traffic, does NOT participate in
Cedar policy evaluation, does NOT hold downstream-service credentials.
It is a narrow identity-transform component on the inbound Data-Plane path.

## Configuration reference

```yaml
# config/standalone_gateway.reference.yml (excerpt)
auth:
  anchors:
    netns: false
    observed_identity: true
  identity_broker:
    enabled: true
    listen_port: 8082
    default_audience: "https://gateway.customer-ai.example.com"
    sso_webhook_shared_secret_ref: "kms://broker/sso-webhook-secret"
    sso_webhook_path: "/sso/webhook"
    jwks_rotation_days: 90
    jti_cache_capacity: 100000
    jti_cache_ttl_seconds: 960     # 16 minutes
    jwt_lifetime_seconds: 900      # 15 minutes
    customer_idp:
      oidc_issuer: "https://customer-tenant.okta.com"
      oidc_jwks_uri: "https://customer-tenant.okta.com/.well-known/jwks.json"
    byo_jwt_issuer: false
```

## Failure modes

| Condition                                                              | Broker behavior                             | Gateway-side impact                                                  |
|------------------------------------------------------------------------|---------------------------------------------|----------------------------------------------------------------------|
| Customer IdP JWKS unreachable                                          | Webhook fails; customer retries             | None — no JWT ever minted                                            |
| Broker signer key rotation in progress                                 | Overlap-window — both keys published         | Gateway accepts JWTs signed by either key during the overlap window |
| Webhook shared-secret mismatch                                         | 401 on `/sso/webhook`                       | None                                                                 |
| `jti` cache eviction under load                                        | New mint succeeds, evicted jti no longer blocks replay (but `exp` bounds risk) | Metric alarm; operator increases `jti_cache_capacity` |
| Broker process crash                                                   | Webhook POSTs fail fast                     | Gateway-side JWKS cache continues to validate in-flight JWTs until expiry, then `ERR_AUTH_FAILED` |

## Cross-references

- `x_observed_identity.schema.json` — JWT payload contract the broker mints.
- `x_observed_identity_flow.md` — validation pipeline + JWKS rotation narrative.
- `openapi.yaml#/components/securitySchemes/x_observed_identity` — Gateway
  security scheme consuming broker output.
- FR-017, FR-020, FR-050, FR-053 in `spec.md`.
