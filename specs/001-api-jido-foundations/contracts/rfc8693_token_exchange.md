# RFC 8693 Token Exchange Contract (Deliverable Q)

**Status**: Phase-1 contract. **Binding for Feature 002+ Gateway /
MCP server implementation.**

**Requirement**: FR-047 (RFC 8693 OAuth 2.0 Token Exchange at the
Gateway-to-MCP-server boundary). **Related**: FR-043 (MCP servers
live OUTSIDE the agent's netns), FR-026 (IdentityContext resolved
once at ingress), FR-016 (protocol-native data-plane errors), FR-003
(`PrincipalProvider`, `SecretsProvider`), FR-021 (attestation
emission on downstream calls), SC-018 (worked round-trip example).

## What this contract solves

An agent running in a Recurse-managed netns needs to make a
downstream call to a customer service (e.g. `https://jira.corp`) as
a specific human principal (Alice). The agent holds NO credentials
for `jira.corp` — not Alice's OIDC token, not a service-account key,
not an API token. The Gateway mints a short-lived,
downstream-service-scoped OAuth 2.0 token via **RFC 8693 Token
Exchange** and injects it into the upstream request that the MCP
server (trusted Recurse infrastructure, outside the netns) sends to
`jira.corp`.

Result: the downstream's audit log reads *"Alice accessed this data
via Recurse-issued OBO"*; the agent holds zero secrets.

## End-to-end flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Recurse-managed netns                                │
│  ┌──────────┐   MCP SSE    ┌──────────┐                                      │
│  │  Agent   │─────────────▶│ in-netns │                                      │
│  │ (BYOC    │              │   shim   │                                      │
│  │  Docker) │              │ (FR-045a)│                                      │
│  └──────────┘              └────┬─────┘                                      │
│                                 │ MCP SSE                                    │
│                                 │ (netns egress, mTLS, SPIFFE SVID)          │
└─────────────────────────────────┼────────────────────────────────────────────┘
                                  │
                                  ▼
                            ┌──────────┐
                            │  Recurse │  IdentityContext (FR-026)
                            │  Gateway │  {machine: spiffe://.../agent/abc,
                            │          │   principal: {kind: obo_human,
                            │          │                subject: alice@...,
                            │          │                issuer: https://auth...}}
                            └────┬─────┘
                                 │
                                 │ Cedar policy gate (FR-039):
                                 │ ┌────────────────────────────────┐
                                 │ │ principal Alice may call       │
                                 │ │ Resource::Downstream "jira.corp│
                                 │ │ for Action "CreateIssue"?      │
                                 │ └────────────────────────────────┘
                                 │ ALLOW
                                 ▼
                            ┌──────────┐
                            │  Gateway │  ┌────────────────────────┐
                            │  token   │─▶│ PrincipalProvider:     │
                            │ exchange │  │ fetch Alice's          │
                            │  path    │  │ subject_token (OIDC)   │
                            └────┬─────┘  └────────────────────────┘
                                 │                    │
                                 │                    │ subject_token = eyJ...
                                 ▼                    ▼
                            ┌─────────────────────────────────┐
                            │  POST /token (RFC 8693)         │
                            │  Host: auth.corp.example.com    │──▶ Customer
                            │  grant_type=token-exchange      │    IdP (Okta)
                            │  subject_token=<Alice's OIDC>   │
                            │  subject_token_type=access_token│
                            │  audience=https://jira.corp     │
                            │  requested_token_type=access    │
                            │  resource=https://jira.corp/... │
                            │                                 │
                            │  (Gateway authenticates with    │
                            │   its own signing identity      │
                            │   FR-046 via SecretsProvider)   │
                            └──────────────┬──────────────────┘
                                           │
                                           │ 200 OK
                                           │ access_token=<scoped_jwt>
                                           │ token_type=Bearer
                                           │ expires_in=300
                                           ▼
                            ┌──────────────────────────────┐
                            │  Gateway hands scoped token  │
                            │  to MCP server as            │
                            │  Authorization: Bearer ...   │
                            └──────────────┬───────────────┘
                                           │
                            ┌──────────────▼───────────────┐   NOTE: MCP server lives
                            │  Recurse-managed MCP server  │   OUTSIDE the agent's
                            │  (host network, trusted)     │   netns per FR-043.
                            │  for jira.corp               │   Trusted Recurse infra.
                            └──────────────┬───────────────┘
                                           │ POST /rest/api/3/issue
                                           │ Authorization: Bearer <scoped_jwt>
                                           │ (customer network, TLS)
                                           ▼
                            ┌──────────────────────────────┐
                            │  Downstream: https://jira.corp
                            │  Audit log:
                            │  "alice@corp.example.com     │
                            │   created issue PROJ-1234    │
                            │   via Recurse-OBO"           │
                            └──────────────────────────────┘

Meanwhile, Gateway emits an attestation (FR-021) for this turn:
  event_kind: tool_call
  principal: {kind: obo_human, subject: alice@corp.example.com, ...}
  tool_sbom_ref: (MCP server SBOM; optional)
  payload_hash: sha256(canonicalized tool-call args)
```

## IdP capability matrix

| IdP                                          | Status          | Notes                                                                 |
|----------------------------------------------|-----------------|-----------------------------------------------------------------------|
| **Okta (OAuth 2.0 Token Exchange add-on)**   | **Certified**   | Certified in v1.0. Full coverage of `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`. |
| **Microsoft Entra ID (Azure AD)**            | **Certified**   | Via `on-behalf-of` flow (Microsoft's RFC 8693-compatible endpoint). Certified in v1.0. |
| **Auth0**                                    | **Certified**   | Via `urn:ietf:params:oauth:grant-type:token-exchange`. Certified in v1.0. |
| Generic OIDC + RFC 8693-compliant            | Best-effort     | Works if the IdP implements the canonical `grant_type` per RFC 8693 §2.1 with `subject_token_type` of `access_token` or `jwt`. No certification; customers test in staging. |
| Keycloak                                     | Best-effort     | RFC 8693 supported since 12.x; confirmed working in practice but not CI-tested by Recurse. |
| Ping Federate                                | Best-effort     | Supported in recent versions; customer verifies per their PingFederate version. |
| ADFS (pre-Entra)                             | **NOT supported**| No RFC 8693 endpoint. Migrate to Entra ID.                            |
| SAML-only IdPs                               | **NOT supported**| SAML does not have a native token-exchange primitive. No Phase-1 workaround. |
| Custom IdPs without RFC 8693                 | **NOT supported**| Adding `grant_type=token-exchange` is the customer's prerequisite.    |

"Certified" means: Recurse CI runs a mock of the IdP's token-exchange
endpoint per release, the flow is explicitly covered in
acceptance tests, and documented quirks (e.g., Entra's
`subject_token_type = urn:ietf:params:oauth:token-type:id_token`
variance) are handled by the Gateway.

"Best-effort" means: the Gateway's RFC 8693 client implementation is
spec-compliant, but the specific IdP is not part of our CI matrix;
customer-reported issues are best-effort to reproduce.

"NOT supported" means: v1.0 will not mint tokens via this IdP. Feature
001's Provider Interface (`PrincipalProvider` + `SecretsProvider`) is
**not** designed to back-door support in a custom shim — if the IdP
cannot exchange tokens, the Gateway denies the call with
`ERR_TOKEN_EXCHANGE_FAILED` (see failure modes).

## Wire protocol details

### Token-exchange request

```http
POST /oauth2/v1/token HTTP/1.1
Host: auth.corp.example.com
Authorization: Basic <base64(gateway_client_id:gateway_client_secret)>
Content-Type: application/x-www-form-urlencoded

grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange
&subject_token=<alice_oidc_token_as_returned_by_PrincipalProvider>
&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token
&audience=https%3A%2F%2Fjira.corp
&requested_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token
&resource=https%3A%2F%2Fjira.corp%2Frest%2Fapi%2F3%2Fissue
&scope=write%3Ajira-issues
```

The Gateway authenticates as itself using either (a) `client_credentials`
attached at `Authorization: Basic` or (b) private-key JWT per RFC 7523
— the exact mechanism comes from `SecretsProvider` bound to the
Gateway's long-lived signing identity (FR-046). `SecretsProvider`
callback `sign/3` signs an assertion that the Gateway's transport
SVID + tenant scope permit the exchange.

### Token-exchange response

```http
HTTP/1.1 200 OK
Content-Type: application/json;charset=UTF-8
Cache-Control: no-store

{
  "access_token":        "eyJ...scoped_jwt...",
  "issued_token_type":   "urn:ietf:params:oauth:token-type:access_token",
  "token_type":          "Bearer",
  "expires_in":          300,
  "scope":               "write:jira-issues"
}
```

Gateway MUST validate:

- `issued_token_type` matches `requested_token_type`.
- `expires_in` ≥ 60 seconds (bound: a scoped token with < 1 minute
  lifetime is a misconfiguration).
- `scope` is a subset of the requested scope (IdP may narrow).

Validation failure → `ERR_TOKEN_EXCHANGE_FAILED`.

### Downstream request (injected by MCP server)

```http
POST /rest/api/3/issue HTTP/1.1
Host: jira.corp
Authorization: Bearer eyJ...scoped_jwt...
X-Correlation-ID: 01HQXZ9RXKCORR00000000000CC
Content-Type: application/json

{ "fields": { "project": {"key":"PROJ"}, "summary": "..." } }
```

The agent NEVER sees the `Authorization` header. The MCP server
injects it upstream of the bytes leaving Recurse-managed infrastructure.

## Failure modes

All failures surface back to the agent as **MCP protocol-native
error frames** per FR-016 (the agent speaks MCP to the shim; raw
HTTPS to `jira.corp` is never a code path in Phase 1). The shim
translates the Gateway's v1.0 Error Envelope into the MCP error
shape.

| `error.code`                  | HTTP @ Gateway | Trigger                                                                           | MCP protocol response to agent                          |
|-------------------------------|----------------|-----------------------------------------------------------------------------------|---------------------------------------------------------|
| `ERR_TOKEN_EXCHANGE_FAILED`   | 502            | IdP rejected exchange (grant denied, subject_token expired, audience rejected, scope narrow, etc.) | MCP `tool_call.error` frame with `code: "token_exchange_failed"`, human-readable `message`, `correlation_id` |
| `ERR_POLICY_DENIED`           | 403            | Cedar denied the downstream call BEFORE token exchange — agent principal not permitted the target resource/action | MCP `tool_call.error` frame with `code: "policy_denied"` |
| `ERR_IDP_UNAVAILABLE`         | 502            | IdP network error / timeout                                                       | MCP `tool_call.error` frame with `code: "idp_unavailable"`; includes retry-after hint |
| `ERR_PRINCIPAL_UNAVAILABLE`   | 401            | `PrincipalProvider` could not produce Alice's `subject_token` (expired session, user revoked) | MCP `tool_call.error` frame with `code: "principal_unavailable"`; may surface as re-auth prompt |
| `ERR_SECRETS_UNAVAILABLE`     | 500            | `SecretsProvider.sign/3` failed for Gateway's own assertion                        | MCP `tool_call.error` frame with `code: "secrets_unavailable"`; operator alert |
| `ERR_DOWNSTREAM_AUTH_FAILED`  | 401 from down- | Scoped token rejected by `jira.corp` (token-exchange succeeded but downstream disagreed) | MCP `tool_call.error` frame with `code: "downstream_auth_failed"` |

All failures emit an attestation per FR-021 with:

- `event_kind`: `tool_call` (unchanged; failure is data, not absence of data).
- A failure predicate extension `error: { code, message, upstream_idp_status? }`.
- `verification_level: signed` initially; advances normally as the
  session's Merkle tree accumulates.

This is the "no crash-loop" guarantee: the agent receives a structured
MCP error frame and MAY choose to retry, degrade, or surface to the
user; it never observes a dropped TCP connection or an opaque 500.

## Zero-secrets-in-agent guarantee (SC-018)

At no point during this flow does the agent process:

- Hold any downstream-service credential.
- Hold Alice's raw OIDC token.
- Hold any Gateway-issued signing key.
- Hold any IdP client secret.

The only thing the agent holds is its own SPIFFE SVID (transport
identity), which it uses to authenticate its mTLS connection from
the shim to the Gateway. All downstream auth material is minted,
carried, and injected strictly within Recurse-managed infrastructure
(Gateway + MCP server + `SecretsProvider` + `PrincipalProvider`).

The worked round-trip example backing SC-018 is in
`quickstart.md` §"End-to-end OBO example" (to be added) and the
contract-test fixtures in `provider_interfaces/principal_provider.ex`
and `provider_interfaces/secrets_provider.ex`.

## Metrics

- `recurse_token_exchange_requests_total{tenant_id, idp, outcome}` —
  counter; `outcome` ∈ `{allow, deny_policy, deny_exchange, idp_error,
  principal_error, secrets_error, downstream_auth_fail}`.
- `recurse_token_exchange_latency_seconds_bucket{tenant_id, idp,
  phase}` — histogram; `phase` ∈ `{cedar, principal_fetch, idp_call,
  downstream}`.
- `recurse_token_exchange_token_ttl_seconds{tenant_id, idp}` —
  distribution of `expires_in` values returned by IdPs (detects
  drift from configured TTL expectations).

## Cross-references

- `audit_payload_broker.md` — the upstream auditor surface that
  retrieves the detached payload bytes captured for this tool_call.
- `cli_verifier_procedure.md` — how auditors verify the attestation
  emitted by this flow.
- `signing_key_archive.md` — the Gateway signing identity used for
  IdP authentication per FR-046.
- `provider_interfaces/principal_provider.ex` — `fetch_subject_token`
  callback.
- `provider_interfaces/secrets_provider.ex` — `sign` callback for
  Gateway's own IdP assertion.
- `../spec.md` FR-047 (full text), FR-043 (MCP-server boundary),
  FR-016 (protocol-native errors).
- `../research.md` D15 (token-exchange backend research).

## Phase-2+ out of scope

- **Intent-aware JIT token minting.** FR-051 was deleted per
  `feedback_no_premature_metaapi.md`; no Phase-1 forward-compat
  hooks. A Phase-2 `PrincipalProvider` may add an `intent` hint to
  `fetch_subject_token` callbacks, but the Phase-1 contract does
  NOT reserve it.
- **Offline air-gapped token exchange.** If the Appliance has no
  route to an external IdP, token exchange is unavailable; the
  deployment relies on `principal.kind: service_account` with
  locally-minted tokens from an on-prem IdP. Documented in
  `contracts/tier_config.schema.json`'s `identity_broker` section.
