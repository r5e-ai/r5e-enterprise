# Contracts (Phase 1 — Feature 001)

Index of contract artifacts produced by `/speckit-plan`. The spec's Deliverable Appendix (A–Q) maps to these files. Items marked **scaffold** are skeletons here; full content lands during `/speckit-tasks` and feature-002+ work.

## Wire-format and schema contracts

| File | Spec Deliverable | Status |
|---|---|---|
| [openapi.yaml](openapi.yaml) | A. API Surface Reference | scaffold (one representative endpoint per plane; full enumeration in tasks) |
| [attestation.schema.json](attestation.schema.json) | E. Attestation Envelope Schema | full (FR-021 signed predicate + outer container) |
| [tier_config.schema.json](tier_config.schema.json) | F. Tier Configuration Model | full (FR-015 / FR-033) |
| [x_observed_identity.schema.json](x_observed_identity.schema.json) | I. `X-Observed-Identity` JWT + Standalone Broker | full (FR-017 / FR-053 contract surface) |

## Elixir behaviour contracts (Provider Interfaces — Deliverable B)

| File | Interface | Notes |
|---|---|---|
| [provider_interfaces/llm_provider.ex](provider_interfaces/llm_provider.ex) | `LLMProvider` | upstream LLM call abstraction |
| [provider_interfaces/ledger_provider.ex](provider_interfaces/ledger_provider.ex) | `LedgerProvider` | Trillian + Postgres-Merkle behind one contract |
| [provider_interfaces/storage_provider.ex](provider_interfaces/storage_provider.ex) | `StorageProvider` | detached payload storage (S3/Splunk/MinIO) |
| [provider_interfaces/secrets_provider.ex](provider_interfaces/secrets_provider.ex) | `SecretsProvider` | KMS/Vault for signing keys (FR-046) and downstream credentials |
| [provider_interfaces/identity_provider.ex](provider_interfaces/identity_provider.ex) | `IdentityProvider` | SPIFFE SVID lifecycle |
| [provider_interfaces/principal_provider.ex](provider_interfaces/principal_provider.ex) | `PrincipalProvider` | OBO human / service-account / autonomous + RFC 8693 capability |
| [provider_interfaces/policy_provider.ex](provider_interfaces/policy_provider.ex) | `PolicyProvider` | OCI bundle distribution + offline-signed-manifest |

**Constitutional rule**: NO Phase-2-forward-compat hooks pre-allocated (FR-051 DELETED in v6.1). When intent-aware JIT minting ships in Phase 2, Provider Interfaces will be extended at that time.

## Documentation deliverables (markdown; created during `/speckit-tasks`)

The following deliverables are documentation contracts (text-based, not machine-readable). Skeletons are noted in this README; full content is sprint work for Phase 1 implementation.

| Deliverable | Description | Source FR(s) |
|---|---|---|
| C. New-Provider Acceptance Checklist | code-review checklist for new Provider implementations | FR-004 |
| D. Gateway/Runtime Responsibility Matrix | subsystem → owning OTP application | FR-035 |
| G. Streaming Policy Matrix | endpoint → sync/sse/ws | FR-012 |
| H. Error Code Enum & HTTP Mapping | complete error code list with status codes | FR-010 |
| J. Audit Plane Contract Suite | broker + key archive + SIEM forwarder + Export Evidence + CLI verifier | FR-030, FR-046, FR-048 |
| K. Policy Bundle Distribution Contract | OCI + offline signed manifest | FR-039, FR-052 |
| L. Session Lifecycle & Attestation Chain | unified state machine diagram | FR-036, FR-037, FR-038, FR-040, FR-041, FR-044 |
| M. Phase-1 Completeness Boundary | L3/L4/L7 accept/drop/attest matrix | FR-043 |
| N. Fail-Open / Fail-Closed Posture Matrix | per Provider Interface and ledger condition | (cross-cutting) |
| O. Cedar Pin & Stability Fixture | Cedar version pin + round-trip CI fixture | FR-039 |
| P. Policy Author UX Spec | Cedar Playground + Discovery-to-Policy + Blast-Radius | FR-049 |
| Q. RFC 8693 Token Exchange Contract | Gateway-side flow + IdP capability matrix | FR-047 |
