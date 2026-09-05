# Fail-Open / Fail-Closed Posture Matrix (Deliverable N)

**Feature**: 001-api-jido-foundations
**Authority**: FR-040 (ledger commit bounded retry), FR-047 (token exchange failure surface —
`ERR_TOKEN_EXCHANGE_FAILED`), FR-010 (error code enumeration), FR-048 (SIEM forwarder as a
degradable audit path), Constitution v1.3.0 Principle II / III.
**Related**: `gateway_runtime_matrix.md`, `completeness_boundary.md`, `attestation.schema.json`.

## Design rule

**Default: fail-closed for any security-affecting condition.** Identity, policy, secrets, and
the completeness boundary itself fail-closed — no request proceeds if the Gateway cannot
confidently stamp it with `(IdentityContext, Cedar decision, policy_canonical_hash)` on a
signed attestation per FR-021 / FR-026 / FR-039.

**Fail-open is acceptable only for audit-path degradation** where the Data Plane has already
produced the security-meaningful record and the issue is downstream observability
(e.g., SIEM forwarder unreachable, Prometheus exporter unable to scrape). Even then, the
receipt state on the global ledger is unaffected.

## Legend

- **Receipt state** values per FR-021 outer container + FR-044 state machine:
  `signed` (DSSE valid, not committed), `local_inclusion_verified` (in session epoch; epoch not
  yet committed), `global_inclusion_verified` (committed to ledger), `commit_retry` (bounded
  retry per FR-040), `commit_retry_exhausted` (FR-040 threshold hit — outer container flag set,
  alert fires per SC-015).
- **Plane response** per FR-016 family and FR-010 error codes.
- **Metric** is the `recurse_*` counter/histogram name in the Prometheus exposition per
  research D17; each listed metric is an SLO-adjacent signal.

## Matrix

| # | Condition | Data Plane behavior | Control / Governance / Audit Plane behavior | Receipt state at failure | Alerting metric fired |
|---|-----------|---------------------|---------------------------------------------|---------------------------|-----------------------|
| 1 | **LLMProvider 5xx (upstream LLM returns 503)** | Surface protocol-native error to agent (OpenAI-compat `error` object per FR-016b). Do NOT block subsequent requests. | Unchanged. | `signed` — failure is itself an attested event (`predicate.kind: "llm_upstream_failure"`). Commits normally. | `recurse_llm_upstream_5xx_total{provider=...}` |
| 2 | **LLMProvider timeout** | Same as row 1 with `upstream_failure_cause: "timeout"`. | Unchanged. | `signed`. | `recurse_llm_upstream_timeout_total` |
| 3 | **LLMProvider connection refused / DNS fail** | Same as row 1 with `upstream_failure_cause: "unreachable"`. | Unchanged. | `signed`. | `recurse_llm_upstream_unreachable_total` |
| 4 | **LedgerProvider commit latency within SLO** | Unaffected. | Unaffected. | Progresses: `signed` → `local_inclusion_verified` → `global_inclusion_verified`. | `recurse_ledger_commit_duration_seconds` (histogram) |
| 5 | **LedgerProvider commit timeout (single attempt)** | Unaffected — Data Plane already served the call; commit is async per FR-036/037. | Audit Plane readyz probe MAY surface `degraded`. | `local_inclusion_verified` → `commit_retry`. | `recurse_ledger_commit_retry_total` |
| 6 | **LedgerProvider commit retry exhausted (FR-040 threshold)** | Still unaffected for NEW calls — Data Plane keeps serving. | Audit Plane surfaces `commit_retry_exhausted: true` in outer container on receipt query; readyz = `degraded`. | Stays at `local_inclusion_verified`; outer container flag set per SC-015. | `recurse_ledger_commit_backoff_exhausted_total` (pages on-call per SC-015) |
| 7 | **LedgerProvider unreachable (network partition)** | Unaffected for local-CAS-write purposes; new events still attest to `local_inclusion_verified`. | Audit Plane readyz = `degraded`. Governance Plane policy simulate/blast-radius unaffected (read-only). | New events stop at `local_inclusion_verified`; when link recovers, Broadway drains the backlog. | `recurse_ledger_commit_unreachable_total` |
| 8 | **SecretsProvider — signer key fetch fails** (KMS down, disk permission error for long-lived key per FR-046) | **FAIL-CLOSED**. Block the Data Plane request; return protocol-native error equivalent to `ERR_INTERNAL` per FR-016e. No attestation can be signed, so no request may proceed. | Control Plane returns `503 ERR_INTERNAL` with `cause: "signing_unavailable"`. | No receipt produced. | `recurse_signer_unavailable_total` (page immediately — security-affecting) |
| 9 | **SecretsProvider RFC 8693 token exchange failure (FR-047)** | **FAIL-CLOSED** for the specific downstream call. The MCP facade returns a protocol-native error to the agent surfacing `ERR_TOKEN_EXCHANGE_FAILED` per FR-016f / FR-047. Session is not aborted. | Unchanged. Governance Plane MAY surface the denial reason in blast-radius explain. | `signed` denial attestation — `predicate.kind: "token_exchange_failed"`. | `recurse_token_exchange_failed_total{idp=...}` |
| 10 | **SecretsProvider — Vault-backed downstream secret fetch fails** (FR-047 downstream auth material not retrievable) | **FAIL-CLOSED** for the affected downstream call (same shape as row 9). | Unchanged. | `signed` denial attestation — `predicate.kind: "downstream_secret_unavailable"`. | `recurse_downstream_secret_unavailable_total` |
| 11 | **PrincipalProvider / IdP unreachable at IdentityContext resolution (FR-026)** | **FAIL-CLOSED**. Reject the request at ingress — IdentityContext cannot be resolved, therefore no attestation can be signed. Return `401 ERR_IDENTITY_UNVERIFIED` (or protocol-native equivalent per FR-016). | Control Plane `401 ERR_IDENTITY_UNVERIFIED`. Audit Plane: no receipt to query. | No receipt produced. | `recurse_identity_resolve_failed_total{provider=...}` (page — security-affecting) |
| 12 | **PrincipalProvider returns a malformed / unverifiable principal claim** | **FAIL-CLOSED**. Same shape as row 11 with `cause: "principal_malformed"`. | Unchanged. | No receipt. | `recurse_principal_invalid_total` |
| 13 | **IdentityProvider (SPIFFE SVID) rotation failure / SVID expiry** | **FAIL-CLOSED**. Fresh requests rejected until rotation recovers. Existing connections drained per the SPIFFE-helper lifecycle (Phase-2 dist-BEAM integration — memory: `research_phase1_recommendations`). | Control Plane degraded; readyz = `not ready`. | No receipt for rejected requests. | `recurse_spiffe_svid_expired_total`, `recurse_spiffe_svid_rotation_failed_total` |
| 14 | **PolicyProvider — bundle refresh fails (supersede source unreachable)** | **FAIL-OPERATIONAL on current bundle**. Continue serving under the previously-cached bundle (last known `policy_canonical_hash`). Do NOT fail-closed on refresh alone — the current bundle is still valid policy. | Control Plane readyz = `degraded` (bundle stale). Governance Plane simulate/blast-radius runs against the cached bundle, clearly labeled. | `signed` normally under the cached `policy_canonical_hash`. | `recurse_policy_bundle_refresh_failed_total` (warns after configured staleness threshold — default 15 min) |
| 15 | **PolicyProvider — bundle parse / validation fails on refresh** | **FAIL-CLOSED on the new bundle**: reject the malformed bundle, continue on the previous valid bundle. If there is no previous valid bundle (cold start), fail-closed at the Data Plane — no request may proceed without a known-good `policy_canonical_hash`. | Control Plane `503 ERR_POLICY_INVALID` if cold-start. Governance Plane surfaces the parse error to the authoring UI. | No receipt for blocked requests; otherwise `signed` under the still-valid prior bundle. | `recurse_policy_bundle_invalid_total` (page — security-affecting) |
| 16 | **Cedar evaluator NIF crash** | **FAIL-CLOSED**. Supervisor restarts the NIF process; in-flight request returns `503 ERR_INTERNAL`. No decision, no attestation. | Control Plane surfaces `degraded` on readyz during restart window. | No receipt for the crashed request. | `recurse_cedar_nif_crash_total` (page) |
| 17 | **StorageProvider — payload write fails (Audit Payload Broker, FR-030)** | **FAIL-CLOSED** for the specific request that required payload durability before response. Returns `503 ERR_INTERNAL`. | Audit Plane payload-fetch returns `404` for the affected `payload_uri` until retry succeeds (if retry layer is configured). | No receipt (payload is a signed-predicate input; if it cannot be stored, nothing to attest). | `recurse_payload_storage_write_failed_total` |
| 18 | **StorageProvider — payload read fails (FR-030)** | N/A (not on Data Plane hot path). | Audit Plane returns `503 ERR_STORAGE_UNAVAILABLE`; Export Evidence builder surfaces a partial-evidence warning. | Unchanged — receipts already on ledger. | `recurse_payload_storage_read_failed_total` |
| 19 | **SIEM Log Forwarder unreachable (FR-048 surface 1)** | **FAIL-OPEN for the Data Plane** — Data Plane writes receipts to the session chain as normal. | Audit Plane readyz = `degraded`. Forwarder buffers locally (bounded queue per tier config); on-call alert fires before buffer drop. | Unchanged — receipts commit to ledger as normal. | `recurse_siem_forwarder_dropped_total`, `recurse_siem_forwarder_buffered_seconds` |
| 20 | **Prometheus exporter / telemetry endpoint unreachable** | **FAIL-OPEN**. Metrics invisible, but Data Plane and audit path unaffected. | No change (alerting paths beyond Prometheus are deployment-owned). | Unchanged. | (scrape failure is the alert — meta) |
| 21 | **Global-ledger commit pipeline (Broadway) crash / restart** | **FAIL-OPEN for fresh Data Plane requests** (they still sign and reach `local_inclusion_verified`). | Audit Plane readyz = `degraded` while pipeline restarts; Supervisor restores within OTP-standard restart interval. | New events queue at `local_inclusion_verified`; pipeline drains on restart. | `recurse_ledger_pipeline_restart_total` |
| 22 | **Interim-commit scheduler (Oban) unreachable / DB down** | **FAIL-OPEN for fresh Data Plane requests**. Session epochs extend past their nominal interim-commit boundary. | Audit Plane surfaces `interim_commit_overdue: true` on affected sessions. | `local_inclusion_verified` for longer than FR-037's nominal window. | `recurse_interim_commit_overdue_total` |
| 23 | **Completeness-boundary netns filter — programming failure at agent spawn (FR-043)** | **FAIL-CLOSED at agent spawn**. Do NOT start the agent container if netfilter rules cannot be programmed (the kernel-level enforcement guarantee of Principle II would be broken). Return `503 ERR_NETNS_SETUP_FAILED` on the spawn endpoint. | Control Plane `503`; Runtime orchestrator records the failure to local CAS for audit. | No session starts; no receipts. | `recurse_netns_program_failed_total` (page — security-affecting, Principle II) |
| 24 | **Completeness-boundary netns filter — rule drift detected mid-session** (periodic sanity check finds the programmed rules have been tampered) | **FAIL-CLOSED for that session**: terminate the agent container; transition session to `aborted` per FR-044; emit a `predicate.kind: "completeness_tampering"` attestation. | Control Plane records the abort. Alerting pages on-call. | Current events stay at last known valid state; session terminates with `aborted`. | `recurse_netns_rule_drift_total` (page — security-affecting) |

## Summary posture table

| Category | Default |
|----------|---------|
| Identity (FR-026) — resolution failures | **Fail-closed** |
| Policy (FR-039) — bundle invalid / NIF crash | **Fail-closed** |
| Secrets (FR-046 / FR-047) — signer unavailable | **Fail-closed** |
| Completeness boundary (FR-043) — netns programming | **Fail-closed** |
| Ledger (FR-040) — commit-path degradation | **Fail-open for Data Plane**, `local_inclusion_verified` ages into `commit_retry` → `commit_retry_exhausted` with alerting |
| Audit observability (FR-048) — SIEM / Prometheus down | **Fail-open** (Data Plane integrity unaffected) |
| Upstream LLM / MCP | **Fail-open** (failure surfaces as attested upstream-failure event per FR-016b) |

Any new condition added in Feature 002+ MUST be classified into one of these buckets and
appended to the matrix above before landing code.
