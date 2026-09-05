# SIEM Log Forwarder Schema (Deliverable J, part 4)

**Feature**: 001-api-jido-foundations
**Authority**: FR-048 surface 1 (daily-ops auditor firehose); FR-022 (audit query semantics);
FR-026 (canonical principal claim); spec.md v6.1 fix #8 (structured `principal`, NOT flat
`human_identity`).
**Related**: `attestation.schema.json` (signed predicate fields reflected here),
`export_evidence_zip.md` (FR-048 surface 2 — point-in-time annual audits),
`cli_verifier_procedure.md` (FR-048 surface 3 — off-platform verifier),
`docs/operator/siem_integration.md` (per-SIEM operator setup).

## 1. Purpose and framing

The SIEM Log Forwarder is the **daily-ops auditor surface**. GRC teams already own a SIEM
(Splunk, Datadog, Microsoft Sentinel); they do NOT want a proprietary Recurse dashboard. The
forwarder emits one flat JSON event per receipt-relevant occurrence into the customer's existing
SIEM, where the customer owns alerting, retention, and dashboarding.

**Recurse's role ends at event emission.** The SIEM holds the data; the auditor correlates,
searches, and alerts in their own tooling. The forwarder is a firehose, not a query API.

**Two classes of receipt verification are explicitly OUT OF SCOPE here:**

1. Cryptographic verification — auditors use the Export Evidence zip (FR-048 surface 2) +
   `recurse-verify` (T077) for offline, off-platform verification. The SIEM event is a
   **summary**, not a proof.
2. Proof-state freshness — the SIEM event carries the `verification_level` AT EMISSION TIME.
   Subsequent transitions (`signed` → `local_inclusion_verified` →
   `global_inclusion_verified`) emit follow-up events (see §4); the SIEM is then eventually
   consistent with the Audit Plane.

## 2. Event schema (per-event JSON)

Every forwarded event is a single JSON object with the following shape. All fields are required
unless marked **optional**. Field semantics mirror the signed-predicate fields in
`attestation.schema.json` (so a SIEM event and its corresponding receipt carry the same
canonical values).

| Field | Type | Source | Description |
|---|---|---|---|
| `event_id` | ULID | forwarder-local | Unique per emitted event; lets dedup on the SIEM side across retries |
| `emitted_at` | RFC 3339 string | forwarder-local | When the forwarder produced THIS event (NOT the receipt timestamp) |
| `recurse_envelope_version` | string | receipt | Mirrors `dsseEnvelope.payload.envelope_version` (e.g., `"1.0"`) |
| `tenant_id` | ULID | receipt | `signed_predicate.tenant_id` |
| `run_id` | ULID | receipt | `signed_predicate.run_id` |
| `session_id` | ULID | receipt | `signed_predicate.session_id` |
| `turn_id` | ULID \| null | receipt | `signed_predicate.turn_id` (present for LLM call + tool calls under that turn; null for top-level LLM or standalone egress) |
| `step_id` | ULID | receipt | `signed_predicate.step_id` |
| `session_chain_position` | integer | receipt | `signed_predicate.session_chain_position` |
| `event_kind` | enum | receipt | `signed_predicate.event_kind`: `llm_call`, `tool_call`, `egress_denied`, `policy_denied`, `session_abort` |
| `timestamp` | RFC 3339 string | receipt | `signed_predicate.timestamp` (authoritative event time per FR-031) |
| `correlation_id` | ULID | receipt | `signed_predicate.correlation_id` (trace join key) |
| `machine_identity` | object | receipt | `{spiffe_id: "spiffe://..."}` for Governance shapes; `{observed_jwt_subject, observed_jwt_issuer}` for Standalone Gateway (FR-017) |
| `principal` | object | receipt | Canonical FR-026 principal; see §2.1 |
| `tool_called` | string \| null | receipt + event-kind | Logical tool identifier (e.g., `"mcp://jira/create_issue"`, `"openai:gpt-4o"`); null for session-boundary events |
| `policy_decision` | enum | policy engine | `ALLOW`, `DENY`, `NOT_APPLICABLE` (latter used for session-boundary events that don't gate) |
| `policy_canonical_hash` | `sha256:<hex>` | receipt | `signed_predicate.policy_canonical_hash` (RFC 8785 JCS of Cedar AST per FR-039) |
| `verification_level` | enum | outer container | `signed`, `local_inclusion_verified`, `global_inclusion_verified` (at emission time of THIS event) |
| `tier_completeness_advisory` | enum | outer container | `complete` (Governance) or `partial` (Standalone Gateway) per FR-038 axis 2 |
| `session_state` | enum \| null | outer container | `active`, `interim_committed`, `commit_retry`, `commit_retry_exhausted`, `aborted`, `cancelled`, `committed` — present for session-boundary events, null for per-turn events |
| `commit_retry_exhausted` | boolean | outer container | `true` only when FR-040 backoff has been exhausted (SC-015 surface) |
| `signer` | string | receipt | `signed_predicate.signer` (document-signing key reference per FR-046; resolvable to public key via SigningKey table or the Export Evidence zip) |
| `payload_hash` | `sha256:<hex>` | receipt | `signed_predicate.payload_hash` |
| `payload_uri` | string | receipt | `signed_predicate.payload_uri` (customer-storage reference; resolved via FR-030 broker) |
| `tool_sbom_ref` | string \| null | receipt | Optional SBOM reference; **optional** |
| `recurse_deployment_shape` | enum | forwarder config | `managed_saas`, `vpc_runner`, `appliance`, `standalone_gateway` — lets the SIEM segment events per shape without cross-referencing tier config |

### 2.1 `principal` object shape (critical — v6.1 fix #8)

`principal` is a **structured object**, not a flat `human_identity` string. The shape matches
the FR-026 canonical principal exactly and is one of three `kind` variants:

**`kind: "obo_human"`** — downstream acting on behalf of a human principal:
```json
{
  "kind": "obo_human",
  "schema_version": "1.0",
  "issuer": "https://corp.okta.com",
  "subject": "alice@corp.example",
  "display_name": "Alice Chen",
  "groups": ["engineering", "finance-readers"]
}
```

**`kind: "service_account"`** — non-human machine principal:
```json
{
  "kind": "service_account",
  "schema_version": "1.0",
  "issuer": "https://corp.okta.com",
  "account_id": "svc-etl-pipeline",
  "scope": ["warehouse:read", "jira:write"]
}
```

**`kind: "autonomous"`** — agent acting under its own SPIFFE identity, no human OBO:
```json
{
  "kind": "autonomous",
  "schema_version": "1.0",
  "spiffe_id": "spiffe://corp.example/agent/nightly-reporter"
}
```

**Why structured, not flat.** A flat `human_identity: "alice@corp.example"` field is ambiguous
under service-account and autonomous principals (no human exists) and loses structure that GRC
teams need for their alerts. The canonical example:

> *"Alert if `principal.kind == "service_account"` AND `policy_decision == "DENY"`
> AND `tool_called` matches `mcp://jira/.*`."*

That alert is impossible to express cleanly against a flat string. Keeping `principal` as an
object makes GRC recipes composable and keeps the SIEM event schema consistent with the signed
receipt.

## 3. Output format and transport

### 3.1 Primary: NDJSON over stdout (fluentd / vector pipeline)

Default output is **Newline-Delimited JSON on stdout**: one event per line, no wrapping array,
no pretty-printing. This is directly consumable by `fluentd`, `vector`, `filebeat`, `splunk
universal forwarder`, and the stock `dd-agent` tail integration. See
`docs/operator/siem_integration.md` for per-SIEM wiring.

```jsonl
{"event_id":"01K0P3JA...","event_kind":"llm_call","policy_decision":"ALLOW","principal":{"kind":"obo_human",...},...}
{"event_id":"01K0P3JB...","event_kind":"tool_call","policy_decision":"DENY","principal":{"kind":"obo_human",...},...}
```

**Encoding**: UTF-8. Line separator: single `\n` (0x0A). No BOM. No trailing `,`.

**Ordering guarantee**: events are emitted in **per-session `session_chain_position` order**.
Cross-session ordering is NOT guaranteed (multiple sessions may interleave on the wire).

**At-least-once**: the forwarder retries on transport failure. SIEMs MUST dedup on `event_id`
(it is stable across retries; do NOT use `emitted_at`, which advances on retry).

### 3.2 Secondary: configurable HTTP push target

For customers without a forwarder agent, the SIEM Log Forwarder exposes an HTTP push mode
configurable per deployment. Operator config keys:

```yaml
siem_forwarder:
  mode: http_push                # OR "stdout" (default)
  endpoint: "https://splunk.corp.example:8088/services/collector"
  method: POST                   # POST only
  content_type: "application/x-ndjson"  # OR "application/json" with JSON array body
  auth:
    kind: bearer                 # OR "hec_token", "datadog_api_key", "sentinel_shared_key"
    secrets_provider_ref: "siem/splunk_hec_token"   # resolved via SecretsProvider per FR-046
  batch:
    max_events: 500              # flush trigger
    max_bytes: 1048576           # 1 MiB flush trigger
    max_interval_ms: 5000        # idle flush
  retry:
    max_attempts: 6              # exponential backoff 1s..64s
    backoff: exponential
  tls:
    verify: true                 # disable ONLY in air-gapped dev
```

**Failure semantics**: HTTP push is at-least-once. If `max_attempts` is exhausted, events are
buffered to a bounded local WAL and retried on Gateway restart. The forwarder **never** drops
events silently; exhaustion raises the metric `recurse_siem_forwarder_dropped_total` and
surfaces in operator alerting (see `failure_matrix.md`).

### 3.3 Field-mapping hooks (per-SIEM)

Some SIEMs require nested fields be flattened (Splunk HEC default) or renamed (Datadog's
reserved `host`, `service`, `source`). Rather than hard-code remaps, the forwarder exposes a
declarative mapping table. See `docs/operator/siem_integration.md` for per-SIEM defaults.

## 4. Example events

### 4.1 Successful LLM call (per-turn, signed state)

```json
{
  "event_id": "01K0P3JA1M6TXZQYBVMKQ9WH73",
  "emitted_at": "2026-04-22T14:03:12.040Z",
  "recurse_envelope_version": "1.0",
  "tenant_id": "01JZXYZZZZZZZZZZZZZZZZZZZZ",
  "run_id": "01K0P3J9KJ8XAZJPBX5B3EHRWD",
  "session_id": "01K0P3J9KP7NB5VHGJ9QM4QXA0",
  "turn_id": null,
  "step_id": "01K0P3JA0Z2MR6EFKH5NW0P82K",
  "session_chain_position": 14,
  "event_kind": "llm_call",
  "timestamp": "2026-04-22T14:03:12.012Z",
  "correlation_id": "01K0P3J9KX4HYV2QX84PDB6M3F",
  "machine_identity": {"spiffe_id": "spiffe://corp.example/agent/finance-bot"},
  "principal": {
    "kind": "obo_human",
    "schema_version": "1.0",
    "issuer": "https://corp.okta.com",
    "subject": "alice@corp.example",
    "display_name": "Alice Chen",
    "groups": ["finance-readers"]
  },
  "tool_called": "openai:gpt-4o",
  "policy_decision": "ALLOW",
  "policy_canonical_hash": "sha256:5e2c...a119",
  "verification_level": "signed",
  "tier_completeness_advisory": "complete",
  "session_state": null,
  "commit_retry_exhausted": false,
  "signer": "spiffe://recurse.cloud/gateway/us-east-1/v3",
  "payload_hash": "sha256:9bb0...dfe4",
  "payload_uri": "s3://corp-agents/prod/01K0P3J9KJ8XAZJPBX5B3EHRWD/step-14.json",
  "tool_sbom_ref": null,
  "recurse_deployment_shape": "managed_saas"
}
```

### 4.2 Tool call with policy DENY

```json
{
  "event_id": "01K0P3JA2N7UYARZCWLRQ9WH84",
  "emitted_at": "2026-04-22T14:03:12.210Z",
  "recurse_envelope_version": "1.0",
  "tenant_id": "01JZXYZZZZZZZZZZZZZZZZZZZZ",
  "run_id": "01K0P3J9KJ8XAZJPBX5B3EHRWD",
  "session_id": "01K0P3J9KP7NB5VHGJ9QM4QXA0",
  "turn_id": "01K0P3JA0Z2MR6EFKH5NW0P82K",
  "step_id": "01K0P3JA2M8PQZJ3E0L1K7WX5D",
  "session_chain_position": 15,
  "event_kind": "tool_call",
  "timestamp": "2026-04-22T14:03:12.198Z",
  "correlation_id": "01K0P3J9KX4HYV2QX84PDB6M3F",
  "machine_identity": {"spiffe_id": "spiffe://corp.example/agent/finance-bot"},
  "principal": {
    "kind": "service_account",
    "schema_version": "1.0",
    "issuer": "https://corp.okta.com",
    "account_id": "svc-finance-bot",
    "scope": ["warehouse:read"]
  },
  "tool_called": "aws:iam:CreatePolicy",
  "policy_decision": "DENY",
  "policy_canonical_hash": "sha256:5e2c...a119",
  "verification_level": "signed",
  "tier_completeness_advisory": "complete",
  "session_state": null,
  "commit_retry_exhausted": false,
  "signer": "spiffe://recurse.cloud/gateway/us-east-1/v3",
  "payload_hash": "sha256:2ff1...aa33",
  "payload_uri": "s3://corp-agents/prod/01K0P3J9KJ8XAZJPBX5B3EHRWD/step-15.json",
  "tool_sbom_ref": null,
  "recurse_deployment_shape": "managed_saas"
}
```

### 4.3 Mid-stream SSE denial (FR-041)

An SSE LLM stream was allowed at turn start, then a mid-stream policy re-evaluation denied
continued streaming (e.g., the model began emitting content that matched a Cedar forbid rule).
One `policy_denied` event is emitted marking the denial point; the LLM call's per-turn event
still records the denial outcome via its own `policy_decision` when emitted at stream close.

```json
{
  "event_id": "01K0P3JB3P8VZBSADXMSR0XJ95",
  "emitted_at": "2026-04-22T14:03:12.489Z",
  "recurse_envelope_version": "1.0",
  "tenant_id": "01JZXYZZZZZZZZZZZZZZZZZZZZ",
  "run_id": "01K0P3J9KJ8XAZJPBX5B3EHRWD",
  "session_id": "01K0P3J9KP7NB5VHGJ9QM4QXA0",
  "turn_id": "01K0P3JA0Z2MR6EFKH5NW0P82K",
  "step_id": "01K0P3JB3N9RAZK4F1M2L8XZ6E",
  "session_chain_position": 16,
  "event_kind": "policy_denied",
  "timestamp": "2026-04-22T14:03:12.476Z",
  "correlation_id": "01K0P3J9KX4HYV2QX84PDB6M3F",
  "machine_identity": {"spiffe_id": "spiffe://corp.example/agent/finance-bot"},
  "principal": {
    "kind": "obo_human",
    "schema_version": "1.0",
    "issuer": "https://corp.okta.com",
    "subject": "alice@corp.example",
    "display_name": "Alice Chen",
    "groups": ["finance-readers"]
  },
  "tool_called": "openai:gpt-4o",
  "policy_decision": "DENY",
  "policy_canonical_hash": "sha256:5e2c...a119",
  "verification_level": "signed",
  "tier_completeness_advisory": "complete",
  "session_state": null,
  "commit_retry_exhausted": false,
  "signer": "spiffe://recurse.cloud/gateway/us-east-1/v3",
  "payload_hash": "sha256:7dd2...bbcc",
  "payload_uri": "s3://corp-agents/prod/01K0P3J9KJ8XAZJPBX5B3EHRWD/step-16.json",
  "tool_sbom_ref": null,
  "recurse_deployment_shape": "managed_saas"
}
```

### 4.4 Session-boundary: interim epoch committed (FR-037 / FR-044)

This is a **lifecycle event**, not a per-turn receipt. It surfaces that a prior batch of events
in this session has transitioned from `local_inclusion_verified` to `global_inclusion_verified`.
The SIEM can use this to drive "proof maturity" dashboards.

```json
{
  "event_id": "01K0P3KC4Q9WACUBEYNTS1YKA6",
  "emitted_at": "2026-04-22T14:08:02.003Z",
  "recurse_envelope_version": "1.0",
  "tenant_id": "01JZXYZZZZZZZZZZZZZZZZZZZZ",
  "run_id": "01K0P3J9KJ8XAZJPBX5B3EHRWD",
  "session_id": "01K0P3J9KP7NB5VHGJ9QM4QXA0",
  "turn_id": null,
  "step_id": "01K0P3KC4P0RBAL5G2N3M9YA7F",
  "session_chain_position": 24,
  "event_kind": "session_abort",
  "timestamp": "2026-04-22T14:08:02.000Z",
  "correlation_id": "01K0P3J9KX4HYV2QX84PDB6M3F",
  "machine_identity": {"spiffe_id": "spiffe://corp.example/agent/finance-bot"},
  "principal": {
    "kind": "obo_human",
    "schema_version": "1.0",
    "issuer": "https://corp.okta.com",
    "subject": "alice@corp.example"
  },
  "tool_called": null,
  "policy_decision": "NOT_APPLICABLE",
  "policy_canonical_hash": "sha256:5e2c...a119",
  "verification_level": "global_inclusion_verified",
  "tier_completeness_advisory": "complete",
  "session_state": "interim_committed",
  "commit_retry_exhausted": false,
  "signer": "spiffe://recurse.cloud/gateway/us-east-1/v3",
  "payload_hash": "sha256:0000...0000",
  "payload_uri": "",
  "tool_sbom_ref": null,
  "recurse_deployment_shape": "managed_saas"
}
```

**Note on `event_kind: session_abort` placeholder.** Phase-1 uses the existing receipt schema
for session-boundary events (see `attestation.schema.json` enum). The distinguishing fact is
`session_state` (non-null for boundary events). Feature 002+ MAY introduce dedicated boundary
`event_kind` values; until then, the SIEM rule to detect boundaries is
`session_state IS NOT NULL` (see HANDOFF note 1 below).

### 4.5 Session-end: session committed (FR-044 final state)

```json
{
  "event_id": "01K0P3LD5R0XBDVCFZOUT2ZLB7",
  "emitted_at": "2026-04-22T14:23:45.009Z",
  "recurse_envelope_version": "1.0",
  "tenant_id": "01JZXYZZZZZZZZZZZZZZZZZZZZ",
  "run_id": "01K0P3J9KJ8XAZJPBX5B3EHRWD",
  "session_id": "01K0P3J9KP7NB5VHGJ9QM4QXA0",
  "turn_id": null,
  "step_id": "01K0P3LD5Q1SBCM6H3P4N0ZB8G",
  "session_chain_position": 128,
  "event_kind": "session_abort",
  "timestamp": "2026-04-22T14:23:45.000Z",
  "correlation_id": "01K0P3J9KX4HYV2QX84PDB6M3F",
  "machine_identity": {"spiffe_id": "spiffe://corp.example/agent/finance-bot"},
  "principal": {
    "kind": "obo_human",
    "schema_version": "1.0",
    "issuer": "https://corp.okta.com",
    "subject": "alice@corp.example"
  },
  "tool_called": null,
  "policy_decision": "NOT_APPLICABLE",
  "policy_canonical_hash": "sha256:5e2c...a119",
  "verification_level": "global_inclusion_verified",
  "tier_completeness_advisory": "complete",
  "session_state": "committed",
  "commit_retry_exhausted": false,
  "signer": "spiffe://recurse.cloud/gateway/us-east-1/v3",
  "payload_hash": "sha256:0000...0000",
  "payload_uri": "",
  "tool_sbom_ref": null,
  "recurse_deployment_shape": "managed_saas"
}
```

## 5. GRC alert recipes

Three worked examples showing how GRC teams build alerts directly in their own SIEM. These are
**illustrative**, not exhaustive; the point is that the structured schema makes composable
alerts trivial. See `docs/operator/siem_integration.md` for per-SIEM config, field-name quirks,
and operator-facing setup.

### 5.1 Splunk SPL — service-account DENY spike

> *"Alert if, in any 10-minute window, a single `service_account` principal accumulates
> ≥ 5 DENY events across sensitive tools."*

```spl
index=recurse sourcetype=recurse:siem
| where principal.kind="service_account"
  AND policy_decision="DENY"
  AND like(tool_called, "aws:iam:%")
| bin _time span=10m
| stats count AS deny_count BY _time, principal.account_id, tenant_id
| where deny_count >= 5
| eval alert="service_account_deny_spike"
```

### 5.2 Datadog Logs — OBO human escalation attempt

> *"Alert if an `obo_human` principal hits ≥ 3 DENYs on admin-scope tools in 5 minutes."*

```
service:recurse @event_kind:tool_call @policy_decision:DENY
  @principal.kind:obo_human
  @tool_called:(aws\:iam\:* OR gcp\:iam\:* OR mcp\://admin/*)
| rollup count by @principal.subject, @tenant_id in last 5m
| where _count >= 3
```

Paired monitor definition (YAML):
```yaml
name: "Recurse — OBO human admin-escalation pattern"
type: log alert
query: |
  logs("service:recurse @event_kind:tool_call @policy_decision:DENY
        @principal.kind:obo_human
        @tool_called:(aws:iam:* OR gcp:iam:* OR mcp://admin/*)")
    .rollup("count").by("@principal.subject","@tenant_id").last("5m") > 3
```

### 5.3 Microsoft Sentinel KQL — commit-retry exhaustion (SC-015 surface)

> *"Alert on any `commit_retry_exhausted: true` — ledger is stalled, operator intervention
> required."*

```kql
Recurse_SIEM_CL
| where commit_retry_exhausted_b == true
| project
    TimeGenerated,
    tenant_id_s,
    session_id_s,
    session_state_s,
    verification_level_s,
    signer_s
| summarize
    exhausted_sessions = dcount(session_id_s),
    earliest = min(TimeGenerated),
    latest = max(TimeGenerated)
  by tenant_id_s
| extend severity = "High"
```

## 6. Versioning and compatibility

- Event schema version equals `recurse_envelope_version`. Phase-1 ships `1.0`.
- Additive field additions (new optional fields) do NOT bump the version.
- Breaking changes (rename, type change, removal) DO bump the version and ship alongside an
  event-translator for one deprecation window.
- Consumers SHOULD tolerate unknown fields (ignore, do not error).

## 7. HANDOFF notes

1. **`event_kind` coverage for session boundaries.** Phase-1 reuses the existing FR-021 enum
   (`llm_call`, `tool_call`, `egress_denied`, `policy_denied`, `session_abort`). Session
   boundary events currently ride as `session_abort` with `session_state IN ("interim_committed",
   "committed")`, which is semantically wrong (the session wasn't aborted). Feature 002+ should
   introduce `session_interim_committed` and `session_committed` enum values in
   `attestation.schema.json`; this doc updates in lockstep. Tracked under the attestation schema
   (not a blocker for the SIEM forwarder contract).
2. **HTTP push `auth.kind` enum extensibility.** The four kinds listed cover Splunk HEC /
   Datadog / Sentinel / generic bearer. Additional SIEMs (Sumo Logic, Elastic, custom) will need
   additional enum values as those integrations are built; Phase-1 ships the three committed
   targets per `docs/operator/siem_integration.md`.
3. **`principal.display_name` / `groups` scrubbing.** Customers with PII concerns MAY want the
   forwarder to redact `display_name` and `groups` before emission. The forwarder exposes a
   per-deployment `principal_redaction` config (boolean per field); the **signed receipt** is
   never redacted (it's the auditor's ground truth and is customer-encrypted at rest per
   FR-030). This redaction is purely a SIEM-transport concern. Full config surface lands in
   Feature 002+ operator config.
