# SC-019 Worked Example — Discovery-to-Policy ("Wiz Pattern") Walkthrough

**Scenario**: Acme Corp runs Recurse in Standalone AI Gateway shape for their
internal "HR-Bot" AI assistant. An agent attempts an unrecognized Snowflake
write; Recurse's Audit Plane records the denial with cryptographic proof, the
Governance Plane proposes a Cedar policy in one click, the AppSec engineer
tightens scope, runs a blast-radius simulation over 30 days of history,
approves, and deploys. The next HR-Bot call succeeds. End-to-end the whole
flow is under five minutes of engineer-time.

This walkthrough is the SC-019 acceptance artifact — concrete proof that
FR-049's three surfaces compose into the "Wiz pattern wedge" sales motion
described in `.specify/memory/research_round2_outcomes.md`.

---

## Cast

- **HR-Bot v2.3** — Acme's internal HR assistant, an OpenAI-compat agent
  running behind Recurse Standalone Gateway. Service account:
  `hr-bot-service-account`. SPIFFE ID: `spiffe://acme.corp/ns/hr/sa/hr-bot`.
- **Alice** — AppSec engineer, Acme Corp. SSO identity:
  `alice@acme.corp`. Principal kind: `obo_human` (acting on behalf of herself
  as operator when she reviews denials in the Governance UI).
- **Recurse Standalone Gateway** — deployed as `recurse.acme.internal:8443`,
  sitting between HR-Bot and `api.openai.com` + `snowflake.acme.corp`.

## Sequence diagram

```
HR-Bot         Gateway           Audit UI         Alice          Governance UI    Policy Bundle Store
  |              |                  |                |                 |                  |
  | write_record |                  |                |                 |                  |
  |------------->|                  |                |                 |                  |
  |              | Cedar: no match  |                |                 |                  |
  |              | record denial    |                |                 |                  |
  |              |----------------->|                |                 |                  |
  | 403 Denied   |                  |                |                 |                  |
  |<-------------|                  |                |                 |                  |
  |              |                  |  (event list)  |                 |                  |
  |              |                  |<---------------|                 |                  |
  |              |                  |                |  propose-from-event              |
  |              |                  |                |---------------->|                  |
  |              |                  |                |  proposed_policy                  |
  |              |                  |                |<----------------|                  |
  |              |                  |                | (tighten scope) |                  |
  |              |                  |                |---------------->|                  |
  |              |                  |                |  blast-radius   |                  |
  |              |                  |                |---------------->|                  |
  |              |                  |                | {impacted: 452} |                  |
  |              |                  |                |<----------------|                  |
  |              |                  |                | publish         |                  |
  |              |                  |                |---------------->|                  |
  |              |                  |                |                 | OCI push         |
  |              |                  |                |                 |----------------->|
  |              |                  |                |                 | supersede notif  |
  |              |<----------------------------------+-----------------|------------------|
  |              | hot-swap bundle  |                |                 |                  |
  | write_record |                  |                |                 |                  |
  |------------->|                  |                |                 |                  |
  |  allow +     | Cedar: allow     |                |                 |                  |
  |  receipt     |                  |                |                 |                  |
  |<-------------|                  |                |                 |                  |
```

---

## Step 1 — Denial captured

HR-Bot v2.3 issues:

```http
POST /v1/tools/snowflake/write_record HTTP/1.1
Host: recurse.acme.internal:8443
Authorization: Bearer <spiffe-svid-jwt>
Content-Type: application/json

{
  "table": "HR.SALARIES",
  "records": [{"employee_id": "E42", "salary": 142000}]
}
```

Gateway loads the active Cedar bundle (digest
`sha256:abc123...`, `policy_canonical_hash` `44ea...`), builds the request:

- `principal = User::"hr-bot-service-account"`
- `action = Action::"write_record"`
- `resource = Resource::"snowflake://HR.SALARIES"`
- `context = {tenant: "acme", acting_for_human: true, business_justification: "Q2 comp review"}`

Cedar evaluates. No matching `permit` exists. Cedar returns `DENY`.

Gateway records the denial in the Audit Plane per FR-021 — DSSE-signed
attestation with `policy_decision: "DENY"` and all IdentityContext fields.
HR-Bot receives `403 Forbidden` with the standard error envelope:

```json
{
  "code": "ERR_POLICY_DENIED",
  "message": "Policy evaluation denied this action. See correlation_id for audit trail.",
  "correlation_id": "01HX8Q7R4T8K2Z...",
  "details": {
    "policy_canonical_hash": "44ea666a2c953505b19b2f197d9128f9c4914149cd7a94f6db06833171cb5542"
  }
}
```

## Step 2 — Alice sees the flagged event

Alice opens the Audit Plane UI and filters `policy_decision = DENY AND
principal.issuer = "spiffe://acme.corp/ns/hr/sa/hr-bot"`. She sees one
event from 3 minutes ago. She clicks it; the detail panel shows:

```
Event: 01HX8Q7R4T8K2Z...
Principal:    hr-bot-service-account (service_account)
Machine ID:   spiffe://acme.corp/ns/hr/sa/hr-bot
Action:       write_record
Resource:     snowflake://HR.SALARIES
Context:
  tenant:                  acme
  acting_for_human:        true
  business_justification:  "Q2 comp review"
Decision:     DENY
Cause:        no matching permit
Bundle hash:  44ea666a...
```

At the bottom of the panel: **[Auto-generate Cedar policy]** button.

## Step 3 — Alice clicks Auto-generate Cedar policy

The UI POSTs:

```http
POST /v1/governance/policy/propose-from-event HTTP/1.1
Host: recurse.acme.internal:8443
Authorization: Bearer <alice-oidc-token>
Content-Type: application/json

{"event_id": "01HX8Q7R4T8K2Z..."}
```

Backend calls `PolicyProvider.propose_from_event/2` with the stored event.
The provider inspects the IdentityContext + action shape, produces:

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "proposed_policy": "permit(\n  principal == User::\"hr-bot-service-account\",\n  action == Action::\"write_record\",\n  resource in Resource::\"snowflake://HR.SALARIES\"\n) when { context.business_justification != null };",
  "scope_suggestions": [
    "tenant-scope",
    "principal-group-scope",
    "resource-pattern-scope"
  ]
}
```

The Governance UI auto-populates the Cedar Playground editor with:

```cedar
permit (
  principal == User::"hr-bot-service-account",
  action == Action::"write_record",
  resource in Resource::"snowflake://HR.SALARIES"
) when {
  context.business_justification != null
};
```

## Step 4 — Alice tightens scope

Alice recognizes this policy is too narrow — she wants ALL HR service
accounts (not just HR-Bot) to be able to write to HR.SALARIES given
justification. She clicks the `principal-group-scope` suggestion. The editor
rewrites to:

```cedar
permit (
  principal in Group::"HR-ServiceAccounts",
  action == Action::"write_record",
  resource in Resource::"snowflake://HR.SALARIES"
) when {
  context.business_justification != null
};
```

As she types, the Playground's right pane shows `ALLOW` against her
auto-populated mock request (`principal=hr-bot-service-account, action=write_record,
resource=snowflake://HR.SALARIES, context.business_justification="Q2 comp review"`).
Evaluation time: 312 microseconds.

## Step 5 — Alice runs Blast-Radius against last 30 days

Alice picks `30 days` from the dropdown, clicks **Run blast-radius**:

```http
POST /v1/governance/policy/blast-radius HTTP/1.1
Host: recurse.acme.internal:8443
Authorization: Bearer <alice-oidc-token>
Content-Type: application/json

{
  "candidate_policy": "permit(\n  principal in Group::\"HR-ServiceAccounts\",\n  action == Action::\"write_record\",\n  resource in Resource::\"snowflake://HR.SALARIES\"\n) when { context.business_justification != null };",
  "historical_window_seconds": 2592000
}
```

Backend calls `PolicyProvider.blast_radius/4`, which replays 30 days of
historical attestations against the candidate policy. After 11 seconds:

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "impacted_runs": 452,
  "impacted_agents": 8,
  "sample_divergences": [
    {
      "run_id": "run_01HX7M...",
      "original_decision": "deny",
      "candidate_decision": "allow",
      "principal": "User::\"hr-bot-service-account\"",
      "action": "Action::\"write_record\"",
      "resource": "Resource::\"snowflake://HR.SALARIES\""
    },
    {
      "run_id": "run_01HX7N...",
      "original_decision": "deny",
      "candidate_decision": "allow",
      "principal": "User::\"payroll-bot-service-account\"",
      "action": "Action::\"write_record\"",
      "resource": "Resource::\"snowflake://HR.SALARIES\""
    }
  ],
  "partial": false
}
```

Alice reads: 452 runs across 8 distinct HR-Group agents would have been
allowed under the new policy. She sanity-checks the sample — both agents are
ones she recognizes as approved HR automation. No surprises.

## Step 6 — Alice publishes

Alice clicks **Publish**. The UI calls `PolicyProvider.publish/2` with the
updated bundle (the existing bundle + the new permit policy appended). The
provider:

1. Serializes the combined PolicySet via Cedar.
2. Computes the new `policy_canonical_hash` =
   `SHA-256(JCS(PolicySet::to_json()))`.
3. Packages as an OCI Artifact (`application/vnd.cedar.policy.v1`).
4. Pushes to the registry configured in Acme's Tier Configuration.
5. New digest: `sha256:def456...`.
6. OCI registry emits a supersede event (webhook or periodic poll); Gateway's
   `PolicyProvider.subscribe_supersede_notifications/2` subscription receives it.

Gateway hot-swaps the bundle. Next evaluation uses the new policy.

## Step 7 — HR-Bot retries

HR-Bot v2.3 (or a retry sibling) issues the same request. Gateway builds the
same Cedar request. Cedar evaluates against the new bundle:

- `permit(principal in Group::"HR-ServiceAccounts", ...)` matches.
- `context.business_justification = "Q2 comp review"` satisfies the `when`.
- Cedar returns `ALLOW`.

Gateway forwards to Snowflake, records the successful attestation
(`policy_decision: "ALLOW"`, new `policy_canonical_hash: 9f3c...`), and
returns the result to HR-Bot.

```http
HTTP/1.1 200 OK
Content-Type: application/json
X-Recurse-Run-Id: run_01HX8Q8...
X-Recurse-Verification-Level: pending

{
  "inserted": 1,
  "row_ids": ["E42"]
}
```

At session end, the attestation's verification level transitions to
`global_inclusion_verified` per FR-021 / FR-036 / product decision 6.

---

## Why this is the wedge

- **Before Recurse**: Alice gets a Slack message from HR-Bot's owner complaining
  it can't write to Snowflake. She spends an afternoon in logs, Cedar docs,
  and trial-and-error simulating. Day of lost productivity.
- **With Recurse**: Alice opens the flagged event, clicks Auto-generate,
  tightens one scope, runs Blast-Radius, publishes. Four minutes.

The differentiator is NOT "strongest sandbox" and NOT "proprietary auditor
dashboard" — it's **flagging unknown behavior + proposing policy in one click**,
grounded in real cryptographic evidence of what the agent actually tried to do.

This flow is why Recurse wins deals where raw OPA + Rego setups stalled: the
AppSec persona can author policy without writing Cedar from a blank slate.

---

## Cross-references

- FR-049 surfaces 1-3: `policy_author_ux.md` (Deliverable P)
- Bundle distribution: `policy_bundle_contract.md` (Deliverable K)
- Starter templates used as Wiz-pattern starting points:
  `apps/recurse_shared/priv/policy_templates/`
- Provider Interface: `contracts/provider_interfaces/policy_provider.ex`
- Auditor side of the same event (SIEM forwarder / Export Evidence):
  `specs/001-api-jido-foundations/contracts/siem_log_forwarder.md` (T086),
  `specs/001-api-jido-foundations/contracts/export_evidence_zip.md` (T087)
