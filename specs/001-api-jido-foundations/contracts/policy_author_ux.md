# Deliverable P — Policy Author UX Spec

**Source FRs**: FR-049 (three policy-author surfaces), FR-039 (policy bundle distribution),
FR-021 (attestation shape that feeds Blast-Radius replay).
**Success criteria**: SC-019 (Discovery-to-Policy worked example — see
`policy_author_ux_examples/wiz_pattern_walkthrough.md`).
**Personas**: AppSec engineer, Cloud IAM engineer, GRC specialist — hereafter "policy
author". Explicitly NOT "agent developer" and NOT "compliance auditor" (auditor UX is
Deliverable J).

This document specifies the three Phase-1 policy-author surfaces at the UI-flow level
plus the backing API contracts. UI implementation lives in a sibling feature; only the
surface contract is in Feature 001 scope. OpenAPI endpoint entries for the three APIs
are added under **T085** (held back on the main thread behind T049).

**Phase-2 explicit deferral — visual policy builder**. A dropdown-based Cedar
construction UI (AWS IAM Visual Editor pattern) is **NOT in v1.0**. Phase-1 ships the
three surfaces below; visual building waits for Phase-2 grounded in real Phase-1 usage
data rather than guessed requirements.

---

## 1. Cedar Playground (FR-049 surface 1)

### UI flow — split-pane editor

A web UI mirroring the AWS Cedar Playground pattern. Three vertical panes:

```
+-------------------------+------------------------+----------------------+
|  Policy Editor          |  Mock Request          |  Simulation Result   |
|  (Cedar source)         |  (form: principal,     |  (ALLOW / DENY +     |
|  syntax autocomplete    |   action, resource,    |   matched rules +    |
|  inline error markers   |   context attrs)       |   evaluation time)   |
+-------------------------+------------------------+----------------------+
```

**Left pane (editor)**:
- Monaco / CodeMirror-class editor with Cedar syntax highlighting.
- Inline error markers driven by `Recurse.Cedar.validate_policy_syntax/1` (the
  Rustler NIF from T042 — re-used; no second parser).
- Autocomplete for Cedar keywords (`permit`, `forbid`, `when`, `unless`, `principal`,
  `action`, `resource`, `context`, `is`, `in`, `==`, `has`).
- "Insert from template" menu sourced from `apps/recurse_shared/priv/policy_templates/`
  (T084 starter library).

**Middle pane (mock request)**:
- Form fields: `principal` (entity UID like `User::"alice@corp"`), `action`
  (`Action::"read"`), `resource` (`Resource::"snowflake://HR.SALARIES"`),
  `context` (key/value grid — typed as string / bool / int / list).
- "Load from recent denial" button → populates from a recent Audit-Plane event
  (pre-seed for the Discovery-to-Policy handoff, §2 below).

**Right pane (result)**:
- `ALLOW` / `DENY` banner.
- Matched rules list (rule IDs or line numbers from the editor).
- `evaluation_micros` microsecond counter (the Playground's sub-millisecond claim).
- "Deploy to bundle" button → packages the current editor content as the next
  policy bundle draft (actual publish flow is `PolicyProvider.publish/2`, covered
  in `policy_bundle_contract.md`).

### Sub-millisecond feedback target

The Playground target is **sub-millisecond evaluation feedback as the engineer
types**. This is achieved server-side by the Cedar NIF, not client-side:
- Editor debounces keystrokes at 150ms.
- POST to `/v1/governance/policy/simulate` with the current editor buffer and the
  current mock-request form state.
- Cedar NIF parses + evaluates in the typical <1ms for Playground-sized
  (<50 policy) bundles. p99 target: 5ms including HTTP round-trip on a loopback;
  10ms over a mesh-internal RPC.

### API contract — `/v1/governance/policy/simulate`

**Method**: `POST`
**Plane**: Governance Plane
**Auth**: standard Governance-Plane auth (human OBO via `PrincipalProvider`;
machine via SPIFFE SVID).
**Idempotency**: not required (read-only, no state mutation).
**Rate limit class**: Governance, per-tenant.
**Streaming**: `sync` (not SSE, not WS).
**Owning OTP application**: `recurse_gateway`.

**Request body**:
```json
{
  "policy_text": "permit(principal == User::\"alice\", action == Action::\"read\", resource);",
  "mock_request": {
    "principal": "User::\"alice\"",
    "action": "Action::\"read\"",
    "resource": "Resource::\"snowflake://HR.SALARIES\"",
    "context": {
      "acting_for_human": true,
      "business_justification": "Q2 comp review"
    }
  }
}
```

**Response body** (HTTP 200):
```json
{
  "decision": "allow",
  "matched_rules": ["policy0"],
  "evaluation_micros": 247
}
```

**Response body** (HTTP 400, policy parse error — surfaces inline in editor):
```json
{
  "code": "ERR_POLICY_SYNTAX",
  "message": "cedar parse error: expected `when` or `;`, found `foo`",
  "correlation_id": "01HX8Q...",
  "details": {
    "line": 5,
    "column": 14
  }
}
```

**Backend**: `PolicyProvider.simulate/3` callback
(`specs/001-api-jido-foundations/contracts/provider_interfaces/policy_provider.ex`).

### Error modes

| Condition                         | HTTP | Error code           | UI surface                               |
|-----------------------------------|------|----------------------|------------------------------------------|
| Policy source parse error         | 400  | `ERR_POLICY_SYNTAX`  | inline marker at line/col in editor      |
| Malformed mock request entity UID | 400  | `ERR_POLICY_INPUT`   | middle-pane form field validation        |
| Policy exceeds size bound         | 400  | `ERR_POLICY_TOO_LARGE` | banner above editor                    |
| `PolicyProvider` unavailable      | 503  | `ERR_PROVIDER_DOWN`  | toast + fallback "try again" button      |

Per FR-010, all errors carry the standard envelope with `correlation_id`.

---

## 2. Discovery-to-Policy Generator (FR-049 surface 2)

### UI flow — one-click policy from a flagged event

Also known as **the Wiz pattern wedge** — this is the differentiator selling
motion (per `.specify/memory/research_round2_outcomes.md` §2). Non-developers
don't know what policies to write in the abstract; they know what policies
they need when Recurse flags a concrete denial.

**Entry point**: the Audit Plane UI's event detail panel, for any event with
`policy_decision: DENY` and no matching ALLOW rule.

**Flow**:
1. Policy author browses recent denials in the Audit Plane.
2. Clicks the flagged event. Event detail shows the full `principal.kind` +
   `principal.subject` + `action` + `resource` + `context` that Cedar saw.
3. Author clicks **"Auto-generate Cedar policy"**.
4. Client POSTs `/v1/governance/policy/propose-from-event` with the `event_id`.
5. System inspects the event's IdentityContext + action shape and generates a
   candidate Cedar policy that would have ALLOWed it, along with scope-suggestion
   alternatives (tenant-scope, principal-group-scope, resource-pattern-scope).
6. Proposed policy auto-populates the Playground editor (§1).
7. Author reviews, tightens scope (typically: narrow a `principal == User::"x"`
   to `principal in Group::"HR-ServiceAccounts"`), re-simulates against the
   original event + related historical events, runs Blast-Radius (§3), and
   publishes.

### Honest framing

The generated policy is a **proposal**, not an automatic deployment. The system
makes the policy-author's job easier by providing a working starting point from
a real denial; it does not bypass human review. The sales motion: "unknown
behavior flagged + proposal offered in one click" — this is what flips
skeptics-from-OPA-experiences into buyers.

### API contract — `/v1/governance/policy/propose-from-event`

**Method**: `POST`
**Plane**: Governance Plane
**Auth**: Governance-Plane auth.
**Idempotency**: not required (pure read against Audit Plane + deterministic
policy generation; re-calling returns the same proposal).
**Rate limit class**: Governance, per-tenant.
**Streaming**: `sync`.
**Owning OTP application**: `recurse_gateway` (calls into `PolicyProvider`).

**Request body** (by event ID):
```json
{
  "event_id": "evt_01HX8Q..."
}
```

**Request body** (inline event — used when the event isn't yet persisted):
```json
{
  "inline_event": {
    "principal": {
      "kind": "service_account",
      "issuer": "spiffe://corp/ns/hr/sa/hr-bot",
      "subject": "hr-bot-service-account"
    },
    "action": "write_record",
    "resource": "snowflake://HR.SALARIES",
    "context": {
      "tenant": "corp",
      "acting_for_human": true
    }
  }
}
```

**Response body** (HTTP 200):
```json
{
  "proposed_policy": "permit(\n  principal == User::\"hr-bot-service-account\",\n  action == Action::\"write_record\",\n  resource in Resource::\"snowflake://HR.SALARIES\"\n) when { context.business_justification != null };",
  "scope_suggestions": [
    "tenant-scope",
    "principal-group-scope",
    "resource-pattern-scope"
  ]
}
```

**Scope suggestions** are hints the UI surfaces as "tighten the proposal"
options. The initial proposal uses the narrowest equality (exact principal,
exact resource); the suggestions flip equality into membership/pattern:
- `tenant-scope` → `resource` widens to `resource in Tenant::"corp"`
- `principal-group-scope` → `principal` widens to `principal in Group::"..."`
- `resource-pattern-scope` → `resource` widens to a wildcarded namespace

The UI presents these as one-click refinements that re-populate the editor;
the author picks one (or writes their own tighter form).

**Backend**: `PolicyProvider.propose_from_event/2`.

### Error modes

| Condition                             | HTTP | Error code              |
|---------------------------------------|------|-------------------------|
| Event ID not found                    | 404  | `ERR_EVENT_NOT_FOUND`   |
| Event not eligible (was already ALLOW)| 409  | `ERR_EVENT_NOT_DENIAL`  |
| Proposal engine unavailable           | 503  | `ERR_PROVIDER_DOWN`     |

---

## 3. Blast-Radius Simulation (FR-049 surface 3)

### UI flow — "what would this policy have done last month?"

Refines PRD §4.3's blast-radius capability. For any draft policy in the
Playground editor, the author clicks **"Run blast-radius sim against last N days"**
and the system replays historical attestations against the candidate policy,
reporting divergences.

**Flow**:
1. Author drafts a policy in the Playground (typically following the
   Discovery-to-Policy flow, §2).
2. Author picks a historical window from a dropdown: 1 day / 7 days / 30 days /
   90 days.
3. Author clicks **"Run blast-radius"**.
4. Client POSTs `/v1/governance/policy/blast-radius` with the candidate policy
   and window.
5. Backend streams historical attestations from the Audit Plane through the
   candidate policy, counting divergences from the actual (at-the-time)
   decision.
6. Response summarizes: how many runs would have been blocked, how many
   distinct agents affected, and an exemplar sample of divergent events.
7. Author reviews. If the blast radius is larger than intended, tightens the
   policy (narrower principal scope, additional `when` guards) and re-runs.

### No state mutation

This surface is read-only with respect to production Cedar evaluation. It
does NOT publish a bundle. Historical attestations are not modified; the
replay runs against an in-memory copy against the candidate policy.

### Phase-1 latency behavior

For Phase-1, blast-radius MAY be synchronous-with-deadline:
- Request carries an implicit deadline (60s recommended; configurable per
  tenant).
- If replay exceeds the deadline, the response returns a partial sample
  (`partial: true` flag) plus an estimated total from the sampled prefix.
- Async-with-job-id is a **Phase-2 extension**. For Phase-2, the API gains a
  `202 Accepted` path returning `{job_id, polling_url}` with a corresponding
  `GET /v1/governance/policy/blast-radius/jobs/{job_id}` endpoint.

Rationale: Phase-1 Managed SaaS history volumes are well within synchronous
budget for typical policy authors (cohort of ~10 AppSec engineers per tenant,
cohort-size of tens to low-hundreds of agents). Customers with higher scale
land in the Phase-2 async window, which ships with the general backpressure
work.

### API contract — `/v1/governance/policy/blast-radius`

**Method**: `POST`
**Plane**: Governance Plane
**Auth**: Governance-Plane auth.
**Idempotency**: not required (read-only; repeatable).
**Rate limit class**: Governance, per-tenant (low limit — historical replay is
expensive; 10/hour/tenant recommended).
**Streaming**: `sync` in Phase-1; reserved for `sse` if future work wants
progress events.
**Owning OTP application**: `recurse_gateway` (calls `PolicyProvider`; provider
reads from `LedgerProvider` + Audit Plane).

**Request body**:
```json
{
  "candidate_policy": "permit(\n  principal in Group::\"HR-ServiceAccounts\",\n  action == Action::\"write_record\",\n  resource in Resource::\"snowflake://HR.SALARIES\"\n) when { context.business_justification != null };",
  "historical_window_seconds": 2592000
}
```

`historical_window_seconds` must be positive; max value is tier-configured (Phase-1
default 90 days = 7776000s).

**Response body** (HTTP 200):
```json
{
  "impacted_runs": 452,
  "impacted_agents": 8,
  "sample_divergences": [
    {
      "run_id": "run_01HX...",
      "original_decision": "deny",
      "candidate_decision": "allow",
      "principal": "User::\"hr-bot-service-account\"",
      "action": "Action::\"write_record\"",
      "resource": "Resource::\"snowflake://HR.SALARIES\""
    }
  ],
  "partial": false
}
```

When `partial: true` (deadline hit), the response includes an
`estimated_total_runs` field with a sampled extrapolation.

**Backend**: `PolicyProvider.blast_radius/4` (candidate_policy,
historical_window_seconds, identity_context) per the behaviour at
`contracts/provider_interfaces/policy_provider.ex`.

### Error modes

| Condition                               | HTTP | Error code                  |
|-----------------------------------------|------|-----------------------------|
| Window exceeds tier max                 | 400  | `ERR_WINDOW_TOO_LARGE`      |
| Candidate policy parse error            | 400  | `ERR_POLICY_SYNTAX`         |
| Rate limit exceeded (per-tenant)        | 429  | `ERR_RATE_LIMITED`          |
| Audit Plane / Ledger unavailable        | 503  | `ERR_PROVIDER_DOWN`         |

---

## Phase-2 deferrals (explicit)

Per FR-049 and `.specify/memory/research_round2_outcomes.md`:

1. **Visual policy builder** — dropdown-based Cedar construction, à la AWS IAM
   Visual Editor. Not in v1.0. Phase-1 ships with starter templates + raw
   editor + Discovery-to-Policy + Blast-Radius as the authoring toolkit.
2. **OPA format support** — nice-to-have. Ship if trivial; defer if not. Neither
   blocks Phase-1 release.
3. **Intent-aware JIT token minting** — FR-051 was deleted in v6.1. When
   intent classification ships in Phase-2, `PolicyProvider` will gain
   intent-related callbacks at that time, not pre-allocated now.
4. **Async blast-radius job API** — Phase-1 is synchronous-with-deadline;
   Phase-2 adds `202 Accepted + job_id` polling for large windows.

---

## Cross-references

- Starter templates: `apps/recurse_shared/priv/policy_templates/README.md`
- Worked walkthrough: `policy_author_ux_examples/wiz_pattern_walkthrough.md` (SC-019)
- Bundle distribution: `policy_bundle_contract.md` (Deliverable K)
- Provider Interface: `contracts/provider_interfaces/policy_provider.ex`
- Cedar pin: `apps/recurse_shared/priv/test_fixtures/cedar_stability/`
- OpenAPI entries for the three endpoints: added under **T085** (held on the
  main thread pending T049's full `openapi.yaml` enumeration).
