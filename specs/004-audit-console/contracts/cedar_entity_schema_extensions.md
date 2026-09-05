# Contract: Cedar Entity Schema Extensions (F004)

**Feature**: F004 | **Spec**: FR-005, FR-006 | **Extends**: F002 `cedar_entity_schema.cedarschema.json`

This contract defines the additions F004 makes to the F002 Cedar Entity Schema: new actions for every UI capability and audit-agent tool, the role-to-action allowlist enforced by Cedar, and the additional principal-attribute requirements that the audit console flow depends on.

**Canonical names**: every action declared in this contract MUST appear in the
canonical action / `event_kind` / lifecycle matrix at `data-model.md` §0
verbatim. If this document and the matrix disagree, the matrix wins; fix this
document.

---

## New actions

The F002 schema declared four actions: `ChatCompletion`, `ReadReceipts`, `ExportEvidence`, `ReadPayload`. F004 adds the following:

### Browser session lifecycle

- `Recurse::Action::"LoginSession"` — performed on every successful sign-in / sign-out / idle-timeout / absolute-timeout (one Cedar evaluation per browser-session lifecycle event). Gated to confirm the principal has a console role at all (i.e., `recurse_role ∈ {tenant_auditor, platform_operator}`); `caller` role is denied.

### Dashboard / read surfaces

- `Recurse::Action::"DashboardQuery"` — used by `GET /v1/audit/sessions/{session_id}`, `GET /admin/live-tail` (WebSocket upgrade), and the Dashboard's structured query bar. The auditor's read-only audit lens.

### Policy authoring

- `Recurse::Action::"PolicySimulate"` — `POST /v1/policy/simulate`.
- `Recurse::Action::"PolicyReplay"` — `POST /v1/policy/replay/{run_id}`. Note: replay is read-only ("how would current policy decide?") and is allowed for auditors.
- `Recurse::Action::"PolicyDraftCreate"` — `POST /v1/policy/drafts`, `POST /v1/policy/drafts/from-receipt`.
- `Recurse::Action::"PolicyDraftEdit"` — `PATCH /v1/policy/drafts/{id}`.
- `Recurse::Action::"PolicyDraftArchive"` — `DELETE /v1/policy/drafts/{id}`.
- `Recurse::Action::"PolicyDraftDryRun"` — `POST /v1/policy/drafts/{id}/dry-run` (Blast Radius compute).

### Suggestions

- `Recurse::Action::"PolicySuggestionGenerate"` — emitted by the Oban-driven heuristic + LLM runners on each cycle (the principal in this case is the system service account; per FR-007 a system principal exists for autonomous activity).
- `Recurse::Action::"PolicySuggestionView"` — `GET /v1/policy/suggestions/{id}` (operator opens a suggestion in the UI). Distinct from the list query, which is a generic `DashboardQuery`.
- `Recurse::Action::"PolicySuggestionAdopt"` — `POST /v1/policy/suggestions/{id}/adopt`.
- `Recurse::Action::"PolicySuggestionDismiss"` — `POST /v1/policy/suggestions/{id}/dismiss`.
- `Recurse::Action::"PolicySuggestionRefresh"` — `POST /v1/policy/suggestions/refresh`.

### Audit Agent (chat drawer)

- `Recurse::Action::"ChatDrawerQuery"` — gates `POST /v1/chat/messages`, `GET /v1/chat/conversations`, `GET /v1/chat/conversations/{id}`. The general "is this principal allowed to use the chat drawer at all?" check.

### Audit Agent tools (six)

- `Recurse::Action::"AuditAgentToolQueryReceipts"`
- `Recurse::Action::"AuditAgentToolFetchReceiptDetail"`
- `Recurse::Action::"AuditAgentToolExplainDenial"`
- `Recurse::Action::"AuditAgentToolFindSimilarReceipts"`
- `Recurse::Action::"AuditAgentToolSimulatePolicyDryrun"`
- `Recurse::Action::"AuditAgentToolSuggestPolicyPattern"`

Per `audit_agent_tools.md`, each tool is gated by its own action so role-based allow/deny can differ per tool (e.g., `suggest_policy_pattern` requires `platform_operator`).

---

## Role-to-action allowlist

The Cedar policy bundle (`apps/recurse_gateway/priv/cedar/platform_roles.cedar`) is extended with `permit` rules realizing this matrix:

| Action | `tenant_auditor` | `platform_operator` | `caller` | `system` |
|---|---|---|---|---|
| F002 `ChatCompletion` | ❌ | ❌ | ✅ | ❌ |
| F002 `ReadReceipts` | ✅ | ✅ | ❌ | ❌ |
| F002 `ReadPayload` | ✅ | ✅ | ❌ | ❌ |
| F002 `ExportEvidence` | ✅ | ✅ | ❌ | ❌ |
| `LoginSession` | ✅ | ✅ | ❌ | ❌ |
| `DashboardQuery` | ✅ | ✅ | ❌ | ❌ |
| `PolicySimulate` | ❌ | ✅ | ❌ | ❌ |
| `PolicyReplay` | ✅ | ✅ | ❌ | ❌ |
| `PolicyDraftCreate` | ❌ | ✅ | ❌ | ❌ |
| `PolicyDraftEdit` | ❌ | ✅ | ❌ | ❌ |
| `PolicyDraftArchive` | ❌ | ✅ | ❌ | ❌ |
| `PolicyDraftDryRun` | ❌ | ✅ | ❌ | ❌ |
| `PolicySuggestionGenerate` | ❌ | ❌ | ❌ | ✅ |
| `PolicySuggestionView` | ❌ | ✅ | ❌ | ❌ |
| `PolicySuggestionAdopt` | ❌ | ✅ | ❌ | ❌ |
| `PolicySuggestionDismiss` | ❌ | ✅ | ❌ | ❌ |
| `PolicySuggestionRefresh` | ❌ | ✅ | ❌ | ❌ |
| `ChatDrawerQuery` | ✅ | ✅ | ❌ | ❌ |
| `AuditAgentToolQueryReceipts` | ✅ | ✅ | ❌ | ❌ |
| `AuditAgentToolFetchReceiptDetail` | ✅ | ✅ | ❌ | ❌ |
| `AuditAgentToolExplainDenial` | ✅ | ✅ | ❌ | ❌ |
| `AuditAgentToolFindSimilarReceipts` | ✅ | ✅ | ❌ | ❌ |
| `AuditAgentToolSimulatePolicyDryrun` | ✅ | ✅ | ❌ | ❌ |
| `AuditAgentToolSuggestPolicyPattern` | ❌ | ✅ | ❌ | ❌ |

**`system` role**: internal, broker-minted only; never user-assignable. Used
exclusively by the Oban-driven suggestion engine for `PolicySuggestionGenerate`.
The role's permission surface is intentionally minimal so a leaked system
identity cannot enumerate other console capabilities.

**Caller**: explicitly denied access to ALL UI / audit-console actions. The `caller` role is the Data Plane consumer (LLM end-users); they have no console privileges. This is the most important boundary — preventing privilege creep of `caller` into audit surfaces.

**Audit-Agent role-deny granularity**: `tenant_auditor` is allowed all read-only / forensic tools; `platform_operator` adds the write-adjacent `suggest_policy_pattern` tool.

---

## New principal-attribute requirements

F004 requires every authenticated principal to carry:

- `principal.recurse_role: String` — REQUIRED. One of `platform_operator`, `tenant_auditor`, `caller`.
- `principal.tenant_id: String` — REQUIRED. The single-tenant ID this principal is authorized within. F004 is single-tenant per deployment, but the attribute is REQUIRED on every principal so that future federation/multi-tenancy doesn't have to retrofit the schema.

The F002 schema already declares `recurse_role` on all three principal types (`Principal::Human`, `Principal::ServiceAccount`, `Principal::Autonomous`). F004 extends each with `tenant_id`:

```json
{
  "Principal::Human": {
    "shape": {
      "type": "Record",
      "attributes": {
        "subject": {"type": "String", "required": true},
        "issuer": {"type": "String", "required": true},
        "display_name": {"type": "String", "required": false},
        "groups": {"type": "Set", "element": {"type": "String"}, "required": true},
        "recurse_role": {"type": "String", "required": true},
        "tenant_id": {"type": "String", "required": true, "$comment": "F004 addition; single-tenant per deployment in F004"}
      }
    }
  }
}
```

The same `tenant_id` attribute is added to `Principal::ServiceAccount` and `Principal::Autonomous`.

---

## Updated `cedar_entity_schema.cedarschema.json` shape

Below is the F004 version of the schema (additions marked with `$comment: "F004"`); the F002 version's existing actions (`ChatCompletion`, `ReadReceipts`, `ExportEvidence`, `ReadPayload`) are unchanged.

```json
{
  "$comment": "F004 extends F002 cedar_entity_schema; Cedar 4.9.1.",
  "Recurse": {
    "commonTypes": {
      "CorrelationContext": {
        "type": "Record",
        "attributes": {
          "tenant_id": {"type": "String", "required": true},
          "correlation_id": {"type": "String", "required": true},
          "timestamp": {"type": "Long", "required": true},
          "client_ip": {"type": "String", "required": true}
        }
      },
      "BrowserSessionContext": {
        "$comment": "F004",
        "type": "Record",
        "attributes": {
          "tenant_id": {"type": "String", "required": true},
          "correlation_id": {"type": "String", "required": true},
          "timestamp": {"type": "Long", "required": true},
          "client_ip": {"type": "String", "required": true},
          "browser_session_id": {"type": "String", "required": true},
          "user_agent": {"type": "String", "required": false}
        }
      }
    },
    "entityTypes": {
      "Principal::Human": {
        "shape": {
          "type": "Record",
          "attributes": {
            "subject": {"type": "String", "required": true},
            "issuer": {"type": "String", "required": true},
            "display_name": {"type": "String", "required": false},
            "groups": {"type": "Set", "element": {"type": "String"}, "required": true},
            "recurse_role": {"type": "String", "required": true},
            "tenant_id": {"type": "String", "required": true, "$comment": "F004"}
          }
        }
      },
      "Principal::ServiceAccount": {
        "shape": {
          "type": "Record",
          "attributes": {
            "subject": {"type": "String", "required": true},
            "issuer": {"type": "String", "required": true},
            "account_id": {"type": "String", "required": true},
            "scope": {"type": "Set", "element": {"type": "String"}, "required": true},
            "recurse_role": {"type": "String", "required": true},
            "tenant_id": {"type": "String", "required": true, "$comment": "F004"}
          }
        }
      },
      "Principal::Autonomous": {
        "shape": {
          "type": "Record",
          "attributes": {
            "spiffe_id": {"type": "String", "required": false},
            "subject": {"type": "String", "required": true},
            "recurse_role": {"type": "String", "required": true},
            "tenant_id": {"type": "String", "required": true, "$comment": "F004"}
          }
        }
      },
      "Resource::LLMEndpoint": {"shape": {"type": "Record", "attributes": {"model": {"type": "String", "required": true}, "provider": {"type": "String", "required": true}}}},
      "Resource::AuditEndpoint": {"shape": {"type": "Record", "attributes": {"endpoint": {"type": "String", "required": true}}}},
      "Resource::PayloadBroker": {"shape": {"type": "Record", "attributes": {"run_id": {"type": "String", "required": true}, "tenant_id": {"type": "String", "required": true}}}},
      "Resource::ConsoleSurface": {
        "$comment": "F004 — single virtual resource representing the audit console as a whole. Used by all UI / dashboard / chat / policy-* actions whose target is the console itself, not a specific receipt or payload.",
        "shape": {
          "type": "Record",
          "attributes": {
            "console_path": {"type": "String", "required": true, "$comment": "e.g., /admin/dashboard, /admin/policy-simulator"}
          }
        }
      }
    },
    "actions": {
      "Action::ChatCompletion": {"appliesTo": {"principalTypes": ["Principal::Human", "Principal::ServiceAccount", "Principal::Autonomous"], "resourceTypes": ["Resource::LLMEndpoint"], "context": {"type": "Record", "attributes": {"tenant_id": {"type": "String", "required": true}, "correlation_id": {"type": "String", "required": true}, "timestamp": {"type": "Long", "required": true}, "client_ip": {"type": "String", "required": true}, "streaming": {"type": "Boolean", "required": true}, "max_tokens": {"type": "Long", "required": false}, "model": {"type": "String", "required": true}}}}},
      "Action::ReadReceipts": {"appliesTo": {"principalTypes": ["Principal::Human", "Principal::ServiceAccount"], "resourceTypes": ["Resource::AuditEndpoint"], "context": {"type": "Record", "attributes": {"tenant_id": {"type": "String", "required": true}, "correlation_id": {"type": "String", "required": true}, "timestamp": {"type": "Long", "required": true}, "client_ip": {"type": "String", "required": true}}}}},
      "Action::ExportEvidence": {"appliesTo": {"principalTypes": ["Principal::Human", "Principal::ServiceAccount"], "resourceTypes": ["Resource::AuditEndpoint"], "context": {"type": "Record", "attributes": {"tenant_id": {"type": "String", "required": true}, "correlation_id": {"type": "String", "required": true}, "timestamp": {"type": "Long", "required": true}, "client_ip": {"type": "String", "required": true}, "run_ids": {"type": "Set", "element": {"type": "String"}, "required": true}}}}},
      "Action::ReadPayload": {"appliesTo": {"principalTypes": ["Principal::Human", "Principal::ServiceAccount"], "resourceTypes": ["Resource::PayloadBroker"], "context": {"type": "Record", "attributes": {"tenant_id": {"type": "String", "required": true}, "correlation_id": {"type": "String", "required": true}, "timestamp": {"type": "Long", "required": true}, "client_ip": {"type": "String", "required": true}, "run_id": {"type": "String", "required": true}}}}},

      "Action::LoginSession": {"$comment": "F004", "appliesTo": {"principalTypes": ["Principal::Human"], "resourceTypes": ["Resource::ConsoleSurface"], "context": {"type": "Record", "attributes": {"tenant_id": {"type": "String", "required": true}, "correlation_id": {"type": "String", "required": true}, "timestamp": {"type": "Long", "required": true}, "client_ip": {"type": "String", "required": true}, "browser_session_id": {"type": "String", "required": true}, "user_agent": {"type": "String", "required": false}}}}},
      "Action::DashboardQuery": {"$comment": "F004", "appliesTo": {"principalTypes": ["Principal::Human"], "resourceTypes": ["Resource::ConsoleSurface"], "context": {"type": "Record", "attributes": {"tenant_id": {"type": "String", "required": true}, "correlation_id": {"type": "String", "required": true}, "timestamp": {"type": "Long", "required": true}, "client_ip": {"type": "String", "required": true}, "browser_session_id": {"type": "String", "required": true}}}}},
      "Action::PolicySimulate": {"$comment": "F004", "appliesTo": {"principalTypes": ["Principal::Human"], "resourceTypes": ["Resource::ConsoleSurface"]}},
      "Action::PolicyReplay": {"$comment": "F004", "appliesTo": {"principalTypes": ["Principal::Human"], "resourceTypes": ["Resource::ConsoleSurface"]}},
      "Action::PolicyDraftCreate": {"$comment": "F004", "appliesTo": {"principalTypes": ["Principal::Human"], "resourceTypes": ["Resource::ConsoleSurface"]}},
      "Action::PolicyDraftEdit": {"$comment": "F004", "appliesTo": {"principalTypes": ["Principal::Human"], "resourceTypes": ["Resource::ConsoleSurface"]}},
      "Action::PolicyDraftArchive": {"$comment": "F004", "appliesTo": {"principalTypes": ["Principal::Human"], "resourceTypes": ["Resource::ConsoleSurface"]}},
      "Action::PolicyDraftDryRun": {"$comment": "F004", "appliesTo": {"principalTypes": ["Principal::Human"], "resourceTypes": ["Resource::ConsoleSurface"]}},
      "Action::PolicySuggestionGenerate": {"$comment": "F004; system principal only", "appliesTo": {"principalTypes": ["Principal::ServiceAccount", "Principal::Autonomous"], "resourceTypes": ["Resource::ConsoleSurface"]}},
      "Action::PolicySuggestionView": {"$comment": "F004", "appliesTo": {"principalTypes": ["Principal::Human"], "resourceTypes": ["Resource::ConsoleSurface"]}},
      "Action::PolicySuggestionAdopt": {"$comment": "F004", "appliesTo": {"principalTypes": ["Principal::Human"], "resourceTypes": ["Resource::ConsoleSurface"]}},
      "Action::PolicySuggestionDismiss": {"$comment": "F004", "appliesTo": {"principalTypes": ["Principal::Human"], "resourceTypes": ["Resource::ConsoleSurface"]}},
      "Action::PolicySuggestionRefresh": {"$comment": "F004", "appliesTo": {"principalTypes": ["Principal::Human"], "resourceTypes": ["Resource::ConsoleSurface"]}},
      "Action::ChatDrawerQuery": {"$comment": "F004", "appliesTo": {"principalTypes": ["Principal::Human"], "resourceTypes": ["Resource::ConsoleSurface"]}},
      "Action::AuditAgentToolQueryReceipts": {"$comment": "F004", "appliesTo": {"principalTypes": ["Principal::Human"], "resourceTypes": ["Resource::ConsoleSurface"]}},
      "Action::AuditAgentToolFetchReceiptDetail": {"$comment": "F004", "appliesTo": {"principalTypes": ["Principal::Human"], "resourceTypes": ["Resource::ConsoleSurface"]}},
      "Action::AuditAgentToolExplainDenial": {"$comment": "F004", "appliesTo": {"principalTypes": ["Principal::Human"], "resourceTypes": ["Resource::ConsoleSurface"]}},
      "Action::AuditAgentToolFindSimilarReceipts": {"$comment": "F004", "appliesTo": {"principalTypes": ["Principal::Human"], "resourceTypes": ["Resource::ConsoleSurface"]}},
      "Action::AuditAgentToolSimulatePolicyDryrun": {"$comment": "F004", "appliesTo": {"principalTypes": ["Principal::Human"], "resourceTypes": ["Resource::ConsoleSurface"]}},
      "Action::AuditAgentToolSuggestPolicyPattern": {"$comment": "F004", "appliesTo": {"principalTypes": ["Principal::Human"], "resourceTypes": ["Resource::ConsoleSurface"]}}
    }
  }
}
```

---

## Cedar policy bundle additions

The platform-roles bundle (`platform_roles.cedar`) uses **`principal.recurse_role` string attribute comparison** for role-based access — NOT a `Recurse::Role::"<name>"` entity type. Rationale: `recurse_role` is already a string claim on the broker-minted JWT (per F002 broker contract); treating it as a string attribute on the Principal entity avoids needing to declare and populate a Role entity type. Cedar's `==` on string attributes is the idiomatic match here for fixed-vocabulary roles.

```cedar
// Auditor permits
permit (
  principal,
  action in [
    Recurse::Action::"LoginSession",
    Recurse::Action::"DashboardQuery",
    Recurse::Action::"PolicyReplay",
    Recurse::Action::"ReadReceipts",
    Recurse::Action::"ReadPayload",
    Recurse::Action::"ExportEvidence",
    Recurse::Action::"ChatDrawerQuery",
    Recurse::Action::"AuditAgentToolQueryReceipts",
    Recurse::Action::"AuditAgentToolFetchReceiptDetail",
    Recurse::Action::"AuditAgentToolExplainDenial",
    Recurse::Action::"AuditAgentToolFindSimilarReceipts",
    Recurse::Action::"AuditAgentToolSimulatePolicyDryrun"
  ],
  resource
)
when { principal.recurse_role == "tenant_auditor" && principal.tenant_id == context.tenant_id };

// Operator permits — superset of auditor + write-adjacent actions
permit (
  principal,
  action in [
    Recurse::Action::"LoginSession",
    Recurse::Action::"DashboardQuery",
    Recurse::Action::"PolicyReplay",
    Recurse::Action::"ReadReceipts",
    Recurse::Action::"ReadPayload",
    Recurse::Action::"ExportEvidence",
    Recurse::Action::"ChatDrawerQuery",
    Recurse::Action::"AuditAgentToolQueryReceipts",
    Recurse::Action::"AuditAgentToolFetchReceiptDetail",
    Recurse::Action::"AuditAgentToolExplainDenial",
    Recurse::Action::"AuditAgentToolFindSimilarReceipts",
    Recurse::Action::"AuditAgentToolSimulatePolicyDryrun",
    Recurse::Action::"PolicySimulate",
    Recurse::Action::"PolicyDraftCreate",
    Recurse::Action::"PolicyDraftEdit",
    Recurse::Action::"PolicyDraftArchive",
    Recurse::Action::"PolicyDraftDryRun",
    Recurse::Action::"PolicySuggestionView",
    Recurse::Action::"PolicySuggestionAdopt",
    Recurse::Action::"PolicySuggestionDismiss",
    Recurse::Action::"PolicySuggestionRefresh",
    Recurse::Action::"AuditAgentToolSuggestPolicyPattern"
  ],
  resource
)
when { principal.recurse_role == "platform_operator" && principal.tenant_id == context.tenant_id };

// System principal for the suggestion engine (heuristic + LLM runners)
// system role is internally-minted, never user-facing; `recurse_role == "system"`
// claim is set only by the broker for trusted internal-actor JWTs (Oban worker
// service identity). NOT a user-assignable role.
permit (
  principal,
  action == Recurse::Action::"PolicySuggestionGenerate",
  resource
)
when { principal.recurse_role == "system" };
```

**Why string comparison instead of `principal in Recurse::Role::"<name>"`**: a Role entity type would require declaring `Recurse::Role` in the entity schema, populating a per-evaluation entity store with Role entities, and maintaining a `principal in role_entity` parent relationship. All of that just to encode three fixed string values (`tenant_auditor`, `platform_operator`, `system`). String-attribute comparison is simpler, faster, and equally expressive for fixed-vocabulary roles. If a future feature introduces hierarchical roles (e.g., `senior_operator` is-a `platform_operator`), revisit this decision.

---

## Property-test surface S′ (extends F002 Surface S)

For every `(role, action)` cell in the matrix, generate synthetic principal+context tuples and assert Cedar evaluation matches the table. **24 actions × 4 roles = 96 cells** (4 F002-reused actions + 20 F004 actions: 14 named F004 + 6 `AuditAgentTool*`; the explicit `system` column included). Running each at 100 iterations gives 9,600 evaluations per CI run — well within the F002 reference per-CI-run budget. **Contract correction (post-Wave-1C)**: an earlier draft of this contract miscounted 23/92 — the actual matrix table enumerates 24/96. Where the prose conflicts with the matrix, the matrix wins (per `data-model.md` §0's tie-breaker rule). The F004 action set is: 14 named (`LoginSession`, `DashboardQuery`, `PolicySimulate`, `PolicyReplay`, `PolicyDraftCreate`, `PolicyDraftEdit`, `PolicyDraftArchive`, `PolicyDraftDryRun`, `PolicySuggestionGenerate`, `PolicySuggestionView`, `PolicySuggestionAdopt`, `PolicySuggestionDismiss`, `PolicySuggestionRefresh`, `ChatDrawerQuery`) + 6 `AuditAgentTool*` (`QueryReceipts`, `FetchReceiptDetail`, `ExplainDenial`, `FindSimilarReceipts`, `SimulatePolicyDryrun`, `SuggestPolicyPattern`).

Plus: a dedicated test asserts the `tenant_id` attribute REQUIRED-ness — any principal missing `tenant_id` MUST fail Cedar evaluation regardless of action.

---

## Migration impact

The Cedar Entity Schema is loaded at Gateway boot. Adding new actions doesn't require migrating data; adding `tenant_id` to existing principal types DOES require backfilling: F002 attestations created before the F004 deploy carry a `signed_predicate.principal` JSON without `tenant_id`. The `BrowserSessionPlug` synthesizes `tenant_id` from the JWT `principal.tenant_id` claim on every request; for **historical receipts read for Blast Radius**, the principal entity is reconstructed with `tenant_id = receipt.tenant_id` (the receipt-level tenant_id is reliable). No data migration required.

---

## Out of scope (Day-2+)

- Multi-tenant principals (a single human across multiple tenants). F004 is single-tenant.
- Custom roles beyond the three (`tenant_auditor`, `platform_operator`, `caller`). Adding a fourth role = constitutional change.
- Action-level resource attributes (e.g., per-policy-draft access lists). Drafts are tenant-shared; per-draft ACLs deferred.
- Cedar schema dynamic reload at runtime. Schema changes require Gateway restart.
