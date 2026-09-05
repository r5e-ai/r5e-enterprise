# Contract: Audit Agent Day-1 Tool Vocabulary

**Feature**: F004 | **Spec**: FR-037 (Q2 clarification) | **Glossary**: Audit Agent, Day-1 Tool Vocabulary, Agent Tool Call

This contract defines the six tools the **Audit Agent** can call on F004 launch. The vocabulary is a **closed set** for F004 — adding a seventh tool is a constitutional-amendment-class change requiring (a) a new Cedar action in `cedar_entity_schema_extensions.md`, (b) a new `event_kind` sub-variant, (c) property-test surface coverage, (d) glossary entry. This discipline is what enforces the "everything attestable" guarantee at the audit-agent layer.

Each tool is implemented as one Elixir module under `apps/recurse_gateway/lib/recurse_gateway/admin/audit_agent/tools/<name>.ex`. The agent runtime (`runtime.ex`) dispatches by tool name, gates each call through Cedar (using the per-tool action), invokes the module, and emits the per-tool attested event before returning the result to the caller.

---

## Common shape

**Cedar action namespace**: `Recurse::Action::"AuditAgentTool<PascalCaseName>"` — e.g., `AuditAgentToolQueryReceipts`, `AuditAgentToolFetchReceiptDetail`.

**Event kind namespace**: `:ui_chat_skill_invoked_<snake_case_name>` — e.g., `:ui_chat_skill_invoked_query_receipts`, `:ui_chat_skill_invoked_explain_denial`.

**Module shape**:

```elixir
defmodule Recurse.Gateway.Admin.AuditAgent.Tools.QueryReceipts do
  @behaviour Recurse.Gateway.Admin.AuditAgent.Tool

  @impl true
  def name, do: "query_receipts"

  @impl true
  def cedar_action, do: ~s|Recurse::Action::"AuditAgentToolQueryReceipts"|

  @impl true
  def event_kind, do: :ui_chat_skill_invoked_query_receipts

  @impl true
  def input_schema, do: @input_schema_json

  @impl true
  def output_schema, do: @output_schema_json

  @impl true
  def call(input, ctx), do: ...
end
```

**Per-call lifecycle** (in `runtime.ex`):

1. Receive `(tool_name, input_json, conversation_ctx)` from the agent.
2. Validate `input_json` against the tool's `input_schema` (Draft 2020-12) — invalid input fails synchronously with a structured error, no Cedar call, no receipt emitted (input validation is a precondition, not an authorization decision).
3. Run Cedar evaluation: `(principal, cedar_action, resource_kind=AuditEndpoint, ctx)`. Deny → emit `:policy_denied` receipt + return error to caller.
4. Invoke the tool module's `call/2`.
5. Emit the per-tool `event_kind` receipt with `signed_predicate.tool_name`, `signed_predicate.input_hash`, `signed_predicate.output_hash`, `signed_predicate.attested_run_ids` (run_ids referenced by the tool, if any).
6. Return `{output, attested_run_id}` to the agent runtime, which renders the call inline in the chat drawer (per FR-037).

**Cost guardrails (LLM-calling tools only)**: tools that invoke the F002 `LLMProvider` are bounded at **≤2K input tokens, ≤1K output tokens** per call. The runtime tracks per-conversation cumulative token spend; the conversation-level cap is **≤30K tokens** combined (reset per new conversation). A tool call that would exceed the cap fails with `error: "agent_token_budget_exceeded"` and the chat surface displays a "conversation token budget reached" advisory. Operators can adjust both limits via tier-config (`console.audit_agent.per_call_*_tokens`, `console.audit_agent.per_conversation_*_tokens`).

**Rate limits**: per-principal-subject, sliding-window: 60 tool calls/minute combined across all six tools (default). Configurable via `console.audit_agent.rate_limit_per_minute`.

---

## Tool 1: `query_receipts`

**Purpose**: faceted query over the audit log; agent-callable equivalent of the dashboard's structured query bar.

**Cedar action**: `Recurse::Action::"AuditAgentToolQueryReceipts"`.

**Required roles**: `tenant_auditor`, `platform_operator` (caller MUST be either).

**event_kind**: `:ui_chat_skill_invoked_query_receipts`.

**Cost**: zero LLM tokens (DB-only). Rate-limit slot: 1.

**Input schema** (Draft 2020-12):

```json
{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "filters": {
      "type": "object",
      "properties": {
        "event_kind": {"type": "array", "items": {"type": "string"}},
        "policy_decision": {"type": "string", "enum": ["allow", "deny"]},
        "principal_subject": {"type": "string"},
        "tool_name": {"type": "string"},
        "since": {"type": "string", "format": "date-time"},
        "until": {"type": "string", "format": "date-time"}
      }
    },
    "limit": {"type": "integer", "minimum": 1, "maximum": 100, "default": 20}
  }
}
```

**Output schema**:

```json
{
  "type": "object",
  "required": ["receipts", "total_match_count_estimate"],
  "properties": {
    "receipts": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["run_id", "event_kind", "policy_decision", "timestamp", "principal_subject", "summary"],
        "properties": {
          "run_id": {"type": "string", "format": "uuid"},
          "event_kind": {"type": "string"},
          "policy_decision": {"type": "string"},
          "timestamp": {"type": "string", "format": "date-time"},
          "principal_subject": {"type": "string"},
          "summary": {"type": "string", "maxLength": 200}
        }
      }
    },
    "total_match_count_estimate": {"type": "integer"}
  }
}
```

---

## Tool 2: `fetch_receipt_detail`

**Purpose**: returns the full receipt detail for a single `run_id`.

**Cedar action**: `Recurse::Action::"AuditAgentToolFetchReceiptDetail"`.

**Required roles**: `tenant_auditor`, `platform_operator`.

**event_kind**: `:ui_chat_skill_invoked_fetch_receipt_detail`.

**Cost**: zero LLM tokens.

**Input schema**:

```json
{
  "type": "object",
  "additionalProperties": false,
  "required": ["run_id"],
  "properties": {"run_id": {"type": "string", "format": "uuid"}}
}
```

**Output schema**: equivalent to F002's `GET /v1/audit/receipts/{run_id}` response — references `https://.../v1/schemas/attestation.json`.

---

## Tool 3: `explain_denial`

**Purpose**: natural-language explanation of why a deny fired for a given receipt — which policy + line + condition tripped, in plain English.

**Cedar action**: `Recurse::Action::"AuditAgentToolExplainDenial"`.

**Required roles**: `tenant_auditor`, `platform_operator`.

**event_kind**: `:ui_chat_skill_invoked_explain_denial`.

**Cost**: **calls F002 `LLMProvider`**. Bounded at ≤2K input tokens (the receipt + matched policy text + Cedar reasoning trace), ≤1K output tokens. Per-call. Rate-limit slot: 1.

**Implementation outline**:
1. Fetch receipt by `run_id`.
2. Fetch the matched Cedar policy + the line range cited in `attestation.signed_predicate.matched_policy`.
3. Build a structured prompt: `{receipt_summary, principal_attrs, policy_source, cedar_eval_reasoning}`.
4. Call `LLMProvider.complete/1` with a system prompt instructing the model to produce a 100–300 word plain-English explanation citing specific policy lines.
5. Return the explanation + a `referenced_policy_lines` array.

**Input schema**:

```json
{
  "type": "object",
  "additionalProperties": false,
  "required": ["run_id"],
  "properties": {"run_id": {"type": "string", "format": "uuid"}}
}
```

**Output schema**:

```json
{
  "type": "object",
  "required": ["explanation", "referenced_policy_lines", "model", "tokens_in", "tokens_out"],
  "properties": {
    "explanation": {"type": "string"},
    "referenced_policy_lines": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["policy_id", "line_start", "line_end", "snippet"],
        "properties": {
          "policy_id": {"type": "string"},
          "line_start": {"type": "integer"},
          "line_end": {"type": "integer"},
          "snippet": {"type": "string"}
        }
      }
    },
    "model": {"type": "string"},
    "tokens_in": {"type": "integer"},
    "tokens_out": {"type": "integer"}
  }
}
```

**Retention note**: per Q3, the full input/output of LLM-calling tools is recorded in `chat_messages.tool_calls` JSONB (subject to `console.retention.chat_history_days`); the attested receipt's `signed_predicate` carries only hashes (subject to F002 audit retention). This split honors Principle IV (no PII in the ledger).

---

## Tool 4: `find_similar_receipts`

**Purpose**: returns a cluster of receipts whose `(principal, action, resource)` shape matches the input receipt's shape.

**Cedar action**: `Recurse::Action::"AuditAgentToolFindSimilarReceipts"`.

**Required roles**: `tenant_auditor`, `platform_operator`.

**event_kind**: `:ui_chat_skill_invoked_find_similar_receipts`.

**Cost**: zero LLM tokens (pure SQL similarity).

**Input schema**:

```json
{
  "type": "object",
  "additionalProperties": false,
  "required": ["run_id"],
  "properties": {
    "run_id": {"type": "string", "format": "uuid"},
    "limit": {"type": "integer", "minimum": 1, "maximum": 50, "default": 10},
    "since": {"type": "string", "format": "date-time"}
  }
}
```

**Output schema**:

```json
{
  "type": "object",
  "required": ["seed_run_id", "similar_receipts", "match_dimensions"],
  "properties": {
    "seed_run_id": {"type": "string", "format": "uuid"},
    "match_dimensions": {
      "type": "array",
      "items": {"type": "string", "enum": ["principal_subject", "event_kind", "resource_kind", "tool_name"]}
    },
    "similar_receipts": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["run_id", "timestamp", "summary", "match_score"],
        "properties": {
          "run_id": {"type": "string", "format": "uuid"},
          "timestamp": {"type": "string", "format": "date-time"},
          "summary": {"type": "string"},
          "match_score": {"type": "number", "minimum": 0, "maximum": 1}
        }
      }
    }
  }
}
```

---

## Tool 5: `simulate_policy_dryrun`

**Purpose**: agent-callable equivalent of `POST /v1/policy/simulate`.

**Cedar action**: `Recurse::Action::"AuditAgentToolSimulatePolicyDryrun"`.

**Required roles**: `tenant_auditor`, `platform_operator` — note auditors CAN simulate even though they cannot save drafts; simulation is read-only.

**event_kind**: `:ui_chat_skill_invoked_simulate_policy_dryrun`.

**Cost**: zero LLM tokens (Cedar NIF only).

**Input schema**: equivalent to `POST /v1/policy/simulate` request body (see `audit_api_extensions.md`); references `https://.../v1/schemas/policy_simulate_request.json`.

**Output schema**: equivalent to `POST /v1/policy/simulate` response; references `https://.../v1/schemas/policy_simulate_response.json`.

---

## Tool 6: `suggest_policy_pattern`

**Purpose**: returns one or more proposed Cedar policy rules informed by a receipt window, with Blast Radius previews. Agent-callable equivalent of the suggestions surface; supports `source: "heuristic"` for cheap/deterministic or `source: "llm"` for nuanced/expensive.

**Cedar action**: `Recurse::Action::"AuditAgentToolSuggestPolicyPattern"`.

**Required roles**: `platform_operator` only — auditors do not invoke pattern suggestion (write-adjacent capability).

**event_kind**: `:ui_chat_skill_invoked_suggest_policy_pattern`.

**Cost**: 
- `source: "heuristic"` → zero LLM tokens.
- `source: "llm"` → calls `LLMProvider`, ≤2K input tokens, ≤1K output tokens.

Rate-limit slot: 1 (heuristic) or 3 (LLM, weighted heavier).

**Implementation outline**:
1. Resolve the receipt window (default trailing 7 days for agent-callable; vs 30 for the cron suggestion engine).
2. If `source == "heuristic"`: run the five heuristic patterns (per `research.md` D3) over the window, return up to N suggestions.
3. If `source == "llm"`: build the curated window summary (counts, top patterns), call `LLMProvider` with the structured-output schema (per D4), return up to N suggestions.
4. For each suggestion, compute Blast Radius synchronously over the window (window is small enough that ≤10K-receipt sync threshold from D5 is met).
5. Return the suggestion array.

**Input schema**:

```json
{
  "type": "object",
  "additionalProperties": false,
  "required": ["source"],
  "properties": {
    "source": {"type": "string", "enum": ["heuristic", "llm"]},
    "window_days": {"type": "integer", "minimum": 1, "maximum": 30, "default": 7},
    "scope_hint": {
      "type": "object",
      "description": "Optional. Narrow the analysis window.",
      "properties": {
        "principal_subject": {"type": "string"},
        "tool_name": {"type": "string"}
      }
    },
    "limit": {"type": "integer", "minimum": 1, "maximum": 5, "default": 3}
  }
}
```

**Output schema**:

```json
{
  "type": "object",
  "required": ["suggestions", "source", "window_days"],
  "properties": {
    "source": {"type": "string"},
    "window_days": {"type": "integer"},
    "suggestions": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["pattern_summary", "proposed_cedar", "confidence", "blast_radius_preview"],
        "properties": {
          "pattern_summary": {"type": "string", "maxLength": 200},
          "proposed_cedar": {"type": "string", "maxLength": 1000},
          "confidence": {"type": "integer", "minimum": 0, "maximum": 100},
          "blast_radius_preview": {
            "$ref": "https://gateway.example.com/v1/schemas/blast_radius_summary.json"
          }
        }
      }
    }
  }
}
```

---

## Failure modes (across all tools)

| Failure | Caller-visible response | Receipt emitted? |
|---|---|---|
| Input fails JSON Schema validation | Sync error: `{error: "invalid_input", details: [...]}` | NO (precondition failure) |
| Cedar denies | flat error envelope: `{error: "ERR_FORBIDDEN", attested_run_id: "<deny-receipt>"}` | YES (`:policy_denied`) |
| LLM provider unavailable / 5xx | flat error envelope: `{error: "ERR_UPSTREAM_UNAVAILABLE", ...}` | YES (per-tool event_kind with `outcome: "upstream_error"`) |
| Token budget exceeded | flat error envelope: `{error: "ERR_AGENT_TOKEN_BUDGET_EXCEEDED"}` | YES (per-tool event_kind with `outcome: "budget_exceeded"`) |
| Rate limit exceeded | flat error envelope: `{error: "ERR_RATE_LIMITED", retry_after: <secs>}` + 429 | NO (rate-limit is a frontline guard, not an authorization decision) |
| Tool implementation crash | flat error envelope: `{error: "ERR_INTERNAL", correlation_id: "..."}` + 500 | YES (per-tool event_kind with `outcome: "crash"`) |

> **Envelope note** — F001-nested envelope retired in MR !31; canonical
> shape is now flat per `priv/schemas/error_envelope.json` (issue #30 /
> Task L). Earlier revisions of this contract used "F001 envelope" as the
> label for what is now the flat shape with `ERR_*` codes built by
> `Recurse.Gateway.AuditPlane.ErrorEnvelope.build/3`.

---

## Property-test surface (per `property_test_surface_catalog_f004.md`)

For each of the six tools, a contract test:

1. Generates a valid input matching the input schema.
2. Calls the tool through the runtime.
3. Asserts (a) output validates against the output schema, (b) exactly one receipt of the expected `event_kind` is committed, (c) the receipt's `signed_predicate.tool_name` matches.

For the two LLM-calling tools (`explain_denial`, `suggest_policy_pattern[source=llm]`), additional tests use a Mox-stubbed `LLMProvider` to verify token-budget enforcement (an upstream that returns a 3K-token output is truncated and the budget-exceeded path fires correctly).

---

## Out of scope (Day-2+)

- Tool versioning. F004 ships v1 of each tool; v2 = breaking changes = new tool name (`query_receipts_v2`) + glossary update + Cedar action.
- Streaming tool outputs. The chat surface handles streaming via SSE for the **agent's text response**; tool outputs are returned atomically.
- Operator-defined tools. The vocabulary is closed; future expansion goes through the constitutional-amendment process described above.
- Tool-call composition (one tool calling another). The agent runtime dispatches one tool per turn; multi-tool flows happen through multiple agent turns.
