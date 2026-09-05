# Contract: LlmCallAttestation + ToolUseDeniedAttestation

**Module**: `Recurse.Gateway.LlmProxy.AttestationEmitter`
**Owner phase**: Phase 5
**Consumed by**: existing audit infrastructure (recurse-verify, audit console "LLM Calls" view)

## Purpose

Sign exactly one DSSE attestation per LLM call carrying full call metadata + per-tool-intent decisions. Additionally emit one `:tool_use_denied` predicate per denied intent (referenced from the parent).

## API

```elixir
@spec emit_call_attestation(
  call_state :: %{
    tenant_id: String.t(),
    principal_id: String.t(),
    session_id: String.t(),
    started_at: DateTime.t(),
    completed_at: DateTime.t(),
    model: String.t(),
    provider: String.t(),
    upstream_host: String.t(),
    transport: :wss | :https_sse,
    api_format: String.t(),
    request_path: String.t(),
    prompt_hash: binary(),
    response_hash: binary(),
    prompt_token_count: integer(),
    completion_token_count: integer(),
    reasoning_token_count: integer() | nil,
    cedar_bundle_hash: binary(),
    upstream_status_code: integer(),
    error_kind: atom() | nil,
    intents: [%{
      call_id: String.t(),
      tool_name: String.t(),
      tool_args_hash: binary(),
      decision: :allow | :deny,
      cedar_rule_id: String.t() | nil,
      deny_reason: String.t() | nil
    }],
    latency_ms: integer(),
    added_latency_ms: integer()
  }
) :: {:ok, run_id :: binary()}
```

Emits:
1. One `:llm_call_attested` predicate (signed via existing DSSE+KMS path)
2. One `:tool_use_denied` predicate per intent with `decision == :deny` (each referencing the parent via `parent_llm_call_run_id`)
3. One `LlmCallRecord` Postgres row + N `ToolUseIntentRecord` rows (one per intent)

## Attestation predicate shapes

### LlmCallAttestation

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "predicateType": "https://recurse.r5e.io/llm-call/v1",
  "subject": [{
    "name": "<principal-id>",
    "digest": {"sha256": "<principal-canonical-hash>"}
  }],
  "predicate": {
    "tenant_id": "...",
    "session_id": "...",
    "started_at": "...",
    "completed_at": "...",
    "model": "gpt-5-codex",
    "provider": "openai_chatgpt",
    "upstream_host": "chatgpt.com",
    "transport": "wss",
    "api_format": "openai_responses",
    "request_path": "/backend-api/codex/responses",
    "prompt_hash": "<sha256-hex>",
    "response_hash": "<sha256-hex>",
    "prompt_token_count": 1234,
    "completion_token_count": 567,
    "reasoning_token_count": 89,
    "cedar_bundle_hash": "<sha256-hex>",
    "tool_use_intents": [
      {"call_id":"call_abc","tool_name":"shell","tool_args_hash":"<sha256>","decision":"deny","cedar_rule_id":"rule_no_destructive","deny_reason":"..."},
      {"call_id":"call_def","tool_name":"edit","tool_args_hash":"<sha256>","decision":"allow"}
    ],
    "decision_summary": "1 allow, 1 deny",
    "upstream_status_code": 200,
    "error_kind": null,
    "latency_ms": 4523,
    "added_latency_ms": 87
  }
}
```

### ToolUseDeniedAttestation

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "predicateType": "https://recurse.r5e.io/tool-use-denied/v1",
  "subject": [{
    "name": "<principal-id>",
    "digest": {"sha256": "<principal-canonical-hash>"}
  }],
  "predicate": {
    "parent_llm_call_run_id": "<run_id-binary-id>",
    "tenant_id": "...",
    "tool_name": "shell",
    "tool_args_hash": "<sha256-hex>",
    "tool_args_size_bytes": 247,
    "cedar_rule_id": "rule_no_destructive",
    "deny_reason": "Tool call 'shell' blocked: command pattern matched 'rm -rf'.",
    "model": "gpt-5-codex",
    "extracted_at": "..."
  }
}
```

## Lockstep migration (Phase 5)

⚠️ Constitution Principle VII — three files MUST land in ONE MR:

1. `apps/recurse_providers/priv/repo/migrations/20260507000004_event_kinds_llm_call_attested_and_tool_use_denied.exs` — drops existing CHECK on `attestations.event_kind`, adds new with `:llm_call_attested` and `:tool_use_denied` as NOT VALID, then VALIDATE in same migration (per !119/!152's pattern)

2. `apps/recurse_shared/lib/recurse_shared/attestation/signed_predicate.ex` — extend `@event_kinds` list

3. `apps/recurse_gateway/lib/recurse_gateway/admin/browser_auth/ui_receipts.ex` — extend `@allowed_event_kinds` + `ui_event_kind` type

Before editing: invoke `consolidation-check` skill.

## Invariants

- **I-001**: Exactly ONE `:llm_call_attested` per LLM call (request → final response chunk). Verified via property test.
- **I-002**: Number of `:tool_use_denied` predicates equals number of `:deny` intents in the parent.
- **I-003**: All intents' `tool_args_hash` and the call's `prompt_hash` / `response_hash` are SHA-256 of canonical JSON (per Constitution Principle IV).
- **I-004**: Attestation emission is the LAST step before connection close — if emission fails, the call's connection is not closed cleanly (signals the failure to the client).

## Test contracts

- **CT-001**: Single allow-only call → 1 `:llm_call_attested`, 0 `:tool_use_denied`
- **CT-002**: Call with 2 allow + 3 deny → 1 `:llm_call_attested`, 3 `:tool_use_denied`
- **CT-003**: Failed call (upstream 500) → 1 `:llm_call_attested` with `error_kind: "upstream_5xx"`, 0 `:tool_use_denied`
- **CT-004**: Predicate canonical form is JCS-stable (same input → byte-identical output)
- **CT-005**: recurse-verify CLI verifies the predicate end-to-end against the customer's KMS key

## Property tests

- **PT-001**: 1 call = 1 `:llm_call_attested` invariant under fuzz with N concurrent calls
- **PT-002**: N denies = N `:tool_use_denied` predicates (cardinality match)

## Dependencies

- Existing DSSE+KMS signing path (per F002)
- Existing Postgres-Merkle ledger (or Trillian in connected-prod)
- Existing recurse-verify CLI (extended to recognize new event_kinds)
