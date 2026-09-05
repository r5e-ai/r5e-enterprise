# Contract: Denial Injector (Streaming Response Rewrite)

**Module**: `Recurse.Gateway.LlmProxy.DenialInjector` + per-API impls
**Owner phase**: Phase 4
**Consumed by**: Phase 2 streaming proxy (returns `forward_directive`s based on Cedar decisions)

## Purpose

When Cedar denies a tool_use intent, rewrite the response stream so the client receives a structured denial in the upstream's expected format. Agent loop sees the denial as model output (text content), continues naturally without breaking.

## API

```elixir
@spec inject_denial(
  api_format :: :openai_responses | :openai_chat_completions | :anthropic_messages | :google_gemini,
  intent :: ToolUseIntent.t(),
  deny :: %{rule_id: String.t(), reason: String.t(), suggested_alternative: String.t() | nil},
  template :: String.t(),
  opts :: keyword()
) :: [synthetic_event :: binary()]
```

`opts` keyword:
- `:output_index` (default 0) — preserve the suppressed item's `output_index` in the synthesized message events.
- `:audit_context` — map carrying audit-substrate identifiers used by the radical-transparency template grammar (R5E-102 follow-on). Optional fields:
  - `:tenant_id` (String.t)
  - `:principal_id` / `:principal_kind` (String.t)
  - `:session_id` (String.t)
  - `:cedar_bundle_hash` (32-byte binary; auto-rendered as full hex via `{cedar_bundle_hash_hex}` and 12-char short-hex via `{cedar_bundle_hash_short}`)
  - `:appeal_uri` / `:appeal_contact` — read from `LlmProviderConfig.metadata["appeal_uri"]` + `["appeal_contact"]` (R5E-104). Empty strings are treated as nil so the optional-clause grammar drops the appeal line cleanly.
  - `:policy_source_uri` — reserved for R5E-105; currently always nil.

Returns a list of synthetic events (SSE frames or WS frames) that replace the original tool_use event sequence.

## Per-API behaviors

### OpenAI Responses API (Codex CLI)

When a `function_call` item with `call_id = "call_abc"` is denied:

1. Suppress the original `response.output_item.added` (item.type=function_call, item.call_id=call_abc)
2. Suppress all subsequent `response.function_call.arguments.delta` events for that call_id
3. Suppress the `response.function_call.completed` event for that call_id
4. Inject:

```
{"type":"response.output_item.added","output_index":<original_index>,"item":{"type":"message","role":"assistant","id":"msg_synthetic_<uuid>","status":"in_progress","content":[]}}

{"type":"response.output_text.delta","output_index":<original_index>,"item_id":"msg_synthetic_<uuid>","delta":"Tool call 'shell' blocked by org policy <rule_id>: <reason>. Try alternative: <alt-or-blank>."}

{"type":"response.output_item.completed","output_index":<original_index>,"item":{"type":"message","role":"assistant","id":"msg_synthetic_<uuid>","status":"completed","content":[{"type":"output_text","text":"Tool call 'shell' blocked..."}]}}
```

Codex agent loop interprets this as the model deciding to send a text message. Continues iteration naturally.

### OpenAI Chat Completions

When a `delta.tool_calls[i]` is denied:
1. Suppress all `delta.tool_calls` chunks for that index
2. Inject `delta.content` chunks with the denial text

### Anthropic Messages

When a `content_block_start` of type `tool_use` is denied:
1. Suppress the `content_block_start` + subsequent `input_json_delta` events for that index
2. Inject `content_block_start` of type `text` + `content_block_delta` with `text_delta` carrying the denial + `content_block_stop`

### Google Gemini

When a `functionCall` part is denied:
1. Suppress that part from the chunk's `parts[]`
2. Inject a `text` part with the denial

## Denial template

Default template — radical-transparency-by-default per R5E-102 + R5E-104 (customer can override per-tenant in `LlmProviderConfig.metadata.denial_template`):

```
Tool call '{tool_name}' (call_id: {call_id}) was blocked by org policy.

- Rule: {rule_id}
- Reason: {reason}
- Policy bundle: {cedar_bundle_hash_short}
- Tenant: {tenant_id}
- Principal: {principal_id} ({principal_kind})
- Session: {session_id}
{? - Try alternative: {suggested_alternative}}
{? - To appeal: ping {appeal_contact} ({appeal_uri}) and cite the rule_id + bundle hash above.}

To appeal, cite the rule_id and bundle hash above with your project context.
```

Surfaces every load-bearing identifier the agent (or the human appealing the denial) needs to navigate to the audit substrate from the message itself. The anti-pattern this replaces is the "your call was blocked, contact your administrator" message — opaque, unactionable, escalation-hostile.

Variables:
- `{tool_name}` — the denied tool's name
- `{call_id}` — the upstream-provided tool-call correlation token
- `{rule_id}` — Cedar rule that fired
- `{reason}` — Cedar's reason field
- `{suggested_alternative}` — optional alternative tool the agent could try (Cedar provides this if the rule's `advice` field is set)
- `{tenant_id}` — Recurse tenant the call was scoped to
- `{principal_id}` / `{principal_kind}` — who-we-acted-for (from inbound JWT)
- `{session_id}` — proxy-issued session correlation token
- `{cedar_bundle_hash_short}` — 12-char hex prefix of the policy bundle's canonical hash
- `{cedar_bundle_hash_hex}` — full 64-char hex; useful for grep against attestation rows
- `{appeal_uri}` / `{appeal_contact}` — per-tenant escalation channel from `LlmProviderConfig.metadata` (R5E-104). The appeal-line clause `{? - To appeal: ping {appeal_contact} ({appeal_uri}) ...}` renders only when BOTH are bound; either nil/empty drops the whole line so there's no half-empty `ping  ()` artifact.
- `{policy_source_uri}` — reserved per R5E-105 (auto-derived from `R5E_CEDAR_BUNDLE_REGISTRY` env vars); currently nil.

Optional-clause grammar `{? body }` includes the body only when EVERY `{var}` it references resolves to a non-nil, non-empty string (R5E-104 generalization — Phase 6 originally gated only on `suggested_alternative`). A clause body with no variable references is vacuously included. Multiple optional-clause blocks per template render independently, so one tenant's missing appeal config doesn't block another tenant's `suggested_alternative` line and vice versa.

## Invariants

- **I-001**: Denied tool_use NEVER appears in forwarded response stream (verified via property test PT-001 in streaming_proxy contract)
- **I-002**: Allowed tool_use ALWAYS appears byte-identical to upstream (verified via property test PT-002)
- **I-003**: Synthetic injected events are valid in their target API format — client SDK does NOT error on them (verified via parser-roundtrip test: parse the synthetic events with the upstream's official client SDK and assert no errors)
- **I-004**: For multi-event tool_use sequences (e.g., Anthropic's content_block_start + N deltas + stop), ALL events are suppressed atomically — no half-suppressed sequences

## Test contracts

- **CT-001**: Each API's denial-injected response parses as valid in that API's official SDK (use openai-python, anthropic-sdk, google-generativeai for round-trip test)
- **CT-002**: Codex CLI fed the synthetic Responses API denial: agent loop displays the denial text and continues iteration (integration test against simulated Codex traffic)
- **CT-003**: Multiple parallel denials in one response: all denied tool_uses replaced; allowed ones forwarded; output stream remains parseable

## Property tests

- **PT-001**: Denied tool_use NEVER reaches client (assertion across random response generation)
- **PT-002**: Allowed tool_use ALWAYS reaches client byte-identical (byte-equality assertion in non-deny case)
- **PT-003**: Synthetic events are syntactically valid for the target API format (random rule + random reason → valid output)

## Dependencies

- Per-API parsers from Phase 1 (to know which events to suppress)
- Cedar gate from Phase 3 (provides the deny decision + reason)
- No new Hex deps
