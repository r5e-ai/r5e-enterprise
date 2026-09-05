# Contract: Payload Canonicalization for `payload_hash`

**Feature**: F002 | **Spec**: FR-018 | **Clarifications**: Session 2026-04-23 GAN round 1, "Q: Payload canonicalization under streaming"

This contract defines the exact bytes over which `payload_hash` is computed. It is the single most load-bearing hash in the system — auditors use it to tie a receipt to the specific bytes that flowed through the Gateway.

## The rule, in one paragraph

`payload_hash` in the Attestation Envelope's signed predicate is SHA-256 over the RFC 8785 JSON Canonicalization Scheme (JCS) encoding of the object:

```json
{"request": <canonicalized-request-json>, "response": <canonicalized-response-json>}
```

where `canonicalized-request-json` and `canonicalized-response-json` are themselves JCS-canonicalized JSON values. The detached payload stored in S3 at `payload_uri` is the same JCS-encoded bytes.

## Request canonicalization

The inbound OpenAI `chat.completion` request body (application/json), parsed as JSON, re-encoded via JCS:
- Members sorted by RFC 8785 key order (lex-ordered UCS code points).
- Numbers in shortest IEEE 754 round-trip form.
- Strings UTF-8; escape only RFC 8259-required chars.
- Whitespace-free.

Request field whitelist (scope-cut per FR-003): `model`, `messages` (text-only), `stream`, `max_tokens`, `temperature`, `top_p`, `n`, `stop`, `frequency_penalty`, `presence_penalty`, `user`, `seed`. Presence of `tools` / `tool_choice` / `functions` / `function_call` / `response_format` / image-or-audio content parts causes rejection at FR-005 layer before canonicalization — these fields MUST NEVER appear in `canonicalized-request-json`.

## Response canonicalization — sync (non-streaming)

The upstream OpenAI `chat.completion` response body, parsed as JSON, JCS-re-encoded.

OpenAI response field whitelist preserved as-is (pass-through): `id`, `object`, `created`, `model`, `choices[]` (with `index`, `message.role`, `message.content`, `message.refusal` if Recurse-injected denial, `finish_reason`, `logprobs`), `usage`, `system_fingerprint`.

Response HEADERS (separately passed through per FR-006) are NOT included in `payload_hash`.

## Response canonicalization — SSE streaming

**This is the most load-bearing rule.** Raw SSE chunks are NOT the bytes hashed. Instead, the Gateway reassembles the final `chat.completion` (non-streaming shape) JSON after stream close and hashes that.

### Reassembly algorithm

Given the stream of SSE events with `data: <json>\n\n` framing, where each `<json>` payload has shape `{"id": ..., "object": "chat.completion.chunk", "created": ..., "model": ..., "choices": [{"index": 0, "delta": {...}, "finish_reason": null | "stop" | ...}], "usage": null | {...}}`:

1. **Accumulate `choices[i].delta.content` across chunks**, preserving order. For a single-choice response (the common case — `n: 1`), concatenate all `delta.content` string values into `accumulated_content`.
2. **If `delta.role` ever appears**, set `message.role = delta.role` (typically `"assistant"` and only on the first chunk).
3. **If `delta.refusal` ever appears**, set `message.refusal = accumulated_refusal` (concatenated likewise).
4. **On the final chunk** (`finish_reason != null`):
   - Capture `choices[0].finish_reason` into the reassembled `choices[0].finish_reason`.
   - If the chunk carries a populated `usage` object, capture it; otherwise set `usage: null` (OpenAI inconsistency documented in research D3 open questions).
5. **Drop stream-internal framing**: `object: "chat.completion.chunk"` becomes `object: "chat.completion"`; all `delta` fields collapse into one `message` field per choice; SSE `data:`/`[DONE]` sentinels discarded.

### Reassembled shape

```json
{
  "id": "<from-any-chunk; first chunk's id>",
  "object": "chat.completion",
  "created": "<first-chunk's created>",
  "model": "<model>",
  "choices": [
    {
      "index": 0,
      "message": {
        "role": "assistant",
        "content": "<accumulated_content>",
        "refusal": "<accumulated_refusal or null>"
      },
      "finish_reason": "<final-chunk's finish_reason>"
    }
  ],
  "usage": <final-chunk.usage or null>
}
```

Then JCS-canonicalized.

### Why reassembled JSON instead of raw SSE bytes

- **Auditor semantics**: `payload_hash` answers "what completion did the agent actually see?" — which, after SSE reassembly on the client, is the concatenated `message.content`. Hashing raw chunks would not match what the agent consumed.
- **Stability across framing**: different upstream providers chunk differently (OpenAI may use `data:` with trailing newlines; others differ); a provider-neutral `LLMProvider` should produce identical `payload_hash` for the same completion regardless of how it streamed.
- **Stability across upstream client choice**: `Req` vs `Finch` vs raw `:httpc` differ in buffering; reassembled JSON is robust to any of these.
- **Audit usability**: `recurse-verify`'s Step 5 (`payload_hash` check) reads the detached payload, JCS-canonicalizes, SHA-256s, and compares — no knowledge of SSE framing required.

### Edge cases

- **Stream terminated early** (client disconnect + server sees `{:error, :closed}` per research D3): the attestation outcome is `:cancelled`; the detached payload is the partially-reassembled JSON as of the last fully-received chunk; `payload_hash` covers that partial. Honest: auditors see "cancelled" and understand the completion was incomplete.
- **Upstream error mid-stream** (OpenAI 5xx mid-SSE, rare): attestation outcome `:upstream_error`; detached payload captures whatever was reassembled before the error; `upstream_status_code` populated in outer container per FR-014.
- **Zero-content completion**: `accumulated_content = ""` — produces a valid canonical JSON with `message.content: ""`. Hash is deterministic.

## JCS canonicalization library

Elixir: use `jason` + a thin JCS wrapper in `apps/recurse_shared/lib/recurse_shared/json_canonicalization.ex`. F001 already ships this (used for principal canonicalization per F001 FR-026). F002 reuses it.

## Property-test surface Q

`contracts/property_test_surface_catalog_f002.md` Surface Q: given a random (request, response) pair, JCS encoding is deterministic + hashing is deterministic. Reassembly property test: given a random OpenAI-chunk sequence with known final content, the reassembler produces the expected reassembled JSON; canonicalization of that JSON yields a stable hash across chunk-granularity permutations that preserve order.
