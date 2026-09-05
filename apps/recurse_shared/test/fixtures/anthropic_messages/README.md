# Anthropic Messages fixtures (captured from Claude Code)

Captured 2026-09-02 for Spike S0 of `specs/012-compose-quickstart/plan.md`
(see `specs/012-compose-quickstart/spike-s0.md` for the verdicts and analysis).

| Field | Value |
| --- | --- |
| Client | Claude Code `2.1.223` (`claude --version`), `User-Agent: claude-cli/2.1.223 (external, claude-desktop, agent-sdk/0.3.255)` |
| SDK | `X-Stainless-Package-Version: 0.94.0`, runtime node v26.3.0, arm64 / MacOS |
| Auth | claude.ai OAuth login (Max subscription); credential sent as `Authorization: Bearer sk-ant-oat01-…` |
| Model | `claude-haiku-4-5-20251001` (`--model haiku`) |
| Invocation | `ANTHROPIC_BASE_URL=http://127.0.0.1:4443 claude -p --model haiku --strict-mcp-config --output-format json [--allowedTools …] < prompt` |
| Stub | Python stdlib reverse proxy on `127.0.0.1:4443` forwarding to `https://api.anthropic.com`; every request/response written to disk as it streamed |

## How they were captured

The stub logged the request line + headers (credential values redacted to the first
8 chars + length), forwarded the request verbatim (all headers except `Host` and
`Accept-Encoding`) and streamed the response back while appending the raw bytes to a
capture file. `Accept-Encoding` was dropped so the upstream answered with identity
encoding; with it, `api.anthropic.com` returns `Content-Encoding: gzip` (SSE) or `br`
(JSON), which is an important fact for the gateway (see spike doc).

Each `claude -p` session produced four requests in this order: `HEAD /api/hello`
(connectivity probe, no auth header), `POST /v1/messages?beta=true` with
`source=generate_session_title` (small, `stream: true`, `output_config` JSON schema, no
tools), `POST /v1/messages?beta=true` with `source=sdk` (the real turn: full system
prompt, 29 tool definitions, `stream: true`, thinking enabled), and after the turn a
`POST /v1/messages?beta=true` with `source=side_query` that has **no `stream` key**
(non-streaming, `application/json` response) classifying whether the agent is blocked.
Every one of them carried the OAuth bearer.

## Files

| Fixture | What it is | Capture |
| --- | --- | --- |
| `text_only.request.json` / `.sse` | Prompt "Reply with exactly the single word PONG". Thinking block (empty, signature only) then one text block, `stop_reason: end_turn`. | req024 |
| `single_tool_use_bash.request.json` / `.sse` / `.request.headers.txt` / `.response.headers.txt` | One `Bash` `tool_use` (`ls -la`), `stop_reason: tool_use`. **The request keeps all 29 tool definitions in full** (~118 KB) and is the canonical "what Claude Code sends" reference. Header dumps are redacted. | req004 |
| `single_tool_use_bash_followup.request.json` / `.sse` | The next request of the same session: assistant `thinking` + `tool_use` echoed back, `user` message with a `tool_result` (`is_error: false`, `cache_control` on it). Response is text, `end_turn`. | req005 |
| `parallel_tool_use.request.json` / `.sse` | Two `tool_use` blocks in one message: `Read` (index 1) then `Bash` (index 2). | req009 |
| `tool_use_write_read.request.json` / `.sse` | Two `tool_use` blocks: `Write` (index 1) then `Read` (index 2). There is no pure Read-only capture; the Read block shape is identical here and in `parallel_tool_use`. | req014 |
| `hook_denied_followup.request.json` / `.sse` | Request after a `PreToolUse` HTTP hook denied the Bash call: the `tool_result` has `is_error: true` and its `content` is the hook's `permissionDecisionReason` verbatim. | req020 |
| `session_title.request.json` / `.sse` | The `generate_session_title` side request: `temperature: 1`, `thinking: disabled`, `output_config.format.type = json_schema`, no tools. | req003 |
| `non_streaming_state_summary.request.json` / `.response.json` | The only non-streaming request Claude Code makes: no `stream` field; response is a plain Messages JSON object, `Content-Type: application/json`. | req006 |
| `error_not_found.request.json` / `.response.json` / `*.headers.txt` | `--model claude-bogus-model-1`: HTTP 404, body `{"type":"error","error":{"type":"not_found_error","message":"model: …"},"request_id":…}`. Claude Code retried this request 4 times in ~2 s. No streaming `error` event was observed in any session. | req028 |

## Sanitization applied (by `scratchpad/sanitize.py`, not committed)

- No credential ever appears in a body. In header dumps `Authorization` is shown as the
  stub logged it: first 8 chars (`Bearer s`) + length.
- `metadata.user_id` (a JSON string) has `device_id` → 64 zeros and `account_uuid` → the
  zero UUID. `session_id` is kept. Response-header `anthropic-organization-id` /
  `anthropic-workspace-id` → zero UUID / `wrkspc_REDACTED`.
- Thinking `signature` values → `"REDACTED_SIGNATURE"` (the blob base64-embeds the org id).
- Email → `user@example.com`; the real home directory → `/home/user`; the scratchpad path →
  `/home/user/spike`; the `ls -la` owner column → `user`.
- Large machine-specific prompt blocks are elided to a short head plus
  `[elided N chars]`: Claude Code's system prompt (28.5 KB, `system[2]`), the
  `<system-reminder>` blocks listing agent types and skills. The billing line in
  `system[0]` and the one-line `system[1]` are intact.
- In every request except `single_tool_use_bash.request.json`, tool descriptions other
  than `Bash`/`Read`/`Write`/`Edit` are truncated to 120 chars. Names and
  `input_schema` are intact everywhere.
- SSE: event order, count, `index`, ids, `usage`, `stop_reason`, `ping`, whitespace
  padding inside `data:` lines are all untouched. The only structural edit: for
  `tool_use` blocks whose input contained the machine path (`parallel_tool_use`,
  `tool_use_write_read`), the `input_json_delta` fragments were re-split after the path
  replacement (same number of fragments, near-equal lengths). `single_tool_use_bash.sse`
  and `text_only.sse` fragments are byte-faithful.
