# Spike S0 — Claude Code against a stub gateway

**Date**: 2026-09-02. **Client**: Claude Code 2.1.223 (`claude --version`), logged in via
claude.ai OAuth (`claude auth status`: `authMethod: claude.ai`, `apiProvider: firstParty`,
`subscriptionType: max`). **Model**: `claude-haiku-4-5-20251001`. **Fixtures**:
`apps/recurse_shared/test/fixtures/anthropic_messages/` (README there lists each file).

## Verdicts

| # | Question | Verdict |
| --- | --- | --- |
| U1 | Does an OAuth (claude.ai) login still send its bearer to a custom `ANTHROPIC_BASE_URL`? | **Yes.** `Authorization: Bearer sk-ant-oat01-…` (115 chars) on every `POST /v1/messages`. No `x-api-key`. |
| U2 | Is plain `http://127.0.0.1:PORT` accepted as `ANTHROPIC_BASE_URL`? | **Yes.** No warning, no TLS requirement, no error. The HTTPS/self-signed fallback was not needed and was not exercised. |
| U3 | Does hook stdin include `transcript_path`? | **Yes**, for both `type: "command"` (stdin) and `type: "http"` (POST body, identical JSON). `type: "http"` deny JSON is honoured. |

## Setup

Stub: Python 3.14 stdlib (`http.server` + `http.client`) on `127.0.0.1:4443`; logs request
line + headers with `authorization`/`x-api-key`/`cookie` values cut to 8 chars + length;
forwards everything except `Host` (and, after the first run, `Accept-Encoding`, see
"Surprises") to `https://api.anthropic.com`; streams the body back chunk-by-chunk while
appending raw bytes to a per-request file. Hook listener: Python `http.server` on
`127.0.0.1:4499` that logs the POST and answers the deny JSON.

Sessions (all from a throwaway directory in the scratchpad, prompt on stdin because
`--allowedTools` is variadic and swallows a trailing positional prompt):

```
ANTHROPIC_BASE_URL=http://127.0.0.1:4443 claude -p --model haiku --strict-mcp-config --output-format json
  (a) text only          — no extra flags
  (b) one Bash call      — --allowedTools 'Bash(ls:*)'
  (c) parallel calls     — --allowedTools 'Bash(pwd:*)' Read      -> Read + Bash in one message
  (d) Write then Read    — --permission-mode acceptEdits --allowedTools Read Write -> Write + Read in one message
  (hook) as (b) from a dir whose .claude/settings.json has a PreToolUse command hook + http hook
  (err) as (a) with --model claude-bogus-model-1
  (proxy) as (a) with HTTPS_PROXY/HTTP_PROXY=http://127.0.0.1:4488 NO_PROXY=127.0.0.1,localhost
```

Nothing prompted interactively; `-p` ran unattended every time. `--strict-mcp-config` was
used only to keep this machine's many MCP servers from starting.

## U1 evidence — redacted request headers of the main turn (req004)

```
POST /v1/messages?beta=true HTTP/1.1
Accept: application/json
Authorization: Bearer s…<redacted len=115>
Content-Type: application/json
User-Agent: claude-cli/2.1.223 (external, claude-desktop, agent-sdk/0.3.255)
X-Claude-Code-Session-Id: ecdcbccc-ecb4-40f4-bbb1-db3ad3b16bca
X-Stainless-Arch: arm64
X-Stainless-Lang: js
X-Stainless-OS: MacOS
X-Stainless-Package-Version: 0.94.0
X-Stainless-Retry-Count: 0
X-Stainless-Runtime: node
X-Stainless-Runtime-Version: v26.3.0
X-Stainless-Timeout: 900
anthropic-beta: oauth-2025-04-20,interleaved-thinking-2025-05-14,thinking-token-count-2026-05-13,context-management-2025-06-27,prompt-caching-scope-2026-01-05,claude-code-20250219,advisor-tool-2026-03-01,extended-cache-ttl-2025-04-11
anthropic-dangerous-direct-browser-access: true
anthropic-version: 2023-06-01
x-app: cli
Connection: keep-alive
Host: 127.0.0.1:4443
Accept-Encoding: gzip, deflate, br, zstd
Content-Length: 155844
```

- Credential header: `Authorization` (bearer, `sk-ant-oat01-` prefix, 115 chars). No
  `x-api-key`, no cookie, no `ANTHROPIC_AUTH_TOKEN` involvement — nothing was set besides
  `ANTHROPIC_BASE_URL`.
- Other auth-ish/identifying headers: `anthropic-beta` (includes `oauth-2025-04-20`; the
  set varies per request kind, see below), `anthropic-version: 2023-06-01`, `x-app: cli`,
  `anthropic-dangerous-direct-browser-access: true`, `X-Claude-Code-Session-Id`,
  `User-Agent: claude-cli/…`.
- Also in the **body**: `metadata.user_id` is a JSON *string*
  `{"device_id":"<64 hex>","account_uuid":"<uuid>","session_id":"<uuid>"}`, and
  `system[0]` is the text `x-anthropic-billing-header: cc_version=2.1.223.<hash>; cc_entrypoint=claude-desktop;`.
- Response headers name the account: `anthropic-organization-id`, `anthropic-workspace-id`,
  plus `anthropic-ratelimit-unified-*` (5h/7d utilisation) and `request-id`.

## U2 evidence

Every session above ran over cleartext `http://127.0.0.1:4443`; the stub log shows
`Host: 127.0.0.1:4443` and Claude Code's `--output-format json` result was
`is_error: false`. The only base-URL-related debug line is
`[ToolSearch:optimistic] disabled: ANTHROPIC_BASE_URL=http://127.0.0.1:4443 is not a
first-party Anthropic host` (see Surprises). Not tested: HTTPS stub / `NODE_EXTRA_CA_CERTS`
(unnecessary).

Proxy environment caveat: with `HTTP_PROXY` set and no `NO_PROXY`, Claude Code sent the
base-URL request *through* the proxy as an absolute-URI `POST http://127.0.0.1:4443/v1/messages`
(the CONNECT-only logger answered 405 → `API Error: 405 status code (no body)`). With
`NO_PROXY=127.0.0.1,localhost` it went direct. README must say so for corporate-proxy users.

## U3 evidence — hook stdin (command hook, `cat > file`), identical JSON in the http POST

```json
{
  "session_id": "d345b5eb-4492-4286-990a-43092fd32b4e",
  "transcript_path": "/home/user/.claude/projects/-home-user-spike-hooktest/d345b5eb-4492-4286-990a-43092fd32b4e.jsonl",
  "cwd": "/home/user/spike/hooktest",
  "prompt_id": "c3199741-a8a9-483e-8b90-8017aefcfcfb",
  "permission_mode": "default",
  "hook_event_name": "PreToolUse",
  "tool_name": "Bash",
  "tool_input": { "command": "ls -la", "description": "List files in current directory" },
  "tool_use_id": "toolu_01RfNRJ9Q5gwiMdH9mfGuNWa"
}
```

Beyond the documented `{session_id, cwd, hook_event_name, tool_name, tool_input}` there are
`transcript_path`, `prompt_id`, `permission_mode`, `tool_use_id`. The http hook arrives as
`POST /hook` with `User-Agent: axios/1.15.2`, `Content-Type: application/json`,
`Accept-Encoding: gzip, compress, deflate, br`. Settings used:

```json
{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[
  {"type":"command","command":"cat > …/command_hook_stdin.json"},
  {"type":"http","url":"http://127.0.0.1:4499/hook"}]}]}}
```

Effect of the deny: the tool did not run; the `--output-format json` result carried
`permission_denials: [{tool_name, tool_use_id, tool_input}]`; the next model request
contained `{"type":"tool_result","tool_use_id":…,"is_error":true,"content":"denied by r5e
spike http hook listener"}` (fixture `hook_denied_followup.request.json`) and the model
repeated the reason verbatim to the user.

## Outbound hostnames (CONNECT-logging proxy, `HTTPS_PROXY` set, base URL excluded via `NO_PROXY`)

- `api.anthropic.com:443` — 7 CONNECTs per session **that bypass the base URL**. Debug log
  identifies one: `GET https://api.anthropic.com/v1/mcp_servers?limit=1000` (claude.ai
  connectors). The others are not named in the debug log (`[Bootstrap] Fetching`, GrowthBook
  flags, OAuth profile/usage are the likely ones; TLS was not intercepted).
- `http-intake.logs.us5.datadoghq.com:443` — telemetry, once per session.
- `127.0.0.1:4443` — model traffic only: `HEAD /api/hello`, then the `/v1/messages` calls.
- No `platform.claude.com` connection was seen (the token did not need refreshing).

Implication: the gateway sees **all model calls** but not account/telemetry chatter; a
network-level allow-list is not part of this design and the README should not claim one.

## Requests Claude Code makes per `-p` turn

| # | Path | `stream` | Purpose (debug `source=`) | Notes |
| --- | --- | --- | --- | --- |
| 1 | `HEAD /api/hello` | – | connectivity probe | `User-Agent: Bun/1.4.0`, **no auth header**; upstream answers 200 `{}`-ish JSON. |
| 2 | `POST /v1/messages?beta=true` | true | `generate_session_title` | ~2.3 KB, `temperature: 1`, `thinking: {type: disabled}`, `output_config.format = json_schema {title}`, no tools, `anthropic-beta` includes `structured-outputs-2025-12-15`. |
| 3 | `POST /v1/messages?beta=true` | true | `sdk` (the real turn) | ~156 KB: `system` 3 blocks (billing line / SDK line / 28.5 KB Claude Code prompt with `cache_control {ephemeral, ttl 1h}`), 29 tools, `thinking: {type: enabled, budget_tokens: 31999, display: "omitted"}`, `context_management.edits [{type: clear_thinking_20251015, keep: all}]`, `max_tokens: 32000`. |
| 4 | `POST /v1/messages?beta=true` | **absent** | `side_query` | ~18.6 KB, `max_tokens: 1024`, no tools; response `Content-Type: application/json`. Only non-streaming call observed. |

The `sdk` request repeats after each tool round with the assistant `thinking` +
`tool_use` blocks echoed and a `user` message of `tool_result`s (last one carries
`cache_control`). Tool definitions are `{name, description, input_schema}` with no
`cache_control` on them (the cache breakpoints are on `system[1]`, `system[2]`, and the
last user block).

## Streaming event sequence for a `tool_use` block (fixture `single_tool_use_bash.sse`)

```
message_start        {message:{id, model, role, content:[], stop_reason:null, usage:{input_tokens, cache_creation_input_tokens, cache_read_input_tokens, cache_creation:{ephemeral_5m_input_tokens, ephemeral_1h_input_tokens}, output_tokens, service_tier, inference_geo}}}
content_block_start  index=0 content_block:{type:"thinking", thinking:"", signature:""}
ping
content_block_delta  index=0 delta:{type:"thinking_delta", thinking:"", estimated_tokens:null}   (×1–2, always empty because display:"omitted")
content_block_delta  index=0 delta:{type:"signature_delta", signature:"<~600–900 base64 chars>"}
content_block_stop   index=0
content_block_start  index=1 content_block:{type:"tool_use", id:"toolu_…", name:"Bash", input:{}}
content_block_delta  index=1 delta:{type:"input_json_delta", partial_json:""}          (first fragment is always empty)
content_block_delta  index=1 delta:{type:"input_json_delta", partial_json:"{\"comm"}   (×N, 2–12 chars each, splits mid-key)
…
content_block_delta  index=1 delta:{type:"input_json_delta", partial_json:"irectory\"}"}
content_block_stop   index=1
message_delta        delta:{stop_reason:"tool_use", stop_sequence:null, stop_details:null} usage:{…, output_tokens, output_tokens_details:{thinking_tokens}, iterations:[…]} context_management:{applied_edits:[]}
message_stop
```

Parallel calls are simply more `content_block_start(tool_use)` … `content_block_stop`
groups at successive indices (1, 2, …) before a single `message_delta`. Text replies use
`content_block_start {type:"text", text:""}` + `text_delta`. `data:` lines carry trailing
whitespace padding of varying length after the JSON (anti-buffering); a parser must
`trim` before `JSON.decode`. `stop_reason` appears **only** in `message_delta.delta`
(it is `null` in `message_start`).

Bash tool input JSON, assembled: `{"command": "ls -la", "description": "List files in the
current directory"}`. `command` is the only required field; `description` is a
model-written summary, not an argument. Read: `{"file_path"}`; Write: `{"file_path",
"content"}` (absolute paths).

## Errors

- Bogus model → HTTP **404** with JSON `{"type":"error","error":{"type":"not_found_error",
  "message":"model: claude-bogus-model-1"},"request_id":"…"}`; Claude Code retried the
  same request 4 times within 2 s, then reported `api_error`. No streaming
  `event: error` frame was produced by any session, so there is no SSE error fixture; the
  documented shape is `event: error` / `data: {"type":"error","error":{…}}` and S4 should
  hand-write one if needed.

## Surprises

1. **Upstream compresses.** Forwarding `Accept-Encoding: gzip, deflate, br, zstd`
   unchanged makes `api.anthropic.com` return `Content-Encoding: gzip` for SSE and `br`
   for JSON. A parser that reads the stream must strip `Accept-Encoding` on the way out
   (what the stub does now) or decode. The existing OpenAI path should be checked for
   the same assumption.
2. **The bearer is an OAuth token with `oauth-2025-04-20` in `anthropic-beta`.** Replaying
   or issuing our own upstream calls with it is out of scope, but the gateway must forward
   `anthropic-beta` verbatim or the upstream rejects the OAuth credential.
3. **Not a first-party host ⇒ different client behaviour.** Debug log: `ToolSearch
   optimistic disabled … not a first-party Anthropic host. Set ENABLE_TOOL_SEARCH=true if
   your proxy forwards tool_…`. Consequence: all 29 tool definitions are sent in every
   request (~118 KB), no deferred tools. Fine for us; worth knowing for size budgeting.
4. **Three request kinds share the endpoint.** Session-title and side-query calls also
   hit `/v1/messages` with the same bearer; they have no tools. If every call becomes an
   `llm_call_attested` receipt, a one-prompt turn yields three receipts. Distinguish by
   absence of `tools` / presence of `output_config` / absence of `stream`, or accept it.
5. **`metadata.user_id` is a JSON-encoded string** carrying `device_id`, `account_uuid`,
   `session_id`. `session_id` also arrives as `X-Claude-Code-Session-Id`. This is the
   natural session key for receipts and for hook↔proxy correlation (hook JSON has the
   same `session_id`).
6. **Thinking is always on (`display: "omitted"`)**, so every response starts with an
   empty `thinking` block whose only payload is a `signature_delta`. The signature
   base64-embeds the org id; fixtures redact it.
7. **Prompt caching**: `cache_control {type: ephemeral, ttl: "1h"}` on `system[1]`,
   `system[2]` and the last user content block (and on the last `tool_result`);
   `anthropic-beta` carries `extended-cache-ttl-2025-04-11` and
   `prompt-caching-scope-2026-01-05`. Usage reports `cache_creation.ephemeral_1h_input_tokens`.
8. **`anthropic-beta` differs per request kind** (title request adds
   `structured-outputs-2025-12-15`; the sdk request adds `claude-code-20250219`,
   `advisor-tool-2026-03-01`, `extended-cache-ttl-2025-04-11`; side query drops
   `claude-code-20250219`). Forward as-is; do not normalise.
9. **`HEAD /api/hello`** goes to the base URL without auth before the first turn. The
   gateway must answer it (200 with any body, or just proxy it) or Claude Code may
   treat the endpoint as unreachable.
10. **Retries**: on the 404 the client retried 4× in 2 s with `X-Stainless-Retry-Count`
    incrementing. Denial injection must not return an HTTP error if it wants a single
    receipt.
11. `--allowedTools` is variadic; a positional prompt after it is eaten
    (`Input must be provided either through stdin or as a prompt argument`). Docs and
    `bin/r5e` examples should put the prompt on stdin or before the flags.

## Implications for S2 / S3 / S4

**S2 (default-upstream routing + Anthropic upstream row)**
- Route `HEAD /api/hello` and `POST /v1/messages` (with `?beta=true` query) for Host
  `127.0.0.1:4443` / `localhost:4443` to `api.anthropic.com`; rewrite `Host` only. Keep
  the query string.
- Forward `Authorization`, `anthropic-beta`, `anthropic-version`, `x-app`,
  `anthropic-dangerous-direct-browser-access`, `X-Stainless-*`, `X-Claude-Code-Session-Id`
  untouched. Drop or rewrite `Accept-Encoding` to `identity` when the stream will be
  parsed. Pass through response headers (rate-limit headers are read by the client for
  its `/usage` display).
- Credential handling: the OAuth bearer is what arrives; the `LlmProviderConfig` row for
  Anthropic needs no stored key in this mode — it is pass-through. Never log the
  `Authorization` value (the stub's 8-char + length redaction is a fine convention).
- Document `NO_PROXY=127.0.0.1,localhost` for users who have `HTTP_PROXY` set.

**S3 (PreToolUse hook endpoint + installer)**
- Hook body has `session_id`, `tool_use_id`, `tool_input`, `transcript_path`, `cwd`,
  `permission_mode`, `prompt_id`. Use `session_id` + `tool_use_id` as the receipt key;
  it is the same `toolu_…` id that appears in the SSE `content_block_start`, so the hook
  receipt and the in-stream `llm_call_attested` intent can be joined without dedupe
  heuristics (this confirms decision D2).
- The `type: "http"` hook works as documented; response body is the same
  `hookSpecificOutput` JSON as a command hook's stdout. Content-Type must be
  `application/json`. The client is axios; a plain 200 with the JSON is enough.
- `transcript_path` is present → a `Stop` hook feeding `Importers.ClaudeCodeSession` is
  viable (nice-to-have stands).
- Installer target: `.claude/settings.json` in the project (what the spike used) or
  `~/.claude/settings.json`; the hook `matcher` can be `"Bash"` or omitted for all tools.

**S4 (Anthropic Messages parser + denial injector)**
- Parser must handle: `ping` events; trailing whitespace after JSON in `data:` lines;
  `thinking` blocks with empty deltas and a `signature_delta`; `input_json_delta` whose
  first fragment is `""` and whose fragments split mid-token (accumulate until
  `content_block_stop`, then decode); multiple tool_use blocks at increasing `index`;
  `stop_reason` only in `message_delta`; `message_start.usage` vs
  `message_delta.usage` (the latter is authoritative for `output_tokens`); the
  non-streaming JSON response shape (`side_query`) which must also be attested or
  explicitly skipped.
- Denial injection point: the `tool_use` block is complete only at `content_block_stop`,
  and input is unknown until then. Two options: (a) buffer from
  `content_block_start(tool_use)` to its `content_block_stop`, evaluate Cedar, then either
  release the buffered events or replace the block with a `text` block carrying the
  denial and, if it was the only tool_use, rewrite `message_delta.stop_reason` to
  `end_turn`; (b) let the block through and rely on the S3 hook. Option (a) is what D2(b)
  wants; the parallel fixture shows a partial denial (deny index 1, allow index 2) must
  keep indices contiguous or re-index. Note `message_start.content` is `[]` and usage
  numbers need not be adjusted.
- Because Claude Code echoes assistant blocks back verbatim in the next request, an
  injected `text` block must be a valid content block (no `signature`), or the next turn
  fails upstream.
- Fixtures to test against: `text_only.sse`, `single_tool_use_bash.sse`,
  `parallel_tool_use.sse`, `tool_use_write_read.sse`, `hook_denied_followup.sse`,
  `non_streaming_state_summary.response.json`, `error_not_found.response.json`.
- `Content-Encoding`: either request identity upstream or add a gzip/brotli decode stage
  before the SSE splitter. Brotli is not in Erlang/OTP; strip `Accept-Encoding`.
- Receipt content: `model` from the request body and `message_start.message.model`;
  `usage` from `message_delta`; session from `X-Claude-Code-Session-Id` /
  `metadata.user_id.session_id`; tool intents from assembled `tool_use` inputs
  (`Bash.command`, `Read.file_path`, `Write.file_path`).

## Housekeeping

Stub, hook listener and CONNECT logger were stopped; the throwaway
`hooktest/.claude/settings.json` was removed; nothing under `~/.claude` was modified.
Raw captures stay in the session scratchpad only. The stub, listener and sanitizer
scripts are not committed (they are ~170 + 20 + 150 lines of Python; the plan's S2 replaces
them with product code).
