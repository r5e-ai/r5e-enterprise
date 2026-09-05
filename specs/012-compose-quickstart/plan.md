# Spec 012 — Compose Quickstart: r5e-enterprise for a stranger's machine

**Status**: plan v1, 2026-09-02. Not yet reviewed by Thomas.
**Workspace**: `r5e-enterprise.docker-compose` (jj workspace off `kmzmzksy`, which
already contains `port/fable-demo-delta`). `r5e-enterprise` itself is NOT touched.
**Bookmark**: `compose/quickstart`.
**Orchestration**: Fable designs and reviews; implementation slices go to subagents.
Reviews use the `local-gan` skill lenses (pedantry for technical claims, spirit for
principles).

---

## 1. Goal

Someone lands on the public repo, runs one command, points their own Claude Code at
it, and *sees* every LLM call and tool call become a signed receipt, sees a destructive
command get denied by Cedar policy that lives in a git repo they control, and can
export + verify evidence offline. No AWS, no IdP, no `/etc/hosts`, no TLS trust
changes for the Claude Code path.

fable-demo proved the flow on Thomas's Mac with Homebrew Postgres, an iex session,
hand-run scripts, and a MITM for Codex. This spec turns that into a portable stack.

### The user journey (this is the README's spine)

```
git clone <repo> && cd r5e-enterprise
cp .env.example .env                 # nothing to edit for the default flow
docker compose up --build            # postgres + gateway (+ policy-sync)
open http://localhost:4000/admin     # "Sign in (local dev)" — no IdP
./bin/r5e claude-code setup          # prints/exports ANTHROPIC_BASE_URL, installs the PreToolUse hook
claude                               # normal session; every call now lands in the ledger
> list the files here                # LLM_CALL receipt appears, tool allowed
> delete /tmp/scratch recursively    # POLICY_DENIED (red) receipt; Claude shows the denial and moves on
# edit policy in your git repo -> policy-sync pulls it -> new bundle hash on the dashboard
./bin/r5e evidence export --latest && ./bin/r5e evidence verify   # VERIFY: PASS, exit 0
```

## 2. What fable-demo is, and why it doesn't port as-is

| fable-demo today | Why it blocks a stranger | Replacement |
|---|---|---|
| Homebrew Postgres, `iex -S mix`, `FableDemo.setup!()` in the shell | Needs the Elixir/Rust toolchain and a human in iex | Prod release in a container; providers installed from env at boot |
| Dev providers (software ES256 signer, filesystem CAS) live in `scripts/fable_demo/demo.exs` | Script-only, not in the release | Promote to `Recurse.Providers.Impls.*` with env-registry shortnames |
| `dev_login_enabled?` set in `config/dev.exs` (compile-time, dev only) | Prod release has it off with no switch | Runtime env flag `R5E_DEV_LOGIN_ENABLED` |
| `/etc/hosts` + socat + two-tier PKI + `CODEX_CA_CERTIFICATE` | Root, macOS-specific, fragile | Not needed for Claude Code: `ANTHROPIC_BASE_URL`. Codex keeps the MITM as an appendix |
| Upstream routing by `Host` header (`chatgpt.com`) | With a base URL the Host is `localhost` | Default-upstream mode (D3) |
| Only an OpenAI-Responses parser + denial injector | Claude Code speaks Anthropic Messages | New parser + injector (S4) |
| Cedar bundle swapped by `swap-bundle.sh` / SIGHUP | No git, no cross-container signal | policy-sync sidecar + mtime polling (S5) |
| `docker-compose.yaml` wants AWS, WorkOS/Okta, a broker image that has no Dockerfile, tier-config files that don't exist | Has never run locally; asserts amd64 in the Dockerfile so it fails on Apple Silicon | New compose file; collapsed broker; arch-agnostic assert |

## 3. Facts established (verified in code/docs on 2026-09-02)

- Claude Code documents a gateway protocol: `ANTHROPIC_BASE_URL` routes model
  requests; `ANTHROPIC_AUTH_TOKEN` / `ANTHROPIC_API_KEY` are the credential vars;
  `ANTHROPIC_CUSTOM_HEADERS` exists. OAuth refresh goes to `platform.claude.com`
  directly and is NOT proxied (fine: we never wanted the auth path).
  Docs: code.claude.com/docs/en/llm-gateway-connect.md, llm-gateway-protocol.md,
  network-config.md.
- Claude Code hooks: `PreToolUse` receives `{session_id, cwd, hook_event_name,
  tool_name, tool_input}` and can deny with JSON
  `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny",
  "permissionDecisionReason":"..."}}`; the reason is shown to the model. Hooks may be
  `type: "http"` (POST to an endpoint) as well as `type: "command"`.
  The Bash tool's input field is `command`.
- Anthropic Messages streaming: `content_block_start{content_block:{type:"tool_use",
  id,name,input:{}}}` → N × `content_block_delta{delta:{type:"input_json_delta",
  partial_json}}` → `content_block_stop`. `message_delta` carries `stop_reason` and
  `usage`.
- Gateway: `R5E_LLM_PROXY_SCHEME=http` is already supported
  (`application.ex#llm_proxy_endpoint_children`). Routing is `UpstreamResolver.resolve
  (tenant_id, host_header)` → `LlmProviderConfig` row; `api_format` enum already has
  `:anthropic_messages`; `parser_for_format/1` in `streaming_proxy.ex` falls through to
  OpenaiResponses for everything; `DenialInjector.inject_denial/5` only has the
  `:openai_responses` clause; `denial/` has one impl.
- Cedar shape used by the gate: `principal` = `User::"<id>"`, `action ==
  Action::"invoke_tool"`, `resource == ToolUse::"<tool_name>"`, `context.tool_args`
  inlined when small (`cedar_tool_use_gate.ex:304`).
- Env provider registry (`config/env_provider_registry.ex`): required roles
  ledger/payload_broker/secrets; shortnames today `postgres_merkle`, `s3`, `aws_kms`,
  `openai`, `oci`, `filesystem` (policy). Tenant from `R5E_TENANT_ID`.
- Broker: `R5E_BROKER_MODE` defaults to `collapsed` (in-process); no broker container
  needed. Release `audit_console` bakes the SPA (`Dockerfile`), so no `pnpm dev`.
- `BundleLoader` reloads only on SIGHUP. `FilesystemPolicyProvider` is the source.
- Receipt kinds: `:llm_call_attested`, `:tool_use_denied` (`signed_predicate.ex`).
  There is no `:tool_use_allowed` kind; allowed intents ride inside the parent
  `llm_call_attested` predicate.

### Unverified — settled by Spike S0

- U1: a claude.ai-subscription (OAuth) login still sends its bearer token to a custom
  `ANTHROPIC_BASE_URL`. Docs only say a gateway credential var "takes precedence over a
  saved login". If false, README says "API key or `ANTHROPIC_AUTH_TOKEN`"; the design
  does not change.
- U2: plain `http://localhost:4443` is accepted as `ANTHROPIC_BASE_URL`. Expected yes
  (Node fetch). If no: serve HTTPS with the existing two-tier PKI script and
  `NODE_EXTRA_CA_CERTS` (documented in network-config.md).
- U3: hook stdin includes `transcript_path`. Nice-to-have for a `Stop` hook that feeds
  the existing `Importers.ClaudeCodeSession`; not on the critical path.

## 4. Decisions

**D1 — Claude Code is the primary target; Codex is an appendix.** Claude Code is
*designed* to be gatewayed (base URL + hooks are supported contracts). Codex requires
DNS override + TLS interception and its internal Responses-over-WS shapes have moved
three times. The README explains both honestly: the MITM exists because some clients
give you no other seam.

**D2 — Two enforcement layers for Claude Code, shipped in this order.**
- (a) `PreToolUse` HTTP hook → gateway decision endpoint → Cedar → deny with reason +
  `tool_use_denied` receipt. Small, robust, tool shape is stable. Lands first.
- (b) In-stream Anthropic Messages parser + denial injector. This is what produces
  `llm_call_attested` receipts for every call (model, usage, tool intents, decisions)
  and denies even if the hook is removed. Bigger; lands second.
Both fire on a denied call; the receipts must dedupe by `(session, tool_use id)` or the
hook must skip emitting when the proxy already denied. Decision: the hook always
evaluates and records; the proxy's in-stream denial suppresses the `tool_use` block, so
Claude never issues the tool call and the hook never fires for it. No dedupe needed.

**D3 — Default-upstream mode.** New env `R5E_LLM_PROXY_DEFAULT_UPSTREAM_HOST`
(default `api.anthropic.com`). In `ProxyRouter.dispatch_proxy/1`, when the request Host
is the gateway itself (`localhost`, `127.0.0.1`, the container name, or anything not
matching an `LlmProviderConfig`), resolve using the default upstream host instead and
rewrite the outbound `Host`. Existing Host-header routing is unchanged, so Codex MITM
keeps working. `BypassDnsResolver` stays; it is harmless without a hosts override.

**D4 — Local providers become first-class impls.** *(Signer algorithm: see §11 — ES256
default today so the existing verifier verifies; Ed25519 behind a flag; §10's Ed25519
default was reverted after the peer sync.)*
- `Recurse.Providers.Impls.LocalPemSecretsProvider` — shortname `local_pem`; ES256
  P-256 key at `R5E_LOCAL_SIGNING_KEY_PATH`; generated on first boot if absent
  (volume-persisted). Same algorithm family as the KMS signer, so `recurse-verify`
  works unchanged.
- `Recurse.Providers.Impls.FilesystemStorageProvider` — shortname `filesystem`;
  content-addressed under `R5E_CAS_ROOT` (volume).
Port from `scripts/fable_demo/demo.exs` (`DevSecretsProvider`, `DevFsStorage`) with
tests. `EnvProviderRegistry` gains both shortnames.

**D5 — Policy from git via a sidecar, not a new PolicyProvider.**
`policy-sync` container (alpine + git): clones `R5E_POLICY_GIT_URL` at
`R5E_POLICY_GIT_REF` (default `main`), every `R5E_POLICY_GIT_INTERVAL` (30s) pulls,
validates nothing itself, atomically copies `R5E_POLICY_GIT_PATH` (default
`policy/bundle.cedar`) to the shared volume. `BundleLoader` gains opt-in mtime polling
(`R5E_POLICY_BUNDLE_POLL_MS`) so no cross-container SIGHUP is needed. Reload failures
keep the last good bundle and surface on `/readyz` + a dashboard banner (existing
telemetry `[:recurse, :policy, :reload_failure]`).
When `R5E_POLICY_GIT_URL` is unset, compose bind-mounts `./policy/` from the checkout,
which ships sane defaults. A `policy-starter/` directory in the repo is the template
users copy into their own repo (README, `bundle.cedar`, schema pointer, a GitHub/GitLab
CI job that runs `cedar-canonical-hash` + syntax validation).

**D6 — Sane default policy.** `policy/bundle.cedar`: baseline permit; forbid
`ToolUse::"Bash"` when `command like "*rm -rf*"`, `"*DROP DATABASE*"`, `"*git push --force*"`,
`"*> /dev/sd*"`; keep the Codex `shell`/`exec_command`/`local_shell`/`unified_exec`
clauses from `deny_destructive.cedar` so the appendix path works with the same file.
Comments in the file teach the reader the shape.

**D7 — Docker.** Single `Dockerfile` (existing multi-stage) made arch-agnostic: replace
the hardcoded amd64 ELF assert with a check against the build platform. New
`docker-compose.yaml` = `postgres`, `gateway`, `policy-sync` (profile-gated when no git
URL), `vector` behind an optional `--profile logs`. The old AWS/WorkOS reference compose
moves to `docker-compose/reference-aws.yaml` with its README note. Broker container
deleted (collapsed mode). Image published by CI later; the first `docker compose up -d`
builds the image.

S7 amendment: the `# syntax=docker/dockerfile:1.7` directive and every
`RUN --mount=type=cache` slot were removed from the Dockerfile. They need BuildKit, and the
stranger's Docker without buildx died at the first one (`docker compose` falls back to the
legacy builder). CI's cache mounts therefore moved out of the Dockerfile; `.gitlab-ci.yml`
may re-add registry-backed caching (`--cache-from`/`--cache-to`) on its own build command.

**D8 — No Agent SDK route.** Thomas raised using the Claude Agent SDK's OAuth for
personal use. That would make r5e the harness that *runs* the agent, which is a
different product shape from governing the user's own sessions. Rejected for this spec;
the only thing it would have bought (credential handling) is answered by U1.

**D9 — Security posture stated plainly in the README.** The gateway sees the user's
bearer token (it must, to forward). Cleartext HTTP is loopback/docker-network only.
Dev login is a local convenience gated by env and off by default in the image.
Receipts store hashes; payloads go to the local CAS volume.

## 5. Slices

Each slice = one subagent task, one jj change on `compose/quickstart`, reviewed before
the next dependent slice starts. Acceptance criteria are the contract.

### S0 — Spike: Claude Code against a stub gateway (no product code)
Files: `specs/012-compose-quickstart/spike-s0.md`,
`apps/recurse_shared/test/fixtures/anthropic_messages/*.sse` (sanitized).
- Run a 20-line Elixir/Python stub on :4443 that logs headers and proxies to
  `api.anthropic.com`. Point `claude` at it via `ANTHROPIC_BASE_URL=http://localhost:4443`.
- Answer U1, U2, U3 with evidence (header dumps, redacted).
- Capture real request + SSE response fixtures for: text-only reply; one `tool_use`
  (Bash); parallel `tool_use`; a `Read`/`Edit` tool call; an error frame.
- Record which Claude Code version was used.
Acceptance: the three U's each have a yes/no with evidence; ≥4 fixtures committed.

### S1 — Compose foundation (boots with zero cloud)
Files: `apps/recurse_providers/lib/recurse_providers/impls/local_pem_secrets_provider.ex`,
`.../filesystem_storage_provider.ex` (+ tests),
`apps/recurse_gateway/lib/recurse_gateway/config/env_provider_registry.ex`,
`config/runtime.exs` (`R5E_DEV_LOGIN_ENABLED`), `Dockerfile`, `docker-compose.yaml`,
`.env.example`, `bin/r5e` (bash), `docker-compose/reference-aws.yaml` (moved).
- Providers per D4; registry shortnames `local_pem`, `filesystem`.
- Dev login runtime-gated; `/admin` shows a "Sign in (local dev)" button when enabled
  (UI change in `ui/`, small) — or, minimum, `bin/r5e login` mints the cookie via curl and
  prints the URL.
- Gateway container env: `R5E_START_HTTP=true`, `R5E_LLM_PROXY_ENABLED=true`,
  `R5E_LLM_PROXY_SCHEME=http`, `R5E_BROKER_MODE=collapsed`, `BROWSER_OIDC_PROVIDER=oidc`,
  `R5E_PROVIDER_LEDGER_IMPL=postgres_merkle`, `R5E_PROVIDER_PAYLOAD_BROKER_IMPL=filesystem`,
  `R5E_PROVIDER_SECRETS_IMPL=local_pem`, `R5E_PROVIDER_POLICY_IMPL=filesystem`,
  `RECURSE_POLICY_BUNDLE_PATH=/policy/bundle.cedar`, `RECURSE_POLICY_SCHEMA_PATH=<baked>`,
  `R5E_TENANT_ID=01TEN_LOCAL`, `SECRET_KEY_BASE` + `GATEWAY_ADMIN_SESSION_SECRET_KEY_BASE`
  generated into `.env` by `bin/r5e init` (or defaults that the README says to rotate).
  Migrations run at container start (`bin/audit_console eval "Recurse.Release.migrate()"`
  — add the module if absent).
- Broker signing key: generated into the `secrets` volume on first boot.
Acceptance: on an Apple Silicon Mac with Docker Desktop, `docker compose up --build`
from a clean checkout reaches `/healthz` all-`ok` and `/readyz` ok; dashboard loads;
dev login works; `mix test` for the two providers green; image also builds under
`--platform linux/amd64`.

### S2 — Default-upstream routing + Anthropic upstream row
Files: `apps/recurse_gateway/lib/recurse_gateway/llm_proxy/proxy_router.ex`,
`upstream_resolver.ex`, `config/runtime.exs`, a boot-time seeder
`apps/recurse_gateway/lib/recurse_gateway/llm_proxy/upstream_seed.ex` driven by
`R5E_LLM_PROXY_UPSTREAMS=anthropic` (idempotent; replaces `seed_real_upstreams.exs` for
the compose path), tests.
- D3 semantics. Outbound `Host: api.anthropic.com`; forward `x-api-key`,
  `authorization`, `anthropic-version`, `anthropic-beta` (extend `HeaderFilter`
  allowlist as needed).
- Non-streaming responses (`stream:false`) must also pass through and attest.
Acceptance: `curl -s localhost:4443/v1/messages -H 'x-api-key: …' -d …` returns the
real answer; one `llm_call_attested` receipt per call with `upstream_host=
api.anthropic.com`, `api_format=anthropic_messages`; Codex Host-header routing tests
still green.

### S3 — PreToolUse hook endpoint + installer
Files: `apps/recurse_gateway/lib/recurse_gateway/hooks/claude_code_handler.ex`,
`router.ex` (`POST /v1/hooks/claude-code/pre-tool-use`), `bin/r5e claude-code setup`,
`docs/quickstart-claude-code.md` (draft), tests.
- Auth: bearer `R5E_HOOK_TOKEN` (generated into `.env`); principal = `R5E_HOOK_PRINCIPAL`
  (default `local-dev@r5e`), overridable per-request via header for multi-user later.
- Map `tool_name` → `ToolUse::"<tool_name>"`, `tool_input` → `tool_args`; build a
  `ToolUseIntent` and call `CedarToolUseGate.evaluate/2` with the active bundle.
- Deny → HTTP 200 with the `hookSpecificOutput` deny JSON whose reason follows the
  existing R5E-102 transparency template (rule, bundle hash, tenant, principal, appeal
  path); emit `tool_use_denied` receipt with `source: "claude_code_hook"`. Allow → 200
  with allow JSON, no receipt (allowed intents are attested by S4's parent receipt).
- Installer writes `.claude/settings.json` in the *project* the user runs it from
  (merging, never clobbering), with a `type: "http"` hook; `--user` targets
  `~/.claude/settings.json`. Prints the `export ANTHROPIC_BASE_URL=…` line.
Acceptance: with S1+S2 running and no S4, `claude` asked to `rm -rf /tmp/x` shows the
denial text and does not execute; red `POLICY_DENIED` row; the hook returns allow in
<50 ms p50 locally (decision cache).

### S4 — Anthropic Messages parser + denial injector
Files: `apps/recurse_shared/lib/recurse_shared/llm_proxy/parsers/anthropic_messages.ex`,
`apps/recurse_gateway/lib/recurse_gateway/llm_proxy/denial/anthropic_messages.ex`,
`denial_injector.ex` (`:anthropic_messages` clause), `streaming_proxy.ex`
(`parser_for_format(:anthropic_messages)`), tests driven by the S0 fixtures.
- Parser implements `Parsers.Parser` (`init/1`, `parse_chunk/2`, `finalize/1`): SSE
  framing (`event:`/`data:` lines, multi-line data, chunk boundaries mid-event),
  `tool_use` block reconstruction per index, parallel tool calls, `message_start`
  model + `message_delta` usage into the summary, non-streaming JSON bodies.
- Injector: suppress the `content_block_start/delta/stop` frames of a denied index;
  inject a `text` content block with the denial message; if every tool_use in the
  message was denied, rewrite `stop_reason` from `tool_use` to `end_turn` in
  `message_delta` so Claude Code doesn't wait for a tool result. Must remain
  byte-faithful for everything else.
- Unhandled event types log `AnthropicMessages parser: unhandled event type=…` (same
  drift-detector convention as the Codex parser).
Acceptance: fixture tests for all S0 captures; live: with the hook *uninstalled*, the
`rm -rf` ask is denied in-stream, Claude displays the denial and continues; both
receipts present; no `unhandled` log lines on a normal 10-turn session.

### S5 — Policy from git
Files: `docker-compose.yaml` (`policy-sync` service), `docker-compose/policy-sync.sh`,
`apps/recurse_gateway/lib/recurse_gateway/policy/bundle_loader.ex` (poll option),
`policy/bundle.cedar` (D6), `policy-starter/` (README, bundle, CI job), tests for the
poll path and last-good-bundle retention.
Acceptance: set `R5E_POLICY_GIT_URL` to a throwaway repo; push a change; within 60 s the
dashboard shows the new bundle hash and the next `rm -rf` decision reflects it; a
syntactically broken push keeps the old bundle active and `/readyz` reports the failure.

### S6 — Docs
Files: `README.md` (rewrite), `docs/quickstart-claude-code.md`,
`docs/codex-mitm.md` (from `scripts/fable_demo/README-real-codex.md`, generalized),
`docs/architecture.md` (one diagram: client → gateway → upstream; hook path; ledger;
policy-sync), `docs/security-notes.md` (D9), screenshots/GIF of the two beats.
README sections: what this is (3 sentences), 60-second tour with the dashboard
screenshot, quickstart, how it works, "why is there a MITM section?", policy authoring,
evidence export + verify, limitations (single tenant, dev login, cleartext loopback),
license. Written for the resume reader first, operator second.
Acceptance: passes S7.

### S7 — Stranger test
A subagent with only the README, a clean clone, and Docker follows the quickstart
literally on this Mac and reports every point of friction. Findings become fixes before
anything is pushed.

## 6. Sequencing

```
S0 ──► S1 ──► S2 ──► S3 ──► S5 ──► S6 ──► S7
              └────► S4 (parallel with S3/S5; needs S0 fixtures + S2)
```
S1 and S0 can run concurrently (S0 has no product-code dependency).

## 7. Out of scope (explicit)

- Multi-tenant / real IdP login (WorkOS/Okta path stays as the AWS reference compose).
- Keeping the Codex parser current with future Codex releases (appendix path, best
  effort; drift detector documented).
- Publishing images to a registry; Helm; EKS (spec 008 territory).
- Anything in `apps/recurse_fold` / spec 010 (other agent, other workspace).
- Claude Desktop / Cowork clients (they read proxy env only from managed settings).

## 8. Open questions for Thomas

1. Public home: GitHub or GitLab (`gitlab.com/r5e-group/r5e-enterprise` today)? Affects
   README links and the policy-starter CI template only.
2. Hook installer default: project-level `.claude/settings.json` (my recommendation;
   scoped, visible, reviewable) or user-level?
3. Should the Codex MITM path be tested as part of S7, or documented as "last validated
   on Codex 0.149 in fable-demo" and left?

---

## 9. Amendments after Spike S0 (2026-09-02, see `spike-s0.md`)

U1, U2, U3 all resolved **yes**. Claude Code 2.1.223, claude.ai OAuth login: the bearer
(`Authorization: Bearer sk-ant-oat01-…`) goes to the custom base URL; plain
`http://127.0.0.1:4443` is accepted silently; hook stdin carries `transcript_path`,
`tool_use_id`, `permission_mode`, `prompt_id`; `type: "http"` hooks receive the same
JSON and a deny reply blocks the call. Fixtures (23 files) are in
`apps/recurse_shared/test/fixtures/anthropic_messages/`.

Requirements added to the slices:

- **S2**: answer `HEAD /api/hello` (unauthenticated connectivity probe) with 200 or proxy
  it; preserve the `?beta=true` query; forward `anthropic-beta` verbatim (it carries
  `oauth-2025-04-20`, without which upstream rejects the OAuth credential), plus
  `anthropic-version`, `x-app`, `anthropic-dangerous-direct-browser-access`,
  `X-Stainless-*`, `X-Claude-Code-Session-Id`; pass upstream response headers back
  (rate-limit headers feed the client's `/usage`). `HeaderFilter` already strips
  `Accept-Encoding` (verified, `header_filter.ex:168`), so no decode stage is needed.
  README: `NO_PROXY=127.0.0.1,localhost` for users with `HTTP_PROXY` set.
- **D2 receipt classification**: one prompt = three `/v1/messages` calls (session title,
  the real turn, a non-streaming side query). All are attested, tagged by kind
  (`tools` present → `agent_turn`; `output_config` present → `session_title`; no
  `stream` → `side_query`). The dashboard defaults to `agent_turn`; the others remain
  in the ledger because they carried the same credential and prompt content.
- **S3**: receipt key is `(session_id, tool_use_id)`; `tool_use_id` is the same `toolu_…`
  id that appears in the SSE `content_block_start`, so hook receipts join the in-stream
  parent receipt without heuristics. `Content-Type: application/json` on the reply.
  Stop-hook import via `Importers.ClaudeCodeSession` promoted from nice-to-have to an
  S3 stretch item (`transcript_path` confirmed).
- **S4**: buffer each `tool_use` block from `content_block_start` to `content_block_stop`
  (input is only known at stop), evaluate, then release or replace. Handle `ping`
  events, the always-present empty `thinking` block with `signature_delta`, empty first
  `input_json_delta`, mid-token fragment splits, `stop_reason` only in `message_delta`,
  `message_delta.usage` as authoritative. Partial denial in a parallel call must keep
  indices contiguous. The injected `text` block must be a valid content block with no
  `signature`, because Claude Code echoes assistant blocks back verbatim next turn.
  Never signal a denial via an HTTP error status: the client retries 4× in 2 s.
- **Docs / `bin/r5e`**: `--allowedTools` is variadic and eats a trailing prompt; examples
  put the prompt on stdin. `ENABLE_TOOL_SEARCH=true` note: a non-first-party base URL
  disables tool-search deferral, so every request carries all ~29 tool definitions
  (~118 KB). Harmless, worth a sentence.
- **Capture guidance for future spikes**: drop `Accept-Encoding` upstream; use
  `claude -p --debug-file` to see request `source=` labels; macOS has no `timeout(1)`;
  response headers leak org/workspace ids and need the same redaction as bodies.

---

## 10. Decisions from Thomas's review (2026-09-02) — supersede §4/§5 where they conflict

**D2 revised — no hooks in the quickstart.** The proxy sees every `tool_use` before the
client executes it (intent) and every `tool_result` echoed in the next request
(execution). Intent and execution are both in-band; in-stream Cedar enforcement is the
enforcement. **S3 is removed.** The hook facts from `spike-s0.md` stay as an optional
appendix (`docs/appendix-claude-code-hooks.md`, S6) for operators who want `cwd` /
`permission_mode` on receipts. Rationale: a hook per machine/repo is unsustainable in
an organization, and it adds nothing the stream doesn't already carry.

**Receipt model — session is the wrap.** The ledger already has a per-session epoch root
under the global root; the session is the wrap Thomas described and calls are leaves.
Every `/v1/messages` call is attested, tagged `kind ∈ {agent_turn, session_title,
side_query}` (rule in §9), and the dashboard groups leaves by session
(`X-Claude-Code-Session-Id` / `metadata.user_id.session_id`) with `agent_turn` as the
default filter. No "evidence of absence" mechanism is invented: the verifier's existing
completeness advisory is the honest statement that a gateway attests only what was
routed through it. **S4 acceptance adds**: in a 10-turn interactive session, record
whether the session-title call recurs after turn 1 (the spike used single-turn `-p`).

**D4 revised — Ed25519 default, matching r5e-core.** `Dsse` already signs Ed25519 or
ES256 by key type; `SecretsProvider` and the `signing_key` schema list `:ed25519`;
r5e-core is Ed25519 + SHA-256 CAS. `LocalPemSecretsProvider` defaults to Ed25519
(`R5E_LOCAL_SIGNING_ALG=ed25519|es256`). **S1 scope grows**: add an Ed25519 verify path
to `docs/auditor/recurse-verify` and a `Dsse.verify_ed25519/4` counterpart, with a
fixture receipt for each algorithm. CAS is SHA-256 in both codebases already.

**S4 addition — parser drift is a product surface.** Unhandled event/output types are
persisted (`parser_drift_events`: api_format, event type, redacted sample, first/last
seen, count) and shown in the dashboard as a "Parser drift" panel with a `/readyz`
warning when new ones appear. Follow-on (not this spec): an AI job proposes the parser
patch from the sample.

**S5 addition — hosted default policy.** `R5E_POLICY_GIT_URL` unset → bind-mount
`./policy/`; set → policy-sync. The README also offers an r5e-hosted starter repo URL as
the "default bundle from git" option, so a user can start from ours and fork later.

**Q1 public home — recommendation: same GitLab repo, no `-local` fork.** A separate repo
is fable-demo again (a fork that must be ported back). Merge `compose/quickstart` to
`main` when S7 passes; set the GitLab default branch to it temporarily if `main` is not
presentable at that time. Add a GitHub push mirror for discoverability.
(Thomas undecided; proceeds under this assumption, changes README links only.)

**Q2 hooks — resolved by D2 revised.** None.

**Q3 Codex — Claude Code only for now.** The Codex MITM runbook is documented as "last
validated on Codex 0.149 in fable-demo" and not re-tested in S7. Note for the README's
"how does this work with Codex" section: the 0.149 binary carries a `chatgpt_base_url`
config key and `CHATGPT_BASE_URL` env var, so a config-level base URL (no DNS override,
no TLS interception) is probably possible. **Spike S0b** (unscheduled): verify it.

**Images — in scope as S8.** CI publishes `gateway` to the GitLab container registry on
tags; the GitHub mirror gets ghcr.io via the same pipeline or a mirror job. Free-tier
storage/transfer quotas unchecked; `docker compose up --build` remains the documented
fallback.

**Claude Desktop (Code tab) — in scope; Cowork out.** Per network-config.md the
Desktop-managed connection reads env only from managed settings and
`~/.claude/settings.json`; `bin/r5e claude-code setup` therefore writes
`ANTHROPIC_BASE_URL` (and `NO_PROXY`) into the `env` block of `~/.claude/settings.json`
(merge, never clobber) as well as printing the shell export. **S7 verifies** in the
Claude desktop app's Code tab on this Mac.

**Sequencing (revised)**

```
S0 ──► S1 ──► S2 ──► S4 ──► S5 ──► S6 ──► S7 ──► S8
```

---

## 11. Attestation honesty + peer sync (2026-09-02, later)

**Renumbered 011 → 012.** The admission-pipeline session's handbook already uses
"spec-011" for the kernel/fold contract.

**Principle (corrected 2026-09-02 after Thomas's pushback): absence at the call level IS
attestable, and the gateway must say so.** Earlier text here inverted Thomas's position;
the inverted version was also relayed to the admission-pipeline session and retracted.

Thomas's position: if the whole response passed through the gateway, and the wire format
defines how a tool call is encoded (Anthropic Messages: a `content_block` of type
`tool_use`; the server-side and MCP tool block types are likewise enumerable for a given
`anthropic-version` + betas), then "this response contains no tool call" is a fact about
the bytes. Refusing to state it is the overreach he has been pushing back on: hedging
into "we can't claim absence" when we hold the complete bytes and an exhaustive
recognizer for the format is under-claiming, not caution.

Inspection of `attestation_emitter.ex` shows why the claim is currently *asserted* rather
than *checkable*: the predicate carries `tool_use_intents`, hashes, token counts and the
bundle hash, but no parser identity, no format version, and no count of events the
parser did not recognize. A Codex shape change (three so far) therefore produced
`tool_use_intents: []` with nothing distinguishing it from a tool-free turn.

What the record must carry so the absence claim is checkable:
1. **Bytes**: `prompt_hash`, `response_hash`, payloads retained in the CAS (exists).
2. **Recognizer identity**: `parser: {module, version, format}` where `format` is the
   wire format + version the parser is exhaustive for (e.g.
   `anthropic_messages/2023-06-01`, with betas), taken from the request headers.
3. **Recognition completeness**: `parse: {eventsTotal, eventsUnhandled, unhandledTypes}`.
Claim semantics: with `eventsUnhandled = 0`, an empty `toolCalls` **claims** the response
contained no tool call in the format's encoding. With `eventsUnhandled > 0`, the record
states extraction is incomplete for the listed types; the claim is downgraded, not
withheld. Parser drift is a downgrade condition, not a reason to hedge every record.
Session-level coverage (calls a client sent around the gateway, as the spike observed) is
a separate, advisory statement and does not weaken any call-level claim.

**S4 requirements added**: the `AnthropicMessages` parser reports `events_total` /
`events_unhandled` / `unhandled_types` and its format version; the emitter writes
`parser` and `parse` into the predicate (schema_version bump); the console renders an
empty intent list with `eventsUnhandled = 0` as "no tool calls in this response" and
with `eventsUnhandled > 0` as "N intents extracted; M events unrecognized (types …)".

**Peer sync (admission-pipeline session).** Its work lives in r5e-kernel `identity/*`,
r5e-core `identity/verifier`, and enterprise `apps/recurse_fold` + `config/*.exs` only.
It does not touch `recurse_gateway` or `recurse_shared`. Its direction: the enterprise
provider behaviours, DSSE predicate kinds, and session/epoch model are **not being
evolved**; the honest record path is enterprise → `R5e.Admission` (kernel) → kernel
export → r5e-core `recurse_verify` escript (Ed25519 only, signed request objects).
Consequences for this spec:
- **S1 scope cut**: no Ed25519 path in the enterprise verifier; local signer defaults to
  ES256 (today's verifier verifies), Ed25519 behind a flag. Provider impls stay thin.
- The LLM proxy still attests through today's ledger because nothing else exists on
  that path yet. **Future slice S9 (unscheduled)**: proxy submits admissions to the
  kernel via the fold, replacing the ledger underneath; the parser/parse fields above
  become the admission's interpretation scope. Awaiting the peer's answer on who owns it.
- Reusable now or soon: `R5e.Signer.Local`, `R5e.Export`, the `recurse_verify` escript,
  `apps/recurse_fold/scripts/fold-demo.sh` (closest existing quickstart script),
  `AgentSession` Kind for session grouping.
- Avoid list (next few days): r5e-kernel/**, r5e-core/verifier/** and spec/**,
  enterprise `apps/recurse_fold/**` and `config/*.exs` (S1 touches `config/runtime.exs`
  for the dev-login flag — a one-line addition; flagged to the peer).

---

## 12. Amendment requested of spec 010 (gateway.r5e.io Kinds) — v1alpha1 → v1alpha2

> **Status: WITHDRAWN (2026-09-02).** The admission-pipeline session pulled this from its
> queue after Thomas's correction; nothing is folded into spec 010 unless Thomas asks.
> Kept here as a proposal only. The proxy-side `parser`/`parse` fields (S4) are an
> enterprise-predicate matter and proceed; whether they belong on the Kinds is undecided.

Requested by this spec; to be folded by the admission-pipeline session (its files, its
transition rule). Proxy-side fields land now under the same names so nothing renames.

**Why.** `LlmResponse.epistemicScope.doesNotClaim` already says absence from the record
is never provable. What is missing is the *positive* scoped claim that makes an empty
`toolCalls` interpretable: which software read the bytes, and how much of the stream it
did not understand. Without it, parser drift (three Codex shape changes to date) is
indistinguishable from a genuinely tool-free turn.

**`LlmResponse` schema fragment** (schema-lite-v2 dialect; add both to `required`):

```json
"parser": {
  "type": "object",
  "required": ["module", "version", "format"],
  "properties": {
    "module":  { "type": "string" },
    "version": { "type": "string" },
    "format":  { "type": "string" }
  },
  "additionalProperties": false
},
"parse": {
  "type": "object",
  "required": ["eventsTotal", "eventsUnhandled", "unhandledTypes"],
  "properties": {
    "eventsTotal":     { "type": "integer", "minimum": 0 },
    "eventsUnhandled": { "type": "integer", "minimum": 0 },
    "unhandledTypes":  { "type": "array", "items": { "type": "string" } }
  },
  "additionalProperties": false
}
```

Notes: `parser.version` is a release version or the SHA-256 of the parser module's
source, as a string. On `outcome: "error"` with no response bytes (e.g.
`upstream_connection_failed`), `parser` still names the parser that would have run and
`parse` is `{0, 0, []}`; the fields are required unconditionally so they cannot be
omitted. `unhandledTypes` is the de-duplicated set of event/type discriminators the
parser logged as unhandled (no payload samples in the Kind; samples live in the
gateway's drift store, §10). No floats anywhere (kernel rule).

**`ToolCall` schema fragment**: the same `parser` object, required. (A ToolCall is an
extraction by a specific parser; naming it on the ToolCall lets a ToolCall be judged
without dereferencing its LlmResponse.)

**`LlmResponse.epistemicScope` additions** (polarity corrected; the first draft said
the opposite and was retracted)

`claims` +=
> "`parser` names the software that interpreted the response bytes and the wire-format
> version it recognizes exhaustively; `parse` counts the events it saw and the events it
> left unrecognized; `toolCalls` are exactly the intents that parser extracted"

`claims` +=
> "when `toolCalls` is empty and `parse.eventsUnhandled` is 0, the response bytes
> contained no tool call in that format's tool-call encoding"

`doesNotClaim` +=
> "that extraction was complete when `parse.eventsUnhandled` > 0 — the listed
> `unhandledTypes` are the events the parser could not classify, and a tool call may be
> among them"

Note for Thomas + the peer to settle (not decided here): the existing `doesNotClaim`
line "that the listed tool calls are all the tool calls the model proposed — absence
from the record is never provable" conflicts with the new conditional claim at the call
level. Thomas's position is that with complete bytes and an exhaustive recognizer it is
provable; the sentence should be narrowed to the `eventsUnhandled > 0` case or to
session-level coverage.

**`ToolCall.epistemicScope`** `claims` += "the extraction was performed by `parser`".

**S9 constraints recorded from the peer** (proxy → kernel, later): call
`Recurse.Fold.admit(kind, spec, opts)` (arrives with `identity/2f`; do not call
`R5e.Admission` directly, do not wire before 2f); submit denials as admissions too (a
Cedar deny is a receipt); specs carry no floats (integers or strings for temperatures
and latencies). The proxy-side `parser`/`parse` fields (S4) are the payload for these
Kinds when S9 lands.

---

## 13. Frame from Thomas (relayed via the admission-pipeline session, 2026-09-02)

**Claims wording.** The hedging frame is too litigious. Absence caveats live in exactly
two places: a Kind's `epistemicScope` and the verifier's not-checked block. Nowhere else:
not the console, not the README, not per-receipt copy. Product statement: traffic is
forwarded to the endpoint, everything the model can do arrives as a tool call, we record
everything we have; a recorded response with no tool call is a response with no tool
call. **S4/S6 rule**: console renders "no tool calls"; the `parser`/`parse` fields are
recorded for the verifier's not-checked block and the drift panel, never surfaced as a
caveat next to a receipt.

**Two security surfaces, two Deployments.** (1) The managed employee laptop (Claude Code
on the user's machine, S7). (2) The autonomous agent in a container or pod. Each is a
Deployment declaration on the chain (the kernel contract's Deployment Kind, signed by the
operator's key) stating its containment: no root, egress only to the endpoint, egress
monitored; a customer security team co-signing is an Endorsement/Badge. README claims
are written "under this declared containment", not as hedges.

**Consequences for this spec (proposed; Thomas to confirm the new slice):**
- **S1 follow-up, container hardening**: the gateway image runs as a non-root user;
  compose sets `read_only: true` with tmpfs where the release needs writes, `cap_drop:
  [ALL]`, `security_opt: [no-new-privileges:true]`; the gateway's network has egress to
  the upstream only (compose `internal` network for postgres, a second network for
  egress). The Dockerfile S1 produced has no `USER` line yet.
- **New slice S-agent (proposed, after S4)**: an optional `agent` compose profile running
  Claude Code headless in a container with no root, no network except the gateway's proxy
  port (`internal: true` network shared with the gateway only), the repo bind-mounted,
  credentials via env. This is surface (2) in a stranger's hands: the agent physically
  cannot reach Anthropic except through the proxy, so the demo's claims are made under a
  containment the compose file itself declares. The compose file + Dockerfile are the
  bytes a Deployment declaration would cite.
- **Infra as code is an artifact**: the compose file, Dockerfile, and any pod policy are
  CAS-addressed bytes a Deployment cites, admitted through the existing CI invariant
  (content-addressed artifact from an immutable revision, digest verified post-deploy).
  SBOM per spec 007. Out of scope to implement here; the README states it as the shape.
- **Trail-along classifiers** run as policy engines at the runtime layer: bundle admitted
  as a PolicyBundle, each verdict a receipt derived from the LlmResponse it judged,
  denials included. Not in this spec; noted so S4's receipt linkage (verdict → response)
  stays compatible.
- Kernel stays minimal; verifier stays outside the runtime. Unchanged wiring boundary.

---

## 14. S9 contract (from the admission-pipeline session, 2026-09-02) — not scheduled

Review closed 2026-09-02: base for S9 is `identity/2f-review` in r5e-enterprise (on
`fold/v2.1`; kernel and r5e-core bookmarks of the same name). `admit/3` additionally
accepts `transition: true` (re-admitting a changed KindDefinition; not needed by S9).
Plan around: the fold's role Endorsement is minted at boot only — if revoked, every
`admit/3` returns `{:refused, "fold authority not effective: …"}` until the next boot
(S9 must surface that on `/readyz` and never drop the call); the fold's grant covers
exactly eleven Kinds (KindDefinition, CasObject, the nine gateway Kinds), so any new Kind
must be seeded by the fold to be admittable. Surface:

```elixir
@spec admit(String.t(), map(), keyword()) ::
        {:ok, map()} | {:denied, map()} | {:refused, String.t()}
def admit(kind, spec, opts \\ [])   # kind = "group/version/Kind"; opts: :name, :derived_from

@spec put_cas(binary(), keyword()) ::
        {:ok, map(), String.t()} | {:denied, map()} | {:refused, String.t()}
def put_cas(bytes, opts \\ [])      # opts: :media_type; returns "bytes:sha256:…" to cite
```

Semantics: the fold signs every request with its own key (endorsed by the node key, role
"fold") and submits through `R5e.Admission`. `{:denied, receipt}` is a recorded denial
(a Cedar deny lands here; submit it, never swallow it). `{:refused, reason}` = nothing
recorded; unreachable for fold-signed requests but in the type. Specs float-free. Kinds at
`gateway.r5e.io/v1alpha1`: LlmCall, LlmResponse, ToolCall, ToolResult, Prompt, Completion,
PolicyBundle, PolicyShape, AgentSession. Shape envelope: `@actor.id`, `@actor.identity`,
`@actor.authorityRefs`, `@actor.authorityRoots`, `@kind`, `@group`, `@version`, `@name`
(`keyFingerprint` gone). Worked example: fold README; demo `apps/recurse_fold/scripts/
fold-demo.sh`.

**S9 plan sketch (when scheduled):** base on `identity/fold`; widen the Docker build
context to `r5e-group` with `r5e-kernel` and `r5e-core/verifier` alongside (D7 option b);
the proxy's `AttestationEmitter` submits `LlmCall` at request open, `Prompt`/`Completion`
bytes via `put_cas`, `LlmResponse` (with `parser`/`parse` per §12 if adopted) and one
`ToolCall` per intent at finalize, denials included; `AgentSession` keyed on the Claude
Code session id for grouping; the enterprise ledger path stays until the kernel export +
`recurse_verify` escript replaces evidence export in the quickstart.

## 15. Follow-on slices recorded (not scheduled)

- **S10 — Cedar schema becomes a contract.** Finding: the NIF does no schema validation
  and `priv/cedar/schema.cedarschema.json` is not valid Cedar JSON schema (`$comment`,
  `::` in ids, `tool_args` undeclared), so bundles are never validated against what the
  gateway evaluates and third parties cannot validate either. Slice: real Cedar JSON
  schema with the `invoke_tool` context declared; validate at bundle load, fail closed;
  put the schema bytes in the CAS and cite them from the PolicyBundle spec so
  "validated against schema X" is checkable (peer request). Vocabulary parity with the
  fold's shapes stays a README note.
- **`principal_source`** (landing in the S4 fix batch): values `jwt | client_metadata |
  mtls_svid | anonymous`; answers "how did the proxy decide which human this was"; never
  aligned with the kernel's `identity`/`signers`, which answer whether request bytes were
  signed. When S9 wires the fold, the signer of every admission is the fold key (custody:
  fold holds it, node key endorsed it for the fold role, chain shows both); the human
  stays an asserted field until the `r5e` client slice gives people their own keys.

## 16. S6 finding: the signature commits to bytes nobody retained (2026-09-02)

Verified in code: `AttestationEmitter` builds the rich predicate (model, prompt/response
hashes, usage, intents + decisions, parser/parse, principal_source, kind);
`EnvelopeBuilder.build_system/4` JCS-encodes it and puts its SHA-256 in the signed
envelope as `payload_hash` with `payload_uri = recurse://system/predicate-only/<run_id>`.
The JCS bytes are never written anywhere (no StorageProvider put in the gateway), the
export packs nothing for them, and `recurse-verify` step 5 prints SKIPPED. Prompt and
response bytes are hashed and never stored (CAS empty after 11 calls). §11 item 1 said
"payloads retained in the CAS (exists)" — false; corrected here. Consequence: the rich
claims were signed only by reference to bytes no verifier could obtain.

**S6b (launched)**: retain the JCS predicate body in the CAS under the hash the signature
commits to; retain request/response bytes behind `R5E_RETAIN_PAYLOADS`; archive every
activated bundle by canonical hash so exports after a policy change still resolve the
bundle that decided (S6 saw `loader_drift` step-4 failures); export packs body, payloads,
archived bundle; verifier step 5 becomes MATCH/FAIL and a payload step is added; console
verify tab does the same check.
**S6c (launched)**: dashboard defects (denials counted under allow; empty tool columns on
denied rows; no kind filter/session grouping; `/admin` root blank), `bin/r5e` details,
and the doc sentences that were false against the running system, rewritten to the S6b
mechanism.

Also from S6: the macOS "modifying applications" prompt Thomas saw was the docs agent
spawning headless Google Chrome for a screenshot (plus `claude -p` auto-update
attempts). Rule recorded: Chrome extension only, `DISABLE_AUTOUPDATER=1`.

**S6b landed (2026-09-02).** Mechanism, as built:
- `EnvelopeBuilder.system_predicate_bytes/1` is the one function that produces the JCS
  bytes `build_system/4` hashes; the emitter re-derives them through it, checks them
  against the envelope's `payload_hash`, puts them via `Resolvers.Payload.store/2` and
  records the URI in `attestations.predicate_body_uri` (parent and every
  `tool_use_denied` child). `payload_uri` keeps the predicate-only sentinel — it is
  what every verify path branches on. A failed put logs a warning and the receipt
  commits with a NULL URI.
- Payloads: `PayloadCapture` sits next to `BodyHasher` in both proxies; the emitter
  stores `{request, response}` bytes under `prompt_hash` / `response_hash` and records
  `llm_call_records.prompt_payload_uri` / `response_payload_uri`. `R5E_RETAIN_PAYLOADS`
  (compose true, runtime default false), `R5E_RETAIN_PAYLOADS_MAX_BYTES` (8 MiB per
  direction; over the cap nothing is stored and `payload_truncated=true` is recorded —
  a prefix cannot be verified).
- Bundles: `Policy.BundleArchive` writes every activation (filesystem + OCI) into the
  F002 `policy_bundles` table by canonical hash; `Resolvers.PolicyBundle` already read
  it first. The `loader_drift` fallback is kept (the zip's manifest records it and
  step 4 fails honestly) rather than turning export into a 500 for pre-S6b receipts.
- The `tool_use_denied` predicate gained `prompt_hash` / `response_hash` so the
  payload check binds to the child's own signature (contract
  `llm_call_attestation.md` §ToolUseDeniedAttestation to be amended).
- Export: `predicate/<run_id>.json`, `payloads/<sha256>`, manifest `predicate_body` /
  `payloads` / `payload_retention`, `format_version` 1.1. `recurse-verify` 0.3.0: step 5
  MATCH/FAIL on the body, new step 7 per payload MATCH / FAIL / NOT INCLUDED; exit codes
  unchanged. Console verify tab check 5 does the same fetch-and-hash.

## 17. S9 rules of engagement (from Tally, the admission-pipeline session, 2026-09-02)

Permission granted to edit `config/{config,test,runtime}.exs` and `apps/recurse_fold/mix.exs`
in this workspace to include `recurse_fold` in the `audit_console` release and widen the
Docker build context to `r5e-group`. Prefer no mix.exs change: `{:r5e, path:
"../../../r5e-kernel"}` already resolves with that context. Keep it a path dep; no
vendoring; no submodules. Every `:r5e` config key stays documented in the fold README's
table; never change the kernel's own dev data-dir defaults.

Dual-write is accepted as a transition with three rules: (1) the README states plainly
which path the quickstart verifies and with which verifier — the enterprise ledger's
`recurse-verify` wrapper and the kernel's `recurse_verify` escript are different
verifiers and a reader must never think the escript checked the enterprise ledger;
(2) every denial goes through `admit/3` too; (3) specs float-free. `{:refused, …}` is
surfaced on `/readyz`; no call is ever dropped silently. Base `identity/2f-review`; the
newest escript is on `verifier-spec-07(-r2)` in r5e-core and kernel.

Repo structure, end state: git deps pinned by commit (`{:r5e, git: <url>, ref: <sha>}`;
the kernel's own pinned dep on r5e-core/verifier) plus a `repos.lock`-style manifest at
the r5e-group level so a public reader reproduces the exact build. Timing constraint:
the identity line is not on any public main; pushing it is Thomas's call in the order
core → kernel → enterprise. Until then: spike S9 against local sibling checkouts, keep
the public quickstart fold-less by default (today's behaviour), flip to pinned git deps
the day the identity bookmarks are pushed. Neither session pushes r5e-kernel or r5e-core
bookmarks.

**S9 slicing (proposed):** S9a spike — workspace on `identity/2f-review`, fold inside
the release, build context r5e-group, fold-demo in-container, `/readyz` refusal surface;
S9b dual-write emitter (LlmCall, Prompt/Completion via put_cas, LlmResponse, ToolCall
per intent, denials, AgentSession per Claude Code session), behind `R5E_FOLD_ENABLED`
(default false in the public compose); S9c kernel export + escript as a second evidence
path with the README's two-verifier statement; S9d flip to pinned git deps after the
identity push.

**Thomas, 2026-09-02, after applying `--write-settings`:** this workspace's own Claude
Code sessions are now attested by the stack. The eventual merge to main is to be done
*through* Recurse: a governed, receipted act performed via the gateway, with each of
r5e-core, r5e-kernel, r5e-enterprise pinned by commit in the group-level manifest (§17).
S9 go given 2026-09-02.

## 18. Truly chained + merge-through-Recurse (Tally, 2026-09-02) and proposed §17 amendment

**No kernel/core change is needed before S9b.** S9b/S9c are written against local
checkouts (S9a's layout). No Release Kind; Deployment (spec 011) is the operator's
containment declaration and is not a release record. Pins are bytes.

**Proposed amendment text (for Tally to fold into §17 / the handbook runbook):**

*Lock format.* A `repos.lock` manifest at the r5e-group level:
```json
{"format":"r5e.repos-lock/1",
 "repos":[{"name":"r5e-core","url":"…","ref":"<sha>","bookmark":"…"},
          {"name":"r5e-kernel","url":"…","ref":"<sha>","bookmark":"…"},
          {"name":"r5e-enterprise","url":"…","ref":"<sha>","bookmark":"…"}]}
```
The lock's bytes are put in the CAS via `put_cas/2`; any act that depends on them cites
`derivedFrom: "bytes:sha256:<lock>"`. Honest boundary, written wherever the lock is
described: git SHAs are content addresses in a different Merkle structure; the chain
proves the act cited these pins, not that the remote holds them — a reader checks the
remote themselves.

*Push policy.* A push to `main` is a Bash `tool_use` from a Claude Code session routed
through the local compose stack running the fold from local checkouts. Its ToolCall spec
carries the tool, the command, and a `pins` array copied from the lock (`repo`, `ref`)
so policy can see them without reading CAS bytes; `derivedFrom` cites the lock. Cedar:
permit a push whose target is `main` only when `derivedFrom` is present and the
command's repo/ref pair is in `pins`; forbid otherwise — the denial is a receipt like any
other. The ToolResult records the push's exit code and stderr as bytes via `put_cas`,
cited from its spec. Specs float-free.

*Sequence.* S9a (fold in the image, local checkouts) → S9b dual-write emitter → S9c
kernel export + escript as the second evidence path, README naming both verifiers →
Thomas performs the three pushes to main (core, kernel, enterprise, in that order; his
keys, his repos, nobody else pushes) through the stack, each admitted with the lock cited
→ S9d flips the public quickstart to pinned git deps + the same `repos.lock`, itself one
more governed push → export the chain and publish its verification beside the lock
(handbook or r5e-recurse; Thomas's call).

*Division.* Gateway side (emitter, ToolCall `pins`, Cedar rule, ToolResult bytes,
readiness surface): this session. Runbook for the merge-through-Recurse act and review
of S9b/S9c against the fold surface: Tally. A named Release record, if ever wanted, is a
gateway v1alpha2 Kind via spec 010's amendment path.

## 19. S9b — the dual-write emitter (2026-09-02)

Built: `Recurse.Gateway.Fold.Submitter` (gateway app, reaches `Recurse.Fold` by name
like `Readyz`; no compile-time dep — `recurse_fold` is a `only: :test` umbrella dep of
the gateway for the dual-write tests). `AttestationEmitter.emit_call_attestation/1` calls
it after the ledger receipt and the audit rows commit, never instead of them; every
fold answer is a value it logs and counts, none fails the emit. Behind `R5E_FOLD_ENABLED`.

Per call, in chain order: `AgentSession` (once per first-seen client session id —
`server`-named, so the id lives in `sourceIds.session`, cached in `:persistent_term`,
found again on the chain after a restart), `CasObject`+`Prompt` (request bytes, when
retained), `LlmCall{model, prompt, provider, upstreamHost, transport, apiFormat,
requestPath, session, sourceIds{session, run: <ledger run_id>}, startedAt}`, one
`ToolCall` per intent **denied or not** (`args` inlined when decoded, else
`{argsHash, argsSizeBytes, argsOmitted}`; `llmCall`+`index`; `callId`), `CasObject`+
`Completion` (response bytes), `LlmResponse{llmCall, outcome, completion, toolCalls,
upstreamStatus, errorKind, usage, latency}`. Float-free; only schema slots — the S4
`parser`/`parse`, `principal_source`, `upstream_org_id`, request kind have no slot in
v1alpha1 (§12 withdrawn) and stay on the enterprise predicate. Unit tests validate every
`spec_for_*` with the kernel's own `R5e.Kind.Validate` over the seed files.

**Decisions.** (1) *Bundle naming*: `PolicyBundle` admits only the literal name `active`,
and activating the gateway's bundle in the fold would deny every non-`invoke_tool` act
(its permit is scoped; the fold governs every Kind through Cedar). So a gateway
activation puts the bundle **bytes** on the chain as a `CasObject` (idempotent by
address, hooked in `BundleLoader` and `OciBundleManager` beside the archive); the
receipts' `cedar_bundle_hash` is Cedar's canonical hash, re-derivable from the object
with `Recurse.Cedar.canonical_hash/1`; `/readyz` `fold.active_bundle_object` shows both.
The fold's `PolicyBundle/active` is untouched. (2) *Mismatch handling*: the vocabulary is
shared (`invoke_tool`, `ToolUse::<tool>`, `context.tool_args` = `spec.args`); the texts
differ (fold: `shell`/`exec_command`; gateway: also `Bash`). Both decisions are recorded
where they were made; the pair is logged at warning and counted as
`fold.decision_mismatches`. A Claude Code `Bash rm -rf` is gateway-deny / fold-allow
today; `shell rm -rf` denies on both. (3) *AgentSession naming*: kernel-named; the
Claude Code id is `sourceIds.session`. (4) Without retained bytes there is no `Prompt`,
hence no `LlmCall`/`LlmResponse` (`prompt` is required and must be backed); `ToolCall`s
and the session still land; counted as `fold.calls_without_bytes`.

**Live acceptance (2026-09-03, image `r5e/gateway:fold` from the widened context, project
`r5e-fold`, 4200/4444).** One allow beat and one deny beat via `claude -p`: 4 calls
submitted (Claude Code's own side calls included), each as `AgentSession`
(found, not repeated) → `CasObject`+`Prompt` → `LlmCall` (citing the ledger `run_id`) →
`ToolCall` → `CasObject`+`Completion` → `LlmResponse`; the `Bash rm -rf` was denied by the
gateway (rule policy6) and **admitted** by the fold (`policy0` of `deny-destructive.cedar`)
— `decision_mismatches: 1`, both receipts on their own records. Export of 54 events
verified with the release-ERTS escript in-container AND offline with the escript built
from r5e-core `identity/2f-review`: `findings: none`, 54/54 signed, 43 endorsement chains
cited, 30 receipts citing evaluation records, refs 32/32 re-derived. One boot-order
finding: the gateway's first bundle activation runs before the fold's kernel is up, so
the boot-time `submit_bundle` was refused (`last_refusal: "the fold's kernel is not
running"`). Fixed in the tree after the run — skipped at boot, the first submitted call
puts the active bundle on the record (`ensure_active_bundle/0`, tested); the live image
predates that fix and was not rebuilt.

**S9c proposal.** Kernel export as the second evidence path in `bin/r5e`
(`bin/r5e evidence export --fold` → `bin/audit_console rpc 'R5e.Export.run(...)'` +
`docker cp`, `evidence verify --fold` → the in-image `/app/bin/recurse_verify --posture
house`); the README two-verifier statement (`docs/auditor/recurse-verify` checks the
enterprise zip, `recurse_verify` checks the kernel export, never the other); fold-demo.sh
env names aligned with `R5E_FOLD_*` (`R5E_FOLD_DATA_DIR`/`R5E_FOLD_PORT`, keeping the
mix aliases); Tally to consider a `Bash` rule in `deny-destructive.cedar` (or reading the
gateway's tool section) so the two engines agree on the Claude Code path.

## 20. Tally's S9b review (2026-09-02) — three corrections, binding

1. **Activation must re-admit `PolicyBundle/active`, not just park the bytes.** My S9b
   shape (CAS object per activation, fold's `PolicyBundle/active` untouched) is half of
   what activation means. `PolicyBundle/active` is literal-named *precisely so that an
   activation is a re-admission that supersedes*: put the bundle bytes in the CAS (as
   S9b does) **and then re-admit `PolicyBundle/active` citing that object**, so the chain
   shows which bundle governed from that seq on and the fold's engine evaluates the same
   bytes the gateway did. Leaving the fold's active bundle untouched records the
   gateway's bundles as loose objects nobody cites.
2. **The decision mismatch is a symptom of (1), not a text diff to patch.** Do NOT copy
   the gateway's tool section into `apps/recurse_fold/priv/policies/deny-destructive.cedar`
   (Tally's file; it stays the fold's shipped default for a chain with no activation yet).
   After (1), the fold evaluates the gateway's own bundle and `decision_mismatches`
   should read 0; any residual is a real engine or shape difference and is a finding
   worth surfacing, not noise. Keep the counter on `/readyz` either way.
3. **Boot order: fix it in the release, keep the catch-up as defensive code.**
   `recurse_fold` is listed before `recurse_gateway` in the `audit_console` release's
   `applications` (the fold does not depend on the gateway), so the first activation
   lands. `ensure_active_bundle/0` stays with a comment saying why it should never fire.
   Tally is adding `Recurse.Fold.ready?/0` so `/readyz` can ask rather than infer.

**Deferred to a spec 010 amendment (Tally folds it after conformance r3; we do not add
fields to the Kinds ourselves):** if the gateway's own decision is to appear on the chain
beside the fold's, `ToolCall` gains an upstream-decision object — engine, bundle address,
decision. Proposed here for Tally to fold. Until then both decisions stay where they were
made and the pair is logged and counted.

*`fold-demo.sh` env-name alignment to `R5E_FOLD_*` is Tally's, queued behind conformance r3.*

### 20a. Proposed spec 010 amendment — `ToolCall.upstreamDecision` (for Tally to fold after conformance r3)

Requested by Tally in the §20 review. Not implemented here; no field is added to any Kind
by this session. Rationale: when the proxy dual-writes, two engines evaluate the same
intent — the gateway's Cedar at the moment the frames were suppressed, and the fold's at
admission. §20(1) makes them evaluate the same bytes, so they should agree; when they do
not, the disagreement is the interesting fact and today it lives only in a log line and a
`/readyz` counter. A record that carries the gateway's verdict beside the fold's makes
the disagreement checkable by a reader instead of trusted.

`ToolCall` schema fragment (schema-lite-v2; `additionalProperties: false`, so it must be
declared to be recordable; optional, not in `required`):

```json
"upstreamDecision": {
  "type": "object",
  "required": ["engine", "decision"],
  "properties": {
    "engine":        { "type": "string" },
    "decision":      { "type": "string", "enum": ["allow", "deny", "error"] },
    "bundleAddress": { "type": "string" },
    "ruleId":        { "type": "string" }
  },
  "additionalProperties": false
}
```

`engine` names the software that decided upstream (e.g. `recurse-gateway/cedar`);
`bundleAddress` is the CAS address of the bundle bytes that engine used, which after
§20(1) is the same object the fold's active `PolicyBundle` cites, so a reader can confirm
both engines saw the same policy; `ruleId` is that engine's rule identifier when it has
one. No floats.

`epistemicScope` additions:

`claims` += "`upstreamDecision` is the verdict the named engine recorded for this intent
against the bundle at `bundleAddress`, before this admission"

`doesNotClaim` += "that the upstream engine's verdict was enforced — enforcement is
recorded by the absence of the tool call from the response bytes, not by this field"

The second sentence matters: the gateway's enforcement is visible because the `tool_use`
block is not in the forwarded bytes, and those bytes are hashed on the enterprise
receipt. The field records a verdict; it does not prove an action.

## 21. S9b-fix + S9c results, and a structural finding for the fold (2026-09-04)

**Tally's §20 corrections held live.** Activation re-admits `PolicyBundle/active` citing
the CAS object (supersede confirmed against `R5e.Admission.readmit_by_mode/4`: `literal`
→ `{:ok, :supersede, entry}`, no extra citation, chain shows `supersedes`/`supersededBy`).
`recurse_fold` precedes `recurse_gateway` in the release, so the first activation lands at
boot with no catch-up (`refusals: 0`, `active_bundle_object` non-null immediately).
Live deny beat: `Bash rm -rf` denied by BOTH engines under `policy6`, the fold citing the
gateway's own bundle bytes; `decision_mismatches: 0`; 63-event export verified by the
kernel escript with no findings.

**FINDING — the fold's admission gate has no floor (Tally's surface, NOT delivered:
her session was gone from the peer list when this was written; deliver it).**
Once the gateway's bundle is the fold's `PolicyBundle/active`, it governs *every* act the
fold records, not only tool calls: `CasObject`, `AgentSession`, `Prompt`, `Completion`,
`LlmResponse` and the next activation arrive as `Action::"admit"`; `LlmCall` as
`Action::"call_model"`. Cedar is deny-by-default, so a bundle that does not permit those
records nothing but denials — and because putting the next bundle's bytes in the CAS is
itself an `admit`, `PolicyBundle/active` can never be superseded again on that chain.
Unrecoverable from the gateway side. Same class, unchased: `endorse_at_boot!/0` mints
under the bundle in force, so a bundle denying `admit` on `Endorsement` would block
re-endorsement at the next boot. Candidate answers (Tally's call): a kernel floor (a
bundle may not deny the acts that record it), a documented recovery path, or an explicit
"operator's rope" with the failure named in the Kind's `epistemicScope`.

Our side: `policy/bundle.cedar` (+ the starter copy) gained a documented section 4
permitting `Action::"admit"` and `Action::"call_model"`, inert for the gateway itself,
with a comment saying what deleting them means; a trap test pins the failure mode so a
future re-scoping fails in the suite rather than in someone's evidence.

**Operational note that belongs in every agent brief:** the public stack (project `r5e`)
bind-mounts this checkout's `./policy` and polls it every 5 seconds, so editing
`policy/bundle.cedar` changes the live policy attesting Thomas's own Claude Code sessions
within 5 seconds. It happened during this slice (2026-09-04T05:02:11Z; active hash
`0c20ff0161f7…` → `2973992108fb…`). The change adds only actions the gateway never
evaluates, so no decision moved.

**Also:** `docker cp` cannot read the gateway container's `/tmp` (it is a tmpfs under
`read_only: true`; `cp` reads image layers) — `bin/r5e evidence …--fold` uses `tar`
streams both ways. `docs/version-pins.md`'s `repos.lock` example still has placeholder
values and `docs/fold-evidence.md` points an offline reader there for the commit to build
the verifier from; that resolves with S9d.

### 21a. Correction to §21's finding — it is a scope conflation, not a missing floor

Thomas, reading §21: *"why does that bundle have to be in the kernel's store, unless it's
the kernel's bundle? The kernel should govern policy for admission upstream — to itself
or core. Downstream, say enterprise, by default can't edit the kernel policy. It'd be
akin to changing how a core webhook in k8s works. You could, but it's no longer k8s."*

He is right, and §21's framing ("the fold's admission gate has no floor") was wrong. A
floor is a patch that preserves the conflation. Checked in the code:

* `apps/recurse_fold/priv/shapes/` holds `tool-call.json`, `llm-call.json`,
  `fallback.json` — the *presentation* of a request to the engine is already per-Kind.
* `Recurse.Fold.Policy.Cedar` has exactly one bundle slot: `@bundle_ref` =
  `PolicyBundle/active`, read fresh per evaluation.

So the design already accepts that Kinds differ in how they are shown to the engine, but
not in *which policy text governs them*. One bundle must therefore cover both the
kernel's own bookkeeping (`admit` on `CasObject`, `Endorsement`, `KindDefinition`,
`PolicyBundle`) and the tenant's workload rules (`invoke_tool`, `call_model`). Making the
gateway's bundle the fold's active policy — §20(1) — is what merged them, and the
lockout is the most dramatic symptom rather than the problem itself.

**The question for Tally, replacing §21's "floor" recommendation:** should a downstream
tenant's bundle govern the kernel's own admission at all? The k8s reading says no: the
kernel's acts are governed by the kernel's policy, which a deployment does not replace;
the tenant's bundle governs tenant Kinds. That is a per-Kind (or per-group) bundle
binding, a natural extension of the shape mechanism already present, not a new concept.

**Withdrawn:** the pre-activation guard offered in §21 (evaluate a candidate bundle
against the recording acts and refuse to activate). It band-aids the conflation and would
make it harder to undo. Not built.

**Unchanged and fine to ship:** `policy/bundle.cedar` section 4's two permits, its comment
block, and the trap test. They are a symptom-fix, correct for today's single-slot design,
and documented as such.
