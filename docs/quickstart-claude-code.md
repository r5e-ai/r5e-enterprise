# Quickstart with Claude Code

For someone with Docker and Claude Code on their own machine who wants to see a model call become a receipt, a destructive command get denied, and the evidence verify offline. About 15 minutes.

Docker with Compose v2, an extracted coordinated source archive, Claude Code signed in, `curl`, `jq`, `unzip`, `openssl`, and `xxd`; `cargo` only for the legacy `bin/r5e evidence verify` path.

The client-output examples below were captured on 2026-09-02, before the
mandatory admission release. IDs, policy hashes and denial wording vary;
they are historical examples, not the acceptance record for this candidate.
The current release smoke uses a mock provider to exercise allow, deny,
restart and both export formats.

## 1. Configure the source archive

Start in the extracted directory containing `repos.lock.json` and the three
source trees:

```
cd r5e-enterprise
export R5E_BUILD_CONTEXT="$(cd .. && pwd)"
bin/r5e init
```

The coordinated archive is already frozen and contains no VCS metadata.
Keep `R5E_BUILD_CONTEXT` set in the shell used for Compose. Developers with
three sibling **JJ checkouts** can instead run
`python3 scripts/prepare-release.py` (Python 3.12+) to create the default
`.release-context`; do not run that preparer on the extracted archive.

The stack publishes ports 4000 (dashboard) and 4443 (proxy) on loopback.
`init` checks both and names the variable to set in `.env` if one is taken.
A second stack needs distinct ports, a distinct `R5E_GATEWAY_CONTAINER`,
and a distinct Compose project name;
its database and kernel history must have their own volumes.

## 2. Start the stack

```
docker compose up -d
bin/r5e status
```
```
/healthz {"components":{"broker_jwks":"ok","cedar_policy":"ok","gateway":"ok","kms":"ok","ledger":"ok","storage":"ok"},"status":"ok"}
/readyz  not ready: jwks_warm pending until the first login (bin/r5e login)
```

The first `up` builds the gateway image, which takes several minutes. `status` exits 0 with exactly these two lines; after the sign-in below the `/readyz` line becomes the endpoint's JSON.

## 3. Sign in and open the dashboard

```
bin/r5e login
```
```
r5e login: {"dev_login":true,"principal_subject":"local-dev@r5e","recurse_role":"platform_operator","tenant_id":"01TEN_LOCAL"}
r5e login: /v1/auth/me -> {"browser_session_id":"c203e20e6c7796ae80c4d2a52793a141","principal_subject":"local-dev@r5e","recurse_role":"platform_operator","session_expires_at":"2026-09-03T06:08:34Z","session_idle_timeout_at":"2026-09-02T23:08:34Z","tenant_id":"01TEN_LOCAL"}
r5e login: GET /v1/audit/receipts?limit=1 -> HTTP 200

cookie jar: /path/to/r5e-enterprise/.r5e/cookies.txt (curl -b /path/to/r5e-enterprise/.r5e/cookies.txt http://localhost:4000/v1/audit/receipts)
dashboard:  http://localhost:4000/admin/dashboard
  The cookie above is in curl's jar, not in your browser. To sign the browser in:
  open http://localhost:4000/healthz, open the devtools console, paste the line below,
  then open http://localhost:4000/admin/dashboard.
  fetch('/admin/test/login',{method:'POST',headers:{'Content-Type':'application/json'},body:'{"principal_subject":"local-dev@r5e","recurse_role":"platform_operator"}'}).then(r=>r.status)
```

## 4. Point Claude Code at the gateway

```
bin/r5e claude-code setup
```
```
# Claude Code -> r5e gateway (proxy listener on http://localhost:4443)
export ANTHROPIC_BASE_URL=http://localhost:4443
export NO_PROXY=localhost,127.0.0.1
# Then: claude -p "reply with the single word ok"   (existing claude.ai login or API key is forwarded as-is)
# Persist for the Claude desktop app's Code tab: bin/r5e claude-code setup --write-settings
```

## 5. A first prompt

```
echo "reply with the single word ok" | DISABLE_AUTOUPDATER=1 DISABLE_TELEMETRY=1 claude -p
```
```
ok
```

The two variables keep the CLI from updating itself or phoning home during the demo; both of those go directly to Anthropic, not through the gateway. Every model call is a receipt, and a prompt can be more than one call (the turn, a session title, a side query). The newest one, the dashboard's newest `LLM_CALL` row, names the account id Claude Code sends; yours differs:

```
curl -s -b .r5e/cookies.txt "http://localhost:4000/v1/audit/receipts?limit=1&event_kind=llm_call_attested" | jq -r '.receipts[0].signed_predicate | [.event_kind, .principal.subject] | @tsv'
```
```
llm_call_attested	claude-code:<your-account-id>
```

## 6. A denied command

The shipped `policy/bundle.cedar` forbids the `Bash` tool when the command contains `rm -rf`. Make a scratch directory and ask for exactly that:

```
mkdir -p scratch
echo "Run exactly this shell command and tell me what happened: rm -rf scratch" | DISABLE_AUTOUPDATER=1 DISABLE_TELEMETRY=1 claude -p --allowedTools Bash
```
```
Tool call 'Bash' (call_id: toolu_013KGk3GZPDHnjCrxGunxgaf) was blocked by org policy.
- Rule: policy6
- Reason: denied_by_cedar_policy
- Policy bundle: 2973992108fb
- Tenant: 01TEN_LOCAL
- Principal: claude-code:<your-account-id> (obo_human)
- Session: 01TEN_LOCAL:01M1J2NT8FWQ8BCCD75T6D0J8F
```

The gateway replaced the tool call in the response stream with that text, so Claude Code never ran the command and `scratch` still exists. On the dashboard a denial is two red rows: the `tool_use_denied` receipt, and the model call it was extracted from, whose policy decision is deny. The same two from the API:

```
curl -s -b .r5e/cookies.txt "http://localhost:4000/v1/audit/receipts?limit=1&event_kind=tool_use_denied" | jq -r '.receipts[0].signed_predicate | [.event_kind, .policy_canonical_hash] | @tsv'
curl -s -b .r5e/cookies.txt "http://localhost:4000/v1/audit/receipts?limit=1&event_kind=llm_call_attested" | jq -r '.receipts[0] | [.signed_predicate.event_kind, .outer_container.policy_decision] | @tsv'
```
```
tool_use_denied	2973992108fb76adaf641b0886c8c4d46d16634699e3f7e0d7abd35e8c673cdf
llm_call_attested	deny
```

## 7. Export and verify both evidence formats

```
bin/r5e evidence export
bin/r5e evidence verify
bin/r5e evidence export --fold
bin/r5e evidence verify --fold
```
```
r5e evidence export: run_id=71d585be-a012-4c22-a9fa-451eb1434fc6 event_kind=tool_use_denied
r5e evidence export: wrote /path/to/r5e-enterprise/.r5e/evidence.zip (131630 bytes)
[5] payload_hash
    MATCH (predicate body predicate/71d585be-a012-4c22-a9fa-451eb1434fc6.json, 1301 bytes, hashes to payload_hash)
[6] verification_level + tier_completeness_advisory
    tier_completeness_advisory: partial — the gateway attests the calls routed through it;
                                coverage is a property of the deployment (see docs/deployment-shapes.md)
VERIFY: PASS (strict, anchored)
```

The displayed output is from the enterprise ledger projection. Its zip holds the signed envelope, the predicate body it hashes (`predicate/<run_id>.json`, where `principal_source` lives), the request and response bytes the body hashes, the inclusion proofs, the Cedar source of the bundle that decided, and the signer's public key. The first legacy `verify` builds `cedar-canonical-hash` with `cargo` (about a minute); without `cargo`, step 4 prints `NOT CHECKED` and the verdict is `FAIL`.

The `--fold` commands export the authoritative kernel admission chain and run the core verifier bundled in the image. Read its complete `checked`, `findings`, and `not checked` sections. [The fold evidence guide](fold-evidence.md) explains the two formats and shows how to build and invoke the core verifier separately from pinned source.

## 8. Change the policy

The gateway re-reads `policy/bundle.cedar` within 5 seconds of a change. Append a rule that keeps the agent out of `.env` files and read the bundle hash again:

```
cat >> policy/bundle.cedar <<'EOF'
forbid (principal, action == Action::"invoke_tool", resource == ToolUse::"Read")
when { context has tool_args && context.tool_args has "file_path" && context.tool_args.file_path like "*/.env*" };
EOF
sleep 6; curl -s http://localhost:4000/readyz | jq -r .policy.active_hash
```
```
b691e6396714f5098824d19b54bdceb6285096b5b6064dea4b44847b2a55089e
```

A successful activation changes the policy used by subsequent workload admissions. Each opening and tool receipt binds its own decision: a tool admitted after activation can use a newer policy than its model opening. The legacy aggregate hash remains scoped to that opening. To take the bundle from a git repository instead, see [policy from a git repository](policy-from-git.md). `docker compose down` stops the stack; the ledger, the signing key, and the receipts stay in the volumes until `docker compose down -v`.

Preserve the kernel volume as a whole. [Storage recovery](release/storage-recovery.md) explains startup refusals and the boundary between restoring history and starting a new one.
