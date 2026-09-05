# BYO mTLS Integration Matrix

**Feature**: 001-api-jido-foundations
**User Story**: US2 — Add a new provider without touching core
**Covers**: FR-045a, FR-045b, SC-017
**Status**: Authoritative for Phase-1 go-to-market (Managed SaaS + Standalone Gateway shapes)

This matrix is the single answer to "will my agent code work against the
Recurse Gateway without modification?" — the question Security / Platform
teams ask before greenlighting a pilot. Two integration paths are
supported:

- **Path (a) — in-netns plaintext-to-mTLS shim** (FR-045a). The customer
  agent process is placed in a network namespace where `localhost:8080`
  is the Recurse Gateway, speaking plaintext HTTP. The sidecar shim
  (`spiffe-helper` + a local mTLS-terminating proxy) rewrites the
  plaintext call to authenticated mTLS against the Gateway's real
  endpoint. The agent SDK sees a plain HTTP endpoint; Recurse handles
  identity injection transparently.
- **Path (b) — customer-configured TLS** (FR-045b). The customer wires
  their agent / SDK directly to read the SPIFFE SVID material from
  disk (populated by `spiffe-helper`) and presents it as a client
  certificate against the Gateway's mTLS endpoint. No netns, no sidecar
  proxy — this is the "I'll handle my own TLS" path.

**Honest-verdict policy**: entries below reflect what a Recurse engineer
can defend in a customer call. "Works OOTB" means zero code changes,
zero config beyond env vars and a DNS entry. "Can support" means a
realistic amount of integration glue (a `httpx.Client(verify=..., cert=...)`
wrapper, a `requests.Session` configured once, or similar). "Not supported"
means the client library cannot be made to work on this path without a
fork or upstream change.

## Environment variables and file paths (Path b)

Path (b) requires the customer agent to consume the following, populated
by `spiffe-helper` running as a sidecar (or directly by the customer's
SPIRE agent):

| Variable | Default path (spiffe-helper convention) | Purpose |
|---|---|---|
| `SPIFFE_SVID_CERT` | `/run/spire/certs/svid.crt` | PEM-encoded X.509 SVID leaf certificate |
| `SPIFFE_SVID_KEY` | `/run/spire/certs/svid.key` | PEM-encoded private key for the SVID |
| `SPIFFE_TRUST_BUNDLE` | `/run/spire/certs/bundle.crt` | Trust bundle (root CA pool) for the trust domain; validates the Gateway's own SVID |
| `RECURSE_GATEWAY_URL` | (customer-supplied) | Full URL of the Gateway's mTLS ingress, e.g. `https://gateway.recurse.internal:8443` |

Rotation: `spiffe-helper` writes atomically (write-tempfile, `rename()`).
SDKs / clients that read cert+key once at startup will not pick up
rotations. Long-lived workers MUST either re-read periodically (minutes,
not hours) or subscribe to `spiffe-helper`'s SIGHUP / file-watch hook.
On BEAM we additionally call `:ssl.clear_pem_cache/0` after rotation
(Phase-1 research recommendation 5); other runtimes need their
equivalent.

## The Matrix

| Client | (a) netns shim — FR-045a | (b) customer-configured TLS — FR-045b |
|---|---|---|
| Python `requests` | **Works OOTB.** `requests.post("http://localhost:8080/v1/chat/completions", ...)` — the in-netns shim handles mTLS. No TLS config on the client side. | **Can support.** One-line change: `requests.Session(); s.cert = ("/run/spire/certs/svid.crt", "/run/spire/certs/svid.key"); s.verify = "/run/spire/certs/bundle.crt"`. Cert+key rotation requires re-creating the Session — document the "re-create Session every 10 minutes or on SIGHUP" pattern. |
| OpenAI Python SDK (`openai>=1.0`) | **Works OOTB.** Set `OPENAI_BASE_URL=http://localhost:8080/v1` (or `base_url="http://localhost:8080/v1"` in the client ctor). The SDK uses `httpx` internally; plaintext against the local shim is fine. | **Can support with minor config.** Pass a custom `httpx.Client(cert=(cert, key), verify=bundle)` via the SDK's `http_client=` param (officially supported since `openai` 1.x). Rotation: same story as `requests` — re-create the `httpx.Client`, which means re-create the SDK client. Document the refresh pattern. |
| Anthropic Python SDK (`anthropic>=0.34`) | **Works OOTB.** Set `base_url="http://localhost:8080/v1"` or env `ANTHROPIC_BASE_URL`. The SDK routes through `httpx` — plaintext to the shim works. | **Can support with minor config.** Same mechanism as OpenAI: pass `http_client=httpx.Client(cert=..., verify=...)`. The `anthropic` SDK exposes `http_client` as a first-class init arg. Tested on `anthropic` 0.34.x — older versions (<0.20) do not expose this hook cleanly; document minimum version. |
| Node.js `fetch` (Node 18+ native) | **Works OOTB.** `await fetch("http://localhost:8080/v1/...")`. Native `fetch` is happy to speak plaintext to localhost. | **Can support.** Node `fetch` does not accept cert/key directly; the customer must build an `https.Agent` with `{ cert, key, ca }` and pass via a `dispatcher` (undici). Example: `new Agent({ connect: { cert, key, ca } })`. Rotation means replacing the Agent. More complex than Python but still a one-time setup. |
| Raw `curl` (CLI) | **Works OOTB.** `curl http://localhost:8080/v1/...` — plaintext against the local shim. The common integration-test command. | **Works OOTB.** `curl --cert $SPIFFE_SVID_CERT --key $SPIFFE_SVID_KEY --cacert $SPIFFE_TRUST_BUNDLE $RECURSE_GATEWAY_URL/v1/...` — all four flags map directly to env vars. Canonical demo command for path (b). |
| Go `net/http` | **Works OOTB.** `http.Get("http://localhost:8080/v1/...")` — plaintext to the shim. Go HTTP client is happy. | **Can support.** Build a `tls.Config{ Certificates: []tls.Certificate{certKeyPair}, RootCAs: pool }` and pass via `http.Transport`. `go-spiffe/v2` (the official Go SPIFFE library) provides `workloadapi.NewX509Source()` that handles rotation automatically — customers who already use `go-spiffe` get rotation for free. Customers using raw `net/http` must re-create the `Transport` on rotation. |

## Notes per client

### Python `requests`

Path (b) has a well-known rough edge: `requests.Session.cert` does not
get re-read on each request — it's cached at Session-creation time.
Rotation requires `session = requests.Session()` again. The
`requests-toolbelt` library offers a `SSLAdapter` that can re-read per
request, but that's heavier than most customers want. Recurse's
reference integration note (in
`docs/developer/byo_mtls_python_requests.md` — to be written in Feature
002+) recommends the "Session-per-worker, rebuild every N minutes"
pattern.

### OpenAI Python SDK

Historically `openai<1.0` used a custom HTTP stack that did not
cleanly support client cert config. `openai>=1.0` (released late 2023)
standardised on `httpx` and added `http_client=`. Phase-1 sales
material should list `openai>=1.0` as the minimum tested version.
Path (a) works against *any* version of the SDK — that's the principal
selling point of FR-045a.

### Anthropic Python SDK

Same story as OpenAI. `anthropic>=0.20` exposes `http_client=`; earlier
versions ship an older HTTP layer that would require a fork to inject
client certs. Path (a) works against any SDK version.

### Node.js `fetch`

Node's undici-backed `fetch` is the default since Node 18. Path (b)
works via the `dispatcher` option. A common foot-gun: Node's default
certificate store does NOT trust arbitrary custom roots; the
`SPIFFE_TRUST_BUNDLE` must be explicitly loaded into the `Agent.connect.ca`
option. Document this prominently — customers who miss it will see
`UNABLE_TO_VERIFY_LEAF_SIGNATURE` errors and file support tickets.

### Raw curl

Canonical "does the integration work?" sanity-check command. Every
pilot's demo day includes a `curl` smoke test. Path (b) via `curl` is
the cleanest possible path (b) demo because all SPIFFE material maps
1:1 to CLI flags.

### Go `net/http`

Go is the native habitat of SPIFFE; `go-spiffe/v2` is the upstream
library and makes path (b) nearly free. Customers using `go-spiffe`
should be directed at
`https://github.com/spiffe/go-spiffe/tree/main/v2/examples/spiffe-tls`
rather than rolling their own. Customers using raw `net/http` should
consider moving to `go-spiffe` — it's the path of least friction for
rotation.

## Not-supported cases (explicit)

The following are **not supported** on either path in Phase-1. Engineers
responding to customer asks should decline cleanly rather than attempting
a custom build:

- Browser `fetch` from a web app. Path (a) requires a netns, which
  browsers don't participate in. Path (b) requires presenting a client
  cert, which no browser will do from user-agent JavaScript. Customer
  browser integrations route through the customer's own gateway, not
  Recurse's.
- SDKs that compile the HTTP client statically and do not expose a
  `base_url` or `http_client` hook. Any such SDK is a Path-(a)-only
  customer.
- Clients on platforms without filesystem access to SPIFFE material
  (e.g., serverless functions where `spiffe-helper` cannot run as a
  sidecar). These customers must use path (a) inside a managed
  container shape (the Managed-SaaS BYOC path).
- Mutual TLS with session resumption disabled by the client. Some old
  Python HTTP stacks (`urllib3 < 1.26` without TLS session cache)
  produce poor throughput under rotation; Phase-1 perf guidance
  assumes TLS session resumption is honored.

## What SC-017 is actually checking

SC-017 reads: "An engineer with a Python `requests` / OpenAI SDK /
Anthropic SDK agent can integrate with Recurse Gateway without
modifying the agent code (path a) OR with one pass of config plumbing
(path b)." The matrix above is the evidence. The staged verification
for SC-017 in Feature 002+ will:

1. Spin up a Managed-SaaS Gateway with the in-netns shim.
2. Run the three Python clients and raw `curl` against
   `http://localhost:8080/v1/chat/completions` from inside the netns —
   MUST all succeed with zero agent-code edits (path a).
3. Move the same four clients to a host with `spiffe-helper` running
   and env vars set per the table above — MUST succeed with the
   documented one-pass config changes (path b).

Steps (2) and (3) ship with Feature 002 integration tests.
