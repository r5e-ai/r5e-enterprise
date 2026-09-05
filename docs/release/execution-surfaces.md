# Release execution surfaces

Scope: the default standalone enterprise release.
The [release contract](oss-release-contract.md) defines the admission boundary.
Internal legacy handlers are retained for compatibility tests; their existence
does not make their routes available.

| Surface | Released behavior | Enforcement and evidence |
| --- | --- | --- |
| Transparent HTTP model proxy | Available for configured providers and supported formats | `Fold.Admission.open` retains and admits the request before upstream request bytes. Tool intents cross kernel admission before executable bytes leave, at every upstream status. Parser/admission/transport failures suppress success terminals. See "The upstream's status code" and "What the parser does not gate" below. |
| Transparent WebSocket model proxy | Available for supported provider messages | Each model request has its own opening admission. A successful handshake does not authorize subsequent turns. Tool intents cross the same kernel boundary. |
| `POST /v1/chat/completions` on the audit/API listener | 503 `capability_unavailable` | `ReleaseSurface` halts before authentication, parsing, or legacy handler dispatch. |
| `POST /v1/chat/messages` (audit agent) | 503 `capability_unavailable` | Same release gate. Stored conversation reads remain available. |
| `POST /v1/mcp/:server/tools/:tool` | 503 `capability_unavailable` | Same release gate. Registry reads and operator quarantine do not execute tools. |
| LLM policy suggestion refresh | Unavailable | Explicit `llm` refresh returns 503; default refresh schedules only heuristics. The worker cancels queued jobs and refuses direct execution; no LLM cron entry remains. |
| Policy drafts, simulation, replay, heuristic suggestions | Available behind existing console authentication and action policy | These operate on drafts or recorded evidence. Adopting a suggestion creates a draft; it does not install an active admission policy. |
| Filesystem or OCI policy activation | Available through admitted activation | Source bytes and the active PolicyBundle must be admitted before publishing the local projection. Rejected activation preserves the prior admitted policy. Tenant policy cannot grant itself upstream jurisdiction. |
| OAuth passthrough selected by `auth.openai.com` | Available to that fixed TLS destination, **selected by the client's own `Host` header** | Authentication traffic, outside the model/tool boundary. Bodies are bounded before connecting. This path does not create model-call evidence or establish authenticated client identity for another request. |
| Health, readiness, schema/manifest publication, local connectivity probe | Local responses | No model or tool execution. Historical parser drift does not authorize a failing request. |
| Audit reads, local verification, legacy receipt export and live tail | Available behind their existing authentication/action gates | Display/export the legacy audit projection. Kernel evidence is exported separately; local legacy verification is not core verifier acceptance. |
| Runtime/governance routes listed by `Router.runtime_only_paths/0` | 501 tier mismatch | No runtime or governance execution on the standalone listener. |

The runtime contains internal provider and legacy handler modules. This
inventory covers remotely exposed release routes and scheduled workers, not
arbitrary code an operator loads through a privileged BEAM console.

## The upstream's status code

An upstream status does not decide whether this gateway enforces. Every
response body goes through the same rule, whatever the status line said:

* the parser runs, and a tool intent it finds is admitted through the
  kernel before its bytes are released;
* a body the parser cannot classify is **withheld** — not forwarded, at
  any status — and the client receives a gateway error envelope of type
  `gateway_upstream_unclassified` carrying the upstream's status and the
  sha256 of the bytes this gateway received;
* the status line and the forwarded response headers are the upstream's
  own and are unchanged, so a client that backs off on `429` and
  `Retry-After`, or correlates on `request-id`, still can.

Until the 2026-09-05 review this was not true: a status of 400 or above
switched the proxy into raw forwarding, and a 429 or 500 body carrying a
`function_call` frame reached the client byte-for-byte with no `ToolCall`
admission. The `LlmResponse` records the outcome either way — `errorKind`,
the `upstreamStatus`, and `responseWithheld: true` when the body was not
released.

What a reader loses: a provider error body that this gateway's parser
cannot read no longer reaches the client verbatim. The status, the headers
and the withheld body's hash do. `non_2xx_admission_test.exs` is the
evidence.

## What the parser does not gate

Two block types are forwarded on the provider's own classification rather
than admitted: `server_tool_use` and `mcp_tool_use` in the Anthropic
messages format. In that API both denote execution **on the provider's
side** — a web search, an MCP connector the provider holds — and the
gateway builds no `ToolUseIntent` for them, so no `ToolCall` is admitted
and their `input_json_delta` frames are forwarded. Every *unknown* block
type fails closed, so this is an allowlist of exactly two names, and the
honest statement of the residual is that for those two the gateway trusts
the provider's label: an upstream that relabelled a client-executable call
as `mcp_tool_use` would have its bytes forwarded unadmitted. Gating them
is tracked as debt, not shipped.

Related: the release's own claim is about tool bytes reaching the client.
No claim is made that a permitted client-side tool actually executed.

## Tenants in this release

The quickstart is **single-tenant**. The tenant id comes from the inbound
`x-recurse-tenant-id` header (or the configured default), and it selects
the provider configuration, the Cedar context's `tenant`, and the
`gatewayContext.tenant` on every receipt. Nothing authenticates the caller
against that value: it is an operator convenience for routing and
labelling, with no security meaning, and a tenant-scoped policy rule in a
multi-tenant deployment would be selected by the caller. The gateway
strips the header before forwarding upstream. Deriving the tenant from an
authenticated identity is future work, and until it exists this release
should be run with one tenant.

## Evidence boundaries

The gateway records its observations and signs admissions with its service
key. Client identifiers and groups extracted from traffic remain observed
claims — `gatewayContext.principal_source` says how each one was obtained
(`jwt`, `client_metadata`, `mtls_svid`, `anonymous`), which is a statement
about provenance and never about verification: none of the four is an
authenticated identity in this release, and a policy rule can refuse
`anonymous` precisely because the difference is now on the record. An
admitted tool intent establishes permission to release that intent;
the gateway does not observe the client's eventual local tool execution.

An interrupted response can retain a partial response artifact. Transport
errors may prevent the client library from returning all received wire bytes
as ordered response events; the retained bytes and hash cover the captured
response prefix, not a packet capture. Specifically: when `Mint.HTTP.stream/2`
returns `{:error, connection, reason, responses}`, the `responses` list can
hold valid events decoded from earlier frames of the same message, and the
proxy discards that list in both its window-message and socket-message
paths. Those bytes never reach the response hasher, capture buffer or
parser, so an interrupted record can describe only the prefix captured
before the failing batch even though more bytes were received. No
admission bypass follows — discarded tool or terminal bytes are not
forwarded — but the current impact is lost evidence and a failed request,
and response-evidence descriptions must allow a captured prefix on
transport failure rather than promise every received byte. A reset before
response headers has no Completion artifact. Completion denotes retained response bytes, and must be
read together with the LlmResponse outcome and error kind.

Engine descriptors report hashes of deployed files and the platform reported
by the producer. They are boot-time, process-produced measurements; they do
not independently attest loaded code, detect later process compromise, or
prove a source-to-binary correspondence. Opening and per-tool receipts bind
their own policy versions. The legacy aggregate's single policy hash is
explicitly scoped to the opening model admission.

ToolCall metadata names that earlier version `opening_model_policy_hash`.
It can differ from the policy governing the tool after a policy activation;
the tool receipt and its cited evaluation identify the policy actually used.
The gateway does not submit an ambiguous `cedar_bundle_hash` as if a pre-read
could establish which policy a later admission will use.

## Regression evidence

`admission_boundary_test.exs` checks closed execution routes, queued suggestion
cancellation and manual refresh behavior. `transport_real_admission_test.exs`
uses actual kernel policy/admission with a mock provider for allow, deny,
cutover, missing evidence and engine failure. `non_2xx_admission_test.exs`
runs the review's own probes: a `function_call` frame in a 429 and a 500
body is admitted, and an unreadable error body is withheld with its status
and hash reported. `streaming_proxy_http2_test.exs`
covers HTTP/2 request delivery, early rejection and reset-before-response.
Loader and OCI manager tests cover admission before projection publication.
