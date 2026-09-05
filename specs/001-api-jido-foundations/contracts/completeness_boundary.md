# Phase-1 Completeness Boundary (Deliverable M)

**Feature**: 001-api-jido-foundations
**Authority**: FR-043 (Phase-1 egress posture and completeness boundary), Constitution v1.3.0
Principle II (Kernel-Level Enforcement, Governance tiers), Principle III (Cryptographic
Provenance — completeness claim).
**Related**: `gateway_runtime_matrix.md` (row 6 — netns egress filter), `failure_matrix.md`.

## Scope and framing

Per FR-043, Phase 1 enforces Principle II via Linux network namespaces (netns) + `iptables`
routing that redirects `0.0.0.0/0` from the agent container into the Gateway. The Gateway
accepts exactly two inbound traffic categories from the agent's netns:

1. **OpenAI-compatible LLM traffic** (`/v1/chat/completions` etc.).
2. **MCP SSE traffic** to Recurse-managed MCP servers.

Everything else is **dropped at the earliest protocol layer possible** and a
**denial attestation** is emitted. Denial attestations share the signed-predicate / outer
container shape of all other attestations (FR-021); the distinguishing field is
`predicate.kind: "egress_denial"` and the subject carries L3/L4/L7 fingerprinting sufficient
for an auditor to classify the attempt without needing the actual packet payload (Principle IV —
detached payloads).

**Honesty about scope.** Full **Code Mode** intercept (arbitrary application-protocol parsing
inside the agent process — e.g., a Recurse shim replacing `libc` or injecting into the
language runtime's HTTP stack) is **out of scope for Feature 001** and is anticipated for a
later feature. Phase-1 completeness is netns-level completeness: we observe every packet that
leaves the namespace. The denial matrix below is thorough at L3/L4/L7-headers; L7-body
parsing for non-accepted protocols is intentionally not performed (we drop before parsing).

## Denial-attestation schema fields (common across all rows)

All denial attestations populate (at minimum) the following fields on the signed predicate per
FR-021; see `attestation.schema.json` for the full shape:

- `predicate.kind`: `"egress_denial"`
- `predicate.denial_layer`: one of `l3` | `l4` | `l7_tls_handshake` | `l7_http_route` | `l7_sni`
- `predicate.protocol`: e.g., `tcp` | `udp` | `icmp` | `quic` | `raw_ip` | `dns` | `http` | `tls`
- `predicate.subject.dst_ip` (if resolvable)
- `predicate.subject.dst_port` (if applicable)
- `predicate.subject.sni` (if TLS ClientHello with SNI extension)
- `predicate.subject.http_host` (if plaintext HTTP Host header — informational only)
- `predicate.subject.attempt_bytes_observed` (header bytes only; no body)
- `predicate.reason_code`: stable enum mapping to `ERR_*` codes per FR-010
- `predicate.session_id`, `predicate.session_chain_epoch` (FR-036 / FR-037)
- `machine_identity`, `principal` (FR-026 IdentityContext; flat top-level fields per `attestation.schema.json`)
- `policy_canonical_hash` (FR-039) — the bundle under which the denial happened
- `completeness`: `"complete"` (Governance tiers per Principle III) or `"advisory"` (BYO shapes)

## Per-protocol matrix

| # | Protocol / Case | Gateway behavior | Denial-attestation fields populated (beyond common) | Reason code |
|---|-----------------|------------------|-----------------------------------------------------|-------------|
| 1 | **TCP / HTTP / SNI-based routing — accept path** (OpenAI-compat + MCP SSE to Recurse-managed MCP servers, SNI / Host match) | **Accept**: terminate TLS, resolve IdentityContext (FR-026), Cedar evaluate, forward. | N/A (success attestation emitted per FR-021, not a denial). | — |
| 2 | **TCP / HTTP — unknown Host header** (plaintext HTTP; Host does not match an allowed upstream) | **Drop** at L7 HTTP route resolution before body parse. | `denial_layer: l7_http_route`, `protocol: http`, `subject.http_host`, `subject.dst_ip`, `subject.dst_port`. | `ERR_EGRESS_NOT_ALLOWED` |
| 3 | **TCP / TLS with SNI — unknown SNI** (TLS ClientHello SNI does not match an allowed upstream) | **Drop** at TLS handshake; do NOT complete the handshake; do NOT attempt ALPN negotiation. | `denial_layer: l7_sni`, `protocol: tls`, `subject.sni`, `subject.dst_ip`, `subject.dst_port`. | `ERR_EGRESS_NOT_ALLOWED` |
| 4 | **TCP / TLS without SNI** (no SNI extension in ClientHello) | **Drop** at TLS handshake. SNI is mandatory for egress in Phase 1 (explicit FR-043 inclusion). | `denial_layer: l7_tls_handshake`, `protocol: tls`, `subject.dst_ip`, `subject.dst_port`, and a `subject.tls_sni_present: false` marker. | `ERR_EGRESS_SNI_REQUIRED` |
| 5 | **TCP — non-TLS, non-HTTP** (e.g., raw TCP to a database port) | **Drop** at L4 after connection accept; send RST to agent. | `denial_layer: l4`, `protocol: tcp`, `subject.dst_ip`, `subject.dst_port`. | `ERR_EGRESS_PROTOCOL_NOT_ALLOWED` |
| 6 | **UDP (any)** | **Drop** at L4 via `iptables` REJECT; Phase-1 agents have no UDP use case. | `denial_layer: l4`, `protocol: udp`, `subject.dst_ip`, `subject.dst_port`. | `ERR_EGRESS_PROTOCOL_NOT_ALLOWED` |
| 7 | **DNS** (UDP/53 or TCP/53 to any resolver other than the Recurse-managed netns-internal resolver) | **Drop** at L4. Phase 1 provides a netns-internal resolver that resolves only allowlisted upstream names; direct DNS egress is denied. (Phase 2 may widen to accept via Recurse-managed resolver per architecture memory.) | `denial_layer: l4`, `protocol: dns`, `subject.dst_ip`, `subject.dst_port`. | `ERR_EGRESS_DNS_NOT_ALLOWED` |
| 8 | **QUIC / HTTP/3** (UDP/443 with QUIC magic) | **Drop** at L4 (UDP already denied per row 6; QUIC-specific attestation recorded for auditor clarity). H3 is not supported in Phase 1. | `denial_layer: l4`, `protocol: quic`, `subject.dst_ip`, `subject.dst_port`. | `ERR_EGRESS_PROTOCOL_NOT_ALLOWED` |
| 9 | **Raw IP (non-TCP, non-UDP, non-ICMP)** (e.g., SCTP, custom protocol numbers) | **Drop** at L3 via `iptables` default-drop. | `denial_layer: l3`, `protocol: raw_ip`, `subject.dst_ip`, `subject.ip_protocol_number`. | `ERR_EGRESS_PROTOCOL_NOT_ALLOWED` |
| 10 | **ICMP — ping to Gateway netns-internal addr** | **Allow** (useful for agent-local readiness / health checks inside the netns). No attestation needed; this is intra-netns. | N/A. | — |
| 11 | **ICMP — any other destination** | **Drop** at L3. | `denial_layer: l3`, `protocol: icmp`, `subject.dst_ip`, `subject.icmp_type`, `subject.icmp_code`. | `ERR_EGRESS_PROTOCOL_NOT_ALLOWED` |
| 12 | **Failed connect — connection reset (RST from upstream)** after an accepted Gateway route | **Surface** as upstream failure to the agent via the protocol-native error shape (FR-016b). Emit attestation with `predicate.kind: "upstream_failure"` (not a denial; this is a permitted route that failed). | `predicate.upstream_failure_cause: "reset"`, `subject.dst_ip`, `subject.dst_port`. | `ERR_UPSTREAM_FAILURE` |
| 13 | **Failed connect — timeout** on upstream connect | **Surface** as upstream failure (FR-016b); emit attestation with `upstream_failure_cause: "timeout"`. | Same as row 12 with `timeout`. | `ERR_UPSTREAM_TIMEOUT` |
| 14 | **Failed connect — agent-side RST / abort mid-ClientHello** | **Record** denial attestation with whatever L3/L4 context was captured; do not synthesize an L7 reason. | `denial_layer: l4`, `protocol: tcp`, `subject.dst_ip`, `subject.dst_port`, `subject.client_aborted: true`. | `ERR_AGENT_ABORTED` |
| 15 | **TLS handshake failure (allowlisted SNI, but cert/negotiation fails)** | **Surface** as upstream failure (row 12/13 sibling); emit attestation with `upstream_failure_cause: "tls_handshake_failure"`. | `subject.sni`, `subject.dst_ip`, `subject.dst_port`, `subject.tls_alert`. | `ERR_UPSTREAM_TLS` |
| 16 | **Fragmented / oversized / malformed IP packet** | **Drop** at netfilter layer (standard hardening); emit a rate-limited denial attestation (one per {dst, minute} bucket to avoid attestation storms). | `denial_layer: l3`, `protocol: raw_ip`, `subject.dst_ip`, `subject.malformed_reason`. | `ERR_EGRESS_MALFORMED_PACKET` |
| 17 | **Loopback / link-local / RFC1918 destinations NOT on the Gateway plumbing** (e.g., agent tries `127.0.0.1:<random>`, `169.254.169.254`, or a private-RFC1918 address outside the netns bridge) | **Drop** at L3 / L4. Cloud instance metadata endpoints (`169.254.169.254`) are an explicit deny target. | `denial_layer: l3`, `protocol: raw_ip` or `tcp`, `subject.dst_ip`, `subject.dst_port`. | `ERR_EGRESS_INSTANCE_METADATA_DENIED` (for 169.254.169.254) or `ERR_EGRESS_NOT_ALLOWED`. |

## Rate-limiting and attestation-storm control

Denial attestations are **per-attempt** by default (high-fidelity auditability). Rows 16
(malformed packets) and 6–8 (UDP / DNS / QUIC flood patterns) MAY be bucketed to one
attestation per `{session_id, dst_ip, minute}` to prevent a malicious agent from generating
attestation storms. The bucketing is a deployment-level config knob exposed via the tier
configuration model (FR-015 / Deliverable F), default **off** in Governance tiers
(attestation completeness per Principle III outweighs storage cost) and **on** in BYO shapes
where completeness is already `advisory`.

## Why "complete" coverage is honest in v1.0 even without full Code Mode

The skeptic's objection: "You don't parse arbitrary application protocols — how can you claim
completeness?"

The answer rests on where the packet-capture point is placed.

Constitution Principle II requires the netns jail in Governance tiers. That jail is a kernel-
level boundary: every packet the agent process emits traverses netfilter on its way out of the
namespace. The Gateway programs netfilter such that **the only allowed L3 next hops are the
Gateway's own interfaces**. This means every packet leaving the agent is either:

1. Routed into the Gateway (accepted path — parsed, attested, forwarded), OR
2. Dropped by netfilter with the Recurse NFLOG target firing a denial attestation.

There is **no third case**. A packet the agent emits cannot silently leave the host because
netfilter sees every packet by kernel invariant. Whether the Gateway parses HTTP inside an
accepted connection or drops a packet whose destination port is 6667 is immaterial to the
completeness claim: **both outcomes produce attestations**. The receipt either says
`predicate.kind: "llm_call"` or `predicate.kind: "egress_denial"`. There is no unaccounted
activity.

Code Mode (future work) buys us **additional intent fidelity** inside accepted connections
— "what did the agent *want* to do with this TCP stream" — but it does not change the
completeness story at the netns boundary. The honest framing is:

> **Phase 1: every packet leaving the agent's netns produces a Recurse attestation — accept,
> deny, or upstream-failure. "Complete" means complete with respect to packet observability.
> The content of accepted application-protocol payloads is attested when Recurse is the L7
> terminator (OpenAI-compat, MCP) and `advisory` otherwise. Wider protocol-body fidelity is
> later work and does not invalidate the Phase-1 completeness claim.**

This is what FR-043 and Constitution Principle III §2.a encode, and what the
`completeness: complete` tag on receipts attests in Governance tiers.

## Tier-scoped completeness

| Tier | Completeness claim on receipts |
|------|---------------------------------|
| Managed SaaS (EKS netns per customer) | `complete` |
| VPC Runner | `complete` |
| Air-Gapped Appliance | `complete` |
| Standalone AI Gateway (no netns) | `advisory` (egress observability is customer-config-dependent per FR-050) |
