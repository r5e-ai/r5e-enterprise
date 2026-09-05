# Gateway / Runtime Responsibility Matrix (Deliverable D)

**Feature**: 001-api-jido-foundations
**Authority**: FR-034 (two OTP applications, single BEAM per customer), FR-035 (Matrix is
authoritative subsystem → application placement reference), SC-006 (coverage = 100% of v1.0
subsystems identified at Feature 001 time).
**Related**: `completeness_boundary.md` (T070 / Deliverable M), `failure_matrix.md` (T071 /
Deliverable N), `docs/developer/architecture.md`.

## Narrative

Per Constitution v1.3.0 Principle I and FR-034, Recurse Phase-1 ships a **single codebase with
two OTP applications** co-located on one BEAM node per customer deployment
(`:recurse_gateway`, `:recurse_runtime`). There is no in-BEAM multi-tenancy — tenant identity is
a fixed deployment-config value (FR-019). The split is functional, not a network boundary.

**Gateway = hot-path, low-latency, largely-stateless-per-request.** It terminates customer
TLS, resolves IdentityContext (FR-026), evaluates Cedar policy, signs attestations, and emits
them. It carries the Data / Control / Governance / Audit plane HTTP surface
(`apps/recurse_gateway/lib/recurse_gateway/planes/{data,control,governance,audit}/`).

**Runtime = lifecycle, batch, async, stateful.** It owns agent-container orchestration, netns
provisioning, session-epoch tracking, durable session-chain CAS, and the Broadway-backed
pipeline that commits session Merkle roots to the global ledger (FR-036 / FR-037 / FR-040).

**Intra-node coordination** uses in-BEAM primitives only — no intra-process RPC over the wire:
- `GenServer.call/2` for synchronous request/response within a plane
- `Phoenix.PubSub` for fan-out (e.g., attestation → multiple subscribers: SIEM forwarder,
  session accumulator, metrics)
- `Broadway` pipelines for batch/retry workloads (global-ledger commit pipeline)
- `Oban` for scheduled jobs (interim-commit scheduler per FR-037)
- `Ecto` transactions for local-CAS writes that must be atomic with session-state transitions
- `Registry` for per-session process lookup

The **Standalone AI Gateway** shape (FR-050) ships the Gateway app only; the Runtime app is
absent. Subsystems that logically live in Runtime appear as `inactive` or are replaced by a
`gateway-stub` that records enough for audit but performs no lifecycle work
(e.g., no agent-container orchestration — the Standalone shape is LLM-call-audit-only).

## Legend

- **Owning app**: `gateway` | `runtime` | `gateway-with-runtime-delegation`
  - `gateway-with-runtime-delegation` = Gateway handles the request on the hot path but
    delegates durable / batch work to Runtime (e.g., attestation emit → Runtime session chain).
- **Coordination edges**: `→ <subsystem>: <primitive>`
- **Session boundary sensitivity**: `yes-mandatory` (participates in session commit; commit fails
  if this subsystem fails), `yes-optional` (contributes but failure is degraded/recoverable),
  `no` (orthogonal to session lifecycle).
- **Standalone availability**: `active` | `inactive` | `gateway-stub`.

## Matrix

| # | Subsystem | Owning app | Intra-node coordination edges | Session-boundary sensitivity | Standalone |
|---|-----------|-----------|-------------------------------|-------------------------------|------------|
| 1 | TLS termination + SPIFFE peer verification (ingress) | gateway | → IdentityContext resolver: `GenServer.call`; → Telemetry: `:telemetry.execute` | no | active |
| 2 | IdentityContext resolver (FR-026) | gateway | → TLS ingress: callee; → PrincipalProvider: `GenServer.call`; → Cedar evaluator: passes immutable struct | yes-mandatory (every receipt carries it per FR-026) | active (binding into FR-053 broker in Standalone) |
| 3 | Cedar policy evaluator (Rustler NIF wrapper) | gateway | → Policy Bundle cache: `GenServer.call`; → Attestation envelope constructor: returns decision | yes-mandatory (decision is a signed predicate field per FR-021) | active |
| 4 | Attestation envelope constructor (FR-021) | gateway | → SecretsProvider (signer key): `GenServer.call`; → Audit Payload Broker: `Phoenix.PubSub` "attestations:emitted"; → Runtime session chain (via PubSub) | yes-mandatory | active (emits; no Runtime session chain — Standalone writes directly to local CAS in gateway-stub mode) |
| 5 | RFC 8693 token exchange client (FR-047) | gateway | → PrincipalProvider: `GenServer.call`; → SecretsProvider: `GenServer.call`; → MCP facade: returns minted bearer token | no (attestation of exchange is session-scoped via #4) | inactive (Standalone has no MCP facade or token exchange per FR-050 shape) |
| 6 | Completeness-boundary netns egress filter (FR-043) | gateway-with-runtime-delegation | → Netns provisioner (Runtime): initial program of `iptables` rules; → Attestation envelope constructor: denial-attestation emit on drop | yes-optional (denials are attestation events; session continues) | inactive (Standalone has no netns; customers route to Gateway by DNS/config per FR-050) |
| 7 | SIEM Log Forwarder (FR-048 surface 1) | gateway | → Audit Payload Broker: `Phoenix.PubSub` subscriber on "attestations:emitted"; → External SIEM: HTTP / syslog | no | active |
| 8 | Standalone Identity Broker (FR-053) | gateway | → PrincipalProvider: `GenServer.call`; → IdentityContext resolver: supplies principal claim | yes-mandatory (when Standalone is using broker as IdP) | active (Standalone only; inactive in Governance tiers) |
| 9 | MCP facade / routing | gateway | → RFC 8693 token exchange: `GenServer.call`; → Cedar evaluator: per-tool-call check; → Attestation envelope constructor: per-call emit | yes-mandatory | inactive |
| 10 | Audit Payload Broker (FR-030) | gateway | → StorageProvider: `GenServer.call`; → Cedar evaluator: authorization check on fetch; → SIEM Forwarder / Export Evidence: via PubSub on emit | no | active |
| 11 | Policy Bundle cache + supersede handling (FR-039 / K) | gateway | → PolicyProvider: `GenServer.call` on bundle refresh; → Cedar evaluator: hot-swap with supersede semantics; → Telemetry | yes-mandatory (bundle hash stamps every attestation) | active |
| 12 | Netns provisioner (Runtime-owned) | runtime | → Agent-container orchestrator: `GenServer.call`; programs kernel via `Port` to `ip` / `iptables` | no | inactive |
| 13 | Agent-container orchestrator | runtime | → Netns provisioner: `GenServer.call`; → Session manager: spawn notification via `Phoenix.PubSub` "sessions:spawn"; → Registry: `{:via, Registry, {Recurse.Runtime.Sessions, session_id}}` | yes-mandatory (session lifecycle bound to container lifecycle) | inactive |
| 14 | Session manager + epoch tracker (FR-036 / FR-037 / FR-044) | runtime | → Agent-container orchestrator: subscriber; → Local session-chain CAS: `Ecto.Multi`; → Interim-commit scheduler: `Oban.insert`; → Global-ledger commit pipeline: `Broadway` producer on epoch close | yes-mandatory | inactive (Standalone has per-request attestation, not session lifecycle; see FR-050) |
| 15 | Local session-chain CAS (durable WAL) | runtime | → Session manager: called within `Ecto.Multi`; → StorageProvider: optional blob offload | yes-mandatory | gateway-stub (Standalone writes minimal per-call local record to Gateway-local CAS; no session epochs) |
| 16 | Global-ledger commit pipeline (Broadway) | runtime | → Session manager: Broadway producer; → LedgerProvider: `GenServer.call` per batch; → Telemetry; → Alerting (`recurse_ledger_commit_*`) | yes-mandatory (commit closes the session per FR-040) | inactive |
| 17 | Interim-commit scheduler (Oban) | runtime | → Session manager: job handler; → Global-ledger commit pipeline: producer insert on tick | yes-optional (interim commits bound latency per FR-037; absence degrades but does not corrupt) | inactive |
| 18 | Blast-radius simulation engine (FR-049.3, historical replay) | runtime | → Local session-chain CAS: read-only; → Cedar evaluator: candidate policy eval; → Governance plane handler: returns simulation result | no (never mutates session state per FR-049.3) | inactive (Standalone gets only the authoring surfaces it can serve locally; blast-radius is Governance-tier) |
| 19 | Discovery-to-Policy generator (FR-049.2, Wiz pattern) | runtime | → Local session-chain CAS: read flagged attempts; → Governance plane handler: `GenServer.call`; → PolicyProvider: draft submission | no | gateway-stub (Standalone's primary wedge per FR-050 — runs in Gateway with local CAS) |
| 20 | Telemetry + Prometheus exporter | gateway-with-runtime-delegation | → all subsystems: `:telemetry.execute`; aggregated via `telemetry_metrics_prometheus` | no | active |
| 21 | Healthcheck / readyz | gateway | → IdentityContext resolver, Cedar evaluator, Policy Bundle cache, LedgerProvider probe: `GenServer.call` with short timeout | no | active |
| 22 | Router / Bandit listener + plane dispatch (Data / Control / Governance / Audit) | gateway | → all plane handlers: `Plug.call`; → Telemetry | no | active (shape differences are response-content level per FR-008, not path level) |
| 23 | Policy author surfaces — Cedar Playground simulate API (FR-049.1) | gateway-with-runtime-delegation | → Cedar evaluator: isolated copy against candidate policy; → Local session-chain CAS (via Runtime): optional historical attestation sampling | no (simulation; no mutation) | active |
| 24 | Export Evidence builder (FR-048 surface 2) | gateway-with-runtime-delegation | → Audit Payload Broker: `GenServer.call`; → Local session-chain CAS (via Runtime): read attestations + epoch proofs; → SecretsProvider: include signer public keys | no | active (Standalone exports are single-call scoped, not session-scoped) |
| 25 | CLI Verifier artifact surface (FR-048 surface 3) | gateway | serves static verifier manifest + checksums; no intra-node edges beyond router | no | active |

**Coverage check (SC-006)**: every v1.0 subsystem enumerated in `plan.md` Project Structure
under `apps/recurse_gateway/lib/recurse_gateway/` and `apps/recurse_runtime/lib/recurse_runtime/`
is represented above. New subsystems added in Feature 002+ MUST append a row here before
landing code, per FR-035.

## Placement heuristic (for future features)

When adding a new subsystem, use this decision rule:

1. Is it on the synchronous request path with strict latency requirements? → **gateway**.
2. Does it own state across many requests or across session boundaries? → **runtime**.
3. Does it do both (hot-path read, async write)? → **gateway-with-runtime-delegation**; the
   Gateway handles the request and emits a `Phoenix.PubSub` / `Broadway` message to the Runtime.

Record the placement decision, coordination edges, and session-boundary sensitivity here at PR
time. This Matrix is the authoritative placement reference per FR-035.
