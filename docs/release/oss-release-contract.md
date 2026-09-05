# OSS release contract — admission governs enterprise

This records the outcome the release is held to, not a claim that the
implementation already satisfies every line of it.

## Outcome

Enterprise uses the core protocol and the kernel admission pipeline as its
mandatory governance path. It cannot perform the governed operation when that
admission is refused, unavailable, or unable to durably record its decision.
An exported chain from real enterprise traffic verifies offline using a
separately built copy of core's reference verifier. The public build is
reproducible from identified source artifacts. Its documentation describes
demonstrated behavior.

The earlier dual-write path is a migration, not completion. Adding a conformant
record after execution does not make execution dependent on admission.

## Sources and existing decisions

- The charter and normative core specs remain upstream of this implementation.
- The integration decision: the enterprise gateway is brought inside the
  fold — its observations are admitted by the kernel, under a service key the
  node endorses, rather than recorded beside it.
- The policy decision: policy jurisdiction runs downward. Kernel-owned policy
  is itself an admitted bundle; Cedar evaluation lives in the kernel/shared
  layer; there is one decision, taken at admission, that the proxy enforces
  without repeating.
- Spec 012 plan section 21a rejects a tenant policy governing kernel bookkeeping.
- The 2026-09-04 clarification requires operational dependence, not merely
  a package edge or an optional conformant export.

Testing a candidate policy for self-replacement must
not be used as a substitute for jurisdiction. Tenant policy cannot acquire
upstream authority by passing a sample evaluation. Recovery and replacement
must follow the governing layer's authority rules.

## Required invariants and acceptance evidence

| ID | Required behavior | Evidence before release |
|---|---|---|
| R1 | Production dependency graph is gateway → fold/kernel → core verifier; governed service cannot start with admission disabled. | Release graph, clean-start tests, both public readiness endpoints, negative configuration tests. |
| R2 | A model request is admitted before its body is sent upstream. A socket handshake does not authorize every future WebSocket request. | Mock upstream observes zero request bytes for refused/unavailable admission; each WS request has its own admission. |
| R3 | A tool intent is durably admitted before executable tool bytes are released to the client. The gateway enforces that answer without a second independent Cedar decision. | Allow, deny, policy-error and persistence-error tests against real kernel admission and fragmented provider streams. |
| R4 | Parser failure, missing policy, malformed intent, unsupported executable format and incomplete tool frames never become raw-forwarding bypasses. | Adversarial HTTP and WS parser tests, including EOF and exceptions. |
| R5 | Policy activation is an admitted operation. Rejected replacement leaves the previous admitted policy effective. | Filesystem and OCI failure tests, restart after admission/projection interruption. |
| R6 | Tenant workload policy cannot govern kernel CAS, vocabulary, role authority or upstream-owned policy replacement. Scope declarations cannot grant their author upward jurisdiction: at admission, a `PolicyBundle`'s `governs` must be a subset of the Kinds its cited authority covers (`*` = all), refused at `authorize` as a recorded denial. | Deny-all workload policy still permits authorized upstream maintenance; unauthorized scope widening and replacement fail; a key endorsed for `PolicyBundle` alone cannot admit a bundle governing `LlmCall`/`ToolCall`. |
| R7 | Admission preserves the intended enforcement inputs and their provenance. The fold's authenticated service key is not silently relabeled as the client's identity. | Tenant/model/group-sensitive policy tests; recorded evaluation input assertions; unsigned client claims explicitly identified. |
| R8 | Policy cutover has one stated meaning. Each admission uses the admitted policy current at that decision; prior decisions remain bound to the version they actually used. | Activation between model request and tool intent; no stale gateway snapshot decides a later act. |
| R9 | Completion records link to actual opening/tool admissions and never re-admit or re-evaluate them. Interrupted/unknown outcomes remain distinguishable from successful completion. | Crash/retry tests, completion-storage failures, no duplicate tool admissions at stream close. |
| R10 | Payload retention limits cannot silently omit mandatory request admission. Missing evidence is explicit; bounded storage failure prevents the work it was meant to precede. | Retention disabled/oversize/CAS failure tests; exported evidence reports match retained bytes. |
| R11 | Every exposed execution surface meets the contract or is unavailable in this release. | Inventory covering transparent HTTP/WS proxy, older chat endpoint, MCP facade, audit-agent model calls and administrative mutation surfaces. |
| R12 | Offline signature verification binds the claimed actor to an actual valid signer and binds key identifiers to key bytes; empty signatures cannot count as verified. | Hostile producer fixtures with valid outer checkpoints and forged/missing actor signatures; independent review of spec and implementation together. |
| R13 | Build descriptors state what was measured. A process reporting a file hash is not represented as independent runtime attestation. | Source-to-description audit and explicit limits in receipt/export documentation. |
| R14 | A fresh reader can build, exercise allow/deny, restart, export and verify the release with exact source pins and without private sibling repositories. | Clean reproduction, published-source availability checked before eventual publication, separate verifier invocation. |

## Implementation boundaries

The public quickstart is a local, single-tenant demonstration. It does not prove
containment of all activity on a client machine, universal client support,
hardware-backed runtime identity, or protection from a signing-key compromise.
Those are not achieved by adding a disclaimer to a path that otherwise violates
R1–R14: the governed path itself must satisfy the contract.

The enterprise audit UI may remain a projection during migration, provided it
does not make an independent enforcement decision or imply that its legacy
receipt format is the kernel chain. Replacing every visualization is not a
release prerequisite; identifying which evidence it displays is.

## Review and working discipline

Read docs, code and commit history before implementation. Reviews use both
lenses: literal attack on technical claims; intended purpose for charter
principles. Prefer existing architecture and surviving implementation over
new abstractions. Passing old tests that encode transitional behavior is not
acceptance evidence.

Preserve the existing genesis artifacts byte for byte. Run independent
adversarial review on the candidate after implementation, recording findings
and their resolution.

## Deferred ideas preserved from the discussion

- Independent checkpoint custody/witnessing to expose conflicting histories.
- Remote evidence exchange with reader-selected trust policy and assurance.
- Independent Rust/Go/other-language verifiers from the normative spec; their
  development recorded through Recurse, after the recording path is reliable.
- Recurse learning experiments, versioned quality criteria and retained dissent.
- A searchable evidence/tree explorer beyond the current audit UI.

These remain useful follow-ons. They do not enlarge the release contract into
building federation, a general orchestrator, or a new UI before shipping.
