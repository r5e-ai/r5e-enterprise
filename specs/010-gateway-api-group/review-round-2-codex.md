# Spec 010 — adversarial review, round 2, second discriminator

**Discriminator**: Codex CLI 0.149.1, `gpt-5.6-sol`, reasoning high, read-only sandbox, 2026-09-02. Target: r2 (bookmark `spec/010-r2`). Verbatim; dispositions in `review-round-3.md`.

---

## A. Major findings

### A1 — Policy evaluation and typed-ref validation occur in the wrong order

**Failure scenario.** `PolicyShape` evaluates `llmCall.spec.model`, but the normative pipeline still authorizes before validation, and the current kernel passes the raw caller request directly to policy before looking up its Kind or checking refs ([admission.ex:38](~/repos/r5e-group/r5e-kernel/lib/r5e/admission.ex:38), [02-kinds-and-admission.md:51](~/repos/r5e-group/r5e-core/spec/02-kinds-and-admission.md:51)). Either the engine independently resolves an unvalidated `event:` string—creating two potentially divergent resolvers—or it cannot implement the promised path. The path contract also says “one event hop” but grammatically permits only `llmCall`, leaving `toolCall.spec.tool` undefined; wildcard shapes cannot be validated against “the target Kind” because `kind: "*"` has no target schema ([spec.md:69](~/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/spec.md:69), [spec.md:134](~/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/spec.md:134)).

**Concrete proposal.** Add a kernel-owned, side-effect-free `prepare` stage before authorization: resolve the KindDefinition, structurally validate typed refs, produce a normative JSON-Pointer-keyed resolution manifest, and pass that exact prepared object to both policy and final validation. Define one-hop traversal generically over any property declared as an event ref, and restrict `*` shapes to envelope fields/literals.

**Item attacked.** S1, S3, FR-003, FR-008, KP-8, one-hop event paths.

### A2 — The replay capsule permits rerunning Cedar, but does not establish what implementation produced the decision

**Failure scenario.** `request + entities`, bundle, shape, and a free-form `engineVersion` can reproduce a result if the auditor independently finds exactly the right Cedar build. They do not bind the engine binary/source, request-envelope format, target KindDefinition, resolver semantics, or shaping implementation. Those matter here: current Cedar derives principal type, UIDs, attributes, and null stripping in code ([cedar.ex:138](~/repos/r5e-group/r5e-enterprise/apps/recurse_fold/lib/recurse_fold/policy/cedar.ex:138), [cedar.ex:194](~/repos/r5e-group/r5e-enterprise/apps/recurse_fold/lib/recurse_fold/policy/cedar.ex:194), [cedar.ex:204](~/repos/r5e-group/r5e-enterprise/apps/recurse_fold/lib/recurse_fold/policy/cedar.ex:204)), while even matched policy IDs vary with Cedar behavior ([cedar.ex:38](~/repos/r5e-group/r5e-enterprise/apps/recurse_fold/lib/recurse_fold/policy/cedar.ex:38)). FR-008 leaves the representation of the “exact canonical engine input” unspecified ([spec.md:88](~/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/spec.md:88)).

The capsule also creates a disclosure regression. Current policy inputs may contain inline tool arguments and principal claims ([cedar_tool_use_gate.ex:185](~/repos/r5e-group/r5e-enterprise/apps/recurse_gateway/lib/recurse_gateway/llm_proxy/cedar_tool_use_gate.ex:185), [cedar_tool_use_gate.ex:338](~/repos/r5e-group/r5e-enterprise/apps/recurse_gateway/lib/recurse_gateway/llm_proxy/cedar_tool_use_gate.ex:338)). Putting the exact input into an exported CAS object either makes those values permanent or makes replay disappear when they are shredded, contrary to the unqualified replay promise and core’s predicate-minimization rule ([04-evidence-and-disclosure.md:5](~/repos/r5e-group/r5e-core/spec/04-evidence-and-disclosure.md:5)).

**Concrete proposal.** Define one versioned `PolicyEvaluationRecord` encoding that includes exact request bytes, exact entity bytes, request-format version, target KindDefinition address, complete resolution manifest, and an `engineBuildAddress` referencing reproducible source/build evidence. Sensitive inputs should be detached/encrypted commitments, and the claim narrowed to replay “when disclosed.”

**Item attacked.** S2, FR-008, stance 10, `engineVersion`, replayability and leakage.

### A3 — `PUT /cas` is an admission bypass, not an inert preprocessing step

**Failure scenario.** Core says admission is the sole gate through which anything enters any substrate and explicitly says requests are acts ([02-kinds-and-admission.md:49](~/repos/r5e-group/r5e-core/spec/02-kinds-and-admission.md:49), [02-kinds-and-admission.md:64](~/repos/r5e-group/r5e-core/spec/02-kinds-and-admission.md:64)). KP-2 instead lets arbitrary bytes enter CAS without an actor, policy decision, receipt, quota, retention rule, or log position ([spec.md:105](~/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/spec.md:105)). A client can upload gigabytes or prohibited content, fail the referencing admission, and leave permanent unowned orphans. This is state mutation even when no later act references it.

**Concrete proposal.** Make uploads authenticated, quota-bound temporary staging objects with opaque upload names. The referencing admission hashes and atomically promotes the staged bytes into CAS, records address/size/owner in its resolution manifest, and garbage-collects abandoned staging objects.

**Item attacked.** New `PUT /cas` design, KP-2, S11’s purported admitted natlang lineage.

### A4 — KP-9 closes only the happy-path race and serializes the most expensive work

**Failure scenario.** A node-wide lock around `authorize → record → admit` serializes Cedar evaluation, resolution, CAS writes, and synchronous disk append. Current Cedar evaluation invokes the NIF synchronously ([cedar.ex:88](~/repos/r5e-group/r5e-enterprise/apps/recurse_fold/lib/recurse_fold/policy/cedar.ex:88)); log append performs a synchronous file write ([log.ex:95](~/repos/r5e-group/r5e-kernel/lib/r5e/log.ex:95)). Calling that “cheap” is incompatible with the inherited target of 100 concurrent streams and sub-50-ms intent decisions ([009 spec:131](~/repos/r5e-group/r5e-enterprise/specs/009-llm-api-proxy/spec.md:131), [009 spec:165](~/repos/r5e-group/r5e-enterprise/specs/009-llm-api-proxy/spec.md:165)).

It also does not fix the dangerous failure: the kernel records a grant before writing the resource ([admission.ex:137](~/repos/r5e-group/r5e-kernel/lib/r5e/admission.ex:137), [admission.ex:165](~/repos/r5e-group/r5e-kernel/lib/r5e/admission.ex:165)). If `PolicyBundle/active` is recorded and the store write fails, the lock is released with the old bundle still active; a later receipt can cite the old policy after the new bundle’s chain position, contradicting Story 2 ([spec.md:51](~/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/spec.md:51)). Replay repairs it only after restart ([bootstrap.ex:37](~/repos/r5e-group/r5e-kernel/lib/r5e/bootstrap.ex:37)). Per-node locking additionally says nothing about deployments sharing policy across nodes.

The stated all-deny recovery—editing the store “is not an act”—is an explicit exempt policy mutation, contrary to the same admission law ([spec.md:72](~/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/spec.md:72)).

**Concrete proposal.** Evaluate optimistically outside the append lock, then compare the captured bundle/shape generations while committing. Retry on generation change, and poison/fail-stop admission after any post-record substrate failure until replay completes. Define a precommitted, signed break-glass admission rule instead of direct store mutation.

**Item attacked.** S4, KP-9, all-deny recovery.

### A5 — Naming remains non-canonical and cannot identify resource generations

**Failure scenario.** S9 asked for explicit activation targeting, but r2 still admits any `PolicyBundle` name and merely says only `active` is evaluated ([spec.md:87](~/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/spec.md:87)). That preserves accepted-but-inert configuration despite claiming draft/activation are collapsed. `AgentSession` now requires a name, but nothing prevents reusing it: two identical empty-session admissions have the same name and `specAddress`, so a later ref’s `{name, resolvedSpecAddress}` cannot distinguish which “opened span” it means. Current storage simply overwrites by name ([resource_store.ex:21](~/repos/r5e-group/r5e-kernel/lib/r5e/resource_store.ex:21)).

Artifacts have the inverse problem: FR-003 says their name is their content address, but the kernel accepts a caller name whenever supplied and content-names only absent names ([admission.ex:124](~/repos/r5e-group/r5e-kernel/lib/r5e/admission.ex:124)).

**Concrete proposal.** Make naming a declarative mode: `content` for artifacts, `literal: "active"` for PolicyBundle, `derived` for PolicyShape, and `required-versioned` for mutable resources. Persist the resolved resource admission event/generation as well as its spec address.

**Item attacked.** S9, FR-003, FR-007, FR-009, KP-10.

### A6 — `supersedes` does not define a unique corrected history

**Failure scenario.** A new `LlmResponse` can supersede a response belonging to a different `llmCall`; likewise a `ToolResult` can supersede one for a different `toolCall`. Typed same-Kind validation does not prevent either. Two responses may also both supersede A, leaving two heads; “consumers follow `supersedes` to the latest” does not say whether highest sequence wins, both remain valid, or admission rejects the branch ([spec.md:74](~/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/spec.md:74), [spec.md:95](~/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/spec.md:95)).

**Concrete proposal.** Require the superseded event to be the current unsuperseded head for the same anchor (`llmCall` or `toolCall`), checked atomically at admission. Reject branching and cross-anchor corrections.

**Item attacked.** New `supersedes` design, FR-015.

### A7 — The enterprise mapping remains silently lossy and changes policy semantics

**Failure scenario.** The table claims every source field is accounted for ([spec.md:138](~/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/spec.md:138)), but omits `upstream_host`, `started_at`, `completed_at`, `principal_kind`, `chatgpt_account_id`, argument size, and extraction time, all present in the actual source model ([attestation_emitter.ex:156](~/repos/r5e-group/r5e-enterprise/apps/recurse_gateway/lib/recurse_gateway/llm_proxy/attestation_emitter.ex:156), [attestation_emitter.ex:443](~/repos/r5e-group/r5e-enterprise/apps/recurse_gateway/lib/recurse_gateway/llm_proxy/attestation_emitter.ex:443), [attestation_emitter.ex:497](~/repos/r5e-group/r5e-enterprise/apps/recurse_gateway/lib/recurse_gateway/llm_proxy/attestation_emitter.ex:497)). One `correlation` cannot losslessly represent session, run, turn, and step IDs, and destination chain sequence is not equivalent to source `session_chain_position`.

More importantly, enterprise pins the bundle at call start so every intent in one stream uses the same policy ([cedar_tool_use_gate.ex:30](~/repos/r5e-group/r5e-enterprise/apps/recurse_gateway/lib/recurse_gateway/llm_proxy/cedar_tool_use_gate.ex:30)); fold reads `PolicyBundle/active` afresh per decision ([cedar.ex:73](~/repos/r5e-group/r5e-enterprise/apps/recurse_fold/lib/recurse_fold/policy/cedar.ex:73)). A mid-stream activation therefore creates a mixed-policy call, silently changing an enforcement guarantee.

**Concrete proposal.** Replace the grouped rows with one row per source field and mark each as preserved, derived, deliberately dropped, or semantically changed. Add a typed call-start policy snapshot to `LlmCall`, use it for all linked ToolCalls, and add distinct `sourceIds`, start/end, upstream, argument-size, and extraction-time fields—or explicitly decline each.

**Item attacked.** S1’s mapping disposition, Story 4, enterprise-to-group table.

### A8 — The normative schemas still do not exist, and KP-7 cannot be implemented consistently from prose

**Failure scenario.** r2 says nine reviewed schemas live in `specs/010-gateway-api-group/kinds/`, but that directory is absent; only the two stale M0 seeds exist. They contain none of the new typed refs, `exactlyOne`, `requires`, enums, naming, or lineage ([tool-call.json:6](~/repos/r5e-group/r5e-enterprise/apps/recurse_fold/priv/kinds/tool-call.json:6), [policy-bundle.json:6](~/repos/r5e-group/r5e-enterprise/apps/recurse_fold/priv/kinds/policy-bundle.json:6)). KP-7 supplies keyword names but no grammar or semantics for array-item refs, nested schemas, presence versus emptiness, or conditional direction ([spec.md:111](~/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/spec.md:111)).

The consumer projection is also still narrower than S10 requested: it pins type and ref target, not enum, pattern, nested type, `exactlyOne`, `requires`, or naming ([spec.md:93](~/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/spec.md:93)). Finally, FR-006 accepts undeclared fields while FR-017 prohibits floats everywhere; an undeclared `{"x": 0.7}` satisfies one and violates the other ([spec.md:86](~/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/spec.md:86), [spec.md:97](~/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/spec.md:97)).

**Concrete proposal.** Land a normative schema-lite meta-schema, all nine seed files, and shared conformance vectors before plan review. Compatibility projections must include every consumed constraint, and “no floats” must be a recursive kernel-level canonicalization rule.

**Item attacked.** S8, S10, KP-7, FR-013, FR-017.

### A9 — Published Kind immutability is still an unenforced promise

**Failure scenario.** FR-001 says a published Kind version is never revised, but no KP enforces that. The current registry and resource store overwrite the same KindDefinition identity with `Map.put` ([kind_registry.ex:12](~/repos/r5e-group/r5e-kernel/lib/r5e/kind_registry.ex:12), [resource_store.ex:21](~/repos/r5e-group/r5e-kernel/lib/r5e/resource_store.ex:21)). An accidental second `gateway.r5e.io/v1alpha1/ToolCall` definition can change ref meanings; discovery and exported `kinds/*.json` then expose only the replacement while older receipts remain on-chain. KP-3 has no specified way to recover the exact schema used at each old admission.

**Concrete proposal.** Reject duplicate `(group, version, kind)` admissions unless byte-identical, require a new version for changes, and cite the KindDefinition’s exact address on every admission receipt.

**Item attacked.** Round-1 C1’s claimed resolution, FR-001, KP-3, S10.

### A10 — The narrowed identity story still emits “findings none” for forgeable biographies

**Failure scenario.** An attacker supplies `x-r5e-actor: person:victim` and any nonempty fingerprint; current authentication accepts it ([admission.ex:55](~/repos/r5e-group/r5e-kernel/lib/r5e/admission.ex:55)). They can then create linked sessions, parent chains, model calls, and tool calls attributed to the victim. SC-001 nevertheless expects `findings none` and does not include the identity slice among its prerequisites ([spec.md:47](~/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/spec.md:47), [spec.md:169](~/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/spec.md:169)).

FR-018’s ban on a person-keyed query does not help: `/events` and exports allow offline aggregation, and the spec expressly exposes actors, session parents, models, and tools ([router.ex:79](~/repos/r5e-group/r5e-kernel/lib/r5e/http/router.ex:79), [spec.md:163](~/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/spec.md:163)). Without verified office/authority, the claim that this is aggregation over exercised power rather than biography is unavailable; core draws that distinction at authority ([03-identity-and-delegation.md:35](~/repos/r5e-group/r5e-core/spec/03-identity-and-delegation.md:35)).

**Concrete proposal.** Make actor-signature verification and an optional typed Endorsement/office link prerequisites of SC-001. Until then, omit cross-session `parent`/`correlation` links or use unlinkable session handles, and require the verifier to report identity as unchecked rather than “findings none.”

**Item attacked.** Narrowed S5 and S6, Story 1, FR-018.

### A11 — The PolicyBundle exception contradicts detachment and does not deliver its claimed permanence

**Failure scenario.** The Charter requires the record and decision process to remain inspectable; it explicitly permits contents to be encrypted ([CHARTER.md:56](~/repos/r5e-group/r5e-core/CHARTER.md:56)). It does not require policy source to be copied into every immutable admission payload. Core, meanwhile, normatively says logs and resources carry hashes and payload bytes live in controlled storage ([01-substrates.md:45](~/repos/r5e-group/r5e-core/spec/01-substrates.md:45)).

A policy can contain person IDs, tenant topology, confidential allowlists, or an accidentally pasted secret, so “never subject content” is not enforceable. Inline source is also not inherently permanent: the entire admission payload is itself only a CAS object referenced by the log ([log.ex:24](~/repos/r5e-group/r5e-kernel/lib/r5e/log.ex:24)); deleting that payload destroys more auditability than deleting a separately referenced source.

**Concrete proposal.** Require `sourceRef`, record both bundle and source addresses on receipts, and assign policy-source objects a mandatory public-record retention class. Detachment changes storage and erasure granularity without making the rule less open.

**Item attacked.** Declined S7, FR-007, stance 7.

## B. Minor findings

- The receipt returns `"event": "sha256:…"` while typed event fields require `event:sha256:…`; Story 1 therefore still makes callers manufacture a ref ([admission.ex:194](~/repos/r5e-group/r5e-kernel/lib/r5e/admission.ex:194), [spec.md:83](~/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/spec.md:83)).
- Stance 3 promises resolved refs on the receipt, but FR-003 specifies them only in the event payload and only for name-form resource refs ([spec.md:20](~/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/spec.md:20), [spec.md:83](~/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/spec.md:83)).
- `argsMediaType` and `resultMediaType` are referenced but omitted from the corresponding optional-field lists and have no declared types ([spec.md:128](~/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/spec.md:128), [spec.md:130](~/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/spec.md:130)).
- `ToolCall.session` is listed without the `→ AgentSession` typed-ref declaration used by Prompt and LlmCall ([spec.md:128](~/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/spec.md:128)).
- `LlmResponse.completion` is optional even for `outcome: "ok"`; the scope nevertheless unconditionally claims response bytes at `completion` ([spec.md:126](~/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/spec.md:126)).
- The group’s transport enum `https|wss` cannot losslessly carry enterprise’s `https_sse|wss` value ([spec.md:124](~/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/spec.md:124), [attestation_emitter.ex:166](~/repos/r5e-group/r5e-enterprise/apps/recurse_gateway/lib/recurse_gateway/llm_proxy/attestation_emitter.ex:166)).
- Structure leakage says object sizes are visible on-chain, but `size` exists only in the unrecorded `PUT /cas` response ([spec.md:37](~/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/spec.md:37), [spec.md:165](~/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/spec.md:165)).
- The required name of the `kind: "*"` fallback PolicyShape is unspecified by the `<engine>.<group>_<version>_<Kind>` formula ([spec.md:70](~/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/spec.md:70)).
- KP-4b must define an atomic discovery snapshot; otherwise a concurrent Kind admission can occur between listing the registry and reading `treeSize/chainHead` ([spec.md:108](~/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/spec.md:108)).
- `errorKind` was weakened from enterprise’s closed vocabulary to an arbitrary string, despite the claim that enumerated fields are schema enums ([attestation_emitter.ex:146](~/repos/r5e-group/r5e-enterprise/apps/recurse_gateway/lib/recurse_gateway/llm_proxy/attestation_emitter.ex:146), [spec.md:126](~/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/spec.md:126)).

## C. Dispositions I disagree with

| Disposition | Argument |
|---|---|
| **S1 applied** | Only the path spelling was added. The policy/kernel resolver ordering is contradictory, wildcard validation is impossible as written, and the real enterprise context remains materially unmapped. |
| **S2 applied** | Exact input plus a version string supports a conditional rerun, not build-pinned replay or verification of shaping. It also ignores disclosure of exact policy inputs. |
| **S3 applied** | Typed declarations are directionally correct, but no normative schema or `resolvedRefs` representation exists; mutable resource generations and policy-before-resolution remain unresolved. |
| **S4 slated as KP-9** | A per-node mutex neither handles post-record store failure nor multi-node state, and it serializes Cedar plus disk I/O. The round-1 fail-stop requirement disappeared. |
| **S5 narrowed** | The synthesis says identity is a dependency of SC-001’s stronger form, but SC-001 itself has no identity dependency and still requires `findings none`. |
| **S6 narrowed** | “The kernel already correlates actors” does not excuse adding session hierarchy, model/tool detail, and correlation keys before authority exists. A query ban cannot prevent aggregation from the public event stream. |
| **S7 declined/narrowed** | Openness does not imply inline storage. Core detachment is normative, policy source may contain subject data, and inline arguments/results remain legal by default despite the same rule. |
| **S8 applied** | The nine reviewed schemas are absent, current seeds are stale, and KP-7 is vocabulary rather than an implementable grammar. |
| **S9 applied** | PolicyBundle still accepts inert non-`active` names; AgentSession name reuse and artifact custom names remain legal. |
| **S10 applied** | Pinning still omits enums and cross-field/nested constraints, while discovery position lacks atomic snapshot semantics. |
| **S11 applied** | A raw CAS upload is content-addressed lineage, but it is not an admitted act. Calling the reviewed natlang document “admitted” is presently false. |

## D. What I tried to break and could not

- KP-1 and the first half of KP-4 really have landed: successful receipts return `name` and `specAddress`, and discovery obtains the admitted KindDefinition address rather than hashing `Kind.to_map/1` ([admission.ex:194](~/repos/r5e-group/r5e-kernel/lib/r5e/admission.ex:194), [router.ex:44](~/repos/r5e-group/r5e-kernel/lib/r5e/http/router.ex:44)).
- The Story 1 count is now correct: two ToolCalls with one denial yield six grants, one denial, and seven admission events ([spec.md:35](~/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/spec.md:35)).
- Separating `event:` from `sha256:` is the correct namespace boundary; once implemented, a verifier need not guess whether a digest is an event or CAS object.
- The backward sequence remains orderable, and required `LlmResponse.toolCalls` can bind both admitted and denied ToolCall receipts in model order.
- On one node, with no post-record failure, a lock covering both ordinary admission and policy supersession does eliminate the original interleaving.
- Bundle + shape + exact request is enough to reproduce a Cedar result when the exact engine build is independently available and the request can be disclosed; the defect is the missing binding and qualification, not the basic replay idea.
- The new mapping preserves the principal call hashes, provider metadata, token counts, statuses, latencies, and per-intent decisions; it is incomplete rather than wholly misdirected.

## E. Termination signal

What remains is structural: admission ordering, CAS authority, policy commit atomicity, identity/biography, executable schemas, replay provenance, and correction semantics can still produce incompatible or falsely clean implementations. A third round is warranted after the normative seeds and these kernel contracts are written; the remaining work is not yet nitpick-level.