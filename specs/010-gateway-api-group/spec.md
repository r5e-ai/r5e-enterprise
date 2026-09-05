# Feature Specification: The Gateway API Group (`gateway.r5e.io/v1alpha1`)

**Feature Branch**: `010-gateway-api-group`
**Created**: 2026-09-01 · **r1** 2026-09-02 (Opus) · **r2** 2026-09-02 (Codex/Sol) · **r3** 2026-09-02 (Opus + Codex round 2)
**Status**: Draft r3 + contract r2 (2026-09-02, after contract round 3). The normative contract is `schema-lite-v2.md` r2 + `kinds/*.json` + `core/kind-definition.v2.json`; the discriminator from here is conformance vectors (§12), not prose review.
**Input**: Thomas, 2026-09-01: "we're going to extend the r5e API … prompts themselves being artifacts … make a policybundle, pick a sane default … the old API is something to design *against*, not design *to* … people know what SPIFFE and shit proves, we don't have to litigate it in our API off rip … r5e-recurse is going to use toolcall, llmcall, and probably policybundle."

**Inputs** (cited inline): milestone-zero plan and debt register (`handbook/design/…`); the enterprise spec corpus with status (`~/Documents/repos/r5e-quarry/ENTERPRISE-SPEC-CORPUS.md`, "CORPUS"); the recovered 2026-04 API generation and its GAP audits (`…/DIGEST.md`); r5e-core spec/00–04; the meta-API philosophy; reviews `review-round-{1,1-codex,2-opus,2-codex,3-opus,3-codex}.md`; syntheses `review-round-{2,3,4}.md`; the verification pass on contract r2 (2026-09-02).

---

## What this is, in one paragraph

The vocabulary by which governance of agent work is expressed on an r5e chain: what a model was asked, what it answered, what tools it asked to invoke, what policy decided from exactly which input, and what came back. It is an **extension** of the r5e meta-API (spec/02): KindDefinitions admitted through the kernel's own door, each on one substrate, each carrying **typed** refs backward in time, every ref resolved by the kernel before policy runs and by the verifier offline. Enterprise provides the engines behind the kernel's seams; r5e-recurse and any other harness consume the admitted group, never the enterprise codebase. Milestone zero proved the pipe with two Kinds; this spec names the rest, the rules, and the kernel and core changes those rules need in order to be checked rather than hoped. **The contract is the schemas**: this prose is commentary and rationale; where they disagree, the schemas (once admitted) win and this file is amended.

## The stance (binding)

1. **Design against the old API, not to it** (DIGEST §b). Each rule that closes one of its fourteen failures names it; each left open is listed.
2. **Schema lives in the API**, never in a validator (DIGEST §b.1). The fold's coded shape moves into an admitted `PolicyShape`, onto the receipt, and into a replayable evaluation record.
3. **Never accept from a caller what is derivable; return what was derived.** Addresses, chain position, actor of record, resolved refs, sizes, and unique names are computed by the kernel and returned on the receipt (KP-1 landed). A caller-supplied duplicate of a derivable is not a field.
4. **Sane defaults, no ceremony.** Required fields are only what the act carries; absent means absent; no sentinels. Third-party Kinds get the modest default scope. This group's Kinds carry their definitions as authored scope on the chain (stance doc amended 2026-09-02).
5. **One position, one identity.** The chain gives every receipt a seq and a hash.
6. **Refs are typed, point backward, resolve before policy, and are checked twice.** A property declares what it may reference (a Kind, an event of a Kind with an outcome facet, or raw bytes). The kernel's `resolve` step (before authorize) checks existence, Kind, outcome, lower seq, and target payload presence, and writes the resolution beside the spec; the verifier repeats it offline. Refs use the kernel's `{"$ref": …}` object form, and CS-1 extends `?resolution=deep` to hydrate every form (schema-lite-v2 §6).
7. **Payloads are detached, and detachment is itself an admission.** Raw bytes enter the CAS only as a granted admission of `core.r5e.io/v1/CasObject` (actor, address, size, class; never the bytes in the payload). Policy source is detached too and cited by address; it is public record and never erased (retention class, below).
8. **Denial is not a Kind.**
9. **The live meta-API is canonical.** `GET /apis` and the KindDefinitions' addresses are the reference. The reviewed natlang (this file) is put to the CAS by a recorded act and every KindDefinition cites it (`derivedFrom`), so the philosophy's three stages are three content-addressed artifacts.
10. **Decisions are replayable when disclosed.** A receipt cites bundle, shape, evaluation record, and engine build, all by address. The verifier does not re-derive decisions and says so. Sensitive inputs in the evaluation record are subject content: erasable, and replay then reports "input erased," not a false pass.
11. **Nothing in this group is admitted to a durable chain until the declarations its schemas carry are enforced by the kernel** (schema-lite v2). This group exists to eliminate declared-but-dead fields (DIGEST §b.4, §b.6); it does not ship one.

## User Scenarios & Testing *(mandatory)*

### User Story 1 — A coding agent's session, on the record and verifiable (Priority: P1)

Establishes a verifiable **record of asserted acts**. Does **not** establish who acted or under whose authority; the verifier's not-checked block says so on every run and SC-001 quotes it. Those claims arrive with the identity slice (actor signatures, endorsements).

Canonical sequence for one model call, in chain order (two ToolCalls, one denied):

1. Admit the prompt bytes as a `core.r5e.io/v1/CasObject` (`PUT /cas`); receipt plus `{address: "bytes:sha256:…", size}`.
2. Admit `Prompt{contentRef: {$ref: P}}` → receipt: name (= content name), specAddress, eventRef.
3. Admit `LlmCall{model, prompt: {$ref: <Prompt name>}, …}` → receipt: eventRef `L`.
4. Per tool intent, in the model's order: admit `ToolCall{tool, args | argsRef, llmCall: {$ref: L}, index}`. `resolve` fetches `L`; the shape may read `llmCall.spec.model`; policy decides; a denial cites bundle, source, shape, evaluation record, engine build, rule.
5. Admit the completion bytes as a `CasObject`; admit `Completion{contentRef}`.
6. Admit `LlmResponse{llmCall: {$ref: L}, completion, toolCalls: [{$ref: …}, {$ref: …}], outcome, …}` — binds bytes and intents (admitted and denied) to one record.
7. Admit `ToolResult{toolCall: {$ref: …}, outcome, result | resultRef}` for the tool that ran.

Eight admissions (six group instances plus two CasObjects), one denial, nine admission events.

**Acceptance (SC-001)**: through a fold kernel with the core schema-lite v2 slice and KP-2/3/9 in place; export; the verifier's `claims:` totals include the bootstrap admissions (Charter, core and group KindDefinitions, bundle, shapes) and the test asserts the nine Story-1 admission events (two CasObjects, six group instances, one denial) by seq, kind, and outcome; `refs:` reports every ref resolved to the declared Kind/outcome; `policy:` reports bundle, source, shape, evaluation-record, and engine-build objects present; findings none; **and the not-checked lines for actor signatures and key-to-identity binding are quoted in the criterion**.

### User Story 2 — Policy changes are on the record, and cannot race (Priority: P1)

Superseding `PolicyBundle/active` or a `PolicyShape` is an admission under the previous rules. Authorize captures the policy generation it read; record compares-and-appends; a change in between retries the decision. A post-record substrate failure halts admission on that node until replay (Story 2's guarantee is per node; multi-node deployments are out of v1alpha1's scope and stated). Recovery from an all-deny bundle by editing the store is not an act and is visible as a gap; a signed break-glass rule is identity-slice work.

### User Story 3 — r5e-recurse consumes the group without depending on enterprise (Priority: P2)

Boot check: `GET /apis` (atomic snapshot: Kinds, addresses, `treeSize`, `chainHead`); pin identity, substrate, and **every constraint the consumer relies on** (required, types, enums, ref targets, exactlyOne, requires, naming); fail naming the Kind and constraint; address drift alone is a notice. Never links the umbrella.

### User Story 4 — Enterprise's proxy emits through the group (Priority: P3, after identity)

Per the per-field mapping table; every source field is preserved, derived, dropped, or **semantically changed** — the last category is where enterprise's stream-pinned bundle differs from the fold's per-decision read, stated.

### Edge Cases

- Tool never executed → `ToolCall` without `ToolResult`; "no result" reads as unknown.
- Completion never arrived → `LlmResponse{outcome: "error", upstreamStatus, errorKind, toolCalls: [...]}`, `completion` absent (`requires` makes `completion` mandatory only when `outcome: "ok"`).
- Concurrent intents → chain order is when the gateway asked; `index` is the model's order.
- Large/sensitive args or results → `argsRef`/`resultRef` (`exactlyOne`); inline content is on the log and not erasable; a shape may dereference `argsRef` through one bounded `bytes` hop so content rules apply to both representations.
- Shape path that cannot be typed against the target Kind → denied at shape admission. Path whose terminal is a declared-optional property the instance omits → "absent" (dropped from context) unless the shape's `whenAbsent` says `deny`. Event hop whose target cannot be fetched → fail closed.
- Shape under the wrong name, or a bundle under a name other than `active` → denied at admission (naming modes `derived` / `literal`).
- ToolCall before any shape for its Kind → coded fallback; receipt says `shape: null` with note; still cites the evaluation record.
- All-deny bundle → allowed, recorded; recovery is a visible gap (Story 2).
- Erasure → delete the object; before export it is listed under `missingObjects` and reported; inside an export the `refs:` check fails for that seq. A shredded evaluation record makes replay report "input erased."
- Correction → `supersedes` must name the current head for the same anchor; branches and cross-anchor corrections are denied at admission.
- Duplicate KindDefinition `(group, version, kind)` → denied unless byte-identical; changes need a new version.
- Re-import → identical bytes are one object; events are acts; the importer's ids go in `sourceIds`.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001** Group `gateway.r5e.io`, version `v1alpha1`; revised in place only until the first durable admission (none yet); then `v1alpha2`. The kernel rejects a duplicate `(group, version, kind)` unless byte-identical (core, S-C1).
- **FR-002** Nine Kinds, one substrate each. Artifacts: `Prompt`, `Completion`. Events: `LlmCall`, `LlmResponse`, `ToolCall`, `ToolResult`. Resources: `PolicyBundle`, `PolicyShape`, `AgentSession`.
- **FR-003** Refs are `{"$ref": <value>}` objects, legal only where the schema declares `type: "ref"`. A property declares `ref`: `{kind: "<group>/<version>/<Kind>"}` (value = the target's API path `group/version/Kind/name`, the form the store's deep resolution understands), `{event: "<group>/<version>/<Kind>", outcome?: "admitted"|"any", sameAnchor?: field}` (value = `event:sha256:<hex>`), or `{bytes: true, json?: schema, retention?: "public-record"}` (value = `bytes:sha256:<hex>`). The kernel's `resolve` step (core spec/02 amendment: authenticate → validateStructure → resolve → authorize → validateConstraints → record → admit; schema-lite-v2 §4) checks every ref — existence, Kind, outcome facet, lower seq, target payload present, `bytes:` backed by a `CasObject` admission — and records the resolution manifest under `resolvedRefs`, a sibling of `spec` on the event payload and on the store entry, copied by replay from the payload (replay trusts the record; the verifier re-derives it), never an input to naming or `specAddress` (KP-3).
- **FR-004** No caller computes a digest, a size, or a unique name. Receipts return `name`, `specAddress`, `eventRef`, `resolvedRefs`; `PUT /cas` is a `core.r5e.io/v1/CasObject` admission returning the receipt plus `{address, size}`.
- **FR-005** Required fields are the minimum in the schemas. No sentinels. No tenant/envelope/session-chain fields; tenancy boundary = the chain, stated. Semantic times are named (`observedAt`, `startedAt`, `endedAt`).
- **FR-006** camelCase; undeclared fields accepted today (DIGEST §b.10 open, debt #12); a schema may set `additionalProperties: false` once enforced; the group's schemas do.
- **FR-007** `PolicyBundle`: `engine` (enum), `sourceRef` (bytes; the policy text), `description`. Naming `literal: "active"` — only that name is admissible. Retention: objects cited by a PolicyBundle carry retention class `public-record` (never erased; the verifier treats absence as a finding). **No subject identifiers in policy source**: entity data belongs in the evaluation record; a bundle that names a principal is a policy-authoring error, stated. Draft/activation collapsed: admitting `active` is activation.
- **FR-008** `PolicyShape` (resource): how instances of one Kind are presented to an engine. Naming `derived`, template `{engine}.{kind}` (`cedar.gateway.r5e.io/v1alpha1/ToolCall`; fallback `cedar.*`; slashes are legal in names, schema-lite-v2 §2), enforced at admission. Paths validated at shape admission against the target Kind's schema per the §8 grammar (one event hop through any event-ref property; one bounded `bytes` dereference only where the ref declares a `json` schema; paths terminate at, never descend into, open objects; `@` envelope fields; `whenAbsent` per key). Receipt policy metadata: `bundle`, `source`, `shape` (or null + note), `evaluation` (the kernel-derived `PolicyEvaluationRecord`, §8 closed schema, equality invariant with the receipt), `engineBuild` (a `CasObject` address of the build descriptor), `matched` (positional ids, stable per bundle address).
- **FR-009** `AgentSession`: naming `server` (the kernel names it by its admission event hash and returns it); supersession only by the admitting actor (kernel rule; the store entry carries `actor`). No `onBehalfOf` until core's Endorsement.
- **FR-010** Denials are denied admissions; mapping table below.
- **FR-011** Every group Kind carries authored `epistemicScope` and `description` in its definition; `derivedFrom` (the `bytes:` address of the reviewed natlang document, this file) is an admission envelope field recorded beside the spec, never inside it, so the seed file is the admitted bytes.
- **FR-012** Assurance `observed` until KP-6.
- **FR-013** Consumers pin all consumed constraints (Story 3); `GET /apis` is an atomic snapshot with chain position.
- **FR-014** One act per request; no batch.
- **FR-015** `supersedes`: same Kind, same anchor (`llmCall` / `toolCall`), same actor, must be the current head; checked at admission; branches denied; latest = the unsuperseded head.
- **FR-016** All constraints in the schemas (`enum`, `exactlyOne`, `requires`, `pattern`, nested types, `ref`, `naming`, `additionalProperties`) are enforced by schema-lite v2 before any durable admission (stance §11).
- **FR-017** No JSON floats: a recursive kernel canonicalization rule (core), not a per-group convention; gateways coerce provider floats to integers at the boundary (latency ms, tokens) and state the rounding.
- **FR-018** Read symmetry: the kernel surface is unauthenticated and symmetric; any added read surface must be subject-mirrorable and provide no person-keyed aggregation query; the positive half of spec/04 (a subject can retrieve every record about them) needs a subject index this group does not provide — open, stated. The verifier's own actor list is named in leakage.

### Core and kernel prerequisites

| # | Where | Change | Status |
|---|---|---|---|
| KP-1 | kernel | receipt: `name`, `specAddress`; **+ `eventRef` (`event:sha256:`) and `resolvedRefs`** | name/specAddress landed; eventRef/resolvedRefs open |
| KP-2 | core + kernel | `core.r5e.io/v1/CasObject` and `CasExpired` event Kinds; `PUT /cas` = admit a CasObject (the kernel builds the spec, writes bytes only on grant); `GET /cas/:addr`; reference counting; TTL sweeper admits `CasExpired` as `system:retention`; export sweep covers `bytes:` refs | open |
| KP-3 | verifier | `refs:` line (every typed ref resolves to the declared Kind/outcome at lower seq; `bytes:` backed by a CasObject admission and coinciding with no payload/spec address; `missingObjects` and `derivedObjects` reported); `policy:` checks that every address in the policy block resolves and the §8 equality invariant holds | open |
| KP-4 | kernel | `GET /apis` carries `specAddress` | landed |
| KP-4b | kernel | `GET /apis` is an atomic snapshot with `treeSize`, `chainHead` | open |
| KP-6 | kernel | per-receipt assurance label | later |
| KP-9 | kernel | the §7 commit protocol: optimistic authorize; at record, under the append lock, re-check the policy generation, every kind-ref generation in the manifest, and every `sameAnchor` head; retry from `resolve` on change, `contended` after N; `halted` after a post-record substrate failure until replay (subsumed by CS-1) | open |
| **CS-1** | **core spec/02 + kernel + verifier** | **schema-lite v2 r2** (one slice): the seven-stage pipeline with `validateStructure` / `resolve` / `validateConstraints`; typed `$ref`s and the resolution manifest; naming modes incl. `path` and `server` with the payload `target.name` omission; `exists`/`nonEmpty`, `enum`, `exactlyOne`, `requires`, `pattern`, `minimum`/`maximum`, nested types, `additionalProperties`, limits; `description` on KindDefinition and `derivedFrom` as an envelope field, carried by `to_map`, export, verifier; duplicate-Kind rejection; recursive no-float rule; the §7 commit protocol; slash-bearing names with left-split resolution; the meta-Kind transition (`core/kind-definition.v2.json`); conformance vectors (§12) | open |

### Key Entities (commentary; `kinds/*.json` is normative)

**Prompt** — artifact, naming `content`. *These bytes, at this address, were submitted as a prompt by the recorded actor at the recorded position.* Required: `contentRef` (bytes). Optional: `mediaType` (absent = `text/plain`, a read convention applied by consumers, never stored), `role` (enum), `session` (→ AgentSession), `observedAt`. Not claimed: that a model received them.

**Completion** — artifact, naming `content`. Required: `contentRef`. Optional: `mediaType`, `observedAt`. Not claimed: which call produced them; that tool calls in them ran.

**LlmCall** — event. Required: `model`, `prompt` (→ Prompt). Optional: `provider`, `upstreamHost`, `transport` (enum `https|https-sse|wss`), `apiFormat`, `requestPath`, `session` (→ AgentSession), `sourceIds` (object of string ids from an importer: session/run/turn/step), `startedAt`, `tools`, `parameters` (string/int/bool values). Not claimed: that the provider received it; that a response occurred.

**LlmResponse** — event. Required: `llmCall` (→ event LlmCall, admitted), `outcome` (enum), `toolCalls` (list of → event ToolCall, outcome any). `requires`: `outcome == "ok"` → `completion`. Optional: `completion` (→ Completion), `upstreamStatus` (int), `errorKind` (enum, enterprise's vocabulary), `usage{inputTokens, outputTokens, reasoningTokens}` (ints), `latency{upstreamMs, addedMs}` (ints), `finishReason`, `completedAt`, `supersedes` (→ event LlmResponse, admitted, same `llmCall`).

**ToolCall** — event. Required: `tool`. `exactlyOne`: `args` | `argsRef` (bytes; `argsMediaType` default `application/json` canonical). Optional: `llmCall` (→ event LlmCall, admitted; `requires` → `index`), `index` (int), `responsePrefixRef` (bytes), `callId`, `session` (→ AgentSession), `purpose`, `extractedAt`. Argument size is derived from the bytes and is not a field. Not claimed: that the tool ran; with these args; that the actor held the key; that anything outside honored the decision.

**ToolResult** — event. Required: `toolCall` (→ event ToolCall, admitted), `outcome` (enum). `exactlyOne`: `result` | `resultRef` (`resultMediaType`). Optional: `durationMs`, `exitCode`, `supersedes` (same `toolCall`).

**PolicyBundle** — resource, naming `literal: "active"`. Required: `engine`, `sourceRef` (bytes, retention `public-record`). Optional: `description`.

**PolicyShape** — resource, naming `derived`. Required: `kind`, `engine`, `action`, `resourceType`, `resourceId`. Optional: `context` (key → path/literal, each with optional `whenAbsent`), `description`.

**AgentSession** — resource, naming `server`. Required: none. Optional: `harness`, `purpose`, `startedAt`, `endedAt`, `parent` (→ AgentSession), `sourceIds`. Not claimed: on whose behalf; completeness.

**Engine build descriptor** — not a Kind. Raw bytes admitted as a `CasObject` and cited by address from receipts; content (engine, crate, version, lockfile hash, NIF checksum, module sha256, platform) defined in `schema-lite-v2.md` §8. A tenth Kind is deliberately not added in v1alpha1 (open question 3).

### Enterprise → group mapping (per field)

| Source field | Group | Class |
|---|---|---|
| `prompt_hash`, `response_hash` | `Prompt.contentRef`, `Completion.contentRef` (bytes, not only hashes) | preserved (stronger) |
| `model`, `provider`, `upstream_host`, `transport` (`https_sse|wss`), `api_format`, request path | `LlmCall.{model, provider, upstreamHost, transport, apiFormat, requestPath}` | preserved |
| `started_at`, `completed_at` | `LlmCall.startedAt`, `LlmResponse.completedAt` (semantic times) | preserved |
| `tool_use_intents[].call_id / tool_name / decision / cedar_rule_id / deny_reason / parallel_index` | `ToolCall.callId / tool` / admission outcome / `policy.matched` / receipt reason / `index` | preserved |
| `tool_use_intents[].tool_args_hash`, `tool_args_size_bytes`, `extracted_at` | `argsRef` when detached (inline args are covered by `specAddress`); size derived (dropped as a field); `extractedAt` | preserved / derived |
| `tool_use_denied` | the denied `ToolCall` admission | preserved |
| `decision_summary` | derived from `LlmResponse.toolCalls` outcomes | derived |
| token counts incl. reasoning; `upstream_status_code`; `error_kind` (enum kept); latencies | `LlmResponse.{usage, upstreamStatus, errorKind, latency}` | preserved |
| response-prefix hash at decision | `ToolCall.responsePrefixRef` | preserved |
| `cedar_bundle_hash` / `policy_canonical_hash` | receipt `policy.source` (the text's own address) / `policy.bundle` (the bundle spec) | preserved (two addresses, two meanings) |
| bundle pinned at call start for all intents in a stream | the fold reads `active` per decision and each receipt cites what it read | **semantically changed**, stated |
| `session_id`, `run_id`, `turn_id`, `step_id` | `session` ref + `sourceIds{session, run, turn, step}` | preserved (as source ids) |
| `session_chain_position` | not recorded; chain seq is the position of record | dropped |
| `principal`, `principal_kind`, `chatgpt_account_id`, `machine_identity`, `tenant_id` | actor of record; tenancy = chain; the rest **dropped** until the identity slice binds a verified principal | dropped |
| `verification_level`, `tier_completeness_advisory`, inclusion proofs, `commit_retry_exhausted`, `envelope_version`, `signer`, `payload_uri` | the chain, the export, the verifier | dropped |
| extractor `tags` | consumer-computed | dropped from chain |

### Non-entities, predicates, structure leakage

As in r2, plus: the confirmation oracle (content-addressed plaintext + open GET confirms guessed text; confidentiality requires encryption, not detachment); the evaluation records are subject content; the verifier prints the actor list; sizes are visible in `CasObject` admissions.

## Success Criteria

SC-001 as above. **SC-002** `GET /apis` group entries: nine, `scopeDefaulted: false`, addresses, snapshot position. **SC-003** shape changes decision + `shape`/`evaluation`; bad path denied; wrong name denied; unresolvable hop fails closed; evaluation record replays to the same decision under the cited engine build. **SC-004** Story 3 tests incl. a pinned-constraint change. **SC-005** zero sentinels. **SC-006** debt #2/#11 retired. **SC-007** erasure inside/before export behaves as stated. **SC-008** wrong-Kind ref denied at admission (naming the expected Kind) and a finding offline. **SC-009** `LlmResponse.llmCall` pointing at a denied LlmCall is denied at admission and a finding offline; `toolCalls` listing a denied ToolCall is accepted. **SC-010** two `AgentSession` admissions by different actors under one server name: the second is denied. **SC-011** a duplicate non-identical KindDefinition is denied.

## What stays open

Positive read symmetry (subject index); multi-node policy generation; break-glass under an all-deny bundle (identity slice); `NetworkCall`; unlinkable session handles; DIGEST §b.10 until `additionalProperties` is enforced (CS-1).

## Open questions (to be settled by the conformance vectors) (on the schemas)

1. `resolvedRefs` as a payload sibling (chosen) vs a kernel-signed side record.
2. `PUT /cas` as a recorded act (chosen) vs staged upload promoted at admission (Codex A3). Staging avoids orphans entirely but makes the kernel rewrite `contentRef` from handle to address inside the spec, which changes what is named; recorded puts keep the spec caller-authored and make orphans legible. Attack.
3. Build descriptor as raw bytes (chosen) vs a tenth Kind.
4. Per-decision bundle read (chosen, chain-truthful) vs call-start pinning (enterprise's guarantee).
