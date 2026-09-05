# Spec 010 — adversarial review, round 1, second discriminator

**Discriminator**: Codex CLI 0.149.1, model `gpt-5.6-sol`, reasoning effort high, read-only sandbox, 2026-09-02. Target: the round-1-revised spec (bookmark `spec/010-r1`). Verbatim output; dispositions are in `review-round-2.md`.

---

## A. Major findings

### 1. Policy-critical enterprise data has no representation

**Scenario:** The existing proxy evaluates each intent with `model`, tenant, principal claims, session, prompt hash, response-prefix hash, and either arguments or their hash ([spec-009:129](~/Documents/repos/r5e-group/r5e-enterprise/specs/009-llm-api-proxy/spec.md:129)). Its final attestation also records provider/transport/API format, reasoning tokens, per-intent decisions, rule IDs, reasons, and latency breakdowns ([attestation_emitter.ex:443](~/Documents/repos/r5e-group/r5e-enterprise/apps/recurse_gateway/lib/recurse_gateway/llm_proxy/attestation_emitter.ex:443), [attestation_emitter.ex:497](~/Documents/repos/r5e-group/r5e-enterprise/apps/recurse_gateway/lib/recurse_gateway/llm_proxy/attestation_emitter.ex:497)). The proposed `ToolCall` has only `tool`, arguments, `llmCall`, index, call ID, session, and purpose ([spec.md:120](~/Documents/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/spec.md:120)). A shape evaluating a mid-stream `ToolCall` cannot reach model, Prompt, authenticated principal claims, or response-so-far through the `llmCall` event because neither admission nor dotted paths resolve event refs. A Cedar rule such as “deny shell for model X or tenant Y” therefore sees missing context and either fails every intent closed or gets weakened to an allow. Story 4’s claim that `llm_call_attested + tool_use_denied` “becomes steps 2–7” loses audit data as well as enforcement semantics ([spec.md:56](~/Documents/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/spec.md:56)).

**Proposal:** Define a lossless mapping table from the existing call state and `tool_use_intents[]`. Require the policy engine to resolve a typed `llmCall` ref and derive model, Prompt address, session, and endorsed principal data itself. Add an engine-computed stream-prefix digest/ref to `ToolCall`. Add provider, upstream, transport, API format, and request path to `LlmCall`; add reasoning tokens, upstream status, added latency, and parse-failure information to `LlmResponse`, or explicitly declare each dropped field. Do not accept derivable identity/context values from the gateway caller.

**Attack:** 1, 2, 9, 10.

### 2. Citing `PolicyShape` does not reconstruct the Cedar request

**Scenario:** `PolicyShape` defines only action, resource type/id, and context paths ([spec.md:126](~/Documents/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/spec.md:126)). The actual Cedar input also depends on principal-type derivation, principal and resource entities, key-fingerprint attributes, null removal, UID encoding, and implementation-specific fallback logic ([cedar.ex:138](~/Documents/repos/r5e-group/r5e-enterprise/apps/recurse_fold/lib/recurse_fold/policy/cedar.ex:138), [cedar.ex:194](~/Documents/repos/r5e-group/r5e-enterprise/apps/recurse_fold/lib/recurse_fold/policy/cedar.ex:194), [cedar.ex:204](~/Documents/repos/r5e-group/r5e-enterprise/apps/recurse_fold/lib/recurse_fold/policy/cedar.ex:204)). Engine version/build identity is also absent. Two implementations can cite the same bundle and shape while evaluating different Cedar requests, and the verifier deliberately does not re-evaluate decisions ([recurse_verify.ex:431](~/Documents/repos/r5e-group/r5e-core/verifier/lib/recurse_verify.ex:431)).

**Proposal:** Have the engine canonicalize the exact Cedar request and entity set it evaluated, put those bytes in CAS, and include `requestAddress`, `engineBuildAddress`, `bundle`, `shape`, and the target KindDefinition’s `specAddress` in policy metadata. The auditor can then inspect or replay the exact input without trusting undocumented shaping code.

**Attack:** 2, 9.

### 3. A ref can resolve to the wrong thing and verify cleanly

**Scenario:** Admit a real `PolicyBundle` and use its `specAddress` as `LlmCall.prompt`. The field is a string, so current validation accepts it ([kind.ex:85](~/Documents/repos/r5e-group/r5e-kernel/lib/r5e/kind.ex:85)). KP-3 checks only that the `sha256:` object exists, not that it is an admitted `Prompt` ([spec.md:102](~/Documents/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/spec.md:102)). The verifier reports the ref resolved. The same defect allows `LlmResponse.llmCall` to point to an earlier `ToolResult`, and `session` to name a `PolicyBundle`; name refs are not checked at all in v1alpha1 ([spec.md:78](~/Documents/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/spec.md:78)). This is DIGEST §b.8 again, now with a syntactically valid digest.

**Proposal:** Make refs typed, for example `{kind, substrate, address}` for artifacts/events and `{resourceRef, resolvedSpecAddress}` for resources. Admission and verification must check existence, target Kind, target substrate, target outcome where relevant, and backward sequence. Resolve name refs at admission and persist the resolved address; do not defer this invariant to v1alpha2.

**Attack:** 3, 9, 10.

### 4. Policy and shape supersession are causally racy

**Scenario:** Request A reads and evaluates the old active bundle. Request B then supersedes `PolicyBundle/active`, records and stores it. A finally appends its receipt after B while citing the old bundle. The chain now says A happened after the supersession even though it used the previous policy, contradicting Story 2’s “every later decision cites the new address” ([spec.md:46](~/Documents/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/spec.md:46)). This is possible because authorization precedes record/write ([admission.ex:31](~/Documents/repos/r5e-group/r5e-kernel/lib/r5e/admission.ex:31)), while resource replacement occurs only afterward ([admission.ex:153](~/Documents/repos/r5e-group/r5e-kernel/lib/r5e/admission.ex:153)). `PolicyShape` has the same race.

**Proposal:** Serialize `authorize → append → resource commit` for policy-sensitive admissions, or use a captured bundle/shape generation with compare-and-append and retry when the active generation changed. A granted policy/shape supersession whose resource write fails must fail-stop the gate until replay restores the state.

**Attack:** 2.

### 5. Story 1 cannot verify actor identity or authority

**Scenario:** An arbitrary client supplies `x-r5e-actor: person:alice` and any nonempty fingerprint. Authentication only checks presence ([admission.ex:46](~/Documents/repos/r5e-group/r5e-kernel/lib/r5e/admission.ex:46)). Story 1 nevertheless promises a governed, independently verifiable session ([spec.md:30](~/Documents/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/spec.md:30)), while its prerequisites contain neither actor signatures nor endorsements. An auditor cannot establish who acted or under whose authority—the Charter’s basic record ([CHARTER.md:8](~/Documents/repos/r5e-group/r5e-core/CHARTER.md:8)). `AgentSession` correctly removed the self-asserted `onBehalfOf`, but nothing replaced it.

**Proposal:** Make the identity slice a prerequisite for Story 1 and SC-001: actor signature over the canonical request, key-to-principal binding, and an optional typed ref to a core `Endorsement` written by the endorser. Otherwise rename and narrow Story 1 to an asserted-actor transport demonstration.

**Attack:** 5, 10.

### 6. `AgentSession` creates a biography index before authority exists

**Scenario:** The draft openly exposes which actors opened sessions, which models and tools they used, and how often ([spec.md:141](~/Documents/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/spec.md:141)). `AgentSession`, its parent link, purpose, correlation, and references from Prompt/LlmCall/ToolCall create a durable cross-event profile ([spec.md:128](~/Documents/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/spec.md:128)). Without an authority/office link, the system cannot distinguish legitimate aggregation over exercised power from forbidden aggregation over a person’s life; the Charter draws that exact line ([CHARTER.md:164](~/Documents/repos/r5e-group/r5e-core/CHARTER.md:164), [03-identity-and-delegation.md:35](~/Documents/repos/r5e-group/r5e-core/spec/03-identity-and-delegation.md:35)). The unauthenticated instance-list surface magnifies this ([spec.md:161](~/Documents/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/spec.md:161)).

**Proposal:** Do not ship cross-session actor correlation until sessions can bind to a verified Endorsement/office and read symmetry is specified. Use per-session unlinkable actor handles for non-authority work, and require policy shapes to consume role/authority predicates rather than accumulated session biography.

**Attack:** 6, 8.

### 7. Payload detachment is applied selectively, contrary to the substrate contract

**Scenario:** Prompt and Completion bytes are detached, but Cedar source remains inline in a mutable `PolicyBundle`, and raw tool arguments/results remain legal inline ([spec.md:82](~/Documents/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/spec.md:82), [spec.md:120](~/Documents/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/spec.md:120), [spec.md:122](~/Documents/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/spec.md:122)). Admission copies the complete spec into the immutable event payload ([admission.ex:132](~/Documents/repos/r5e-group/r5e-kernel/lib/r5e/admission.ex:132)). A secret in `args` or `result` therefore cannot be erased, and policy documents live in the resource/log rather than the artifact substrate.

**Proposal:** Change `PolicyBundle.source` to a required `sourceRef`; require exactly one of `argsRef` or an explicit small non-sensitive inline form; and make `resultRef` the default with inline data governed by an explicit size/classification rule. The receipt should cite both the bundle spec and source object.

**Attack:** 8, 9.

### 8. The proposed invariants exceed the validator by much more than enums

**Scenario:** The draft requires `args` XOR `argsRef`, `llmCall` ⇒ `index`, constrained nested `parameters` values, dotted-path validity, ref formats, and conditional Completion behavior. The validator enforces only top-level required presence and declared primitive type ([kind.ex:85](~/Documents/repos/r5e-group/r5e-kernel/lib/r5e/kind.ex:85)); KP-7 adds only enums ([spec.md:106](~/Documents/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/spec.md:106)). A caller can submit safe inline `args` plus a dangerous `argsRef`; policy evaluates the inline object while an executor follows the detached object. Both fields are admitted.

**Proposal:** Add a prerequisite for `oneOf`, `dependentRequired`, nested property/value validation, string patterns, `additionalProperties`, and typed-ref constraints. Require exactly one argument representation, require `{llmCall,index}` together, and require `LlmResponse.toolCalls` as an array, including `[]`, because its scope claims completeness. Publish the actual nine normative seed schemas as part of the reviewed contract.

**Attack:** 4, 9.

### 9. Resource naming permits silent non-activation and session aliasing

**Scenario:** `AgentSession` requires neither fields nor an envelope name. The kernel content-names any unnamed instance from its spec ([admission.ex:115](~/Documents/repos/r5e-group/r5e-kernel/lib/r5e/admission.ex:115)). Two empty sessions therefore receive the same name, and the second overwrites the first in the resource index ([resource_store.ex:21](~/Documents/repos/r5e-group/r5e-kernel/lib/r5e/resource_store.ex:21)); earlier session refs now hydrate to the later session. Separately, a valid `PolicyShape` submitted under the wrong name is admitted successfully but never selected, producing the same accepted-but-ignored failure as DIGEST §b.6.

**Proposal:** Require a nonempty caller-selected name for `AgentSession`. Derive and enforce the `PolicyShape` name from `{engine, kind}` in the kernel, and require `PolicyBundle` activation requests to target `active` explicitly. Reject mismatches instead of admitting inert configuration.

**Attack:** 2, 4, 10.

### 10. Story 3’s compatibility check accepts breaking schema changes

**Scenario:** A deployment supersedes `ToolCall` so `argsRef` changes type or disappears, but leaves substrate and required fields unchanged. The proposed consumer boot check passes ([spec.md:52](~/Documents/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/spec.md:52)); the consumer then emits payloads interpreted differently. Current discovery cannot return the original address at all: `GET /apis` emits `Kind.to_map` ([router.ex:44](~/Documents/repos/r5e-group/r5e-kernel/lib/r5e/http/router.ex:44)), which adds normalized/defaulted fields and is not the admitted spec whose address was stored ([kind.ex:70](~/Documents/repos/r5e-group/r5e-kernel/lib/r5e/kind.ex:70)).

**Proposal:** Preserve the original admitted KindDefinition and its `specAddress` in the registry. Let consumers declare a compatibility projection covering every property/type/enum/ref rule they use, and fail if that projection is not satisfied. Return the discovery snapshot’s chain head/sequence so the recorded capability set has a causal position.

**Attack:** 7, 10.

### 11. The natural-language source has no admitted lineage

**Scenario:** The draft calls this file the natlang step and the KindDefinitions the meta-construct ([spec.md:26](~/Documents/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/spec.md:26)), but no KindDefinition references an admitted copy of this specification. An offline consumer receives scopes and schemas but cannot establish which reviewed natural-language contract they were derived from. KP-5’s inline `description` does not create the three separately content-addressed stages required by the cited meta-API philosophy ([meta-api-philosophy.md:45](~/Documents/repos/handbook/design/meta-api-philosophy.md:45)).

**Proposal:** Admit the reviewed spec as a CAS artifact and add a `definitionRef`/`derivedFrom` address to every KindDefinition. Include that object in export and verify the lineage.

**Attack:** 8, 10.

## B. Minor findings

- FR-002 says nine Kinds, while the binding stance still says “eight Kinds” ([spec.md:21](~/Documents/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/spec.md:21), [spec.md:77](~/Documents/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/spec.md:77)).
- Story 1 enumerates six admitted instances plus one denied ToolCall, not “7 admissions, 1 denials”; SC-001 separately says seven admissions plus one denial ([spec.md:44](~/Documents/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/spec.md:44), [spec.md:147](~/Documents/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/spec.md:147)).
- SC-001 requires the verifier’s `policy:` line to cite a shape, but no KP requires extending the policy reporter beyond bundle checking.
- `LlmResponse.toolCalls` is optional even though its scope claims the list is exact; absence cannot mean both unknown and empty ([spec.md:118](~/Documents/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/spec.md:118)).
- Prompt/Completion `size` is derivable from CAS bytes and should be returned by `PUT /cas`, not accepted from the caller.
- `mediaType` allegedly defaults to `text/plain`, but the kernel stores absent fields unchanged; remove the default or specify a derived read projection.
- `LlmResponse.status` has no type or vocabulary; the enterprise source distinguishes integer upstream status and error kind.
- `argsRef` and `resultRef` do not define the referenced bytes’ media type or canonical encoding, so Cedar cannot know whether an object is JSON.
- Dotted literals have no escaping, type, or namespace rules; two engines can parse `"spec.tool"` and quoted literals differently.
- Specific-shape versus `*` fallback precedence is not stated.
- FR-015’s “first duplicate wins” prevents explicit correction and lets a premature false response dominate; use a typed `supersedes` relation or make cardinality admission-enforced.
- Current Cedar exposes positional IDs such as `policy1`, so “receipt cites the rule” is unstable when a preceding policy is inserted ([recurse_fold README:81](~/Documents/repos/r5e-group/r5e-enterprise/apps/recurse_fold/README.md:81)).
- SC-007 must distinguish deleting an object before export from deleting it inside an already-created export; only the former updates `manifest.missingObjects`.

## C. Contradictions between the draft and cited sources

1. **Caller-facing refs**

   Draft: “A caller references what the kernel told it” using `sha256:` addresses, while name refs remain unresolved ([spec.md:78](~/Documents/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/spec.md:78)).

   DIGEST: “Callers write names; the server resolves” and “server stores the resolved digest for audit-trail integrity” ([DIGEST.md:187](~/Documents/repos/r5e-quarry/DIGEST.md:187)).

2. **Detached payloads**

   Draft: `PolicyBundle` requires inline `source`; ToolCall/ToolResult allow inline arguments/results ([spec.md:82](~/Documents/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/spec.md:82), [spec.md:120](~/Documents/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/spec.md:120)).

   Core: “Detached payloads — normative. Logs and resources carry hashes; payload bytes live in controlled storage” ([01-substrates.md:45](~/Documents/repos/r5e-group/r5e-core/spec/01-substrates.md:45)).

3. **Authored epistemic scope**

   Draft: “every Kind in this group carries an authored `epistemicScope`” ([spec.md:86](~/Documents/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/spec.md:86)).

   Binding milestone stance: “The API design must not require authored scopes per Kind” and the two M0 scopes “are not the pattern” ([fold-milestone-zero.md:213](~/Documents/repos/handbook/design/fold-milestone-zero.md:213)).

4. **Where the Cedar shape belongs**

   Draft: `PolicyShape` is a separate resource and calls that presentation rather than authority ([spec.md:83](~/Documents/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/spec.md:83)).

   Cited milestone debt: “Kind→Cedar shape declared on the KindDefinition instead of code” ([fold-milestone-zero.md:242](~/Documents/repos/handbook/design/fold-milestone-zero.md:242)). The draft says it “amends” that exit without amending the cited design document.

5. **Natlang admission**

   Draft: “This file is the natlang step” but only admitted KindDefinitions are live artifacts ([spec.md:26](~/Documents/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/spec.md:26)).

   Meta-API philosophy: natlang, meta-construct, and invocation are each “a CAS artifact, visible and referenceable” ([meta-api-philosophy.md:45](~/Documents/repos/handbook/design/meta-api-philosophy.md:45)).

6. **Authority in the promised record**

   Draft: Story 1 promises a governed, offline-verifiable session while `AgentSession` expressly records no on-behalf-of authority ([spec.md:30](~/Documents/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/spec.md:30), [spec.md:84](~/Documents/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/spec.md:84)).

   Charter: the record must establish “who acted, under whose authority” ([CHARTER.md:10](~/Documents/repos/r5e-group/r5e-core/CHARTER.md:10)).

7. **Read symmetry**

   Draft: read symmetry is “a deployment concern this spec does not settle” ([spec.md:161](~/Documents/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/spec.md:161)).

   Core: “No conformant deployment may grant an operator reads the subject cannot mirror” ([04-evidence-and-disclosure.md:23](~/Documents/repos/r5e-group/r5e-core/spec/04-evidence-and-disclosure.md:23)). This is a conformance condition, not an optional deployment detail.

## D. What I tried to break and could not

- **Backward streaming order:** `Prompt → LlmCall → ToolCall(s) → Completion → LlmResponse` is orderable. `LlmCall` anchors mid-stream decisions; `LlmResponse` can point backward to Completion and both admitted and denied ToolCall events ([spec.md:32](~/Documents/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/spec.md:32)). The remaining defect is typed target validation, not direction.
- **`AgentSession.onBehalfOf`:** The current draft no longer contains the unverified string; FR-009 explicitly excludes it pending a core Endorsement ([spec.md:84](~/Documents/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/spec.md:84)).
- **Scope defaulting itself:** Six defaulted Kinds would not violate the Charter or spec/02. Spec/02 expressly supplies a modest default ([02-kinds-and-admission.md:31](~/Documents/repos/r5e-group/r5e-core/spec/02-kinds-and-admission.md:31)). They simply could not support the richer claims in Stories 1–2. The current draft now specifies nine authored scopes, not six of eight.
- **Exact admitted-spec address determinism:** For the same decoded JSON value, key order and source-file whitespace do not change `specAddress`; maps are sorted before hashing ([canonical.ex:29](~/Documents/repos/r5e-group/r5e-core/verifier/lib/recurse_verify/canonical.ex:29)). The break is discovery normalizing away from that original object, not cross-deployment hashing of the original.
- **Sequential shape supersession:** With no concurrency and with the exact shape address on every receipt, an auditor can distinguish decisions made before and after supersession. The failure is the concurrent authorization/append window and the incomplete Cedar-request definition.