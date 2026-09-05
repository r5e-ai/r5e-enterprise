# Spec 010 — round 3 (contract review), second discriminator

**Discriminator**: Codex CLI 0.149.1, `gpt-5.6-sol`, reasoning high, read-only sandbox, 2026-09-02. Target: `schema-lite-v2.md` + `kinds/*.json` at bookmark `spec/010-r3`. Verbatim; dispositions in `review-round-4.md`.

---

# Round-3 adversarial review — contract discriminator

## A. Major

### A1 — The validation algebra is not complete, and one rule rejects a required seed case

Two implementations can disagree on all of the following:

- Whether “present” in `exactlyOne`, `requires`, and conditions means “the key exists” or “the value is non-empty.” Only `required` defines emptiness, and it counts `{}` and `[]` as absent ([schema-lite-v2.md:50](~/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/schema-lite-v2.md:50), [schema-lite-v2.md:54](~/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/schema-lite-v2.md:54)).
- Whether `values` on `{}` succeeds vacuously.
- Whether `properties` and `values` on the same object are conjunctive.
- Whether a multi-type declaration is an “any-of” union, whether an empty/duplicate type list is legal, and whether `ref` may occur in such a list.
- Whether `{"$ref":"…","extra":1}` is a ref. The prose gives the expected shape but does not explicitly require exactly one key ([schema-lite-v2.md:59](~/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/schema-lite-v2.md:59)).
- Whether regex matching searches or matches the whole value, what invalid patterns do, and which precise RE2 syntax/Unicode rules apply. “Anchored as written” removes implicit anchoring but does not define the match operation ([schema-lite-v2.md:53](~/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/schema-lite-v2.md:53)).
- Whether undeclared meta-schema keywords and illegal combinations—`items` without array, `ref` without type `ref`, undeclared names in `required`, empty `exactlyOne` groups—deny the KindDefinition or are ignored.

There is already a concrete contradiction: `LlmResponse.toolCalls` is required but intentionally may be `[]`; the global required rule says `[]` is absent ([llm-response.json:11](~/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/kinds/llm-response.json:11), [spec.md:121](~/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/spec.md:121)).

**Concrete fix:** define two predicates explicitly:

```text
exists(o, f) := o has own key f
nonEmpty(v) := v != null && v != ""       # objects/arrays may be empty
```

Make `required`, `present`, `exactlyOne`, and `then` use `exists`; let type and optional `minItems`/`minProperties` govern emptiness. Add a closed validity table for every schema keyword and combination; define type lists as non-empty duplicate-free unions; refs as exact singleton objects; `values` as vacuously true and conjunctive with `properties`; regex as RE2 UTF-8 unanchored search with invalid compilation denying the KindDefinition.

### A2 — `resolve` cannot safely run on the unvalidated request, and `resolvedRefs` has no normative shape

The pipeline says `authenticate → resolve → authorize → validate`, but the resolver is consequently handed unchecked values before it knows whether a typed-ref field is an exact `$ref` object, an array with valid items, or even the declared type ([schema-lite-v2.md:75](~/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/schema-lite-v2.md:75), [spec.md:83](~/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/spec.md:83)). One implementation can reject malformed wrappers at `resolve`; another can skip them and later deny at `validate`, producing different stages, receipts, and policy invocations.

The manifest is also underdefined:

- Only name refs receive a stated record shape.
- Event and bytes entries have no shape.
- Keys may be field names, dotted paths, JSON Pointers, or an array.
- Array duplicates, ordering, and repeated identical refs are unspecified.
- `admissionEvent` does not say whether it is `sha256:` or `event:sha256:`.
- Missing event payloads are not specified. The target Kind, outcome, actor, and `sameAnchor` are inside the detached payload, not the log envelope ([log.ex:24](~/repos/r5e-group/r5e-kernel/lib/r5e/log.ex:24), [admission.ex:141](~/repos/r5e-group/r5e-kernel/lib/r5e/admission.ex:141)).

**Concrete fix:** split validation:

```text
authenticate
→ validateStructure       # types, exact ref wrapper, arrays, no floats
→ resolve(snapshot)
→ authorize(request, manifest)
→ validateConstraints     # enum, pattern, requires, exactlyOne
→ compareAndRecord
→ admit
```

Normatively define `resolvedRefs` as an array sorted by RFC 6901 path, preserving array indices and duplicates, for example:

```json
{
  "path": "/toolCalls/0",
  "class": "event",
  "input": "event:sha256:...",
  "eventRef": "event:sha256:...",
  "seq": 17,
  "target": "gateway.r5e.io/v1alpha1/ToolCall",
  "outcome": "denied",
  "specAddress": null
}
```

Specify entries for all three ref classes and require a missing or malformed referenced payload to deny at `resolve`.

### A3 — `sameAnchor` does not prevent optimistic correction races

Two corrections can both resolve the same current head, authorize under the same policy generation, and then append sequentially. The second still creates a branch because KP-9 compares only the policy generation; no captured correction-head generation is specified ([spec.md:50](~/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/spec.md:50), [spec.md:110](~/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/spec.md:110)).

There are further divergent readings:

- “same anchor” may compare the complete `$ref` object, its string, or its resolved identity.
- “current unsuperseded head” may be global, per Kind and anchor, or per Kind, anchor, and actor.
- The commentary requires the same actor, but §4 does not; `sameAnchor` checks only the target’s anchor and head status ([schema-lite-v2.md:72](~/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/schema-lite-v2.md:72), [spec.md:95](~/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/spec.md:95)).
- It is not stated whether denied superseding attempts participate in the head graph.

**Concrete fix:** define a correction key `(group, version, kind, canonicalResolvedAnchor, actorId)` and an admitted-event-only head graph. `resolve` captures `headEvent`; `compareAndRecord` atomically verifies that exact head plus policy generation and mutable name-ref generations. Any mismatch retries the entire resolve-and-authorize sequence. Add `sameActor: true` to the ref declaration, or explicitly make it mandatory whenever `sameAnchor` appears.

### A4 — `server` naming is circular and its create/update protocol contradicts itself

For a new `AgentSession`, the name is the admission event’s hash ([schema-lite-v2.md:30](~/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/schema-lite-v2.md:30)). But the event payload normally contains `target.name`, and the event hash commits to the payload address ([admission.ex:141](~/repos/r5e-group/r5e-kernel/lib/r5e/admission.ex:141), [log.ex:95](~/repos/r5e-group/r5e-kernel/lib/r5e/log.ex:95)). That creates a hash fixed-point problem.

The mode also says the kernel names the instance, then says a caller may submit that same name again. Implementers can therefore either reject all caller names, accept them only as update selectors, or treat them as ordinary names. The seed exposes no `supersedes` field to resolve that choice ([agent-session.json:10](~/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/kinds/agent-session.json:10)).

**Concrete fix:** define two operations within server mode:

- Create: caller name must be absent; `target.name` is omitted from the event payload; after hashing, the store name is the resulting `event:sha256:…`; replay derives it identically.
- Replace: caller name must be an existing server-generated name; the new event records it as the update target and requires the original actor. State whether the resource keeps the same name or receives a new server name.

The event-hash preimage rule must explicitly cover this omission.

### A5 — The derived-name template does not generate the name required by the contract

The seed says:

```json
"derive": "{engine}.{kind|*}"
```

The only stated special behavior is that `{kind|*}` renders `*` as `*`; no rule converts `gateway.r5e.io/v1alpha1/ToolCall` into `gateway.r5e.io_v1alpha1_ToolCall` ([schema-lite-v2.md:29](~/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/schema-lite-v2.md:29), [policy-shape.json:6](~/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/kinds/policy-shape.json:6)). Literal substitution therefore gives `cedar.gateway.r5e.io/v1alpha1/ToolCall`, contradicting the prescribed `cedar.gateway.r5e.io_v1alpha1_ToolCall` ([spec.md:88](~/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/spec.md:88)).

**Concrete fix:** define a template grammar and named transforms, for example:

```json
"derive": "{engine}.{kind|pathSlug}"
```

with `pathSlug("*") = "*"` and otherwise `pathSlug(s) = replace every "/" with "_"`. Specify missing/non-string variables, escaping braces, output character constraints, and complete examples.

### A6 — The three address namespaces are not yet a reproducible storage/export/hydration contract

The contract requires a distinct raw-bytes subtree but never defines its path mapping or whether identical bytes may exist in both partitions ([schema-lite-v2.md:73](~/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/schema-lite-v2.md:73), [schema-lite-v2.md:77](~/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/schema-lite-v2.md:77)). The current store accepts only `sha256:` and maps everything into one tree ([cas.ex:18](~/repos/r5e-group/r5e-kernel/lib/r5e/cas.ex:18), [recurse_verify/cas.ex:9](~/repos/r5e-group/r5e-core/verifier/lib/recurse_verify/cas.ex:9)).

The current export sweep recursively notices only bare strings beginning `sha256:` and then filters through that same validator. It will omit every `bytes:` object, whether bare or inside `{"$ref":…}` ([export.ex:54](~/repos/r5e-group/r5e-kernel/lib/r5e/export.ex:54), [export.ex:91](~/repos/r5e-group/r5e-kernel/lib/r5e/export.ex:91)). `event:` refs need no separate object copy in a full-log export, but their target payload must remain available.

The assertion that the existing `$ref` convention makes deep resolution hydrate event refs is false today: deep resolution recognizes only `sha256:` CAS refs and four-segment resource names; `event:` and `bytes:` fall into “unrecognized ref shape” ([resource_store.ex:60](~/repos/r5e-group/r5e-kernel/lib/r5e/resource_store.ex:60), [resource_store.ex:93](~/repos/r5e-group/r5e-kernel/lib/r5e/resource_store.ex:93)).

**Concrete fix:** specify an address codec and bundle layout, e.g. `cas/internal/<shard>`, `cas/bytes/<shard>`, and log lookup for `event:`. Define export traversal per prefix and define deep hydration results:

- name ref → stored entry plus lineage;
- event ref → immutable event envelope plus decoded payload;
- bytes ref → JSON value only when media/type rules permit, otherwise a base64/raw wrapper.

### A7 — Policy paths cannot be validated purely from the target schema

The grammar leaves `name` undefined and does not specify escaping, dots in field names, parse precedence between literals and paths, or behavior when an optional intermediate object is absent ([schema-lite-v2.md:83](~/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/schema-lite-v2.md:83)).

More seriously, `bytesProp.json.foo` cannot be typed from a declaration containing only `{bytes:true}`. The schema says nothing about the JSON held by those bytes. One implementation can accept every suffix after `.json`; another must deny all nontrivial suffixes under the “validated against the target schema” rule ([schema-lite-v2.md:94](~/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/schema-lite-v2.md:94), [tool-call.json:21](~/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/kinds/tool-call.json:21)).

It is also unstated which types are admissible for `resourceId`, whether Cedar-compatible conversion occurs, and how whole objects/arrays are represented.

**Concrete fix:** define a lexical grammar for path segments and exact traversal typing. Extend byte refs with an optional declared content schema, for example:

```json
"ref": {"bytes": true, "mediaType": "application/json", "json": {"type":"object", ...}}
```

Only permit `.json.*` when that schema exists. Require `resourceId` to resolve to a string and define handling of every context result type and absent intermediate.

### A8 — Evaluation/build records are examples, not deterministic contracts

The record blocks contain ellipses and comments rather than closed schemas. The types and ordering of `request`, `entities`, `resolution`, and `matched` are undefined; the build hashes have no address grammar; and `moduleVersion` is unspecified ([schema-lite-v2.md:100](~/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/schema-lite-v2.md:100), [schema-lite-v2.md:117](~/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/schema-lite-v2.md:117)).

“Exact bytes the engine saw” is represented as a JSON object, so either the engine must be required to consume the record’s canonical encoding or the record must preserve the actual byte strings. Neither is stated. `decision`, `matched`, bundle, shape, and engine build are duplicated between the evaluation record and receipt with no equality invariant, allowing mutually contradictory evidence ([schema-lite-v2.md:128](~/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/schema-lite-v2.md:128)).

There is also an event-ordering hole: an evaluation record is raw bytes, so recording its storage through `cas.stored` must occur before the admission/denial event can cite it. Story 1 counts only two payload puts, not one additional `cas.stored` per evaluated request ([spec.md:36](~/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/spec.md:36), [schema-lite-v2.md:79](~/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/schema-lite-v2.md:79)).

**Concrete fix:** publish closed schema-lite definitions or byte-level ABNF for both records. Mandate canonical JSON as the bytes passed to Cedar, deterministic entity and matched-policy ordering, and exact equality between duplicated receipt and evaluation fields. Specify whether derived evaluation objects receive their own `cas.stored` event and update event counts/order, or define an explicit atomic kernel-derived-object exception.

### A9 — `cas.stored` and `cas.expired` break the stated self-hosting boundary

`PUT /cas` directly appends `cas.stored`, and expiry appends `cas.expired`, but neither event has a KindDefinition, schema, epistemic scope, naming rule, or admission outcome ([schema-lite-v2.md:79](~/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/schema-lite-v2.md:79)). That conflicts with core’s “every piece of state belongs to one substrate” and “no exempt path” admission rule ([01-substrates.md:3](~/repos/r5e-group/r5e-core/spec/01-substrates.md:3), [02-kinds-and-admission.md:49](~/repos/r5e-group/r5e-core/spec/02-kinds-and-admission.md:49)).

They can be counted as raw log events, but not as schema-validated claims or Kind instances. Verifiers will therefore disagree about bootstrap totals, `claims:` totals, and whether these are findings.

**Concrete fix:** add core `CASStored` and `CASExpired` event KindDefinitions and run the request through authentication, authorization, validation, and recording, with the raw-byte write ordered explicitly. Alternatively, define a normative class of kernel-envelope events and amend core’s “no exempt path” law, including exact verifier accounting.

### A10 — The contract does not contain the self-hosted meta-Kind or fully materialized seeds

The proposed contract changes the shape of `KindDefinition`, but it does not supply the replacement `core.r5e.io/v1/KindDefinition` seed. The current meta-Kind lacks `naming`, `description`, `derivedFrom`, `exactlyOne`, `requires`, and all ref declaration validation ([kind-definition.json:1](~/repos/r5e-group/r5e-kernel/priv/kinds/kind-definition.json:1)). “Meta-Kind supersession and address migration” appears only as a CS-1 task, not an executable transition ([spec.md:111](~/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/spec.md:111)).

All nine normative seed files also omit `derivedFrom`; an unspecified seeder mutates it at admission ([schema-lite-v2.md:20](~/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/schema-lite-v2.md:20)). Implementers can hash different reviewed documents, preserve different source bytes/newlines, or calculate the KindDefinition address before versus after injection.

**Concrete fix:** include:

1. The exact replacement meta-Kind JSON.
2. A transition algorithm and old/new address-pinner behavior.
3. Fully materialized admitted seed JSON or a signed seed manifest naming the exact source file bytes and deterministic injection transform.
4. Conformance vectors containing admitted and denied KindDefinitions and instances.

## B. Minor

- `description` must be “one paragraph,” but paragraph syntax and newline handling are not defined ([schema-lite-v2.md:19](~/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/schema-lite-v2.md:19)).
- Malformed `epistemicScope` is not distinguished from absent scope; the current kernel silently defaults both ([kind.ex:119](~/repos/r5e-group/r5e-kernel/lib/r5e/kind.ex:119)).
- `predicates` delegates its meaning to spec/02, so `schema-lite-v2.md` alone is not self-contained ([schema-lite-v2.md:21](~/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/schema-lite-v2.md:21)).
- Address syntax does not explicitly require 64 lowercase hexadecimal digits.
- `outcome: "any"` should explicitly mean admitted or denied admission events, not arbitrary kernel events.
- There are no maximum schema depth, array length, property count, or regex-size limits.
- Integer fields permit negative indices, durations, status codes, token counts, and latency values because the language has no range keyword.
- `retention: "public-record"` states a class but does not define the operation that prevents expiry or how a verifier distinguishes prohibited deletion from ordinary missing content.
- Resource-ref resolution says “instance exists” but does not say whether only admitted instances count after a logged post-record substrate failure.
- No rule says `sameAnchor` is legal only on a self-event ref named `supersedes`.
- The resolution failure reason is required to name “the field,” but array/nested paths require a normative path notation.
- The engine descriptor’s claim that equal descriptor addresses imply identical evaluation needs a declared platform/ABI/runtime boundary, or narrower wording.

## C. Seed-file defects

A shared defect affects all nine files: each omits `derivedFrom`, so none is the exact KindDefinition ultimately promised for admission; the seeder’s mutation is not reproducible from the seed file alone.

### `agent-session.json`

- `required: []` permits `{}`, but the description and claim say the span is “under one harness”; `harness` is optional ([agent-session.json:9](~/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/kinds/agent-session.json:9), [agent-session.json:11](~/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/kinds/agent-session.json:11), [agent-session.json:43](~/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/kinds/agent-session.json:43)).
- The description promises actor-restricted supersession, but no property or seed constraint represents an update/supersession operation.
- Its `server` mode inherits the circular name and undefined create/update behavior from A4.

### `completion.json`

- “Identical bytes are one artifact whatever produced them” is false under `content` naming because the name hashes the entire spec; changing `mediaType` or `observedAt` produces a different name for the same `contentRef` ([completion.json:6](~/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/kinds/completion.json:6), [completion.json:9](~/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/kinds/completion.json:9)).

### `llm-call.json`

- `parameters.values.type: ["string","integer","boolean"]` depends on the undefined union semantics from A1 ([llm-call.json:80](~/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/kinds/llm-call.json:80)).
- Otherwise its declared properties, transport enum, and ref targets match the Key Entity commentary.

### `llm-response.json`

- Required `toolCalls` cannot be empty under the global non-empty rule, contradicting the explicit “may be `[]`” contract.
- The epistemic claim unconditionally says response bytes are at `completion`, although `completion` is absent for error outcomes ([llm-response.json:116](~/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/kinds/llm-response.json:116)).
- `supersedes` inherits the missing same-actor and atomic-head semantics from A3.

### `policy-bundle.json`

- The seed’s `literal: active`, engine enum, source ref, and declared retention match the commentary.
- No admitted draft can exist. That is consistent with “draft/activation collapsed”: draft text may exist only as unattached raw bytes, not as a `PolicyBundle` resource ([spec.md:87](~/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/spec.md:87)).
- Retention remains declarative until A6/B7 is fixed.

### `policy-shape.json`

- The derived template does not produce the prescribed slash-to-underscore name.
- `resourceId` and `context.*.path` are only strings in the seed; all path grammar and cross-Kind validation live in an underspecified special admission hook ([policy-shape.json:36](~/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/kinds/policy-shape.json:36), [policy-shape.json:39](~/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/kinds/policy-shape.json:39)).
- An empty `context` depends on unspecified vacuous `values` behavior.

### `prompt.json`

- The description says “bytes sent to a model, exactly as sent,” while its scope expressly does not claim that a model received them ([prompt.json:9](~/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/kinds/prompt.json:9), [prompt.json:50](~/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/kinds/prompt.json:50)). Change “sent” to “submitted for sending.”
- Its properties, role enum, and refs otherwise match the Key Entity commentary.

### `tool-call.json`

- Whether `args: {}` satisfies `exactlyOne` depends on the unresolved meaning of “present” ([tool-call.json:18](~/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/kinds/tool-call.json:18), [tool-call.json:64](~/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/kinds/tool-call.json:64)).
- `argsMediaType` is accepted with inline `args`, although commentary assigns its default specifically to detached `argsRef`; add a conditional rule if that distinction is intended.
- The scope’s policy/evaluation claim requires the missing receipt-to-evaluation equality invariant from A8.

### `tool-result.json`

- `result` relies on undefined multi-type union semantics, and `result: {}` depends on the unresolved `exactlyOne` presence rule ([tool-result.json:30](~/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/kinds/tool-result.json:30), [tool-result.json:61](~/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/kinds/tool-result.json:61)).
- `resultMediaType` is not conditioned on `resultRef`.
- `supersedes` inherits A3’s missing actor/head atomicity.

## D. Not broken

- All nine Kind identities and substrate assignments match the Key Entities list: two artifacts, four events, and three resources ([spec.md:81](~/repos/r5e-group/r5e-enterprise/specs/010-gateway-api-group/spec.md:81)).
- The six artifact/event seeds use `content`; `PolicyBundle` uses `literal`; `PolicyShape` uses `derived`; `AgentSession` uses `server`. The mode selection itself is correct.
- Every declared Kind ref targets one of the nine seeds with the expected substrate.
- Every event ref targets an existing event Kind.
- Every `required`, `exactlyOne`, `requires`, and `sameAnchor` field name used by a seed is declared in that seed’s properties.
- The LlmResponse `outcome`, ToolResult `outcome`, Prompt `role`, LlmCall `transport`, PolicyBundle/PolicyShape `engine`, and LlmResponse `errorKind` enums match the r3 commentary.
- `LlmResponse.toolCalls` correctly uses `outcome: any`, while causal refs such as `llmCall` and `toolCall` require admitted events.
- Both supersession refs point backward to the same Kind and name a required anchor field.
- PolicyShape’s seed pattern is explicitly `^…$`, so the seed does not itself depend on implicit anchoring.
- A full-chain export does not need to copy an object for an `event:` string: the referenced event is already in `log.jsonl`, and its payload is swept from the event list. The broken part is `bytes:` handling.
- Collapsing PolicyBundle draft and activation is coherent: no draft resource exists, and unattached source bytes do not become active policy.
- The policy-specific-before-wildcard precedence and wildcard restriction are unambiguous as stated.
- Raw evaluation records being erasable is consistent with core’s detached-payload erasure model ([04-evidence-and-disclosure.md:59](~/repos/r5e-group/r5e-core/spec/04-evidence-and-disclosure.md:59)).

## E. Termination signal

**Not ready to brief CS-1 from this contract. It needs another contract pass.**

The remaining defects are not implementation choices or minor editorial gaps. Independent implementers would produce different admission stages, accepted instance sets, names, correction histories, manifests, CAS layouts, exports, deep-resolution views, policy records, and verifier totals.

The next pass should be narrow and mechanical: close the validation algebra, publish the exact manifest and record schemas, define atomic correction state, remove the server-name hash cycle, formalize template/path/address codecs, introduce typed CAS lifecycle events, and include the replacement meta-Kind plus fully materialized seeds. After those changes, conformance vectors—not another prose review—should be the discriminator.