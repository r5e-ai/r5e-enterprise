# Schema-lite v2 — the normative meta-schema for KindDefinitions (proposed core amendment, CS-1)

> **r7, 2026-09-02**, after contract review round 3 (Opus + Codex/Sol; both
> reports beside this file) and the CS-1a/1b/1c/1d and fold-v2 implementation
> findings (`contract-amendments.md`, A–E series). The reference kernel
> enforces §0–§7, §9, §11, §12; the fold implements §8; the verifier checks
> §10 including the §8 equality invariant. The published copy is
> r5e-core `spec/05-kind-schema.md`; this file is the drafting source and the
> two are kept identical in normative content. Companion to `spec.md` r3. This is the syntax the
> seeds in `kinds/` use and the syntax the kernel enforces once CS-1 lands.
> Every keyword here is implemented; nothing a KindDefinition may declare is
> accepted-but-ignored. Stratum: core spec/02 (what a KindDefinition means),
> kernel (enforcement), verifier (offline re-check). The discriminator after
> this revision is **conformance vectors** (§12), not another prose review.

## 0. Two predicates, used everywhere

```
exists(obj, f)   := obj has own key f and obj[f] != null
nonEmpty(v)      := v != "" and v != {} and v != []   (null is never nonEmpty)
```

`required`, `exactlyOne`, `requires.then`, and `{present: f}` use **exists**. Emptiness is governed only by `nonEmpty` (§3) and by `type`. `[]`, `{}`, `""` are values, not absences. An explicit `null` on a declared property is not-exists: it fails `required`, does not count for `exactlyOne`/`present`, and is not type-checked (it is treated as the key being absent).

## 1. KindDefinition, top level

| key | required | meaning |
|---|---|---|
| `group`, `kind`, `version` | yes | identity. A second definition with the same identity is denied unless byte-identical (canonical encoding). |
| `substrate` | yes | `artifact` \| `event` \| `resource` |
| `naming` | yes | §2 |
| `schema` | yes | §3 |
| `epistemicScope` | no | `{claims: [string+], doesNotClaim: [string+]}`. Absent → modest default, flagged `scopeDefaulted`. **Malformed** (present but not that shape) → the KindDefinition is denied. |
| `description` | no | string; newlines allowed; carried by `to_map`, export, verifier. |
| `predicates` | yes | array, may be `[]` (exists, not nonEmpty). Semantics: spec/04. |

**Envelope fields at admission** (not in `spec`, recorded beside it on the payload, the store entry, and the receipt): `derivedFrom` (optional, `bytes:sha256:…` of the natlang document the definition was derived from). It is never an input to naming or `specAddress`, so the repo file *is* the admitted bytes.

Undeclared top-level keys, undeclared schema keywords, and illegal combinations (`items` unless `type` is exactly `"array"`; `ref` without `"ref"` in `type`; `pattern` without `"string"` in `type`; `minimum`/`maximum` without `"integer"` in `type`; a name in `required`/`nonEmpty`/`exactlyOne`/`requires` not declared in `properties`; a `sameAnchor` whose anchor field is not a declared property (B2); an empty `exactlyOne` group; a regex that does not compile or uses a construct outside the RE2 subset — backreferences `\1`–`\9`, lookaround `(?=` `(?!` `(?<=` `(?<!`, atomic groups, possessive quantifiers, recursion) **deny the KindDefinition at `validateStructure`**. Every defect in a KindDefinition, and every naming/readmit/envelope defect on any admission, denies at `validateStructure` (A3): a KindDefinition's own §1 check fires before, and instead of, the meta-Kind's nested schema check, so exactly one message is produced (A14).

## 2. Naming modes

Rendered names match `[A-Za-z0-9._:@*-]+(/[A-Za-z0-9._:@*-]+)*` (full match), ≤ 255 bytes; `*` is legal so the fallback shape `cedar.*` can be named. Braces are not name characters, so a `derived` template has no escape syntax (A8). A name may contain `/`; a resource API path is therefore split **from the left into `group/version/Kind` plus the remainder as the name** (kernel change to `resolve_resource_ref` and the router, which already accepts percent-encoded slashes).

| mode | who names | create | readmit (same name) |
|---|---|---|---|
| `content` | kernel | name = canonical hash of the caller's spec, `sha256:<hex>`. Caller-supplied name → denied. | events: a new event, no store entry to change. artifacts/resources: **idempotent** — a byte-identical spec is a new event and the store entry is unchanged; a different spec cannot share the name. |
| `path` | kernel | name = `{group}/{version}/{kind}` from the spec (the meta-Kind's own mode). A caller-supplied name must equal it or the admission is denied (A5). | **deny** unless byte-identical (§1). |
| `literal` | schema | `{mode: "literal", value: "active"}`; any other name → denied. | **supersede**: any authenticated actor, subject to policy. **Supersession record (A4)**: the new entry carries its own `admissionEvent` and `supersedes` (the displaced entry's `admissionEvent`); the displaced entry is retained, stamped `supersededBy` (the new `eventRef`), readable through the store's superseded index. Unbounded retention of displaced entries is named open. |
| `derived` | kernel | `{mode: "derived", derive: "<template>"}`. Template = literal text plus `{field}` where `field` is a declared top-level `string` property; no operators, no escapes; an undeclared or non-string field → the KindDefinition is denied. A caller-supplied name must equal the rendered name or the admission is denied. | **supersede** as `literal`. |
| `server` | kernel | caller name must be absent; the payload's `target.name` is **omitted** at record; name = the admission event's hash rendered `event:sha256:<hex>`; the store entry and replay both derive it from the event, never from the payload. A caller name that matches no entry is denied with the replace rule's reason (A7). | **replace**: the caller submits the existing server name; denied unless `actor.id` equals the actor of record on the entry (a kernel integrity rule, not a policy decision: it fires at `validateStructure`, before policy, so the receipt carries no policy block — A3); the entry keeps its name and records the supersession as under `literal`. |
| `caller` | caller | free name; an absent name is the canonical hash of the spec (the v1 kernel behaviour, A6). Not used by this group; pre-v2 definitions replayed from an existing log are loaded in this mode with `legacy: true`. | supersede as `literal`. |

## 3. `schema`

```
schema := { required: [field…],            // exists
            nonEmpty?: [field…],           // nonEmpty, evaluated only when the field exists
            properties: { field: prop … },
            exactlyOne?: [[field, field…]…],   // exactly one member exists per group
            requires?: [ { when: cond, then: [field…] } … ],
            additionalProperties: false }  // required in v2; undeclared keys denied
prop   := { type: T | [T, T…],              // non-empty, duplicate-free union; "ref" may not appear in a union
            enum?: [scalar…], pattern?: regex,             // pattern: RE2 subset (§1); "string" must be in type
            minimum?: integer, maximum?: integer,          // "integer" must be in type
            items?: prop,                                  // required when type is exactly "array"; a union containing "array" passes arrays whole
            properties?: {…}, required?: […], additionalProperties?: false,   // when "object"
            values?: prop,                                 // when "object": every value matches; vacuously true on {}
            ref?: refdecl }                                // required when type == "ref"
T      := "string" | "integer" | "boolean" | "object" | "array" | "ref"
cond   := { field: name, equals: scalar } | { present: name }
```

- `properties` and `values` on one object prop are conjunctive.
- `pattern`: RE2 subset (§1), UTF-8, **full match** of the whole string. Reference implementation: Erlang `:re` compiled as `\A(?:<pattern>)\z` with `[:unicode, :ucp]`; a union value that is not a string is not matched.
- No JSON float anywhere in a spec, at any depth, declared or not: validation error.
- An object whose only key is `$ref` is a **ref value**; it is admissible only where `"ref"` is the declared type. A `$ref` key anywhere else → validation error. A ref value with any other key → validation error.
- Limits (denied above): depth 16, array length 4096, properties 256, regex 1 KiB, spec 1 MiB.

## 4. Refs

```
refdecl := { kind: "g/v/K" }                                   // value = the target's API path g/v/K/name
         | { event: "g/v/K", outcome?: "admitted"|"any", sameAnchor?: field }   // value = event:sha256:<hex>
         | { bytes: true, json?: prop, retention?: "public-record" }            // value = bytes:sha256:<hex>; json = the prop the decoded bytes must match
```

`<hex>` is exactly 64 lowercase hex digits. `substrate` is not declared (derivable from the target Kind).

| class | value | `resolve` checks | manifest entry adds |
|---|---|---|---|
| `kind` | `g/v/K/name` | the path's `g/v/K` equals the declared kind; an admitted instance with that name exists on the store (admitted = a granted admission whose substrate write succeeded; a logged post-record failure does not count until replay) | `specAddress`, `admissionEvent` (the entry's `eventRef`), `generation` (the entry's admission seq) |
| `event` | `event:sha256:<hex>` | an admission event on this chain with that hash (existence), whose outcome matches the facet (default `admitted`; `any` also admits `admission.denied`) — checked separately so the reason is legible; its payload present in the CAS (**missing payload → denied at `resolve`**, reason `targetPayload: missing`); the payload's `target.{group,version,kind}` equals the declared `g/v/K` in all three segments (B5). "Lower seq" is not a resolve check — an unappended event has no hash to cite — it is a verifier check against the recorded `seq` (B1) | `seq`, `outcome`, `targetKind`; with `sameAnchor`: `anchorField`, `head` (the observed current head's `event:` ref; on an admitted manifest it equals `value`, and is recorded so §7's `record` has something to compare) (B3) |
| `bytes` | `bytes:sha256:<hex>` | a `core.r5e.io/v1/CasObject` admission with that address exists (§5); the address is **not** any event's `payload` address nor any admitted `specAddress` (the partition is a property of the act, checked here via §5's reference index and by the verifier; before 1c the kernel scans the log, B6) | `size`, `casObjectEvent` (`null` until 1c records the admission, B7) |

`sameAnchor` (legal only on a property named `supersedes` whose declared event Kind is the enclosing Kind): the canonical encoding of the named anchor field in the submitting spec equals that in the target's spec; both must exist; the target's actor of record equals the submitter's `actor.id`; the target is the **current head** for `(kind, anchor)` — heads are computed over admitted events only. `resolve` records the observed head; `record` re-checks it (§7).

**Pipeline** (spec/02 amendment): `authenticate → validateStructure → resolve → authorize → validateConstraints → record → admit`. `validateStructure` = Kind lookup, `type`, ref wrapper form, `additionalProperties`, no-float, limits. `resolve` = pure lookups, no writes; failure = denial at stage `resolve` naming the JSON pointer, the declared target, and what was found. `validateConstraints` = `required`, `nonEmpty`, `enum`, `pattern`, `minimum`/`maximum`, `exactlyOne`, `requires`. An unknown Kind is denied at `validateStructure`.

**Resolution manifest** (`resolvedRefs`): an array sorted by pointer in **byte order** (so `/a/10` precedes `/a/2`; B4), canonically encoded, one entry per ref *location* (array members individually; a location matched by both `properties` and `values` yields one entry, the named property's; the same value at different locations yields one entry each):

```
{ "path": "/toolCalls/0",                  // RFC 6901 pointer into spec
  "class": "kind"|"event"|"bytes",
  "value": "<the ref string as submitted>",
  … class-specific keys from the table above … }
```

It is a sibling of `spec` on the event payload and on the store entry; replay copies it from the payload (it trusts the record; KP-3 re-derives it offline). It is never an input to naming or `specAddress`. The kernel passes it to the policy engine as the request key `resolved`. Store entries carry `admissionSeq`, the `generation` a kind ref captures.

## 5. Raw bytes: `core.r5e.io/v1/CasObject`

Two core event Kinds, naming `content`, admitted through the full pipeline like everything else:

- `CasObject` — schema `{required: [address, size, class], properties: {address: {type: string, pattern: "bytes:sha256:[0-9a-f]{64}"}, size: {type: integer, minimum: 0}, class: {type: string, enum: [raw]}, mediaType: {type: string}}, additionalProperties: false}`. `PUT /cas` = "admit a CasObject": the kernel hashes the body, builds the spec itself (the caller supplies only optional `mediaType`), runs the pipeline, and on grant writes the bytes as the `admit` step and returns the receipt plus `{address, size}`. The bytes are written **only** on a granted admission. Body ≤ the deployment's ceiling.
- `CasExpired` — schema `{required: [address], properties: {address: {type: string, pattern: "bytes:sha256:[0-9a-f]{64}"}}, additionalProperties: false}`, actor `system:retention`, admitted by the sweeper through the pipeline. "Unreferenced" = the address is cited by **no** admitted spec, no resolution manifest (admitted or denied — a refused request's manifest is a citation, so bytes a denial names are pinned; C2), no event payload address, and no admitted `specAddress`; the kernel keeps a reference index over all four, keyed on the bare `sha256:<hex>` so the partition is one lookup. A `CasObject`'s or `CasExpired`'s own `address` field is the record of the object, not a citation of it, and is excluded from the scan (C1). A `CasObject` admission whose address already coincides with an event payload address or an admitted `specAddress` is **denied at `validateConstraints`** (the partition is enforced at both ends; C4). When an address has several `CasObject` admissions, a citation names the **first** (C3); `derivedFrom` on a KindDefinition envelope is a `bytes:` citation and must be backed like any other (C8); it is **not yet** one of the four retention citation sources, so an object cited only by a `derivedFrom` is expirable — open (D7, debt #22). Both Kinds are materialized as `core/cas-object.v1.json` and `core/cas-expired.v1.json`.

`retention: "public-record"` on a bytes ref: a `CasExpired` for an address cited by such a ref is denied at `validateConstraints`; the verifier reports a missing public-record object as a finding, not a gap, and a `CasExpired` at a **higher** seq than a public-record citation as a finding (an expiry that precedes the citation is legal at every step and is not one; C5). `PUT /cas` over the size ceiling is an HTTP refusal before the gate (413, no admission, no receipt) and is therefore pinned by HTTP tests, not by a conformance vector (C7).

**Kernel-derived objects**: a policy evaluation record (§8) is produced *inside* an admission and cannot be its own admission. The engine writes it during `authorize` and registers it as `derived`; the policy meta carries `derivedObjects: [address…]` (an additive key of the policy contract), which the kernel copies onto the event payload as `derivedObjects` beside `policy`, so replay rebuilds the derived class from the log and an export after a restart lists them (fold-v2 finding: in-memory registration alone lost the class on restart and the verifier reported 24 findings). The export manifest's `derivedObjects` is the union over payloads. The verifier checks presence and, once §8 lands, the equality invariant; until then `derivedObjects` is a producer claim the verifier cannot falsify, and its output says so (C6). The reference-count rule treats a derived object as referenced.

## 6. Address forms and layout

| form | means | store | export | `?resolution=deep` |
|---|---|---|---|---|
| `sha256:<hex>` | an admitted spec or an event payload (kernel-written) | `cas/<2>/<62>` | swept when cited | fetched as a CAS blob (existing) |
| `event:sha256:<hex>` | an event hash | the log | nothing to copy; the payload is swept with the event | the event envelope plus its decoded payload |
| `bytes:sha256:<hex>` | a raw object admitted as `CasObject` | same tree, same layout; the partition is the act (§4) | swept when cited (export sweep matches `sha256:` and `bytes:` string values, bare or inside `$ref`; a payload's `target.name` is a name, not a citation, and is not swept — B10; admitted spec objects are derivable from the inline spec and are not swept) | the bytes as a JSON value when `json` is declared, otherwise `{size, base64}` plus `mediaType` when a `CasObject` admission recorded one (B8) |
| `g/v/K/name` (kind ref) | a resource by path | store key | the entry is on the log | the stored entry plus lineage (existing) |

## 7. Commit (KP-9)

`authorize` runs optimistically (no lock). **Commit is one call on the append lock**: halt check → staleness check → append → substrate write, in that order (D1: if the substrate write were outside the lock, a reader between append and write would cite a generation the chain had already displaced). The append-before-substrate order — the legible gap — is unchanged.

Captured generations re-checked at commit: the policy engine's `generations` (a map `resourceRef => admissionSeq` of every admitted resource it read, carried in its policy meta — the one additive key of the policy contract), every manifest `kind` entry's `generation`, and every `sameAnchor` entry's `head`. On mismatch the kernel retries from `resolve` (not from `authenticate`; the readmit decision from `validateStructure` is captured on the first pass and re-read by the store at write time, D6) up to `commit_retries` (default 3); after that the admission is denied at stage `record` with reason `contended: <what moved — the ref, the generation it read, the generation now>`. A moved `sameAnchor` head never reaches `contended`: the retry's `resolve` re-runs the head check and denies there with the current head named (D2). A `contended` denial's policy block cites the stale generation on purpose — it is the evidence for the refusal — so the invariant "no receipt cites a displaced generation at a later seq than the displacement" holds over granted admissions (D5). Retry is not fair; under a hot key most contenders lose and `commit_retries` is a livelock budget, not a tolerance (D3; a fair queue is open).

A post-record substrate failure raises to the caller — the act is on the chain and a denial receipt would contradict it (D4) — and puts the node in `halted`: every later admission is denied at `record` with reason `halted: <the original failure>`, recorded, until replay completes. Two concurrent supersessions of one `literal`/`derived`/`server` name are both admitted in chain order: §7 protects *readers* of a resource, not writers of it (D8). All per node; multi-node is out of scope and stated.

## 8. PolicyShape path grammar and the evaluation record

```
path     := "spec" ("." name)+
          | hopProp ".spec" ("." name)+       // one hop through any property declared { event: … }
          | bytesProp ".json" ("." name)*     // one dereference of a property declared { bytes: true, json: … }; ≤ 64 KiB; typed against that json schema
          | "@" envField
name     := [A-Za-z_][A-Za-z0-9_]*
envField := "actor.id" | "actor.keyFingerprint" | "kind" | "group" | "version" | "name"
literal  := a JSON string in double quotes
```

- A path may **terminate** at a property declared `object` without `properties` (passed whole) but may not descend into it; descending is denied at shape admission. Arrays are passed whole; no indexing.
- `resourceId` must resolve to a string (denied at shape admission otherwise); context values may be any JSON value.
- Absent-optional terminal → key dropped, unless `whenAbsent: deny`. Absent intermediate on the `spec` branch → same rule. Unfetchable hop target → fail closed.
- A `*` shape may use only `@` fields and literals. Precedence: Kind-specific over `<engine>.*`.
- **Path or literal (E1)**: a string matching one of the four productions is a path; anything else is a literal; a string wrapped in double quotes is a literal even when it would parse as a path.
- **`@name` on a `server`-named Kind is absent at `authorize`** (the name is the event hash, which does not exist yet); `resourceId` has no `whenAbsent`, so such a shape fails closed. The fallback shape therefore uses `@kind` for `resourceId` (E2).
- **When nothing was handed to the engine** (unfetchable hop, absent required slot, missing policy source): no evaluation record is written, `evaluation: null`, `decision: "error"`, and a `note` names what could not be read (E3).
- `resolution` records only path-valued slots, one entry per distinct path, sorted by path; a literal is not a resolution (E5).
- `PolicyShape` naming: `derived`, `derive: "{engine}.{kind}"` where `kind` is the target's API path or `*` → `cedar.gateway.r5e.io/v1alpha1/ToolCall`, `cedar.*` (slashes are legal names, §2).

**PolicyEvaluationRecord**, canonical JSON, kernel-derived object, closed schema:

```
{ format: "r5e.policy-evaluation/1",
  engine: string, engineBuild: bytes-address,
  kindDefinition: sha256-address,          // the target Kind's admitted specAddress
  bundle: sha256-address, source: bytes-address, shape: sha256-address | null,
  requestBytes: base64,                    // the exact bytes handed to the engine
  entitiesBytes: base64,
  resolution: [ { path: string, value: any | "absent" } … ]   // sorted by path
  decision: "allow"|"deny"|"error", matched: [string…] }      // matched sorted
```

Invariant (verifier): `engine`, `engineBuild`, `bundle`, `source`, `shape`, `decision`, `matched` equal the receipt's policy block byte for byte.

**Engine build descriptor** (raw bytes, admitted as a `CasObject` by the operator once per build):

```
{ format: "r5e.engine-build/1", engine: "cedar", crate: "cedar-policy", crateVersion: "4.9.1",
  cargoLockSha256: "<64 hex>", nifSha256: "<64 hex>", module: "Recurse.Fold.Policy.Cedar",
  moduleSha256: "<64 hex of the module's beam bytes>", platform: "<target triple>" }
// the three sha256 fields are bare hex: they measure local files, not chain objects (E6)
```

Equal descriptor addresses mean the same engine bytes on the same platform; nothing more is claimed.

## 9. Receipt (kernel)

`name`, `specAddress`, `eventRef`, `resolvedRefs`, `derivedFrom` (when supplied), `derivedObjects` (when the engine registered any), and `policy` (engine-owned keys plus the kernel's documented ones: `engine`, `decision`, `bundle`, `bundleRef`, `matched`, `generations`, `derivedObjects` — E4: `bundleRef` stays; the fold emits it; the core verifier checks that every address in the block resolves and the §8 equality invariant).

## 10. Verifier (KP-3)

`refs:` — per class: count; every manifest entry re-derived from the bundle and checked against the **declaration** read from the exported KindDefinition's schema at the entry's pointer (a Kind absent from `kinds/` leaves that check unmade, and the line says so — B11); event refs at a lower seq than the citing event (B1); `bytes:` addresses backed by a `CasObject` admission and coinciding with no payload or spec address; a `$ref` in an **admitted** spec with no manifest entry is a finding (a denial's spec may legitimately hold unresolved refs — B12). Address predicates in the verifier are three: `valid_address?` (any of the three forms), `object_address?` (`sha256:` or `bytes:` — fetchable), `event_address?` (B9).

## 11. The replacement meta-Kind

`core/kind-definition.v2.json` beside this file is the exact `core.r5e.io/v1/KindDefinition` this contract requires (naming `path`; substrate `resource` — the v1 meta-Kind says `artifact`, and the change is part of the transition; `schema` declares `naming`, `description`, `predicates`, `epistemicScope`, `substrate` enum, `schema` as an open object whose contents §3 governs at the kernel, not at the meta-Kind). Transition: the kernel admits it as a supersession of the v1 meta-Kind under naming `path` (byte-different, so denied by §1's rule — the transition is the **one** exempt-by-design act, recorded with actor `system:bootstrap` and reason `schema-lite-v2 migration`, and the verifier prints it as such). Pinners of the old address see a boot notice, not a failure, because `naming` is a new constraint they never pinned.

## 12. Conformance vectors (the discriminator from here on)

`vectors/` beside this file (produced with CS-1): for every keyword in §3–§4 and every naming mode, an admitted instance and a denied instance with the expected stage and reason; the Story-1 sequence as a vector set; the seeds themselves as admitted KindDefinitions; the meta-Kind transition. Two implementations agree iff they agree on every vector.
