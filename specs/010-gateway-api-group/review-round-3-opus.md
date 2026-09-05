# Spec 010 — round 3 (contract review), first discriminator (Opus)

**Discriminator**: Claude Opus subagent, 2026-09-02, on `schema-lite-v2.md` r1 + `kinds/*.json` at bookmark `spec/010-r3`. Condensed; dispositions in `review-round-4.md`.

## (A) Major

- **A1** `required`/`exactlyOne` treating empty as absent makes the modal instance of LlmResponse (`toolCalls: []`), ToolCall (`args: {}`), ToolResult (`result: ""`) inadmissible, and `predicates: []` on every seed. Fix: `exists` vs `nonEmpty`, separately.
- **A2** Kind-ref values are "names", and content/server names are themselves `sha256:`/`event:` addresses, so the three-way partition collapses and `?resolution=deep` hydrates none of the seeds' forms (`resource_store.ex:60-108` dispatches structurally). Fix: ref value = API path `g/v/K/name`.
- **A3** The `bytes:` subtree is nominal: identical bytes hash identically in both subtrees, so an attacker puts the policy text as raw bytes and passes the partition check. Fix: the partition is a property of the act (`cas.stored` records class), verifier checks the address is no payload/spec address.
- **A4** `resolvedRefs` has no shape; it is inside the payload hash, so two kernels produce different chains. Missing target payload behaviour unstated (erasure would DoS admission or defeat facets). Fix: JSON-pointer-keyed manifest; missing payload → deny at resolve.
- **A5** `sameAnchor` head check at pure `resolve` + KP-9 comparing only the policy generation → two supersedes race. Fix: head recorded at resolve, re-checked at record as a second captured generation; canonical-encoding comparison of the anchor field.
- **A6** `cas.stored` is an event with no Kind on a chain with no exempt path; invisible to `claims:` totals, inflates the actor list; `cas.expired` has no actor. Fix: `core.r5e.io/v1/CasObject` (+ `CasExpired`, actor `system:retention`), `PUT /cas` as an admission.
- **A7** Only `server` has a re-admission rule; Story 2 depends on `literal` re-admission; `content` idempotence unstated. Fix: `readmit` column (`deny` | `supersede` | `idempotent`) + `supersededBy` on the entry.
- **A8** The `derived` template has no operators, contradicts FR-008's underscore form, and no mode can name the meta-Kind (`group/version/kind`). Fix: total template function, a `path` mode, slashes legal in names with left-split resolution.
- **A9** `{"$ref": …}` inside an open `object`/`string|object` value is undefined: hydrated, swept, never resolved; defeats `exactlyOne`. §6 contradicts itself on paths into open objects. Fix: `$ref` only where `type: ref`; paths may terminate at, not descend into, open objects.
- **A10** `derivedFrom` injected into `spec` after authoring breaks byte-identity and re-opens M2. Fix: envelope field recorded beside `spec`.

## (B) Minor (17)

`outcome` on kind refs is dead (denials have no store entry); `request` "canonical JSON" vs "exact bytes" (`cedar.ex` uses `JSON.encode!`); no equality invariant between the evaluation record and the receipt; "anchored as written" is contradictory; CS-1 omits `naming` from `to_map`; `from_map` discards `naming` today; `substrate` on refdecl is derivable; path grammar lives outside the schema; `hopProp`/`envelope` namespace collision (`kind`); bytes hop > 64 KiB / non-JSON unstated; `values`+`properties` co-occurrence; `retention` has no kernel behaviour and no reference index; export sweep ignores `bytes:`/`event:` and the KP table lists no export change; replay trusts the manifest (say so); `content` denies caller names while `derived` accepts a correct one; "actor of record" = id or id+fingerprint?; stage for unknown Kind / malformed ref unstated.

## (C) Seed defects

agent-session: server-name circularity (`target.name` in the payload), `harness` claim vs optional, `sourceIds` open vs closed. completion/prompt: "identical bytes are one artifact" false under spec-hash naming. llm-call: `parameters` cannot hold floats (state string coercion); `transport` source value is `https-sse` (hyphen) and `https` has no source. llm-response: `toolCalls` A1; `errorKind` enum has zero overlap with enterprise's `["upstream_4xx","upstream_5xx","parser_failure","policy_evaluation_failure","upstream_connection_failed"]`; "exactly" is a completeness claim. policy-bundle: no `supersedes`, no readmit rule, scope claims about other records and future events; `cedar.ex` still reads inline `source`. policy-shape: template vs FR-008; `kind` pattern rejects digits; missing actor disclaimer; grammar outside schema. tool-call: `args: {}` A1; open `args` un-typable; scope over-claims for the `shape: null` fallback. tool-result: `result: ""` A1; arrays excluded; `{"$ref"}` in `result`. All: no `derivedFrom`.

## (D) Not broken

The nine Kinds, substrates, and field sets match the prose; the outcome facet is applied correctly; multi-type is in the grammar; resolve-before-authorize is right; `whenAbsent` and the bounded hops close M6; "input erased" is right; `eventRef` on receipts closes the caller-manufactures-a-ref defect; the duplicate-Kind rule sits in the right place.

## (E) Termination signal

Not ready to brief CS-1; **one more pass on `schema-lite-v2.md` only**, plus regeneration of the three affected seeds and the enum corrections. A fourth prose round would be waste; a single verification pass confirming the ten fixes are internally consistent would not.
