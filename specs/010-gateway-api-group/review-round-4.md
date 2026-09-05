# Spec 010 — round 4 synthesis (contract round 3 → schema-lite-v2 r2)

**Inputs**: `review-round-3-opus.md` (A1–A10, 17 minors, seed defects), `review-round-3-codex.md` (A1–A10, minors, seed defects). **Synthesis**: Fable, 2026-09-02. The two reports overlap almost one-to-one; every major from both is applied in `schema-lite-v2.md` r2, the regenerated `kinds/*.json`, `core/kind-definition.v2.json`, and `spec.md`.

| Finding (Opus / Codex) | Disposition in r2 |
|---|---|
| A1 / A1 presence vs emptiness | **applied**: §0 `exists` and `nonEmpty` as separate predicates; `required`/`exactlyOne`/`requires`/`present` use `exists`; a `nonEmpty` list where wanted (`model`, `tool`, shape fields); `toolCalls: []`, `args: {}`, `result: ""` admissible; `predicates: []` admissible |
| A2 / (A6) ref value form; deep hydration false | **applied**: kind-ref value = API path `g/v/K/name`; `substrate`/`outcome` dropped from kind refs; slashes legal in names with left-split resolution; deep hydration semantics per address form (§6) |
| A3 bytes partition nominal | **applied**: partition is a property of the act — `bytes:` must be backed by a `CasObject` admission and coincide with no payload/spec address; single CAS tree |
| A4 / A2 manifest shape; missing payload | **applied**: §4 pointer-sorted array with per-class keys; missing target payload → deny at `resolve` |
| A5 / A3 correction race; sameAnchor | **applied**: head recorded at `resolve`, re-checked at `record` with policy and name-ref generations (§7); canonical-encoding comparison; same actor; heads over admitted events; legal only on `supersedes` |
| A6 / A9 `cas.stored` exempt path | **applied**: `core.r5e.io/v1/CasObject` + `CasExpired` Kinds; `PUT /cas` is an admission; kernel-derived objects (evaluation records) defined as a class with export manifest listing |
| A7 / (A5) readmit rules | **applied**: `readmit` column per mode; `supersededBy` on entries; `content` idempotent; `path` deny-unless-identical |
| A8 / A5 derived template; meta-Kind name | **applied**: total template (`{field}` only, brace escapes); `path` mode; `PolicyShape` = `{engine}.{kind}`; `core/kind-definition.v2.json` written; §11 transition |
| A9 / A7 `$ref` in open values; paths into open objects | **applied**: `$ref` legal only where declared; paths terminate at, never descend into, open objects; `bytes` deref only with a declared `json` schema; `@` envelope namespace; `name` lexical rule; `resourceId` must be a string |
| A10 / A10 `derivedFrom` in spec | **applied**: envelope field beside `spec`; seed files are the admitted bytes; the meta-Kind and transition included |
| Codex A2 / Opus B2-3 evaluation record | **applied**: closed schema, `requestBytes`/`entitiesBytes` base64, sorted `matched`, equality invariant with the receipt; build descriptor closed with `platform` and `moduleSha256`, claim narrowed |
| Codex A4 / Opus B `record` details | **applied**: §7 retry/`contended`/`halted` |
| Codex A8 / Opus B limits, ranges, regex | **applied**: limits, `minimum`/`maximum`, RE2 full-match, no-op on non-strings, invalid regex denies the KindDefinition |
| seed defects (both) | **applied**: `errorKind` = enterprise's five; `transport` `https-sse`; `parameters` floats as decimal strings (stated); `argsMediaType`/`resultMediaType` require the ref; `result` admits arrays; policy-shape `kind` pattern admits digits; actor disclaimer on all nine; scope claims rewritten as claims about this instance and its own window; prompt/completion naming stated honestly; `sourceIds` closed on both Kinds; `harness` claim conditioned |
| Opus B minors | **applied** (`naming` in `to_map`, `from_map` parses `naming`, `values`+`properties` conjunctive, `retention` enforcement via `CasExpired` denial, export sweep covers `bytes:` bare or in `$ref`, replay trusts the manifest — stated, actor of record = `actor.id` — stated in §2 `server`, stages for unknown Kind / malformed ref named) |

**Declined**: none. **Open (stated in the contract)**: multi-node commit; positive read symmetry; break-glass.

**Discriminator from here**: §12 conformance vectors, produced with CS-1, checked by a reviewer against the seeds and the meta-Kind. One internal-consistency verification pass on r2 precedes the CS-1 brief, per Opus (E).
