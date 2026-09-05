# Contract amendments from implementation (schema-lite v2)

> The contract was reviewed four times; CS-1a was its first implementer and
> found fourteen things the text left open. Each is decided here and folded
> into `schema-lite-v2.md` r3 (and r5e-core `spec/05-kind-schema.md`, synced
> in CS-1b). The kernel's conformance vectors pin each decision.

| # | Finding (CS-1a) | Decision |
|---|---|---|
| A1 | `items` beside a union containing `array` is legal-but-ignored | **deny**: `items` only when type is exactly `"array"` (§1) |
| A2 | `pattern` on a non-string type is a pure no-op | **deny** unless `"string"` ∈ type; same for `minimum`/`maximum` and `"integer"` (§1) |
| A3 | stage for §1 meta-checks, naming, readmit, envelope defects unstated; server-replace-by-another-actor denies before policy runs | all at `validateStructure`; the ownership check is a kernel integrity rule, not policy — stated (§1, §2) |
| A4 | `supersededBy` + previous `admissionEvent` cannot both live on one name-keyed entry | new entry: `admissionEvent` + `supersedes`; displaced entry retained with `supersededBy`, readable via a superseded index; unbounded retention named open (§2, debt #19) |
| A5 | `path` mode silent on a caller-supplied name | must equal the rendered path (§2) |
| A6 | `caller` mode with an absent name | canonical hash of the spec (§2) |
| A7 | `server` create-with-name vs replace indistinguishable without a store read | denied with the replace rule's reason (§2) |
| A8 | `{{ }}` escape renders characters outside the name charset | escape removed; braces are not name characters (§2) |
| A9 | Story-1 vectors cannot omit required ref fields | vectors use well-formed unresolved refs until 1b; noted in the vector README |
| A10 | `resolvedRefs: []` from a pass-through `resolve` lies by omission | accepted for 1a; 1b makes it real |
| A11 | Erlang `:re` is PCRE; RE2-only patterns diverge silently | RE2 subset enforced at KindDefinition admission: backreferences, lookaround, atomic/possessive groups, recursion denied (§1); 1b adds vectors |
| A12 | nested `additionalProperties` defaults open | as written; the group's seeds close theirs |
| A13 | §11's exemption is unnecessary (a legacy meta-Kind is `caller` mode, readmit supersede) | keep the `transition` flag as a declaration, not an exemption; §11 wording follows in 1b's sync |
| A14 | malformed `epistemicScope` denied by two sources with two messages | the KindDefinition's own §1 check fires first and alone (§1) |


## CS-1b findings (B1–B12), 2026-09-02

| # | Finding (CS-1b) | Decision |
|---|---|---|
| B1 | "lower seq" is unconstructible at `resolve` (an unappended event has no hash) | verifier check only; resolve records `seq` (§4, §10) |
| B2 | `sameAnchor`'s anchor field need not be a declared property → every citation denied | anchor field must be declared; denied at KindDefinition admission (§1) |
| B3 | manifest keys for the observed head unnamed | `anchorField`, `head` (§4) |
| B4 | "sorted by pointer" ambiguous for arrays ≥ 10 | byte-order string sort, stated (§4) |
| B5 | `payload.target.kind` is only `K`; declaration is `g/v/K` | compare all three segments (§4) |
| B6 | bytes partition check is O(chain) without the §5 index | accepted until 1c's reference index; stated (§4) |
| B7 | `casObjectEvent` has no honest value before 1c | `null` until 1c; verifier prints a conditional not-checked line (§4) |
| B8 | `{mediaType, size, base64}` cannot include `mediaType` before CasObject | `mediaType` only when a CasObject admission recorded one (§6) |
| B9 | one `valid_address?` cannot gate reads for three forms | three predicates named (§10) |
| B10 | the sweep reported phantom gaps from `target.name` under content naming | names are not citations; not swept; admitted spec objects not swept (derivable) (§6) |
| B11 | `refs:` needs the declaration, which the manifest does not carry | verifier walks the exported KindDefinition's schema; absent Kind → check unmade and said (§10) |
| B12 | completeness cannot be asked of denials | the no-manifest-entry finding fires only on admissions (§10) |
| minor | one manifest entry per location (named property wins); outcome facet checked separately from existence | stated (§4) |


## CS-1c findings (C1–C8), 2026-09-02

| # | Finding (CS-1c) | Decision |
|---|---|---|
| C1 | a CasObject's own `address` is a string in its spec, so "cited by no admitted spec" made every object unexpirable | own-address fields of CasObject/CasExpired are records, not citations; excluded (§5) |
| C2 | "resolution manifest" is unqualified; a denial's manifest pins bytes | taken literally: denials' manifests are citations; stated (§5) |
| C3 | which CasObject admission `casObjectEvent` names when there are several | the first (§5) |
| C4 | the partition was enforced only at citation time | also at CasObject admission: deny an address that is already a payload/spec address (§5) |
| C5 | public-record/CasExpired finding has no ordering rule | a finding only when the expiry's seq is higher than the citation's (§5) |
| C6 | `derivedObjects` is an unfalsifiable producer claim until §8 | accepted; the verifier says so (§5) |
| C7 | the PUT /cas ceiling cannot be a conformance vector | HTTP tests; stated (§5) |
| C8 | `derivedFrom` was not required to be backed | it is a `bytes:` citation; backing required (§5; kernel rule in 1d) |
| bug | `consistency_test.exs` left stale bundles in `$TMPDIR`; `Export.run` merges into a non-empty dir | test fixed by 1c; `Export.run` into a non-empty directory → debt #20 |


## CS-1d findings (D1–D8), 2026-09-02

| # | Finding (CS-1d) | Decision |
|---|---|---|
| D1 | re-checking the store at `record` while the store write is outside the lock leaves the store behind the chain by an unbounded amount | commit = one call on the append lock: halt check → staleness → append → substrate write (§7) |
| D2 | a moved `sameAnchor` head cannot produce `contended`: the retry's `resolve` denies first | stated; `contended` is for policy and kind-ref captures only (§7) |
| D3 | retry is unfair under a hot key (100-way race: ~38 granted, ~62 contended at 25 retries) | `commit_retries` is a livelock budget; fair queue open (§7, debt #23) |
| D4 | what the caller of a post-record failure gets is unstated | re-raise; no denial receipt (the chain says granted) (§7) |
| D5 | a `contended` denial's policy block cites the stale generation | on purpose (evidence); invariant holds over granted admissions (§7) |
| D6 | retry from `resolve` skips `validateStructure`'s readmit decision | harmless (the store re-reads at write); stated (§7) |
| D7 | C8 backing is not retention: an object cited only by `derivedFrom` is expirable | named open; closing changes §5's citation set (debt #22) |
| D8 | two concurrent supersessions of one literal name are both admitted | consistent: §7 protects readers, not writers; stated (§7) |


## Fold-v2 findings (E1–E6 + the kernel gap), 2026-09-02

| # | Finding (fold v2) | Decision |
|---|---|---|
| gap | evaluation records registered as derived in memory only; export after restart loses the class (24 findings) | policy meta `derivedObjects: [addr…]`; kernel copies to the payload beside `policy`; RefIndex replays from it; verifier unions payloads (§5; kernel slice CS-1e) |
| E1 | which shape slots are path-valued vs literal is unstated | a string matching a production is a path; else literal; double-quoted = literal (§8) |
| E2 | `@name` on a `server`-named Kind does not exist at `authorize`; the briefed `cedar.*` shape denies every AgentSession | fails closed as specified; the fallback shape uses `@kind` for `resourceId` (§8; fold seed change) |
| E3 | `requestBytes` when nothing was handed to Cedar | no record; `evaluation: null`; `decision: "error"`; `note` (§8) |
| E4 | brief's meta key set dropped `bundleRef`, which the kernel documents | `bundleRef` stays; the fold emits it (§9) |
| E5 | `resolution` vs literals and duplicate paths | path-valued slots only; one per distinct path; sorted (§8) |
| E6 | build-descriptor sha256 fields: bare hex or `sha256:` address | bare hex — they measure files (§8) |
| harness | the fold's tests share one global kernel; shape admissions in one test govern later ones | fresh kernel per test file, as the kernel's `R5e.Vectors.with_fresh_kernel/1` does (debt #24) |

**Closed by CS-1e (2026-09-02).** All eight rows are implemented and pinned.
The kernel gap: `R5e.Policy` documents `derivedObjects` as the second
additive meta key and checks the form of each entry (a malformed one is a
malformed policy answer, denied at `authorize`); `R5e.Admission` copies the
list verbatim onto the payload beside `policy` and onto the receipt, on
grants and denials alike; `R5e.RefIndex` replays the class from it;
`R5e.Export` lists the union. Five conformance vectors under
`test/vectors/derived/` pin the honest case, the replay, the denial, the
unwritten address the kernel copies and only the verifier can falsify (C6),
and the malformed one it refuses. The verifier re-derives the manifest's
`derivedObjects` as the union over the payloads and reports either direction
of disagreement by address, plus any declared object missing from the
bundle. E1–E6 are in `schema-lite-v2.md` §8/§9 and in the fold: the Cedar
engine emits `derivedObjects` and `bundleRef`, and `priv/shapes/fallback.json`
reads `@kind` for `resourceId`. The harness row (debt #24) is retired:
`Recurse.Fold.FreshKernel` gives every fold test file a kernel of its own in
`setup_all`, and the ordering workarounds this table described are gone.
`test/fold_restart_test.exs` and step 11 of `scripts/fold-demo.sh` boot, run
Story 1, restart the node over the same data directory, export, and verify —
no findings, `derivedObjects` equal before and after.

Also logged: `R5e.Kind` grew to 1,291 lines / 207 functions in 1a; a simplification pass is scheduled after 1d (debt register #18).
