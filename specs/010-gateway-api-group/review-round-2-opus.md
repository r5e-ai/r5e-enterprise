# Spec 010 — adversarial review, round 2, first discriminator (Opus)

**Discriminator**: Claude Opus subagent, 2026-09-02, on r2 (bookmark `spec/010-r2`), with the kernel at `fold/kp-1-4`. Condensed from the agent's report; dispositions in `review-round-3.md`.

## (A) Major findings

- **M1 Outcome facet on event refs.** `LlmResponse.llmCall` can resolve to a *denied* LlmCall (denials are events with `target.kind`); `toolCalls` must accept denied targets. Proposal: `{event: Kind, outcome: "admitted" | "any"}`, default admitted; verifier prints the facet.
- **M2 `resolvedRefs` placement.** Inside `spec` it changes artifact names and `specAddress` across a restart (`Bootstrap.replay` rehashes `payload["spec"]`); beside `spec` only on the log, the store keeps caller names and `?resolution=deep` re-resolves at read time. Proposal: sibling key on the payload **and** on the store entry, reconstructed by replay; never an input to naming.
- **M3 `ref: bytes` unfalsifiable.** Event payloads, admitted specs, and raw bytes share one `sha256:` namespace; a `contentRef` can point at a payload or the policy text. Proposal: raw puts get `bytes:sha256:` in a distinct subtree; verifier checks the partition.
- **M4 `PUT /cas` off-record + oracle.** Bytes enter with no actor/event/manifest entry (a denied Prompt leaves invisible retention); content-addressed plaintext + open GET = confirmation oracle. Proposal: authenticate the put, size-bound it, append a `cas.stored` event (actor, address, size); TTL for unreferenced objects, recorded; state that confidentiality needs encryption.
- **M5 Caller-chosen session names.** A unique name is derivable (the admission hash); caller names allow cross-actor re-attribution by supersession and create the person-keyed index FR-018 forbids. Proposal: `naming: "server"`; supersession restricted to the admitting actor.
- **M6 Absent vs unresolvable; detached args unpoliceable.** Optional `llmCall` + fail-closed paths = global deny once a model-aware shape exists; no `bytes` dereference in paths means detached args escape content rules. Proposal: absent-optional yields "absent"; per-key `whenAbsent`; one bounded `bytes` dereference.
- **M7 `engineVersion` string; request object is subject content.** Proposal: `engineBuild` = address of a build descriptor resource; request object in leakage/erasure scope; size ceiling; shape validator flags paths into inline args.
- **M8 Seeds missing; SC-001 counts impossible** (`count_claims` includes bootstrap admissions). Proposal: land the nine seeds; restate SC-001 with totals including bootstrap and the not-checked lines quoted.
- **M9 KP-7/8/10 are core changes** (they change what a KindDefinition means); until enforced, this group's own declarations are accepted-but-inert. Proposal: one core slice "schema-lite v2" with explicit syntax; no durable admission until enforced.

## (B) Minor (19)

Positional Cedar ids unstated; `cedar_bundle_hash`/`policy_canonical_hash` both → `bundle` (which hashes the spec incl. description); `argsRef` has no home when args inline; session position not recorded; tenancy = chain, unstated; `to_map` must carry `naming`/`description`/`derivedFrom`; discovery reads three stores unsynchronized; the kernel already has a `{"$ref": …}` convention that `?resolution=deep` hydrates — the group's bare strings bypass it; SC-002 scope to the group; `supersedes` needs same-actor/same-anchor/latest rules; `*` shape name undefined; `mediaType` convention unowned; KP-3 puts engine keys into the core verifier line — check the generic invariant instead; the verifier itself prints an actor index; positive read symmetry unimplementable here; "serialized" is per node; the record→admit gap is healed by replay; float coercion for latency/usage; undeclared fields holding `sha256:` are swept but unchecked.

## (C) Disagreements

S7 (inline policy) — right answer, wrong reason; policy may carry subject identifiers; restate or detach. S6 — the narrowing's load-bearing sentence is wrong: a named, queryable, caller-labelled session index is a new artifact. S3/S2/S8 — half-applied / narrowed without label / deliverable missing. S5 — SC-001 must quote the not-checked lines.

## (D) Not broken

Story-1 arithmetic; backward refs incl. denied ToolCall targets; `exactlyOne(args, argsRef)`; FR-013 pinning is now mechanically possible via `to_map`'s verbatim `schema`; address determinism (if `resolvedRefs` stays out of `spec`); supersession-as-activation under a single-node lock; PolicyShape cannot grant authority; the stance-doc amendments are real.

## (E) Termination signal

Structural but localized (M1, M2, M3, M9 alter the ref syntax and KP-8); none change the nine Kinds or substrates. A fourth prose round would be nitpick; a first round on the JSON seeds would settle most of it by forcing it into syntax.
