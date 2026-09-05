# Spec 010 — round 3 synthesis (dispositions of round-2 findings → r3)

**Inputs**: `review-round-2-opus.md` (M1–M9, 19 minors), `review-round-2-codex.md` (A1–A11, minors). **Synthesis**: Fable, 2026-09-02. Both discriminators judged the remainder structural; both located it in the ref/naming/commit contracts and the missing schemas. r3 is the last prose revision; the normative contract moves to `schema-lite-v2.md` + `kinds/*.json`, and round 3 reviews those.

| Finding | Disposition in r3 |
|---|---|
| Opus M1 outcome facet on event refs | **applied**: `ref: {event, outcome: admitted\|any}`; SC-009 |
| Opus M2 `resolvedRefs` placement | **applied**: sibling of `spec` on payload and store entry; reconstructed by replay; never an input to naming |
| Opus M3 `bytes` namespace | **applied**: `bytes:sha256:` under a distinct subtree; verifier checks partition |
| Opus M4 / Codex A3 `PUT /cas` off-record | **applied (Opus variant)**: authenticated, size-bounded, `cas.stored` event, TTL as `cas.expired`; Codex's staging alternative is open question 2 (it would make the kernel rewrite `contentRef` inside the spec) |
| Opus M4 oracle | **applied**: leakage statement; confidentiality needs encryption |
| Opus M5 / Codex A5 naming | **applied**: naming modes `content` (artifacts, caller names rejected), `literal: active` (PolicyBundle), `derived` (PolicyShape), `server` (AgentSession, by admission hash; supersession by admitting actor only; store entry carries `actor`); SC-010 |
| Opus M6 absent vs unresolvable; detached args | **applied**: `whenAbsent`; one bounded `bytes` dereference in shape paths |
| Opus M7 / Codex A2 engine pin and evaluation record | **applied**: `PolicyEvaluationRecord` versioned encoding (request bytes, entity bytes, format version, target KindDefinition address, resolution manifest, engine build address); `engineBuild` = address of a build descriptor (raw bytes; open question 3); evaluation record = subject content, erasable, replay reports "input erased" |
| Opus M8 / Codex A8 seeds missing; SC-001 impossible | **applied**: `kinds/*.json` + `schema-lite-v2.md` written with r3; SC-001 restated with bootstrap totals and quoted not-checked lines |
| Opus M9 / Codex A8 KP-7/8/10 are core | **applied**: folded into **CS-1**, one core slice with explicit syntax, meta-Kind supersession and address migration; stance §11 (no durable admission until enforced) |
| Codex A1 resolve before authorize; wildcard shapes; generic one-hop | **applied**: `resolve` stage (spec/02 amendment) in CS-1; one hop through *any* event-ref property; `*` shapes limited to envelope fields/literals |
| Codex A4 / Opus B16-17 KP-9 | **applied (Codex variant)**: optimistic authorize + captured generation + compare-and-append + retry; halt after post-record failure; per-node stated; break-glass = identity slice |
| Codex A6 / Opus B10 `supersedes` | **applied**: same Kind, anchor, actor; current head; branches denied |
| Codex A7 mapping lossy / semantic change | **applied**: per-field table with classes; `upstreamHost`, `startedAt`/`completedAt`, `sourceIds`, `extractedAt`, `errorKind` enum, `transport` incl. `https_sse`; stream-pinning listed as *semantically changed* (open question 4) |
| Codex A9 KindDefinition immutability | **applied**: duplicate `(group,version,kind)` rejected unless byte-identical (CS-1); SC-011 |
| Codex A10 / Opus C-S5 identity in SC-001 | **applied**: SC-001 quotes the not-checked lines; Story 1 title and claim narrowed; `parent`/`sourceIds` kept (sub-agent orchestration is the use case) with the identity dependency stated |
| Codex A11 / Opus C-S7 policy source | **reversed**: `sourceRef` (bytes) with retention class `public-record`; receipts cite `bundle` and `source`; FR: no subject identifiers in policy source |
| Opus B8 kernel `$ref` convention | **applied**: refs are `{"$ref": …}` objects so `?resolution=deep` hydrates them |
| Opus B2 / Codex mapping: bundle vs source hash | **applied**: two addresses, two meanings |
| Opus B13 core verifier and engine keys | **applied**: KP-3 checks the generic "every address in the policy block resolves" |
| Opus B18 / Codex A8 floats | **applied**: recursive kernel rule in CS-1; boundary coercion stated |
| remaining minors (both) | **applied** in the schemas or the prose (transport enum, `argsMediaType`/`resultMediaType` declared, `ToolCall.session` typed, `completion` required when ok, `*` shape name, snapshot atomicity, `errorKind` enum, tenancy = chain, verifier actor list in leakage, `size` recorded in `cas.stored`, receipt `eventRef`) |

**Declined**: none outright. **Narrowed**: Codex A10's "omit parent/correlation until identity" → kept with dependency stated (the orchestration use case needs sub-agent links; the identity slice is next).

**Termination**: both reviewers said a further prose round is not the right instrument. Round 3 = review of `schema-lite-v2.md` and the nine seeds against r3, by both models, with the explicit question: does the syntax force the ambiguities they found into one reading?
