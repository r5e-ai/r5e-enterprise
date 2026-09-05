# Spec 010 — adversarial review, round 1

**Discriminator**: Claude Opus (subagent), 2026-09-02, with full read access to r5e-core (charter, spec/00–04, GOVERNANCE), the kernel, the verifier, `apps/recurse_fold`, the quarry digest and corpus survey, and the handbook stance docs. Second discriminator (Codex, `gpt-5.6-sol`, high effort) ran in parallel; its findings are in `review-round-1-codex.md` when present.
**Synthesis**: Fable. Disposition per finding: **applied** (verifiable against code, changed the spec), **slated** (accepted, needs a slice elsewhere), **declined** (with reason).

## (A) Major findings

| # | Finding | Evidence (verified) | Disposition |
|---|---|---|---|
| A1 | The admission receipt does not return the admitted instance's `name` or `specAddress`, so a caller cannot build a `sha256:` ref without recomputing the canonical hash itself — the anti-pattern the spec cites GAP-33 to forbid. | `r5e-kernel/lib/r5e/admission.ex:183-194` returns outcome/event/seq/assurance/scope only; router returns it verbatim. | **applied** → FR-004; **slated** KP-1 (kernel). |
| A2 | `sha256:` names two disjoint namespaces (CAS objects and event hashes). The export sweep tries every `sha256:` string in the CAS and files event refs under `missingObjects`; the verifier reads neither `missingObjects` nor nested refs, only `event["payload"]`. A ref to a benign or nonexistent prompt passes admission and verifies clean. SC-001 as written was a check nobody performs. | `export.ex:91-95`, `recurse_verify.ex:382-401`, `cas.ex:11-15`. | **applied** → FR-003 (`event:` prefix), stance §6; **slated** KP-3 (verifier `refs:` check). |
| A3 | Inline `Prompt.content` puts customer bytes in the admission event payload, which the verifier requires intact; erasure then permanently produces findings. spec/01 "Detached payloads — normative" and spec/04 erasure are violated. | `admission.ex:132-151` records the spec in the payload. | **applied** → stance §7, `contentRef`, KP-2 (`PUT /cas`), SC-007. |
| A4 | Blanket scope-defaulting puts the group's honesty in a markdown file the verifier never prints; the verifier prints `claims: matches schema; does NOT claim: anything else` for the Kinds that assert facts about the world. FR-003 and FR-009 relied on "the scope says so" while FR-011 removed the scope. KindDefinition has no `description` field to carry natlang. | `recurse_verify.ex:576-589`, `kind.ex:33-51, 72-83`. | **applied** → FR-011 (our nine Kinds carry authored scopes; third parties still default), stance §4; **slated** KP-5 (`description`). |
| A5 | `Completion` carried `latencyMs`/`status`/`llmCall` in its identity, so identical response bytes got different content addresses; an event wearing an artifact's substrate. | `admission.ex:115-124` names artifacts by canonical hash of the spec. | **applied** → Completion is bytes only; new `LlmResponse` event carries the call outcome and binds `toolCalls`. |
| A6 | `AgentSession.actor` (required) duplicated the kernel's actor of record and enabled custody laundering; `onBehalfOf` written by the delegate inverts spec/03 (endorsements are written by the endorser; a session cannot self-authorize). | `admission.ex:51-54`, spec/03:20-28. | **applied** → FR-009: no required fields, no `onBehalfOf` in v1alpha1. |
| A7 | FR-013 pinning had no mechanism: `GET /apis` returns a normalized `to_map` with no address, and its hash differs from `specAddress` for all eight Kinds; pinning by address deadlocks with FR-011's supersession. Address determinism across deployments itself holds. | `router.ex:44-51`, `kind.ex:72-83`, `canonical.ex:29-38`. | **applied** → FR-013 pins identity+substrate+required set; **slated** KP-4. |
| A8 | Streaming order is admissible, but nothing bound tool intents to the response bytes; `parallel_index` and `tool_args_hash` had no home; `ToolCall.llmCall` optional loses the parent link. | CORPUS §1 rows for `tool_use_intents[]`; spec text. | **applied** → canonical order in Story 1; `LlmResponse.toolCalls`; `index` required when `llmCall` present; `argsRef`. |
| A9 | `PolicyShape` on the chain but not on the receipt: receipts decided by the coded fallback and by an admitted shape were indistinguishable; supersession windows unreconstructible; a typo'd path yielding `""` turns a deny into an allow. | `cedar.ex:166-176, 79-84`, `policy.ex:13-25`, `admission.ex:32-34` (policy runs before validation). | **applied** → FR-008: shape on receipt, path validation at shape admission, fail-closed at decision; edge case added. |
| A10 | `LlmCall.parameters` would put the protocol's first float on the chain; the kernel's canonical form delegates float rendering to the JSON library, so a second-implementation verifier could recompute a different hash. | `canonical.ex:9-13`. | **applied** → FR-017 (no floats); open item (RFC 8785). |

## (B) Minor findings and dispositions

1. Story 3 needs a Prompt to admit an LlmCall — **applied**.
2. "Eight-admission sequence" did not exist — **applied** (counts stated by the test).
3. PolicyShape name lacked the engine — **applied** (`<engine>.<kind path>`).
4. The `*` fallback shape violated its own `kind` schema — **applied** (literal `*` allowed).
5. Declared enums unenforced by the kernel — **applied** as FR-016 + KP-7; honesty stated.
6. FR-006 did not close §b.10 — **applied**: moved to "What stays open".
7. No cardinality stated — **applied** FR-015.
8. No predicates — **applied**: explicit `predicates: []` + v1alpha2 candidates.
9. spec/01 structure-leakage statement missing — **applied**.
10. `endedAt` as observed state through spec; no concurrency control — **applied** (semantic-time naming; §f.6 open).
11. Caller timestamps vs stance §3 — **applied** (semantic-time carve-out named).
12. SC-002 depended on an unlanded `--scope` flag — **applied** (criterion rewritten).
13. FR-012 tied assurance to identity for the wrong reason — **applied** (KP-6, visibility grounds).
14. Unauthenticated instance listing returns prompt bodies — **applied** by detaching payloads; read symmetry left open.
15. `*.r5e.io` namespace allocation unstated — **applied** to "What stays open" (core GOVERNANCE sentence needed).
16. Draft/activation collapsed silently — **applied**: FR-007 states it.
17. `ToolResult` without `result`, `LlmCall` without `provider` are fine — **declined** (no change needed; agreed).

## (C) Contradictions, all resolved in the revision

C1 in-place edit of v1alpha1 Kinds vs spec/02 — resolved by FR-001 (no durable admission yet; after the first, v1alpha2). C2 prose scopes vs DIGEST §e — resolved by FR-011. C3 ref direction vs the M0 plan — the plan was wrong; spec keeps backward refs and prices the cost with `LlmResponse`. C4 SC-001 vs the verifier — resolved by KP-3. C5 "the scope says so" vs defaulted scopes — resolved by FR-011. C6 supersession vs pinning — resolved by FR-013. C7 FR-004 vs GAP-33 — resolved by KP-1. C8 inline content vs spec/01 — resolved by stance §7. C9 FR-008's misuse of DIGEST §c.8 — citation corrected; debt #2's exit amended.

## (D) Tested and not broken (carried forward as assumptions)

Backward-ref admissibility of the streaming order; `specAddress` determinism across deployments (bytewise key sort); denials-are-not-a-Kind end to end; `PolicyBundle` supersession-as-activation; idempotent re-import via content naming; substrate placement of the events and the two policy resources; fail-closed on an all-deny bundle; empty required fields rejected (`nil`/`""`, not `{}`/`[]`).
