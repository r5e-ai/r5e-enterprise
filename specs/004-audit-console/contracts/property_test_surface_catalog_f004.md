# F004 Property-Test Surface Catalog

**Feature**: F004 | **Constitution**: Principle VI | **Spec**: SC-004, SC-008 | **Extends**: F002 surfaces N–S

F004 adds three new property-test surfaces (T, U, V) plus a contract test per audit-agent tool (six tests). Each surface follows the project template: (a) property invariant, (b) StreamData generator shape, (c) file location, (d) minimum iteration count.

All F004 property tests use `ExUnitProperties` + `StreamData` per F001 + invoke `elixir:stream-data-thinking` skill before authoring (per `feedback_invoke_elixir_skills.md`). Tests reference contracts directly so drift fails CI.

---

## Surface T — Blast Radius classifier correctness

**Location**: `apps/recurse_gateway/test/admin/blast_radius_property_test.exs`

**Invariant**: for any draft Cedar policy + historical receipt window, the matches-intent vs unintended classification matches a rule-based oracle on **≥95% of receipts** (matches SC-008).

**Generator**:
- `StreamData.bind` over a constrained Cedar grammar producing legal `permit/forbid` rules. The grammar is restricted to:
  - `permit (principal, action, resource)` and `forbid (principal, action, resource)` headers
  - `when { ... }` clauses with `&&` / `||` / `==` / `!=` / `in` operators
  - References to `principal.recurse_role`, `principal.tenant_id`, `principal.subject`, `context.tenant_id`, `resource.endpoint`
- `StreamData.list_of` random receipt fixtures (size 50–500 per iteration), each with:
  - Random `signed_predicate.principal` matching the F004 Cedar Entity Schema (Human / ServiceAccount / Autonomous)
  - Random `signed_predicate.event_kind` from a fixed enum
  - Random `original_decision: :allow | :deny` weighted 4:1 to mirror real distributions
- For each `(cedar_source, fixtures)` tuple the generator includes a **rule-based oracle** that computes the expected classification per receipt by:
  1. Constructing the entity store identically to `synthesize_entity_store/1`.
  2. Calling Cedar evaluation directly (NOT through the algorithm under test).
  3. Computing classification per the rule in `blast_radius_algorithm.md` §"Classification rule".

**Properties**:
1. Algorithm under test (`compute_blast_radius/1`) produces classifications agreeing with oracle on ≥95% of receipts. Disagreements > 5% fail the property.
2. `classify_pair(:allow, :allow)` always returns `:no_change`.
3. `classify_pair(:allow, :deny)` always returns `:unintended`.
4. The cached `last_blast_radius_summary` matches a fresh recomputation when source + window are unchanged.

**Iterations**: 100 (each iteration runs 50–500 Cedar evaluations + per-receipt classification — heavy).

**Operator-labeled benchmark**: a separate non-property test asserts the same algorithm against `apps/recurse_gateway/test/fixtures/blast_radius_benchmark.json` (~200 hand-curated receipt+rule pairs) at ≥95% precision; this is the contract-level SC-008 verification.

**Shrinking discipline**: per `elixir:stream-data-thinking`, the Cedar-source generator uses `bind` (constructive) not `filter` to avoid pathological shrinking; the receipt-fixture generator uses `bind` over typed components for the same reason.

---

## Surface U — Heuristic suggestion engine determinism

**Location**: `apps/recurse_gateway/test/suggestion_engine/heuristic_property_test.exs`

**Invariant**: running the heuristic engine twice over a byte-identical receipt window produces byte-identical suggestion sets — every field of every suggestion (`pattern_summary`, `proposed_cedar`, `confidence`, `pattern_name`, deduplication key) is reproducible.

**Generator**:
- `StreamData.list_of` random receipt fixtures (size 100–10_000 receipts per window). Each fixture has timestamps drawn from a 30-day window, principals drawn from a finite set (10 unique principals per iteration), tools drawn from a finite set (8 unique tool names), and policy_decisions weighted 4:1 allow:deny.
- The same fixture window is passed to two separate engine invocations.

**Properties**:
1. `engine.run(fixtures) == engine.run(fixtures)` (byte equality of sorted suggestion list).
2. Reordering the input fixtures (still chronologically valid via re-sort by `committed_at`) produces the same suggestion set.
3. For each of the five heuristic patterns (`recurring_allow`, `recurring_deny`, `anomalous_burst`, `cross_tenant_access`, `stale_role_creep`), running the pattern in isolation against a fixture window crafted to trigger it produces exactly the expected suggestion shape.
4. Deduplication: a fixture window with two principals matching the same pattern produces two suggestions (one per principal) — never one merged suggestion or three duplicates.

**Iterations**: 200 (DB-free; pure-function patterns; cheap).

---

## Surface V — Browser session cookie integrity

**Location**: `apps/recurse_gateway/test/admin/browser_session_plug_property_test.exs`

**Invariant**: round-trip preserves the JWT; tampered cookie bytes are rejected; expired cookies are rejected; cross-key compatibility (primary + secondary) round-trips.

**Generator**:
- `StreamData.bind` over `{jwt_payload, issued_at_offset, key_set}`:
  - `jwt_payload` is a synthetic minted-broker JWT structure (any valid base64 string suffices for round-trip; signature validity isn't tested here — that's Surface N).
  - `issued_at_offset` ∈ `[-30000, +1000]` seconds relative to `now`.
  - `key_set` ∈ `[primary_only, primary+secondary, secondary_only_after_rotation]`.

**Properties**:
1. **Round-trip**: `encrypt(payload, primary) → decrypt(_, primary)` recovers the exact `payload`. Byte-equality.
2. **Tampering rejection**: any single-byte mutation of the encrypted ciphertext (random byte index, random value) → `decrypt/2` returns an error tuple. Zero false positives across 1,000 iterations.
3. **Expiry enforcement**: a cookie with `issued_at = now - 8h - 1s` is rejected with `:absolute_expired`; `issued_at = now - 1h - 1s, last_activity_at = now - 1h - 1s` is rejected with `:idle_expired`.
4. **Cross-key compatibility**: cookie encrypted with primary AND with a secondary key both decrypt correctly when both are configured. After "rotation" (primary→secondary list, fresh primary), old cookies still decrypt for the grace period.
5. **Replay rejection (mutation-only rotation per `browser_oidc_flow.md` Step 6)**:
   the cookie's `issued_at` is rotated only on mutating HTTP methods (POST / PATCH / PUT / DELETE);
   GETs / HEAD / OPTIONS leave it untouched. Generator emits a sequence of N concurrent requests
   from the same browser session (mix of GETs and mutations).
   - **Concurrent GETs** all succeed: every GET reads the current `issued_at` without writing,
     so the per-`browser_session_id` rotation cache is not touched. Asserted by 50 parallel GETs
     in the property body — all return 200, no `:replayed` errors.
   - **Concurrent mutations** rotate exactly once: of N parallel mutations (random N ∈ [2, 20]),
     exactly ONE successfully rotates the cookie's `issued_at`; all others fail with `:replayed`
     against the new cache value. The "winner" is non-deterministic but exactly-one is invariant.
   - **Replay of a mutation's previous `issued_at`**: a request carrying a cookie whose
     `issued_at < cache.latest_issued_at` is rejected with `:replayed`. Asserted across 100
     iterations of (issue mutation, capture cookie, issue another mutation, replay first cookie).
   - **GET-only burst followed by single mutation**: the mutation succeeds normally; preceding
     GETs do not consume the cookie's rotation slot.
   - **Tradeoff acknowledged**: this trades a slightly larger replay window (until next user
     mutation) for tab-restore reliability. Per `browser_oidc_flow.md` D6, this is the
     accepted tradeoff for the F004 audit-console persona's workflow shape.

**Iterations**: 1000 (security-critical surface; mirrors F002 Surface N's rigor).

**Shrinking**: scalar fields (timestamps, byte indices) shrink cleanly; the tampering generator emits a structurally-valid ciphertext with one byte mutated, so shrinking reveals minimal-diff failure cases.

---

## Audit-agent tool contract tests (six)

Per `audit_agent_tools.md`, each of the six tools has its own contract test asserting (a) a valid input produces an output validating against the output schema, (b) exactly one receipt of the expected `event_kind` is committed, (c) the receipt's `signed_predicate` carries the expected fields.

These are **contract tests, not property tests** — they assert specific inputs/outputs against specific schemas, not invariants. They live alongside the property surfaces in this catalog because they are the same kind of "interface contract" coverage.

**Locations** (one file per tool):

```
apps/recurse_gateway/test/admin/audit_agent/tools/
├── query_receipts_test.exs
├── fetch_receipt_detail_test.exs
├── explain_denial_test.exs
├── find_similar_receipts_test.exs
├── simulate_policy_dryrun_test.exs
└── suggest_policy_pattern_test.exs
```

**Test shape (template, per tool)**:

```elixir
defmodule Recurse.Gateway.Admin.AuditAgent.Tools.QueryReceiptsTest do
  use ExUnit.Case
  alias Recurse.Gateway.Admin.AuditAgent.Tools.QueryReceipts

  setup [:seed_fixture_receipts, :setup_authenticated_principal]

  test "valid input produces output matching schema and emits receipt", %{ctx: ctx} do
    input = %{filters: %{policy_decision: "deny"}, limit: 5}

    assert {:ok, output, %{attested_run_id: run_id}} = QueryReceipts.call(input, ctx)
    assert :ok = JsonSchema.validate(output, QueryReceipts.output_schema())

    assert [receipt] = Repo.all(from a in Attestation, where: a.run_id == ^run_id)
    assert receipt.event_kind == :ui_chat_skill_invoked_query_receipts
    assert receipt.signed_predicate["tool_name"] == "query_receipts"
  end

  test "Cedar denies for caller role", %{ctx: ctx} do
    ctx = %{ctx | principal: %{ctx.principal | recurse_role: "caller"}}
    assert {:error, %{error: "forbidden", attested_run_id: deny_id}} = QueryReceipts.call(%{filters: %{}}, ctx)
    assert deny_receipt = Repo.get_by(Attestation, run_id: deny_id)
    assert deny_receipt.event_kind == :policy_denied
  end

  test "input validation failure (no Cedar call, no receipt)", %{ctx: ctx} do
    assert {:error, %{error: "invalid_input"}} = QueryReceipts.call(%{filters: 42}, ctx)
    refute Repo.exists?(from a in Attestation, where: a.principal_subject == ^ctx.principal.subject)
  end
end
```

For LLM-calling tools (`explain_denial`, `suggest_policy_pattern`), additional Mox-stubbed `LLMProvider` tests verify token-budget enforcement (an upstream returning >1K output tokens is bounded; budget exhaustion fires `:agent_token_budget_exceeded`).

---

## Surface "Manifest stability" (referenced in `well_known_manifest.md`)

**Location**: `apps/recurse_gateway/test/admin/well_known_manifest_property_test.exs`

**Invariant**: the served `/.well-known/r5e-audit.json` is byte-identical to the on-disk source-of-truth file (`apps/recurse_gateway/priv/schemas/manifest.json`), modulo deterministic key ordering.

**Properties**:
1. `serve_manifest/0` returns identical bytes across N invocations (no per-request mutation).
2. Every `endpoint.schema_uri` points at a schema name present in `manifest.schemas`.
3. Every `schema.version` major-version ≤ `manifest.version` major-version.
4. Every `endpoint.requires_role` element is in `["tenant_auditor", "platform_operator"]`.
5. Every `endpoint.cedar_action` is declared in `cedar_entity_schema_extensions.md` action set.

**Iterations**: 50 (light; the manifest is small).

---

## Surface summary vs F002

| Surface | F001 | F002 | F004 |
|---|---|---|---|
| A–M | shipped | unchanged | unchanged |
| N — JWT validation | — | shipped | unchanged |
| O — RFC 8693 round-trip | — | shipped | extended (new test for /login/start round-trip via broker) |
| P — JWKS kid-miss coalescing | — | shipped | unchanged |
| Q — Payload canonicalization | — | shipped | unchanged |
| R — RFC 9162 round-trip via Postgres-Merkle | — | shipped | unchanged |
| S — Cedar entity-schema + policy stability | — | shipped | extended (S′ — F004 actions × roles matrix coverage) |
| **T — Blast Radius classifier correctness** | — | — | **new in F004** |
| **U — Heuristic suggestion engine determinism** | — | — | **new in F004** |
| **V — Browser session cookie integrity** | — | — | **new in F004** |
| Manifest stability | — | — | new in F004 |
| Audit-agent tool contracts (6) | — | — | new in F004 |

**Total property surfaces at F004 merge**: 22 (13 F001 + 6 F002 + 3 F004 new + manifest + 6 tool contracts as a logical group). Each surface has ≥ 1 property/contract test per Constitution Principle VI.

**CI gate**: `mix test --include property` runs all surfaces; a failing surface fails CI. Default iteration counts run on every push; nightly extended job runs at 10× iteration counts.

---

## End-to-end coverage (Playwright, separate from property tests)

For visibility — these are e2e tests, not property tests, but they cover the user stories:

| User Story | Playwright file |
|---|---|
| US1 — Auditor signs in + audit log | `ui/src/tests/e2e/us1_auditor_audit_log.spec.ts` |
| US2 — Receipt detail + verify locally | `ui/src/tests/e2e/us2_receipt_detail.spec.ts` |
| US3 — Policy draft from receipt + Blast Radius | `ui/src/tests/e2e/us3_policy_draft.spec.ts` |
| US4 — Audit agent conversation | `ui/src/tests/e2e/us4_audit_agent.spec.ts` |
| US5 — Policy suggestions | `ui/src/tests/e2e/us5_suggestions.spec.ts` |
| US6 — Replay against deployed policy | `ui/src/tests/e2e/us6_replay.spec.ts` |

Each e2e test asserts (a) the user-visible UX matches the spec's Acceptance Scenarios, (b) the corresponding receipts appear in the audit log within SC-009's 2-second budget, (c) the receipt's `event_kind` matches `cedar_entity_schema_extensions.md`'s mapping.
