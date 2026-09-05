# F002 Property-Test Surface Catalog

**Feature**: F002 | **Constitution**: Principle VI | **Spec**: SC-008 | **Extends**: F001 property_test_surface_catalog (Surfaces A–M)

F002 adds surfaces N–S. Each surface has (a) a property invariant, (b) a StreamData generator shape, (c) a file location where tests will live, (d) a minimum iteration count per Constitution Principle VI.

All F002 property tests use `ExUnitProperties` + `StreamData` per F001 + invoke `elixir:stream-data-thinking` before writing (per `feedback_invoke_elixir_skills.md` memory rule).

---

## Surface N — `X-Observed-Identity` JWT validation

**Location**: `apps/recurse_gateway/test/identity/jwt_validator_property_test.exs`

**Invariant**: the Gateway's JWT validator MUST accept exactly the valid class and emit the correct error category for each invalid class.

**Generator**:
- Valid JWTs (`StreamData.bind` over random {subject, groups, role, iat offset, exp offset, kid from configured set}).
- Invalid class 1: `exp in the past` → error `:token_expired`.
- Invalid class 2: `nbf in the future` → error `:token_not_yet_valid`.
- Invalid class 3: `aud` mismatched → error `:invalid_audience`.
- Invalid class 4: `iss` mismatched → error `:invalid_issuer`.
- Invalid class 5: `alg = "none"` → error `:forbidden_alg`.
- Invalid class 6: tampered signature → error `:invalid_signature`.
- Invalid class 7: reused `jti` → error `:token_replayed`.
- Invalid class 8: unknown `kid` (after JWKS refresh) → error `:unknown_kid`.
- Invalid class 9: 5-segment (JWE) compact serialization → error `:unsupported_token_format`.

**Iterations**: 1000 default (Constitution SC-014 security-critical surface).

**Shrinking discipline**: StreamData's default shrinking is fine for scalar fields (strings, ints); for the signature-tampering generator, ensure the generator emits structurally-valid tokens whose only defect is the signature byte — otherwise shrinking reveals less interesting counterexamples.

---

## Surface O — RFC 8693 Token Exchange round-trip

**Location**: `apps/recurse_broker/test/token_exchange_property_test.exs`

**Invariant**: a valid OIDC `id_token` exchanged at `POST /token/exchange` produces an `X-Observed-Identity` JWT that (a) validates at the Gateway's validator (Surface N), (b) resolves to the expected `recurse_role` per the broker's `role-mapping.yaml`, (c) passes Cedar evaluation against `platform_roles.cedar` for all actions its role allows.

**Generator**:
- Bind over: `{subject, email, groups[], role-mapping.yaml}` where the mapping determines the expected `recurse_role`.
- Generator produces both the OIDC `id_token` (signed with a test JWKS) + the expected `recurse_role` + the expected Cedar `Allow`/`Deny` decisions for the three Cedar actions.
- Property 1: exchanged JWT validates at Gateway.
- Property 2: `principal.recurse_role` equals the generator's expected role.
- Property 3: Cedar eval of `{Action::ReadReceipts, Action::ExportEvidence, Action::ChatCompletion}` matches the generator's expected Allow/Deny matrix.

**Iterations**: 500 default (composite end-to-end test; heavier than Surface N).

**Shrinking**: use `StreamData.filter` sparingly — filter-heavy generators are a known sharp edge (per elixir:stream-data-thinking skill); prefer `StreamData.bind` to constructively generate.

---

## Surface P — JWKS `kid`-miss refresh coalescing

**Location**: `apps/recurse_gateway/test/identity/jwks_cache_property_test.exs`

**Invariant**: concurrent requests with an unknown `kid` MUST coalesce behind a single JWKS refresh, and all requests eventually resolve (no spurious 401s under race).

**Generator**: property-concurrent — spawn N (random 2–50) processes racing to validate a JWT whose `kid` is absent from cache, with the JWKS endpoint responding either after a random delay or with a stale response.

**Properties**:
- Exactly one upstream JWKS fetch occurs (verifiable via a mock upstream counter).
- All N processes either all succeed (if the refreshed JWKS contains the kid) or all fail with the same `:unknown_kid` error.
- No deadlock (the refresh completes within test timeout even under contention).

**Iterations**: 100 default (concurrency tests are slower).

**Note**: this surface needs `elixir:otp-thinking` guidance — coalescing = `GenServer.call` pattern, NOT process-per-request.

---

## Surface Q — Payload canonicalization (streaming reassembly + JCS stability)

**Location**: `apps/recurse_gateway/test/data_plane/payload_canonicalization_property_test.exs`

**Invariant**: for any valid (request, response) pair under FR-018's rules, JCS encoding is deterministic AND the resulting SHA-256 is stable across (a) SSE chunk-granularity permutations that preserve content order, (b) unrelated OpenAI response metadata insertions (e.g., `system_fingerprint` added after the fact).

**Generator**:
- Bind over: `{request, final-content, chunk-granularity}` where chunk-granularity ∈ `[1-char, 10-char, 100-char, random]`.
- Generate an SSE chunk sequence matching the granularity.
- Reassemble via `Recurse.Gateway.DataPlane.SseProxy.reassemble/1`.
- JCS-encode + SHA-256.

**Properties**:
- For the same (request, final-content), all granularities yield the same hash.
- For two structurally-identical requests with different key insertion orders, hashes match.
- For an OpenAI response with `system_fingerprint = nil` vs absent, hashes **DIFFER** (RFC 8785 §3.2.3 does NOT elide null members; both the key's presence and its `null` value are canonicalized). If the F002 protocol wants nil-as-absent equivalence, that is a PRE-JCS normalization step owned by the caller — NOT a JCS behavior. Verified at T030 property-test time; catalog originally claimed elision, corrected 2026-04-24.

**Iterations**: 300 default.

---

## Surface R — RFC 9162 inclusion-proof round-trip (Postgres-Merkle)

**Location**: `apps/recurse_providers/test/impls/postgres_merkle_ledger_property_test.exs`

**Invariant**: for any session with N (random 1–1000) attestations, the Postgres-Merkle ledger's generated inclusion proofs (session-local and global) verify against the computed roots AND the RFC 9162 `TransItem` encoding is byte-stable.

**Generator**:
- Bind over: `N ∈ 1..1000`, random attestation byte-sequences.
- Insert all into Postgres-Merkle ledger via `commit_attestation/1`.
- Request `generate_inclusion_proof(run_id)` for a random subset.

**Properties**:
- Each proof verifies via F001's `Recurse.Shared.Attestation.Rfc9162` verifier.
- Encoding the `TransItem` to bytes + decoding returns the same logical proof.
- Under `force_commit_for_run_ids/2`, previously `:local_inclusion_verified` attestations become `:global_inclusion_verified` AND global proofs verify.

**Iterations**: 200 (heavier — DB-backed).

**Note**: this surface extends F001 Surface D; F001 had a stub; F002 operationalizes with real Postgres.

---

## Surface S — Cedar entity-schema + policy evaluation stability

**Location**: `apps/recurse_gateway/test/policy/cedar_evaluator_property_test.exs`

**Invariant**: for any valid principal + resource + action + context tuple under `cedar_entity_schema.cedarschema.json`, Cedar evaluation against `platform_roles.cedar` produces the expected Allow/Deny, AND `policy_canonical_hash` is stable across whitespace/comment/key-order perturbation of the bundle file.

**Generator**:
- Bind over: `{role ∈ [platform_operator, tenant_auditor, caller], action ∈ [ChatCompletion, ReadReceipts, ExportEvidence, ReadPayload], resource}`.
- For each, compute the expected decision per the reference policy.
- Perturb the bundle file (add whitespace, reorder `permit` statements, add comments).

**Properties**:
- Decision matches expectation for the non-perturbed bundle.
- Decision unchanged after perturbation.
- `policy_canonical_hash` unchanged after perturbation.

**Iterations**: 500.

---

## Surface summary vs F001

| Surface | F001 status | F002 status |
|---|---|---|
| A (DSSE PAE) | shipped | unchanged |
| B (in-toto canonicalization) | shipped | extended (reassembled-JSON rules in Surface Q) |
| C (Cedar JCS stability) | shipped | reused in Surface S |
| D (RFC 9162 TransItem) | stubbed | operationalized in Surface R |
| E–M (F001) | shipped | unchanged |
| N — JWT validation | new in F002 | |
| O — RFC 8693 round-trip | new in F002 | |
| P — JWKS kid-miss coalescing | new in F002 | |
| Q — Payload canonicalization | new in F002 | |
| R — RFC 9162 round-trip via Postgres-Merkle | new in F002 | |
| S — Cedar entity-schema + policy stability | new in F002 | |

**Total property-test surfaces at F002 merge**: 19 (13 F001 + 6 F002 new/extended). Each surface has ≥ 1 property test per Constitution Principle VI + F002 SC-008.

**CI gate**: `mix test --include property` runs all surfaces; a failing surface fails CI. Surface iteration counts stay at defaults for routine CI; a dedicated "extended" CI job runs 10× iteration counts nightly.
