# Property-Test Surface Catalog — SC-014 / Constitution Principle VI

**Purpose**: authoritative catalog of property-based tests that Feature 002+ business-logic
implementations MUST cover at minimum. Feature 001 implements the Phase-1 subset (shared-types
layer); downstream features that add Gateway/Runtime behavior extend this catalog with their
own surfaces.

**Why property tests, not examples**: Constitution Principle VI is NON-NEGOTIABLE because the
failure mode of an audit-log bug — silent corruption of evidentiary records that compliance
teams only discover under subpoena — is not recoverable after the fact. Example-based tests
catch known failure modes; property tests catch the shapes of failure you didn't think to
enumerate. Every surface below has at least one case where a subtle generator bug in
Feature-002+ code would manifest as a receipt that round-trips cleanly in dev but fails
auditor verification nine months later — the property test is the guard against that.

**Framework**: Elixir `stream_data` (`ExUnitProperties`). Default 100 iterations; scale to
40–50 for slow generators, scale to 200+ for cheap ones. CI runs the full suite; local dev
can scale down via `@moduletag :property_fast`.

---

## Surface A — DSSE PAE round-trip (SC-014.a)

**Already shipped**: `apps/recurse_shared/test/attestation/dsse_property_test.exs` (T031).

**Property**: for all `(payload_type, payload_bytes)` generated pairs,
`decode(encode(payload_type, payload_bytes)) == {:ok, payload_type, payload_bytes}` byte-identically.
PAE itself is deterministic: re-encoding the same input MUST yield byte-identical PAE bytes.

**Generators**:
- `payload_type` — arbitrary non-empty UTF-8 string (length 1–200).
- `payload_bytes` — arbitrary binary (length 0–4096).

**Failure modes caught**:
- Off-by-one in PAE length prefixes (ITE-5 uses space-separated decimal lengths; a `length(bytes)` that silently counts codepoints instead of bytes breaks at any multi-byte UTF-8 char).
- Non-deterministic key ordering in DSSE envelope JSON (would fail under re-sign).
- Accidental base64 re-encoding of already-base64 payload (doubled encoding).

**Feature-002+ extension**: full sign + verify round-trip with a KMS-backed signing key
(FR-046). Extend to verify `signatures[*].keyid` matches the archive entry.

---

## Surface B — in-toto v1.0 predicate canonicalization (SC-014.b)

**Already shipped**: `apps/recurse_shared/test/attestation/in_toto_property_test.exs` (T032).

**Property**: for all generated predicate payloads, JCS-canonicalizing the same payload with
randomly-permuted key orderings MUST yield byte-identical canonical form.

**Generators**:
- `predicate` — map with FR-021 signed-predicate fields (envelope_version, run_id, step_id,
  turn_id, session_id, session_chain_position, timestamp, tenant_id, machine_identity,
  principal, policy_canonical_hash, tool_sbom_ref, payload_hash, payload_uri,
  correlation_id, signer).
- Inject key-order permutation via `Enum.shuffle/1` at map construction time.

**Failure modes caught**:
- JCS implementation that doesn't sort keys lexicographically (outputs shuffled form).
- JCS that doesn't normalize number representation (e.g., `1.0` vs `1` vs `1e0`).
- Nested-map ordering drift (JCS MUST sort every nested map, not just the top level).

**Feature-002+ extension**: Add a fixture pair (known canonical bytes for a known predicate)
asserted against the `Recurse.Shared.Jcs` encoder; catches regressions that don't fail
self-round-trip but diverge from RFC 8785 reference.

---

## Surface C — Cedar JCS canonicalization stability (SC-014.c)

**Already shipped**: `apps/recurse_shared/test/cedar_property_test.exs` (T046).

**Property**: for all generated (policy_text, perturbation) pairs,
`canonical_hash(policy_text) == canonical_hash(perturbation(policy_text))` when the
perturbation preserves semantic equivalence — whitespace, comments, trailing commas,
line endings, block-comment-vs-line-comment substitution.

**Generators**:
- `policy_text` — a small set of seed Cedar policies (`permit(principal, action, resource);`
  through the starter templates in `priv/policy_templates/`).
- `perturbation` — random composition of: insert whitespace, insert line comment, reformat
  line endings, normalize/denormalize trailing commas.

**Failure modes caught**:
- Cedar-minor-version upgrade that changes `PolicySet::to_json()` output shape — `policy_canonical_hash` changes without anyone noticing until receipts stop verifying.
- `serde_jcs` behavior drift between Rust minor versions.
- BOM or unicode normalization inconsistency between source and canonical form.

**Three-component pin check** (research D2): Property is backstopped by
`mix recurse.cedar.stability_check` which asserts the `cedar_fixture_hash` against the
locked value under the pinned `cedar_crate_digest`. If property passes but fixture fails,
Cedar source byte-identity has broken — investigate the crate tarball for re-publication.

---

## Surface D — RFC 9162 TransItem encode/decode (SC-014.d)

**Already shipped**: `apps/recurse_shared/test/attestation/rfc9162_property_test.exs` (T033).

**Property**: for all generated `inclusion_v1` TransItems with randomized leaf, tree_size,
and audit_path, `decode(encode(ti)) == {:ok, ti}` byte-identically. The binary wire format
is stable across encode rounds.

**Generators**:
- `leaf_hash` — 32-byte binary.
- `tree_size` — positive integer up to 2^32.
- `leaf_index` — non-negative integer below `tree_size`.
- `audit_path` — list of 32-byte binaries, length ≤ 32.

**Failure modes caught**:
- TLS-style length-prefix encoding with wrong prefix width (uint8 vs uint16 vs uint24).
- Audit-path serialization that forgets the list-length prefix.
- Big-endian-vs-little-endian on index fields.
- RFC 9162 extension type tag drift (currently `VersionedTransType = 0x0100`).

**Feature-002+ extension**: cross-validate against a reference CT v2.0 log implementation's
wire output (Trillian test fixture or sunlight). Our wire format MUST be byte-compatible.

---

## Surface E — Merkle inclusion proof generation + verification (both backends)

**Phase-1 status**: NOT YET SHIPPED — Feature 002+ implements both `LedgerProvider` reference
impls (Trillian, Postgres-Merkle). This catalog entry defines the acceptance bar.

**Property 1 — generation round-trip**: for all generated `(leaves, target_index)` pairs,
`verify(generate_proof(leaves, target_index), root(leaves)) == :ok`. Generation and
verification disagree on nothing.

**Property 2 — tamper detection**: for all generated proofs, flipping any single bit in
the proof data or the target leaf MUST cause verification to fail. No silent corruption.

**Property 3 — cross-backend interchange**: A proof generated against `TrillianLedger` and
a proof generated against `PostgresMerkleLedger` for byte-identical leaves at the same index
MUST verify against either backend's root. This enforces the research D5 claim that both
backends emit RFC 9162 `TransItem`-compatible proofs.

**Generators**:
- `leaves` — list of 32-byte binaries, length 1–10000 (test across tree_size=1, powers of 2,
  and non-power-of-2 to catch padding edge cases).
- `target_index` — `leaves` index (property runs for every index, not just random).

**Failure modes caught**:
- Audit-path direction reversal (left/right sibling confusion — very easy bug, silent corruption).
- Off-by-one between `leaf_index` and 0-indexed vs 1-indexed tree position.
- Postgres-Merkle backend using row-insertion-order instead of canonical tree ordering.
- Trillian backend using log-entry-index instead of tree-leaf-index (subtle).
- Root-hash domain separation byte (RFC 9162 prefixes leaves with 0x00, internal nodes with 0x01 — forgetting this silently passes self-verification but fails against any other RFC 9162 implementation).

**Feature-002+ acceptance**: both `LedgerProvider` impls MUST pass all three properties;
CI gate.

---

## Surface F — RFC 8693 token exchange flow (SC-018 gated)

**Phase-1 status**: NOT YET SHIPPED — Feature 002+ implements `SecretsProvider.exchange_for_downstream_token/4` +
`PrincipalProvider.supports_rfc8693?/1` composition (FR-047).

**Property**: for all generated `(identity_context, downstream_service, policy_decision)`
triples where policy permits the call, `exchange_for_downstream_token/4` returns a token
whose claims match the identity_context's principal, carry the correct `aud`, and expire
within the configured TTL. For all triples where policy denies, `ERR_TOKEN_EXCHANGE_FAILED`
propagates without any token being minted OR cached.

**Generators**:
- `identity_context` — all three principal kinds (FR-026) across multiple tenants.
- `downstream_service` — enum of configured services (jira, confluence, slack, snowflake).
- `policy_decision` — Allow / Deny randomly assigned.

**Failure modes caught**:
- Token exchange that mints even when Cedar deny was the actual policy decision (rare but catastrophic — the agent should never get a downstream token under deny).
- Token-cache leak: successful token minted for principal A somehow returned to principal B on a subsequent call (tenant-isolation breach).
- `aud` claim not rewritten to downstream service (token would be accepted by wrong service).
- Expiry handling: token's `exp` beyond the configured max TTL.

**Gated on SC-018** — the worked end-to-end example in Deliverable B (Provider Interface
Contracts). Until a reference Okta/Entra/Auth0 impl exists (Feature 002+), this surface's
property tests run against a Mox-backed IdP that echoes claims. Real-IdP coverage lands as
part of the IdP certification matrix (FR-047).

---

## Surface G — IdentityContext immutability (SC-016)

**Already shipped**: `apps/recurse_shared/test/identity_context_property_test.exs` (T030).

**Property**: `IdentityContext.new/1` produces structurally-equivalent values for equivalent
input; no public mutator exists on the struct; `Module.module_info(:exports)` includes only
`new/1` and `resolved?/1` as public entry points. Any future addition of a `put/3` or
`update/3` function to `Recurse.Shared.IdentityContext` breaks the property test.

**Why structural**: Elixir has no first-class immutability enforcement at the type level
(unlike e.g. Rust's `&mut`). The defense is architectural: if the module exports no mutator,
callers cannot mutate. This property test is the canary.

**Failure modes caught**:
- Future refactor adds a `with_additional_claim/2` function "for convenience" — SC-016 violation.
- `@derive`-ed protocol accidentally exposes `Access` behavior allowing `put_in/3` mutation.

**Feature-002+ extension**: cross-plane propagation test. After the Gateway resolves the
IdentityContext at ingress, every downstream handler that receives it MUST pass it by reference
(not reconstruct). A property test at the integration level will generate random call chains
and assert the IdentityContext reference identity stays constant across hops.

---

## Surface H — Session state machine transitions (FR-044)

**Already shipped**: `apps/recurse_shared/test/session/state_machine_property_test.exs` (T034).

**Property**: only the FR-044-documented transitions succeed; all other `(from_state, to_state)`
pairs return `{:error, :invalid_transition}`. Re-tested: terminal states (`committed`,
`cancelled`, `aborted`) admit no outgoing transitions.

**Failure modes caught**:
- Future refactor adds a state (e.g., `:paused`) and forgets to add transitions — silent dead-end.
- Allowed-transition table drifts from FR-044 documented behavior.
- `:committed -> :active` accepted (session resurrection — should be impossible).

---

## Feature-002+ surfaces (tracked here; not yet implemented)

These surfaces DON'T have Phase-1 property tests because the code they exercise doesn't
exist yet. Feature 002+ authors MUST add property tests at these surfaces as part of their
acceptance bar.

### I — Cedar policy evaluation determinism

**Property**: `evaluate(policy_set, request) == evaluate(policy_set, request)` byte-identically
across repeat calls, concurrent calls, and calls that cross a Gateway process restart boundary.
Cedar is deterministic by design; this guards against state leakage in our NIF wrapper.

### M — TLS SNI parsing (Constitution Principle VI — required)

**Status**: catalog-only in Phase 1; implementation ships in Feature 002+ with the Gateway's
TLS termination path. Constitution Principle VI explicitly enumerates "TLS SNI parsing"
as one of the security-critical paths REQUIRING property-based tests — missing it from this
catalog was the `speckit-pr-review` F004 finding on PR #1.

**Property 1 — parser accepts well-formed SNI extensions**: for all generated valid
ClientHello byte sequences with an SNI extension containing a syntactically valid host name
(length-prefixed per RFC 6066), the parser extracts the host name and only the host name —
no surrounding bytes, no off-by-one truncation, no trailing whitespace.

**Property 2 — parser rejects malformed SNI gracefully**: for all generated malformed SNI
payloads (over-long length prefix, truncated extension, non-ASCII host-name bytes, zero-length
host name, embedded null byte), the parser returns `{:error, reason}` — never crashes, never
returns a partial host name as valid.

**Property 3 — no information leak in error responses**: when parsing fails, the error
value the caller receives contains a bounded category (`:malformed_sni`, `:truncated`,
`:invalid_host_name`) and NOT the raw offending bytes. This is defense-in-depth against
the Gateway's error path accidentally echoing attacker-controlled TLS bytes into logs.

**Property 4 — buffer-boundary handling**: ClientHello can straddle TLS record boundaries.
For all generated split-points across a valid ClientHello, the parser either completes
successfully (if the accumulated bytes reach the SNI extension) or returns `:need_more_bytes`
— never silently succeeds on partial input.

**Generators**:
- Valid host names via `StreamData`: lowercased ASCII labels separated by `.`, length 1-253.
- Malformed payloads via targeted generators: length-prefix corruptions, truncations at
  random offsets, non-ASCII injections.
- Split-point indexes: uniform over `[1, ClientHello length - 1]`.

**Failure modes caught**:
- Off-by-one in the TLS length-prefix parse (reading one byte past the host name buffer).
- Accepting an empty-host-name SNI as a valid wildcard (security-sensitive; must reject).
- UTF-8 vs ASCII confusion — SNI host names are ASCII-only per RFC 6066; a UTF-8 multi-byte
  char in the name field must be rejected, not decoded.
- Leaking attacker-controlled bytes into error logs (principle VI defense-in-depth).

**Feature-002+ ownership**: implemented alongside `apps/recurse_gateway/lib/recurse_gateway/ingress/`
— the TLS termination path reads SNI before any Cedar evaluation occurs, so this must be
correct before FR-025 binds.

### J — Netns filter drop-packet correctness

**Property**: for all generated L3/L4/L7 protocol samples, the netns filter either (a) forwards
to the Gateway's allowed ingress port, OR (b) drops AND emits a denial attestation. No packet
is silently dropped without an attestation; no packet is forwarded outside the allowlist.

### K — Session commit atomicity

**Property**: under arbitrary interleaving of event emission and commit timing, a session
either transitions cleanly through `active → (interim_committed | commit_retry →
commit_retry_exhausted | aborted | cancelled) → committed` OR remains at `local_inclusion_verified`
awaiting operator intervention. No event ever ends up with `verification_level: signed` without
eventually transitioning to at least `local_inclusion_verified` as the session epoch fills.

### L — Export Evidence zip DSSE-over-manifest integrity

**Property**: for all generated run_ids, `recurse-verify` (T077) applied to the emitted zip
succeeds end-to-end AND detects single-bit corruption injected at any file path inside the zip.
The manifest.json's DSSE signature is the global integrity anchor; flipping any bit in any
artifact MUST cause recurse-verify to fail with a specific exit code mapped in T080.

---

## Catalog maintenance policy

When a Phase-1 shared-types property test is extended in Feature 002+ (e.g., "add real IdP
coverage"), update the corresponding section above with the new acceptance bar AND add the
Feature ID that owns the extension. This file is the catalog; it grows with the platform.
