# Cedar Version Pin + Stability Fixture — Deliverable O (FR-039)

**Purpose**: document the three-component content-addressed Cedar pin, the stability
fixture mechanism, the CI assertion, and the Cedar-upgrade migration procedure.

**Authoritative source for the current pin**: `apps/recurse_shared/priv/test_fixtures/cedar_stability/`.
The values in this document MAY drift from the fixture during a Cedar upgrade window; the
fixture is truth.

---

## Why we pin Cedar three ways, not one

Feature 001's `/speckit-analyze` + /speckit-implement discussion established that
"Cedar version 4.9.1" is a weaker claim than content-addressing. Semver lets an attacker
or a crates.io mirror substitute a tampered crate with the same version number; content
hashes don't. Cargo.lock already records SHA-256 checksums for every crate as source
provenance — we surface that in the receipt-verification path rather than leaving it
silent in the build toolchain.

The three components advance **in lockstep**. Changing any one without the others is a
spec violation and fails `mix recurse.cedar.stability_check`.

### Component 1 — `cedar_version`

**What**: the human-readable semver label. Currently `4.9.1`.

**Where**:
- `native/recurse_cedar/Cargo.toml` — `cedar-policy = "=4.9.1"` (exact pin, not caret).
- `apps/recurse_shared/priv/test_fixtures/cedar_stability/cedar_version.txt` — plain text.
- Tier Configuration `policy.cedar_version` — surfaced to operators + receipts.

**Who reads it**: humans scanning receipts + changelogs.

### Component 2 — `cedar_crate_digest`

**What**: SHA-256 of the `cedar-policy-4.9.1.crate` source tarball as published on crates.io.
Currently `sha256:50368b44367cd7664627bbee9bfe5721d10ab2433daf77645833645e8eb746da`.

**Where**:
- `Cargo.lock` — `checksum = "50368b44..."` under the `cedar-policy` package entry. This is
  the source of truth; everything else copies from here.
- `apps/recurse_shared/priv/test_fixtures/cedar_stability/cedar_crate_digest.txt` — fixture.
- Tier Configuration `policy.cedar_crate_digest` — surfaced to operators + receipts.
- Export Evidence zip `evidence/{run_id}/cedar_engine/cedar_crate_digest.txt` (per T087).

**Who reads it**: auditors cross-checking the Cedar source against crates.io; CI enforcement.

**How to verify it yourself** (auditor workflow):
```bash
curl -sL https://crates.io/api/v1/crates/cedar-policy/4.9.1/download \
  | sha256sum
# Expected: 50368b44367cd7664627bbee9bfe5721d10ab2433daf77645833645e8eb746da
```

### Component 3 — `cedar_fixture_hash`

**What**: the `policy_canonical_hash` (SHA-256 of `JCS(PolicySet::to_json())`) computed by
the pinned Cedar version over the pinned stability fixture policy set. Currently
`44ea666a2c953505b19b2f197d9128f9c4914149cd7a94f6db06833171cb5542`.

**Where**:
- `apps/recurse_shared/priv/test_fixtures/cedar_stability/expected_hash.txt` — the locked
  expected value.
- `apps/recurse_shared/priv/test_fixtures/cedar_stability/representative_policy_set.cedar` —
  the input that produces this hash.
- Export Evidence zip `evidence/{run_id}/cedar_engine/stability_fixture.json` (per T087) —
  `{policy_set, expected_hash}` pair for the auditor to replay locally.

**Who reads it**: `mix recurse.cedar.stability_check` on every CI run; auditors replaying
the fixture locally to confirm their Cedar build produces the same hash.

**Empirical confirmation**: this hash is NOT hand-computed. It is the output of running
the actual NIF against the fixture at T044 time. Re-generate by running:
```bash
iex -S mix
iex> policy = File.read!("apps/recurse_shared/priv/test_fixtures/cedar_stability/representative_policy_set.cedar")
iex> Recurse.Cedar.canonical_hash(policy) |> Base.encode16(case: :lower)
```

---

## CI assertion — `mix recurse.cedar.stability_check`

**Implementation**: `apps/recurse_shared/lib/mix/tasks/recurse.cedar.stability_check.ex` (T045).

**What it does**:
1. Read `cedar_crate_digest.txt`, `cedar_version.txt`, `representative_policy_set.cedar`,
   `expected_hash.txt` from the fixture directory.
2. Read `Cargo.lock` and extract the `checksum` field for the `cedar-policy` package entry.
3. Assert `Cargo.lock.checksum == cedar_crate_digest.txt` — this catches crate substitution
   or un-committed Cargo.lock drift.
4. Load the Cedar NIF. Compute `Recurse.Cedar.canonical_hash/1` on the representative
   policy set.
5. Assert the computed hash matches `expected_hash.txt` — this catches Cedar minor-version
   upgrade drift or any change to the `serde_jcs` / SHA-256 path that would change the hash.

**On success**: prints `✓ Cedar stability fixture OK (4.9.1, digest sha256:50368b44, hash 44ea666a...)` and exits 0.

**On failure**: prints a loud error citing which component drifted, and exits 1. The CI
workflow (`.github/workflows/ci.yml`) fails the build.

**Running locally**: `mix recurse.cedar.stability_check`. Any engineer can re-run this at any
time; the fixture is in-repo.

---

## Cedar-upgrade migration procedure

Cedar minor-version bumps MUST follow this procedure. NO silent Cedar upgrades.

### Step 1 — open a migration spec

File a new Feature under `specs/NNN-cedar-upgrade-X-Y-Z/`. The spec documents:
- Old pin: `(version, crate_digest, fixture_hash)` triple.
- New pin: target triple.
- Known breaking changes in the new Cedar version (read upstream changelog).
- Migration window duration: transition window during which receipts emitted under the new
  hash MAY carry a `legacy_policy_canonical_hash` advisory field referencing the old hash
  for a bounded period.

### Step 2 — bump the three components atomically

In one commit (single atomic change):
1. Edit `native/recurse_cedar/Cargo.toml`: `cedar-policy = "=NEW.VERSION"`.
2. Run `cargo update -p cedar-policy --precise NEW.VERSION` — Cargo.lock updates its `checksum` field.
3. Update `apps/recurse_shared/priv/test_fixtures/cedar_stability/cedar_version.txt`.
4. Update `apps/recurse_shared/priv/test_fixtures/cedar_stability/cedar_crate_digest.txt` to
   match the new Cargo.lock checksum.
5. Run `mix recurse.cedar.stability_check` — this WILL fail with "hash mismatch" because the
   expected_hash.txt is still the old value. That's expected.
6. Re-bake `expected_hash.txt` by running:
   ```bash
   mix run -e 'IO.puts Recurse.Cedar.canonical_hash(File.read!("apps/recurse_shared/priv/test_fixtures/cedar_stability/representative_policy_set.cedar")) |> Base.encode16(case: :lower)'
   ```
   Copy output to expected_hash.txt.
7. Re-run `mix recurse.cedar.stability_check` — MUST pass now.

**Invariant**: at the end of this commit, all three components point to the new Cedar
version and everything is consistent. There is NEVER a commit in main where the three
components disagree (the CI gate enforces this).

### Step 3 — transition window for live receipts

**If the fixture_hash changed**: old receipts reference the old `policy_canonical_hash`.
Their Cedar bundles won't re-canonicalize under the new Cedar version to produce the same
hash. This is fine — old receipts remain verifiable using the old Cedar version (the one
recorded in their `cedar_version` and `cedar_crate_digest` fields in the Export Evidence zip).

For a bounded transition window (default: 30 days), the Gateway MAY emit new receipts with
an optional `legacy_policy_canonical_hash` field referencing what the hash would have been
under the old Cedar, to help operators/auditors bridge the upgrade. After the transition
window, new receipts are only new-Cedar.

### Step 4 — update documentation

Update:
- This file (`contracts/cedar_pin.md`) — new values in the "Component 1/2/3" sections.
- `research.md` D2 — new `cedar_version` + `cedar_crate_digest`.
- Changelog entry at the API-version level (FR-006 / SC-004): if `policy_canonical_hash`
  output shape changed, this is a MAJOR version bump (receipt-verification-breaking).

---

## Auditor verification path (long-horizon)

At T+N years, an auditor holding an Export Evidence zip can verify the Cedar path end-to-end
without any network access to Recurse:

1. Read `evidence/{run_id}/cedar_engine/cedar_version.txt`, `cedar_crate_digest.txt`,
   `stability_fixture.json` from the zip.
2. Pull the exact Cedar crate from crates.io: `cargo install --version X.Y.Z cedar-policy` OR
   download the tarball directly:
   `curl -L https://crates.io/api/v1/crates/cedar-policy/X.Y.Z/download -o cedar.crate`.
3. Verify `sha256(cedar.crate) == cedar_crate_digest.txt`. If crates.io is unreachable, any
   mirror with the same tarball suffices.
4. Build a minimal Cedar canonical-hash tool from the crate source (10-20 lines of Rust
   calling `PolicySet::from_str → to_json → serde_jcs::to_string → Sha256::digest`).
5. Run the fixture through your local tool. Confirm output == `stability_fixture.json.expected_hash`.
6. Now trust that: the Cedar version Recurse pinned IS the crates.io-published version, AND
   that version produces the `policy_canonical_hash` values in this zip's receipts.
7. For any specific receipt, fetch its `policy_bundle/<bundle_digest>.tar.gz` from the zip,
   re-canonicalize via your local Cedar tool, confirm the resulting hash matches the
   receipt's `policy_canonical_hash`.

This chain does NOT require Recurse to be online, or Recurse to attest to anything beyond
what's already in the zip + what crates.io has published. If crates.io itself goes away, the
auditor falls back to any mirror of the published tarball — the `cedar_crate_digest` is the
content-address that makes this work.

---

## FAQ

**Q: Why pin to `=4.9.1` and not `~> 4.9`?**
A: FR-039 demands `policy_canonical_hash` stability across time. Even patch-version Cedar
releases have occasionally changed `PolicySet::to_json()` output shape; we cannot inherit
their backward-compat guarantees without testing. Exact pin + explicit migration procedure
gives us certainty.

**Q: What if the fixture policy set has a syntax error after a Cedar bump?**
A: `PolicySet::from_str` fails during `Recurse.Cedar.canonical_hash/1`, which surfaces as a
loud NIF error in `mix recurse.cedar.stability_check`. Treat as a migration blocker: update
the fixture policy set to use new-Cedar-compatible syntax (document in the migration spec
per Step 1).

**Q: What if crates.io re-publishes the same version number with different bytes?**
A: `cedar_crate_digest` fails, `mix recurse.cedar.stability_check` fails, CI blocks. File a
migration spec (per Step 1) to audit the change. This is the attack vector the three-component
pin defends against.

**Q: Why not pin by git SHA of the Cedar upstream repo instead of crates.io digest?**
A: Auditors verifying receipts shouldn't need GitHub access — air-gap-native constitutional
principle. Crates.io tarballs can be mirrored trivially onto USB/local registry; git SHAs
tie verification to a live upstream.

**Q: How does this interact with the receipt signature path (FR-046)?**
A: Independent. Receipts are DSSE-signed with the Gateway's long-lived KMS key (FR-046);
that signs the predicate payload which CONTAINS `policy_canonical_hash`. The three-component
Cedar pin is what lets an auditor INDEPENDENTLY CONFIRM that the `policy_canonical_hash` in
the signed payload actually came from the Cedar source pinned by the deployment. Both are
needed for full chain-of-custody; neither substitutes for the other.
