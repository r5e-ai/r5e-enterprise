# CLI Verifier Procedure (Deliverable J — Part 3)

**Status**: Phase-1 auditor deliverable. **Binding for Feature 002+
Gateway attestation emission — every field named here must be
produced verbatim.**

**Requirement**: FR-048 surface 3 ("open-source CLI verifier procedure
documentation"). **Recurse ships NO proprietary verifier binary.** We
document the procedure end-to-end using stock open-source tools; the
auditor verifies entirely off our platform, in their own terminal.
**No network calls to Recurse infrastructure.**
**Related**: FR-021 (attestation envelope), FR-038 (verification
levels), FR-039 (`policy_canonical_hash`), FR-046 (signing-key
archive), FR-048 surface 2 (Export Evidence zip), SC-005 (under 30
minutes), SC-009 (two-level verification), SC-020 (T+1 year).

## Tooling

Auditor provides these, installed locally:

| Tool          | Purpose                                                              | Install                                   |
|---------------|----------------------------------------------------------------------|-------------------------------------------|
| `sigstore-cli`| DSSE signature verification                                          | `brew install sigstore` / GitHub release  |
| `jq`          | JSON field extraction                                                | `brew install jq`                         |
| `sha256sum`   | Payload / canonicalization hashing                                   | preinstalled on Linux; `coreutils` on mac |
| `openssl`     | PEM parsing, base64 decode                                           | preinstalled                              |
| `unzip`       | Extract the Export Evidence zip                                      | preinstalled                              |
| `recurse-verify` | Thin bash wrapper shipped under `docs/auditor/recurse-verify`     | Extract from Recurse docs repo; no package manager |

Optional:

| Tool                 | Purpose                                                          |
|----------------------|------------------------------------------------------------------|
| `cedar-cli`          | Local Cedar AST parse for `policy_canonical_hash` rebuild         |
| A generic RFC 9162 verifier (e.g., `ct-log-verifier`, or `sigstore-cli verify-proof`) | RFC 9162 TransItem inclusion-proof verification |

## The Export Evidence zip (input)

The zip is produced by Recurse on the auditor's request via FR-048
surface 2; see T087 for its exporter spec. Layout:

```
<run_id>.zip
  evidence/<run_id>/
    ├── MANIFEST.json           index of every file and its SHA-256
    ├── run_metadata.json       tenant_id, session_id, time range, event counts
    ├── attestations/
    │   ├── <step_id_1>.json    full Recurse-native envelope (mediaType + dsseEnvelope + outer)
    │   └── <step_id_2>.json
    ├── payloads/
    │   ├── <payload_hash_1>.bin  detached payload bytes; filename IS the hash
    │   └── <payload_hash_2>.bin
    ├── signing_key_archive/
    │   ├── INDEX.json
    │   └── <key_id>/v<version>/
    │         ├── public.pem
    │         └── metadata.json
    ├── policy_bundle/
    │   ├── cedar_version.txt   e.g., "4.9.1"
    │   ├── policy_set.cedar    the policy source
    │   └── policy_canonical_hash.txt    the hash locked at emission
    └── merkle_proofs/
        ├── <step_id>.local.rfc9162    base64 RFC 9162 TransItem (per-event, in-session)
        ├── <epoch_id>.global.rfc9162  base64 RFC 9162 TransItem (per-epoch-root, in-global-ledger)
        └── epoch_roots.json           map step_id → epoch_id → session_chain_root
```

`MANIFEST.json` is the auditor's index-of-truth; its SHA-256 column is
what the wrapper verifies each file against.

## End-to-end procedure

Numbered steps map 1-to-1 to sections in
`docs/auditor/verification_walkthrough.md` and to functions in the
`recurse-verify` script.

### Step 1 — Extract the zip

```bash
$ unzip -q <run_id>.zip -d ./evidence-workdir
$ cd ./evidence-workdir/evidence/<run_id>
```

Verify `MANIFEST.json` is present and that every file listed in it
exists on disk. Any mismatch = `EXIT 11 (manifest integrity failure)`.

### Step 2 — Verify DSSE signatures

For each `attestations/<step_id>.json`:

1. Extract the DSSE envelope from the file's `dsseEnvelope` key (`jq`).
2. Read the first `signatures[0].keyid` — format is
   `<key_id>:v<key_version>`.
3. Locate the matching `signing_key_archive/<key_id>/v<key_version>/public.pem`.
4. Run DSSE verification:

```bash
$ sigstore-cli verify dsse \
    --envelope      attestations/<step_id>.json.dsse \
    --public-key    signing_key_archive/<key_id>/v<version>/public.pem \
    --payload-type  application/vnd.in-toto+json
OK  attestations/<step_id>.json.dsse  verified against <key_id>:v<version>
```

Any failure = `EXIT 21 (DSSE signature verification failed)`.

### Step 3 — Verify RFC 9162 inclusion proofs (two levels)

**Level 1 — per-event in-session local inclusion.** For each
attestation, consult its `outer.inclusion_proof_local`. This is a
base64 RFC 9162 `TransItem` that proves the attestation's DSSE
envelope hash is a leaf in the session-chain epoch identified by
`outer.session_chain_epoch`, with tree head equal to
`outer.session_chain_root`:

```bash
$ echo "$PROOF_B64" | base64 -d > /tmp/local.transitem
$ sigstore-cli verify-proof \
    --proof       /tmp/local.transitem \
    --leaf-hash   "$DSSE_ENVELOPE_SHA256" \
    --root-hash   "$SESSION_CHAIN_ROOT"
OK  leaf included in session-chain epoch <N>
```

**Level 2 — per-epoch-root global-ledger inclusion.** Consult
`merkle_proofs/<epoch_id>.global.rfc9162`. This proves the epoch
root is a leaf of the global ledger at the global-ledger tree head
recorded in `merkle_proofs/epoch_roots.json`:

```bash
$ sigstore-cli verify-proof \
    --proof       /tmp/global.transitem \
    --leaf-hash   "$SESSION_CHAIN_ROOT" \
    --root-hash   "$GLOBAL_LEDGER_ROOT"
OK  session-chain epoch root included in global ledger
```

Level 1 failure = `EXIT 31 (local inclusion proof failed)`.
Level 2 failure = `EXIT 32 (global inclusion proof failed)`.

For `verification_level: signed` events Level 1 and 2 are expected
absent — the wrapper skips and reports `SKIPPED (level=signed)`.
For `verification_level: local_inclusion_verified`, Level 2 is
skipped. This matches the monotonic FR-038 progression.

### Step 4 — Verify `policy_canonical_hash`

The attestation's signed predicate carries
`policy_canonical_hash = sha256(JCS(Cedar::PolicySet::to_json(parse(source))))`
per FR-039. Auditor rebuilds it locally:

```bash
# Pin Cedar at the version the zip declares
$ cedar_version=$(cat policy_bundle/cedar_version.txt)           # e.g., 4.9.1
$ locked_hash=$(cat policy_bundle/policy_canonical_hash.txt)
$ receipt_hash=$(jq -r '.dsseEnvelope.payload' attestations/<step_id>.json \
    | base64 -d \
    | jq -r '.predicate.policy_canonical_hash')

# Using the Recurse Cedar NIF-equivalent CLI (or a reimplementation
# via cedar-cli + a JCS tool):
$ recurse-verify cedar-hash policy_bundle/policy_set.cedar "$cedar_version"
sha256:44ea666a2c953505b19b2f197d9128f9c4914149cd7a94f6db06833171cb5542

# All three must match:
[ "$locked_hash" = "$receipt_hash" ] && echo "OK"
```

The stability fixture at
`apps/recurse_shared/priv/test_fixtures/cedar_stability/` is the
canonical reference implementation of this step; auditors running
against their own Cedar installation should get the same hash for
the same policy source.

Hash mismatch = `EXIT 41 (policy canonical hash mismatch)`. A
mismatch at this step means either (a) the zip was tampered with,
(b) the auditor's Cedar version differs from `cedar_version.txt`,
or (c) the signed predicate was produced by a Gateway with a
different Cedar pin — all three are exceptional and require
escalation per `verification_walkthrough.md`.

### Step 5 — Verify `payload_hash` against detached payload

```bash
$ receipt_hash=$(jq -r '.dsseEnvelope.payload' attestations/<step_id>.json \
    | base64 -d \
    | jq -r '.predicate.payload_hash')                            # sha256:abc...
$ payload_file="payloads/${receipt_hash#sha256:}.bin"
$ computed=$(sha256sum "$payload_file" | awk '{print "sha256:"$1}')
[ "$receipt_hash" = "$computed" ] && echo "OK  payload bytes match"
```

Mismatch = `EXIT 51 (payload hash mismatch)`.

### Step 6 — Correlate `verification_level` + `tier_completeness_advisory`

The wrapper prints a final summary table. Each row is one attestation:

```
step_id                              vlevel                     tier      session_state
01HQXZ9RXKSTEP00000000001A01         global_inclusion_verified  complete  committed
01HQXZ9RXKSTEP00000000001A02         global_inclusion_verified  complete  committed
01HQXZ9RXKSTEP00000000001A03         local_inclusion_verified   partial   interim_committed
```

Interpretation:

- `global + complete` = the strongest claim. Event cryptographically
  proven in the global ledger; deployment-shape guarantees no other
  unrecorded events.
- `global + partial` = event proven; but on Standalone Gateway (UDP /
  QUIC / raw IP may have bypassed interception) other events may be
  missing. Per FR-038, honest framing.
- `local + *` = event proven in-session; will advance to `global` at
  next epoch boundary. If the zip was exported before that boundary,
  the auditor should request a fresh export after the next commit
  tick to see `global`.
- `signed + *` = zip was exported mid-session with no epoch yet; the
  pre-commit state. Rare in practice; procedurally identical to
  `local + *`.
- Any `session_state == commit_retry_exhausted` = **operator
  intervention required**. The ledger has been unreachable longer
  than the configured bound; escalate per
  `verification_walkthrough.md`.

Correlation is not a verification step per se — it is the auditor's
editorial interpretation of the proven facts. The wrapper's job is
to print the table; the auditor's is to draw conclusions.

## Exit codes

| Code | Meaning                                                          |
|------|------------------------------------------------------------------|
| `0`  | All events verified at `verification_level` claimed               |
| `1`  | Usage / argument error                                            |
| `11` | MANIFEST integrity failure (missing files, SHA-256 mismatches)    |
| `21` | DSSE signature verification failed (one or more events)           |
| `31` | Local (in-session) inclusion proof failed                         |
| `32` | Global-ledger inclusion proof failed                              |
| `41` | Policy canonical hash mismatch                                    |
| `51` | Payload hash mismatch                                             |
| `99` | Missing tool in PATH (sigstore-cli / jq / etc.)                   |

The wrapper fails-fast on the first error by default; pass `-k` to
continue through all events and emit a full error summary.

## Sample end-to-end run

```
$ ./recurse-verify --zip 01HQXZ9RXKRUN000000000RU01.zip
[1/6] Extracting evidence zip                                           OK
[1/6] MANIFEST integrity (12 files, SHA-256 checked)                    OK
[2/6] DSSE signatures (42 attestations, keys: rec-signing-2026q2:v3)    OK
[3/6] RFC 9162 local inclusion (42/42)                                  OK
[3/6] RFC 9162 global inclusion (1 epoch root: ep-0000001)              OK
[4/6] Cedar policy canonical hash (cedar 4.9.1)                         OK
      locked    sha256:44ea666a2c953505b19b2f197d9128f9c4914149cd7a94f6db06833171cb5542
      receipt   sha256:44ea666a2c953505b19b2f197d9128f9c4914149cd7a94f6db06833171cb5542
      rebuilt   sha256:44ea666a2c953505b19b2f197d9128f9c4914149cd7a94f6db06833171cb5542
[5/6] Payload hashes (42/42)                                            OK
[6/6] Summary:
      42 events  global_inclusion_verified  complete
       0 events  local_inclusion_verified
       0 events  signed
       0 events  commit_retry_exhausted
VERIFIED  run_id=01HQXZ9RXKRUN000000000RU01  tenant=01HQXZ9RXK0000000000000T01
```

## Honest framing

- **No Recurse infrastructure is contacted** during verification. The
  auditor's machine does not reach any `*.recurse.ai` hostname. This
  is what FR-048 surface 3 promises — an off-platform verification
  procedure using stock OSS tools.
- **We do NOT ship a proprietary verifier.** `recurse-verify` is a
  thin bash wrapper that chains `sigstore-cli`, `jq`, `sha256sum`,
  `openssl`, `unzip`. All primitives are replaceable with any
  auditor's preferred equivalent.
- **The zip is self-contained.** Public keys, policy source, payloads,
  proofs — everything needed to verify is inside. SC-020 falls out
  of this property automatically.
- **Completeness advisory is honest.** A `partial` claim is not hidden
  — it prints in Step 6's summary and the
  `verification_walkthrough.md` documents how to interpret it.

## Cross-references

- `audit_payload_broker.md` — live payload-fetch path (if an auditor
  prefers streaming over a zip-based export; same verification flow
  applies once bytes are in hand).
- `signing_key_archive.md` — authoritative source of `public.pem`
  material the zip bakes in.
- `session_lifecycle.md` — state machine that `session_state` values
  refer to.
- `docs/auditor/recurse-verify` — the executable wrapper.
- `docs/auditor/verification_walkthrough.md` — reader-facing
  walkthrough.
- `apps/recurse_shared/priv/test_fixtures/cedar_stability/` — Cedar
  `policy_canonical_hash` reference implementation.
