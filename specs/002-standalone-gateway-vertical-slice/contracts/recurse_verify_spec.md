# Contract: `recurse-verify` CLI Wrapper

**Feature**: F002 | **Spec**: FR-033 (+ US3 acceptance scenarios) | **Supersedes F001**: `cli_verifier_procedure.md` exit-code taxonomy now pinned per F002 GAN round 1 resolution.

This contract defines the wire behavior of `docs/auditor/recurse-verify` — the Recurse-shipped bash wrapper an auditor runs against an Export Evidence zip.

## Synopsis

```
recurse-verify --zip <path> [--trust-anchor <kms-arn-or-file>]
               [--json] [--verbose] [--help]
```

## Flags

| Flag | Required | Type | Semantics |
|---|---|---|---|
| `--zip` | ✓ | path to `.zip` | The Export Evidence zip per F001 FR-048 surface 2 + F002 FR-022. |
| `--trust-anchor` | REQUIRED for strict pass | string | Either a KMS key ARN (resolved via `aws kms get-public-key` using the auditor's own AWS credentials) OR a file path to a PEM/DER-encoded public key the auditor independently obtained from the customer. **Omission → exit 2 (unanchored pass, WARNING)** — not evidentiary-grade. |
| `--json` | no | flag | Emit a structured JSON report on stdout in addition to human-readable trace. |
| `--verbose` | no | flag | Include step-by-step byte-level computations (useful for debugging). |
| `--help` | no | flag | Print usage + exit 0. |

## Exit codes

| Code | Meaning | Use |
|---|---|---|
| 0 | **Strict cryptographic pass** — `--trust-anchor` supplied, Step 0 matched zip's archived signer pubkey against the anchor, AND all subsequent steps passed. (The tool asserts no compliance-framework grade: nothing in the record supports framework conformance, and exit 0 is reachable with a Step 3 that only checks the proof's internal consistency. RC review 2026-09-05, F5.) |
| 1 | **Verification failure** — any of the seven verification steps failed (including `--trust-anchor` mismatch in Step 0). Human trace identifies the failing step. |
| 2 | **Unanchored pass** (WARNING) — `--trust-anchor` was NOT supplied; verification continued using the zip's bundled signer pubkey as the verifier key; Steps 1–6 all passed. **This is NOT evidentiary-grade**; auditors operating under compliance frameworks MUST re-run with `--trust-anchor`. |
| 3 | **Bad input** — zip malformed, required stock tools (`openssl`, `jq`, bundled Merkle verifier) absent, or flag parsing failed. Not a verification verdict. |

## Output format (human mode)

```
$ recurse-verify --zip receipt-01H...ZR.zip --trust-anchor arn:aws:kms:us-east-1:123:key/abc

recurse-verify 0.2.0 (F002 build)
Zip: receipt-01H...ZR.zip
Trust anchor: arn:aws:kms:us-east-1:123:key/abc (resolved via aws kms get-public-key)

[0] Trust anchor match
    expected pubkey sha256: a3f9...
    zip archive pubkey sha256: a3f9...
    MATCH ✓

[1] DSSE signature (Constitution Principle III)
    algorithm: ES256
    signed bytes (PAE): 3891 bytes
    signature: <72-byte DER, verified against zip archive pubkey>
    VALID ✓

[2] RFC 9162 local inclusion (session-chain epoch root)
    session_chain_epoch: 0
    leaf: <32 bytes>
    proof: <2 sibling hashes>
    computed epoch_root: 7fa3...
    expected (from outer_container.session_chain_root): 7fa3...
    MATCH ✓

[3] RFC 9162 global inclusion path — internal consistency only
    sequence: 4712
    leaf (session_epoch_root): 7fa3...
    proof: <12 sibling hashes>
    computed global_root: c9d1...
    the computed root is folded from this proof and re-checked against itself;
    it is not compared against any independently published ledger root
    CONSISTENT (computed root c9d1...)

[4] policy_canonical_hash
    bundle_bytes: <from zip>
    computed SHA-256(JCS(PolicySet::to_json())): 8be4...
    expected (from signed_predicate): 8be4...
    MATCH ✓

[5] payload_hash
    payload.json: <4287 bytes from zip>
    computed SHA-256(JCS({"request": ..., "response": ...})): 2f0a...
    expected (from signed_predicate): 2f0a...
    MATCH ✓

[6] verification_level + tier_completeness_advisory
    verification_level: global_inclusion_verified
    tier_completeness_advisory: partial (Standalone AI Gateway — scope is per-traversal, not per-agent-egress)
    INTERPRETED ✓

VERIFY: PASS (strict, anchored)
```

### Output format (failure, `--trust-anchor` omitted)

```
$ recurse-verify --zip receipt-01H...ZR.zip

WARNING: no --trust-anchor supplied.
This verification uses the zip's bundled signer pubkey as its own verifier key.
This is NOT evidentiary-grade under SOC2/ISO27001/HIPAA/FedRAMP.
Auditors MUST re-run with --trust-anchor pointing at a customer-supplied anchor
(KMS key ARN or independently-obtained public key file).

[0] Trust anchor match
    SKIPPED (no anchor supplied)
    UNANCHORED ⚠

[1] DSSE signature (using zip's bundled pubkey)
    VALID ✓
...
[6] verification_level + tier_completeness_advisory
    INTERPRETED ✓

VERIFY: UNANCHORED PASS (exit 2 — NOT evidentiary-grade)
```

## Implementation notes

- **Bundled RFC 9162 Merkle verifier**: `docs/auditor/verify-bundled-merkle` — a Recurse-vendored binary (or, if portable, a second bash file that uses `openssl dgst -sha256` primitives directly). Provenance MUST be documented in the same directory: source URL, SHA-256 of the binary, build date, license. The intent is "verifiable by an auditor with zero Recurse trust" — bundling is a convenience, not a trust root.
- **No network access required**: all verification happens offline. `--trust-anchor <kms-arn>` is the sole exception, and it uses the auditor's OWN AWS credentials against AWS's public endpoint — no Recurse interaction.
- **Portable bash**: the wrapper uses only `bash 4+`, `openssl`, `jq`, `unzip`, `sha256sum`. Tested on macOS (default `bash 3.2` insufficient — instruction: `brew install bash` OR use the vendored binary).

## Behavior matrix

| Scenario | `--trust-anchor` | Steps 1–6 | Exit | Output |
|---|---|---|---|---|
| Good zip + correct anchor | supplied, matches | all pass | 0 | "PASS (strict, anchored)" |
| Good zip + wrong anchor | supplied, mismatch | Step 0 fails | 1 | "FAIL: trust anchor does not match zip signing-key archive entry" |
| Good zip + no anchor | omitted | all pass | 2 | "UNANCHORED PASS (exit 2 — NOT evidentiary-grade)" |
| Tampered payload | anything | Step 5 fails | 1 | "FAIL: payload_hash mismatch at Step 5 — detached payload bytes do not match signed predicate" |
| Tampered signature | anything | Step 1 fails | 1 | "FAIL: DSSE signature invalid at Step 1" |
| Malformed zip | anything | N/A | 3 | "FAIL: bad input — zip missing required member: signed_predicate.json" |
| Missing `openssl` | anything | N/A | 3 | "FAIL: bad input — openssl not found; install it (brew install openssl@3)" |
| Anchor is ARN, `aws` CLI missing | supplied as ARN | N/A | 3 | "FAIL: bad input — aws CLI not found; use --trust-anchor /path/to/pubkey.pem instead" |
