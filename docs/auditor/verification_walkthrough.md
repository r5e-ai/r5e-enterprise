# Verification walkthrough

For an auditor who has been handed an evidence export zip and needs a pass or fail determination on a machine with no access to the gateway that produced it.

## What you receive

| Item | From |
|---|---|
| an evidence zip, one receipt per zip | the customer's console (Export Evidence) or `bin/r5e evidence export` |
| the gateway's public signing key, PEM | the customer, through a channel other than the zip |
| `recurse-verify` and `verify-bundled-merkle` | `docs/auditor/` in this repository |

The zip contains the signed envelope, the outer container with its ledger proofs, the Cedar bundle that decided, the signer's public key, and, for a model call or a denial, the predicate body at `predicate/<run_id>.json` and, with payload retention on, the request and response bytes under `payloads/`. What is inside is listed in `manifest.json`.

## Run

The tools are bash, `openssl`, `jq`, `unzip`, `xxd`, `sha256sum` or `shasum`, and `python3`. Step 4 also uses `cedar-canonical-hash` next to the script; without it the step is `NOT CHECKED` and the verdict is `FAIL`. `bin/r5e evidence verify` builds it once with `cargo`.

```
recurse-verify --zip <run_id>.zip --trust-anchor <public-key.pem>
```

```
[0] Trust anchor match
    MATCH (sha256: 305601d0fc3efdeb...)
[1] DSSE signature (Constitution Principle III)
    VALID (ES256)
[2] RFC 9162 local inclusion (session-chain epoch root)
    MATCH
[3] RFC 9162 global inclusion path — internal consistency only
    the computed root is folded from this proof and re-checked against itself;
    it is not compared against any independently published ledger root
    CONSISTENT (computed root 8caf3f9e05c1d69e50a8ceecaff88976f61c6a58691a2cc3820f05ada9d339a9)
[4] policy_canonical_hash
    MATCH (rule 1: Cedar-canonical JCS hash via bundled cedar-canonical-hash)
[5] payload_hash
    payload_uri: recurse://system/predicate-only/71d585be-a012-4c22-a9fa-451eb1434fc6
    MATCH (predicate body predicate/71d585be-a012-4c22-a9fa-451eb1434fc6.json, 1301 bytes, hashes to payload_hash)
[6] verification_level + tier_completeness_advisory
    verification_level: global_inclusion_verified (reported by producer, not checked)
    tier_completeness_advisory: partial — the gateway attests the calls routed through it;
                                coverage is a property of the deployment (see docs/deployment-shapes.md)
    INTERPRETED
[7] detached payloads (prompt_hash / response_hash)
    prompt: MATCH (payloads/0c1537e70d638516..., 362712 bytes hash to prompt_hash)
    response: MATCH (payloads/d5d40d42fb8f9f33..., 5940 bytes hash to response_hash)

VERIFY: PASS (strict, anchored)
```

The receipt above is the quickstart's denied `rm -rf`; a receipt of a console read has no predicate body and prints `SKIPPED` at steps 5 and 7.

## Steps

| Step | Checks |
|---|---|
| 0 | the key you supplied is the key bundled in the zip |
| 1 | the DSSE signature over the envelope verifies against that key |
| 2 | the receipt is in the session epoch tree the envelope claims |
| 3 | the global inclusion path folds to a root consistent with itself; nothing compares that root to a published ledger root |
| 4 | the bundled Cedar source hashes to `policy_canonical_hash` in the envelope |
| 5 | `predicate/<run_id>.json` hashes to `payload_hash` in the envelope |
| 6 | `verification_level` and `tier_completeness_advisory` are read out, not checked |
| 7 | the bytes under `payloads/` hash to `prompt_hash` and `response_hash` in the body |

Each step prints `MATCH` (`VALID` at step 1, `CONSISTENT` at step 3, `INTERPRETED` at step 6), `FAIL` with the two hashes that differ, or `SKIPPED` with what the export does not carry. `SKIPPED` is a statement about the export, not a failure.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | every step passed with a trust anchor supplied and matched |
| 1 | a step failed; the `FAIL` line names it and the values that differ |
| 2 | every step passed but no trust anchor was supplied; the zip's own key was used |
| 3 | bad input: zip not found or malformed, a required tool missing, or a bad flag |

Without `--trust-anchor` the last line reads `VERIFY: UNANCHORED PASS (exit 2 — NOT evidentiary-grade)`: the signature was checked against a key the zip itself supplied. Rerun with the key you received out of band.

## On a failure

Steps 0 and 1 failing means the zip was not signed by the key you hold, or its bytes changed after signing. Step 2 failing means the receipt is not in the session epoch tree its envelope claims. Step 3 failing means the global inclusion path is malformed; it cannot tell you the epoch root is absent from the ledger, because it never compares the root it computes against a published one. Step 4 failing means the bundled policy is not the one this receipt was evaluated against. Steps 5 and 7 failing means the bundled bytes are not the bytes the receipt hashed. In each case request a fresh export over a different channel and, if it fails the same way, escalate to the customer's security contact with the `FAIL` line.

`--json` prints the same steps as a JSON report for filing.
