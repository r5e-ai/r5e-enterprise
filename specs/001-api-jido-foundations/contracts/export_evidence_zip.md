# Export Evidence Zip Format (Deliverable J, part 5)

**Feature**: 001-api-jido-foundations
**Authority**: FR-048 surface 2 (point-in-time annual audit artifact); FR-021 (attestation
envelope); FR-030 (audit payload broker); FR-039 (policy bundle + canonical hash); FR-046
(long-lived document-signing key archive).
**Related**: `attestation.schema.json`, `siem_log_forwarder.md` (FR-048 surface 1 — daily-ops
firehose), `cli_verifier_procedure.md` (T076 — documented off-platform verification), the
`recurse-verify` wrapper at `docs/auditor/recurse-verify` (T077).

## 1. Purpose and framing

The Export Evidence Zip is the **point-in-time annual-audit surface**. When a Big 4 auditor
samples N `run_id`s from a customer's history, an enterprise admin clicks "Export Evidence" in
the Recurse UI and receives ONE `.zip` per `run_id`. Each zip is **self-contained**: the
auditor can walk off with it, disconnect from the network, and verify it end-to-end on a
laptop running only open-source tooling.

**Recurse's role ends when the zip is emitted.** Verification is off-platform, offline. The
auditor does NOT trust Recurse's "Valid" checkmark in any UI — they run `recurse-verify`
(T077), which chains stock `sigstore-cli` + a generic Merkle-proof library + JSON Schema
validation. The zip is the contract between Recurse and the auditor ecosystem, and the zip is
all that crosses the boundary.

**Explicit NOT-scope:**
- Proprietary Recurse verifier (we document `sigstore-cli` + Merkle verification instead;
  see `cli_verifier_procedure.md`).
- Cross-`run_id` bundle. One zip per `run_id`. A sampled set of 50 `run_id`s produces 50 zips.
- Re-signing. The signed DSSE payload is emitted once at receipt time and never re-signed.
  Subsequent zips for the same `run_id` may differ only in outer-container fields
  (`verification_level` progression, refreshed inclusion proofs).

## 2. Zip layout

Every Export Evidence zip has the following structure. `{run_id}` is a ULID string.

```
manifest.json                                  # zip-root file listing — see §3
manifest.json.dsse                             # DSSE envelope wrapping manifest.json — see §5
evidence/
  {run_id}/
    payload.json                               # detached payload retrieved via FR-030 broker
    attestation.json                           # Recurse-native container (FR-021) — one file
                                               # per step; see §2.1
    inclusion_proofs/
      local.bin                                # RFC 9162 TransItem — session-chain
      global.bin                               # RFC 9162 TransItem — global ledger (if reached)
    signing_key_archive/
      {key_id}-v{version}.pem                  # long-lived signing-key public material (FR-046)
      {key_id}-v{version}.metadata.json        # {not_before, not_after, signer_spiffe_id, ...}
    policy_bundle/
      {bundle_digest}.tar.gz                   # Cedar policy bundle (FR-039)
      {bundle_digest}.sig                      # bundle signature (offline-manifest path; FR-052)
    cedar_engine/
      cedar_version.txt                        # e.g., "4.9.1"
      cedar_crate_digest.txt                   # "sha256:<hex>" of crate tarball from Cargo.lock
      stability_fixture.json                   # {policy_set, expected_hash} re-bake fixture
```

### 2.1 Multi-step runs

A single `run_id` typically contains many steps (LLM calls + tool calls). Each step has its own
attestation envelope. When exporting, attestations are emitted as ONE FILE PER STEP at
`evidence/{run_id}/attestation.json` is REPLACED by a directory
`evidence/{run_id}/attestations/` containing `{step_id}.json` per step, AND a sibling
`evidence/{run_id}/attestations_index.json` enumerating steps in `session_chain_position` order
to support deterministic iteration by auditors.

**Revised shape for multi-step runs:**

```
evidence/
  {run_id}/
    payload/                                   # detached payloads, one per step
      {step_id}.json
    attestations/
      {step_id}.json                           # Recurse-native container per FR-021
    attestations_index.json                    # ordered list of {step_id, session_chain_position}
    inclusion_proofs/
      local/
        {step_id}.bin
      global/
        {step_id}.bin                          # present only when verification_level = global_inclusion_verified
    signing_key_archive/                       # union of signers referenced by any attestation
    policy_bundle/                             # union of bundle digests referenced by any attestation
    cedar_engine/
```

Single-step zips MAY collapse the directory form to the flat form in §2 if and only if the
run contains exactly one step (convenience; the auditor tooling handles both).

### 2.2 File-by-file semantics

| Path | Content | Verification role |
|---|---|---|
| `manifest.json` | Zip index (see §3) | Entry point; sha256 of every file for tamper detection |
| `manifest.json.dsse` | DSSE envelope signing `manifest.json` (see §5) | Proves the zip was emitted by a trusted Gateway |
| `evidence/{run_id}/payload/{step_id}.json` | Detached payload the signed `payload_hash` covers | `sha256(payload.json) == signed_predicate.payload_hash` |
| `evidence/{run_id}/attestations/{step_id}.json` | FR-021 Recurse-native container (signed predicate + outer container + DSSE envelope) | DSSE signature verifies against the signing key in `signing_key_archive/` |
| `evidence/{run_id}/attestations_index.json` | Ordered `{step_id, session_chain_position}` list | Deterministic iteration + ordering invariants |
| `evidence/{run_id}/inclusion_proofs/local/{step_id}.bin` | RFC 9162 TransItem — proves the step is in the session epoch Merkle tree | Verifies against `outer.session_chain_root` |
| `evidence/{run_id}/inclusion_proofs/global/{step_id}.bin` | RFC 9162 TransItem — proves the session epoch root is in the global ledger | Verifies against a globally-pinned ledger root (supplied out-of-band or via Recurse's published ledger STH) |
| `evidence/{run_id}/signing_key_archive/{key_id}-v{version}.pem` | Long-lived signing-key public material per FR-046 | DSSE signature check binds to this key via `keyid = "<key_id>:<version>"` |
| `evidence/{run_id}/signing_key_archive/{key_id}-v{version}.metadata.json` | Key lifecycle envelope (see §4) | Auditor can confirm the key was in-validity-window at `signed_predicate.timestamp` |
| `evidence/{run_id}/policy_bundle/{bundle_digest}.tar.gz` | Cedar policy bundle (OCI Artifact payload) per FR-039 | `sha256(bundle) == bundle_digest`; re-baking with pinned Cedar produces `policy_canonical_hash` |
| `evidence/{run_id}/policy_bundle/{bundle_digest}.sig` | Bundle signature (offline signed-manifest path per FR-052) | Optional but PRESENT when exporting a bundle originally distributed via offline manifest |
| `evidence/{run_id}/cedar_engine/cedar_version.txt` | Cedar minor version (e.g., `4.9.1`) | Auditor re-bakes with this version to reproduce `policy_canonical_hash` |
| `evidence/{run_id}/cedar_engine/cedar_crate_digest.txt` | `sha256:<hex>` of the Cedar crate tarball from `Cargo.lock` | Reinforces version pin — auditor can re-download from crates.io and sha256-check |
| `evidence/{run_id}/cedar_engine/stability_fixture.json` | `{policy_set, expected_hash}` — the CI stability fixture per Deliverable O | Auditor re-bakes the fixture to confirm their Cedar toolchain matches Recurse's |

## 3. `manifest.json` schema

The manifest is the zip's authoritative file listing. Every data file in the zip has an entry;
`manifest.json` does NOT list itself (the DSSE envelope covers it separately).

```json
{
  "manifest_version": "1.0",
  "run_id": "01K0P3J9KJ8XAZJPBX5B3EHRWD",
  "tenant_id": "01JZXYZZZZZZZZZZZZZZZZZZZZ",
  "recurse_envelope_version": "1.0",
  "exported_at": "2026-04-22T17:44:01.003Z",
  "exported_by_gateway_signer": "spiffe://recurse.cloud/gateway/us-east-1/v3",
  "files": [
    {
      "path": "evidence/01K0P3J9KJ.../payload/01K0P3JA0Z.json",
      "sha256": "sha256:9bb0...dfe4",
      "size": 18342,
      "kind": "payload"
    },
    {
      "path": "evidence/01K0P3J9KJ.../attestations/01K0P3JA0Z.json",
      "sha256": "sha256:a001...7e29",
      "size": 4219,
      "kind": "attestation"
    },
    {
      "path": "evidence/01K0P3J9KJ.../attestations_index.json",
      "sha256": "sha256:b312...19ac",
      "size": 612,
      "kind": "attestations_index"
    },
    {
      "path": "evidence/01K0P3J9KJ.../inclusion_proofs/local/01K0P3JA0Z.bin",
      "sha256": "sha256:3310...8f77",
      "size": 256,
      "kind": "inclusion_proof_local"
    },
    {
      "path": "evidence/01K0P3J9KJ.../inclusion_proofs/global/01K0P3JA0Z.bin",
      "sha256": "sha256:ff21...90de",
      "size": 288,
      "kind": "inclusion_proof_global"
    },
    {
      "path": "evidence/01K0P3J9KJ.../signing_key_archive/recurse-gw-us-east-1-v3.pem",
      "sha256": "sha256:0a11...cd55",
      "size": 804,
      "kind": "signing_key_pem"
    },
    {
      "path": "evidence/01K0P3J9KJ.../signing_key_archive/recurse-gw-us-east-1-v3.metadata.json",
      "sha256": "sha256:4411...77aa",
      "size": 318,
      "kind": "signing_key_metadata"
    },
    {
      "path": "evidence/01K0P3J9KJ.../policy_bundle/sha256-5e2ca119....tar.gz",
      "sha256": "sha256:5e2c...a119",
      "size": 22041,
      "kind": "policy_bundle"
    },
    {
      "path": "evidence/01K0P3J9KJ.../cedar_engine/cedar_version.txt",
      "sha256": "sha256:88ee...4433",
      "size": 6,
      "kind": "cedar_version"
    },
    {
      "path": "evidence/01K0P3J9KJ.../cedar_engine/cedar_crate_digest.txt",
      "sha256": "sha256:aa00...bb11",
      "size": 71,
      "kind": "cedar_crate_digest"
    },
    {
      "path": "evidence/01K0P3J9KJ.../cedar_engine/stability_fixture.json",
      "sha256": "sha256:cc22...dd33",
      "size": 1204,
      "kind": "cedar_stability_fixture"
    }
  ]
}
```

### 3.1 Per-entry schema

Every `files[]` entry:

| Field | Type | Required | Description |
|---|---|---|---|
| `path` | string | yes | POSIX-style zip-relative path |
| `sha256` | `sha256:<hex>` | yes | Content digest (lower-case hex) |
| `size` | integer (bytes) | yes | Exact size, in bytes |
| `kind` | enum | yes | Well-known kind; see below |

**`kind` enum (v1.0):**
`payload`, `attestation`, `attestations_index`, `inclusion_proof_local`,
`inclusion_proof_global`, `signing_key_pem`, `signing_key_metadata`, `policy_bundle`,
`policy_bundle_signature`, `cedar_version`, `cedar_crate_digest`,
`cedar_stability_fixture`.

Auditor tooling SHOULD tolerate unknown `kind` values (ignore the entry but keep verifying
known kinds) — future additive kinds do not invalidate prior bundles.

## 4. Signing-key metadata envelope

Each `signing_key_archive/{key_id}-v{version}.metadata.json`:

```json
{
  "key_id": "recurse-gw-us-east-1",
  "version": 3,
  "algorithm": "ecdsa-p256-sha256",
  "not_before": "2026-01-01T00:00:00Z",
  "not_after": "2026-06-30T23:59:59Z",
  "signer_spiffe_id": "spiffe://recurse.cloud/gateway/us-east-1",
  "kms_key_ref": "arn:aws:kms:us-east-1:...:key/abcd1234",
  "rotated_from": "recurse-gw-us-east-1:v2",
  "archived_at": "2026-01-01T00:00:00Z"
}
```

Auditor interpretation: the DSSE envelope's `keyid` field (`<key_id>:<version>`) must appear in
the archive, AND `signed_predicate.timestamp` must fall within `[not_before, not_after]`.

## 5. Tamper-evidence: `manifest.json.dsse`

The manifest is itself DSSE-signed with the Gateway's long-lived signing key (the SAME key that
signs receipts — see FR-046), producing `manifest.json.dsse` alongside `manifest.json`:

- `payloadType`: `application/vnd.recurse.evidence-manifest+json;version=1.0`
- `payload`: base64-encoded `manifest.json` bytes, **verbatim** (not JCS-canonicalized — we
  want auditors to diff the zip's `manifest.json` byte-exactly against the signed payload)
- `signatures[0].keyid`: `<key_id>:<version>` resolving into `signing_key_archive/`

**Auditor verification chain:**

1. DSSE-verify `manifest.json.dsse` against the signing-key PEM in `signing_key_archive/`.
2. For each `files[]` entry, sha256 the referenced file on disk; compare against `sha256` in
   the manifest.
3. (Parallel) For each attestation, DSSE-verify `attestations/{step_id}.json`'s `dsseEnvelope`
   against `signing_key_archive/`; then verify `inclusion_proof_local` against
   `outer.session_chain_root`; then (if present) verify `inclusion_proof_global` against the
   pinned global ledger STH.
4. Re-bake policy: install pinned Cedar minor version (`cedar_version.txt`), sha256-check
   against `cedar_crate_digest.txt`, re-compute `policy_canonical_hash` from
   `policy_bundle/{digest}.tar.gz`, confirm it matches every attestation's
   `signed_predicate.policy_canonical_hash`.
5. Re-bake the stability fixture from `cedar_engine/stability_fixture.json` to confirm the
   auditor's local Cedar toolchain produces the same hash Recurse produces.

Steps 1–5 are automated by the `recurse-verify` wrapper (T077). `cli_verifier_procedure.md`
(T076) documents the equivalent by-hand sequence using stock `sigstore-cli` + a generic Merkle
verifier. Both are off-platform — no network call to Recurse is required.

## 6. Retention and snapshot semantics

- **Point-in-time snapshot.** Each Export Evidence zip is a snapshot of state at
  `manifest.exported_at`. It contains whatever `verification_level` the receipts had achieved by
  that moment.
- **Successive exports of the same `run_id` MAY differ** only in:
  - Outer-container state (`verification_level` progression
    `signed → local_inclusion_verified → global_inclusion_verified`)
  - Presence of `inclusion_proof_global/*.bin` (absent until the session-chain epoch is
    globally committed)
  - `commit_retry_exhausted` flag
- **The signed predicate is BYTE-IDENTICAL across exports.** The DSSE envelope, signed-core
  fields, and `payload_hash` all remain identical — the signed predicate is immutable by
  construction (FR-021).
- **Per SC-020, a zip emitted at T0 verifies at T0+1 year** using the archived signing-key PEM,
  even after the Gateway's transport SVID has rotated many times. This is the core durability
  property.
- **Customer retention**: the zip is the auditor's (or customer's) to retain. Recurse does NOT
  guarantee indefinite server-side storage of any specific zip — `AuditExport` rows retain
  payload and policy references, but the zip itself is a materialization for delivery.

## 7. Interop notes

- **Zip format**: standard PKZIP (RFC 1950 DEFLATE; or stored, no compression). No encryption
  at the zip layer (auditors prefer transparent zips; transport confidentiality is the delivery
  channel's responsibility).
- **Character encoding**: UTF-8. No BOM. Filenames are ASCII-safe (ULID + hex + literal tokens
  per the layout above).
- **Path separator**: forward slash (`/`) — POSIX, even on Windows zip tooling.
- **Total size**: typical zip is 50 KiB – 5 MiB per `run_id`; large payloads dominate.
  Extraordinarily large detached payloads (>100 MiB) MAY be replaced in `payload/` with a
  Recurse-signed "payload locator" JSON pointing at customer-storage (FR-030), accompanied by a
  signed `payload_hash` — Feature 002+ scope; Phase-1 zips inline the payload.

## 8. Cross-references for auditors

- **Verification walkthrough**: `cli_verifier_procedure.md` (T076). The canonical off-platform
  procedure using `sigstore-cli` + stock Merkle tooling.
- **Wrapper script**: `docs/auditor/recurse-verify` (T077). Thin bash wrapper that chains DSSE
  verify + session-chain Merkle verify + global-ledger RFC 9162 verify against a downloaded
  zip.
- **Attestation schema**: `attestation.schema.json`. Validates
  `attestations/{step_id}.json`.
- **Cedar pin + stability fixture**: `cedar_pin.md` (T091). Source-of-truth for
  `cedar_engine/cedar_version.txt` + `stability_fixture.json`.

## 9. HANDOFF notes

1. **`/v1/audit/export` endpoint is NOT specified here.** The endpoint shape (request,
   response, async-job flow for large runs) is T089 scope; T089 has a hard dependency on T049
   (US1's OpenAPI expansion) and is held to the main thread. This contract specifies ONLY the
   zip artifact itself.
2. **Global-ledger STH pinning is under-specified.** Step 3(c) of §5's verification chain
   requires the auditor to have a pinned global-ledger STH (Signed Tree Head) to verify
   `inclusion_proof_global` against. Phase-1 distributes the current STH out-of-band (Recurse
   publishes it on a stable URL; air-gapped appliances ship it in the deployment bundle).
   Feature 002+ should formalize STH distribution — either by including the STH in the zip
   (and requiring separate cross-signatures to prevent circular trust), or by pointing at
   Recurse's public log-monitoring page. Tracked as Feature 002+ scope.
3. **Multi-step layout split (§2 vs §2.1).** Phase-1 zips MAY emit either flat (single-step) or
   directory (multi-step). Tooling accepts both. If this creates auditor confusion, Feature
   002+ can collapse to always-directory; the manifest already supports both paths uniformly.
4. **Cedar stability fixture shape.** `stability_fixture.json` references a `{policy_set,
   expected_hash}` pair. The exact schema of `policy_set` (inline Cedar source vs. AST JSON
   dump) is owned by T091 / Deliverable O. This doc defers to whatever T091 produces.
5. **Payload encryption at customer-storage layer.** FR-030 describes broker-mediated retrieval;
   if customer storage encrypts payloads at rest with customer-owned KMS keys, the Export
   Evidence zip ships the DECRYPTED payload (it has to, for the auditor to compute
   `sha256(payload) == signed_predicate.payload_hash`). Customer-controlled zip encryption on
   the delivery channel is out-of-scope; the zip ships as-is and relies on transport
   confidentiality.
