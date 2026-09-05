# `verify-bundled-merkle` provenance

## Source

- **Origin**: First-party Recurse implementation. NOT a third-party
  binary. The script is human-auditable bash + `openssl dgst -sha256` +
  `xxd` only.
- **Source path**: [`docs/auditor/verify-bundled-merkle`](./verify-bundled-merkle)
  (same directory as this file).
- **Repository provenance**: Tracked under the r5e-enterprise monorepo
  (this file); Feature 002 task T066.

## Algorithm

Implements [RFC 9162](https://datatracker.ietf.org/doc/html/rfc9162)
§2.1.2 (inclusion-proof verifier) for the `inclusion_v1` TransItem
variant encoded by
[`Recurse.Shared.Attestation.Rfc9162.encode/1`](../../apps/recurse_shared/lib/recurse_shared/attestation/rfc9162.ex).

Hash primitive: `SHA-256` only. RFC 9162 leaf prefix is `0x00`; interior
prefix is `0x01`. The verifier computes `hash_interior(l, r) =
SHA-256(0x01 || l || r)` via `openssl dgst -sha256` and compares the
reconstructed root to the expected root bytewise.

Wire format parsed (TLS presentation syntax from RFC 9162 §2):

```
struct {
  VersionedTransType versioned_type;     // uint16 big-endian = 0x0100
  opaque log_id<32..32>;                  // 32 bytes
  uint64 leaf_index;                      // 8 bytes big-endian
  uint64 tree_size;                       // 8 bytes big-endian
  opaque inclusion_path<0..2^16-1>;       // concatenated 32-byte hashes
} TransItem;
```

## Why bash + openssl (not a vendored binary)

Per `specs/002-standalone-gateway-vertical-slice/contracts/recurse_verify_spec.md`
§Implementation notes, the goal is "verifiable by an auditor with zero
Recurse trust." A short bash script using stock `openssl dgst -sha256`
as its only cryptographic primitive achieves that goal: the auditor can
read the script in five minutes and confirm it implements RFC 9162 §2.1.2
faithfully. Bundling a binary (Google Trillian `tclient`, sigstore
`ct-log-verifier`, etc.) is a viable fallback for InfoSec teams that
require a named binary, but bundling it here without a named-binary
requirement is net-negative auditability.

If a customer's InfoSec team REQUESTS a named binary, the F002 deliverable
remains correct by pointing at Google Trillian's upstream `tclient`
(https://github.com/google/trillian) at a pinned tag; `tclient` accepts
RFC 9162-compatible wire formats and will reproduce the same PASS/FAIL
decision. The byte-wire format is the real contract; this script is one
implementation of the verifier half.

## Cross-references

- [`../../specs/002-standalone-gateway-vertical-slice/contracts/recurse_verify_spec.md`](../../specs/002-standalone-gateway-vertical-slice/contracts/recurse_verify_spec.md)
  — F002 auditor wrapper contract. §Implementation notes covers the
  bundling decision.
- [`../../apps/recurse_shared/lib/recurse_shared/attestation/rfc9162.ex`](../../apps/recurse_shared/lib/recurse_shared/attestation/rfc9162.ex)
  — authoritative Elixir encoder for the TransItem bytes this script
  decodes. Surface R property test round-trips these bytes.
- [`../../apps/recurse_providers/lib/recurse_providers/impls/postgres_merkle_ledger/merkle_tree.ex`](../../apps/recurse_providers/lib/recurse_providers/impls/postgres_merkle_ledger/merkle_tree.ex)
  — the matching Elixir verifier (`verify_inclusion_proof/5`). This
  bash script is a bytes-compatible reimplementation. Cross-reference
  T034 + T068.

## Review

- **Directly tested** by the F002 integration test
  `apps/recurse_gateway/test/integration/us3_export_verify_test.exs`
  (T067) — emits a synthetic attestation, writes the TransItem bytes to
  the Export Evidence zip, and verifies them with this script end-to-end.
- **Cross-validated** against the Elixir reference verifier
  `MerkleTree.verify_inclusion_proof/5`: both must return the same
  PASS/FAIL verdict for any given `{TransItem, leaf_hash, root_hash}`
  triple. Surface R property test (T068) asserts the
  encode-decode-verify loop on the Elixir side; the bash script tracks
  that surface bytewise.

## License

Same as the r5e-enterprise monorepo (see repo root `LICENSE`).

## Change log

- 2026-04-24 — Initial implementation (T066). Bash 4+, `openssl`, `xxd`.
