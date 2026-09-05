# Cedar stability fixture

Implements the three-component content-addressed Cedar pin from
`specs/001-api-jido-foundations/research.md` D2 and FR-039. All three files
in this directory advance lockstep with every Cedar upgrade, and
`mix recurse.cedar.stability_check` asserts them in CI (T045).

## Files

| File                        | Source                                                                                                          |
|-----------------------------|------------------------------------------------------------------------------------------------------------------|
| `cedar_version.txt`         | Plain-text semver tag, mirrors `cedar-policy = "=<version>"` in `native/recurse_cedar/Cargo.toml`.             |
| `cedar_crate_digest.txt`    | SHA-256 of the `cedar-policy` crate source tarball, copied from `native/recurse_cedar/Cargo.lock`'s `checksum = "..."` field under the `cedar-policy` package entry. |
| `representative_policy_set.cedar` | Cedar source for a 4-policy RBAC + ABAC + denylist set. Input to `canonical_hash/1`.                       |
| `expected_hash.txt`         | Lowercase hex-encoded SHA-256 output of `Recurse.Cedar.canonical_hash/1` applied to `representative_policy_set.cedar` under the pinned Cedar version. |

## Regenerating after a Cedar bump

1. Update `cedar-policy = "=<new>"` in `native/recurse_cedar/Cargo.toml`.
2. Run `cargo update -p cedar-policy --manifest-path native/recurse_cedar/Cargo.toml`.
3. Copy the new `version` and the new `checksum` from `Cargo.lock` into
   `cedar_version.txt` and `cedar_crate_digest.txt`.
4. Recompile the NIF: `mix deps.compile recurse_shared --force`.
5. Re-bake the hash in IEx:
   ```elixir
   path = Path.join(:code.priv_dir(:recurse_shared), "test_fixtures/cedar_stability/representative_policy_set.cedar")
   path |> File.read!() |> Recurse.Cedar.canonical_hash_hex() |> IO.puts()
   ```
6. Paste the output into `expected_hash.txt` (one line, lowercase hex, no `0x` prefix).
7. Document the transition in
   `specs/001-api-jido-foundations/contracts/cedar_pin.md` (T091) with both the old
   and new fixture hashes — consumers verifying historical receipts need both
   during the transition window.

## Verification

```bash
mix recurse.cedar.stability_check
```

Exits 0 only when `cedar_version`, `cedar_crate_digest`, and the recomputed
canonical hash all match the values pinned here.
