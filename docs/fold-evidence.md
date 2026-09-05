# The fold's evidence path

This follows the default stack from the [quickstart](quickstart-claude-code.md). Kernel admission is mandatory; the former `docker-compose.fold.yaml` override remains only for compatibility with old local commands.

## Two records, two verifiers

One admitted call appears in the authoritative kernel chain and in the enterprise ledger projection. Each record has a verifier of its own.

| Record | Export | Verifier |
|---|---|---|
| The enterprise ledger: one signed receipt, its payload, its Merkle inclusion proofs | `bin/r5e evidence export` | `docs/auditor/recurse-verify`, run by `bin/r5e evidence verify` |
| The fold's chain: the whole hash-chained log the embedded r5e kernel wrote, its CAS objects, its KindDefinitions | `bin/r5e evidence export --fold` | `recurse_verify`, built from core, run by `bin/r5e evidence verify --fold` |

They are different programs over different bytes. A pass from one says nothing about the other's export, and neither one reads it.

## Export the chain

```
bin/r5e evidence export --fold
```

It runs `R5e.Export.run/1` inside the gateway container and streams the bundle out. The CLI uses the default quickstart's `r5e` Compose project. Set `R5E_FOLD_PROJECT` or pass `--project NAME` for a differently named stack. `--out DIR` writes somewhere other than `.r5e/fold-export`, which is git-ignored.

## Verify it

```
bin/r5e evidence verify --fold
```

The escript runs inside the container, on the release's own ERTS, with `--posture house`. The command exits with the verifier's code: 0 clean, 1 findings, 2 the bundle could not be read.

The report checks the chain, checkpoint signature, Merkle proofs, retained
payloads, request signatures, authority references and recorded policy inputs.
Read the full `findings`, `not checked` and Kind epistemic-scope sections.
A copied verdict must retain its limitations.

## What is in the bundle

| Path | Contents |
|---|---|
| `log.jsonl` | the chain, byte for byte |
| `cas/` | every object the chain references that this deployment holds |
| `kinds/` | the admitted KindDefinitions |
| `manifest.json` | counts, the checkpoint, the signer's key, and `missingObjects` |

`missingObjects` names referenced objects the deployment no longer holds. Read the verifier's findings and disclosures for the consequences of each missing object.

## Verifying without this image

The escript in the container is built from `r5e-core/verifier`. A reader who will not run this image builds it themselves from that repository at the commit named in [version pins](version-pins.md):

```
mix deps.get && mix escript.build
./recurse_verify /path/to/fold-export --posture house
```

Run the build in `r5e-core/verifier`. This uses an independently built copy of
the same reference implementation; it is not an independently implemented
verifier. Verification requires no connection to the gateway.

To check that a later export extends an earlier checkpoint without rewriting
its prefix, retain both bundles and run:

```
./recurse_verify /path/to/fold-after --posture house --prior /path/to/fold-before
```

The release smoke (`scripts/smoke-release-compose.sh`) exports and verifies the
chain before and after a container restart and compares the two manifests; it
does not run the `--prior` comparison.

## The bundle the fold reads

Activation admits the source bytes and the workload PolicyBundle before the gateway publishes its projection. The live proxy enforces the kernel admission receipt; it does not make a second local Cedar decision over the tool intent.

Kernel-owned policy governs evidence, authority, vocabulary and policy maintenance. Workload policy governs model and tool admissions. A workload bundle that denies every tool does not thereby prohibit recording the denial or installing an authorized replacement. The [execution inventory](release/execution-surfaces.md) identifies the boundary and evidence limits.
