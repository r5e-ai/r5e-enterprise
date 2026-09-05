# Version pins

For anyone who wants to rebuild the image someone else ran, and for the operator who will push to `main` through the stack.

## Pinned repositories

The compose image always contains enterprise, the kernel admission service, and the core verifier. Three commits in three repositories decide what the image contains.

`python3 scripts/prepare-release.py` snapshots one resolved JJ revision from each sibling checkout into `.release-context`. It writes this manifest inside that context:

```json
{"format":"r5e-source-snapshot/v1",
 "repositories":{"r5e-core":{"commit":"<sha>","archiveSha256":"<sha256>"},
                 "r5e-kernel":{"commit":"<sha>","archiveSha256":"<sha256>"},
                 "r5e-enterprise":{"commit":"<sha>","archiveSha256":"<sha256>"}}}
```

`commit` is the resolved source revision. `archiveSha256` covers the deterministic tar.gz produced from that repository tree: file order, ownership, timestamps, and gzip metadata are normalized. Ignored files, VCS metadata, and moving checkout state are not inputs.

Use `--core-revision`, `--kernel-revision`, and `--enterprise-revision` to select revisions explicitly. Use `--archive r5e-source-snapshot.tar.gz` to emit the complete buildable source distribution as well as the directory. Its SHA-256 is printed by the command. After extracting that archive, this builds the same source context without access to the original sibling checkouts:

```
docker build --no-cache -f r5e-enterprise/Dockerfile -t r5e/gateway:local .
```

## CI source identity

Hosted CI assembles the same three-repository layout from a different lock. `release-dependencies.json` records full Git commit IDs and HTTPS source URLs for core and kernel. The enterprise input is the commit checked out by the CI job. `scripts/prepare-ci-sources.py` fetches those exact revisions, rejects forbidden runtime and secret-like paths, creates deterministic component archives, and writes the same `repos.lock.json` format used by the local release snapshot.

The CI variable `R5E_SOURCE_SHA256` is the SHA-256 of the complete `repos.lock.json` bytes. It therefore covers all three commit IDs and all three component archive hashes. It is not the SHA-256 of the outer source-distribution archive. GitLab uses this composite value for immutable image and chart identity. Its `buildcache-linux-amd64` registry tag is a mutable build optimization and is not a release identifier.

For merge requests and the `main`, `develop`, and `demo` branches, `source:prepare` emits the coordinated context and `backend:test` tests that context. The image, chart, and environment-manifest jobs depend on that test job. This gate can run only after the pinned core and kernel commits are available from the URLs in `release-dependencies.json`; source availability remains a separate publication check.

`R5E_COMPANION_GIT_BASE` redirects companion repository fetches to another host while preserving exact commit IDs. A pipeline that fetched through it does not establish availability from the public URLs above; public source availability is checked after publication.

`.gitlab-ci.yml` is the authoritative gate set and `.github/workflows/ci.yml` mirrors it (it runs at least the same gates, plus ESLint, the UI codegen drift gates and the production build). Both now gate the kernel's own `mix compile --warnings-as-errors`: Mix does not propagate that flag to dependencies, so compiling the enterprise umbrella with it had left every kernel warning ungated while the gate was listed as passing.

## The lock and the chain

The image embeds the source manifest at `/app/etc/fold/repos.lock.json`. This identifies its build inputs. Startup does not admit that manifest or attach it to every gateway record.

Recording a release manifest and the publication workflow on the chain is planned release work. The current transparent proxy records the tool intent it receives; it does not add a `pins` array, enforce commit-specific push policy, or observe a client's local command execution.

A publication record must distinguish permission to release a push intent from evidence that the push actually ran and succeeded. That workflow has not been executed for this candidate.

## The honesty boundary

A git SHA identifies repository content. A manifest naming it does not prove that a remote holds it or that a running process executes the corresponding binary. A reader checks source availability separately.

## Two verifiers

The stack can produce two records, and each has its own verifier.

| Record | Verifier |
|---|---|
| The enterprise ledger: receipts, Merkle roots, and the evidence export zip | `recurse-verify`, the enterprise ledger's wrapper; its steps are in [the verification walkthrough](auditor/verification_walkthrough.md) |
| The fold's chain export: the kernel's admitted observations and decisions | `recurse_verify`, built from core's verifier |

They are different programs reading different records. A pass from one is not a statement about the other.

Kernel admission is required by the default compose stack. The kernel chain is the authoritative admission record. The enterprise ledger remains a projection with its older evidence format, so the two verifiers still have distinct inputs.

## Status today

Before publication, the exact core, kernel, and enterprise commits in `repos.lock.json` must be publicly available. The coordinated source archive makes the build independent of private sibling checkouts, but the archive does not prove that a remote hosts those commits; a reader checks that separately. The release-chain sequence is core, kernel, then enterprise.
