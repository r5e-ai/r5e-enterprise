# The public tree

This repository is published as it is tracked. What you can see in the
tree is what is released. There is no second list of directories that are
"not really part of it": material that is internal to the operator —
deployment topology, working plans, agent tooling, handoff notes, the
state of one deployment — is not kept here at all. It lives in a private
handbook, and the documentation in this tree states the decisions it
depends on rather than citing pages you cannot read.

The same holds for the two companion repositories in the coordinated
source distribution, `r5e-core` and `r5e-kernel`. They are published
whole.

## What the packer does

`scripts/prepare-release.py` freezes the three trees into a release
context; `scripts/prepare-ci-sources.py` does the same from Git commits in
CI and imports the same policy. `test/scripts/prepare_release_test.py`
and `test/scripts/prepare_ci_public_tree_test.py` pin the rules below,
and check that this page names every path they mention.

The packer's job is small: keep out what cannot be tracked in a public
tree in the first place, stop if something internal-shaped has crept back
in, and search what remains for the operator's own infrastructure.

### It refuses runtime state and secrets

A tracked path that looks like runtime state or a private key stops the
release with an error. Nobody decided to publish it, so the right answer
is to stop and look. The shapes: any `.r5e`, `.r5e.*` or `.r5e-*`
directory (kernel data: history, CAS, signing keys), `.git`, `.jj`,
`secrets/`, `.env` and `.env.*` (except `.env.example`), and files ending
in `.key`, `.pem`, `.p12`, `.pfx` or `.jks`.

### It omits two tracked paths, and build output

Two paths are tracked but dropped from the archive before the manifest
hash is computed, so the manifest covers exactly what is published.

`.release-forbidden` holds the content gate's own patterns. The strings
that must not be published cannot be one of the published files.

The published tree has no `.gitlab/` directory. The public pipeline,
`.gitlab-ci.yml`, includes `.gitlab/ci/private-deploy.yml` only when an
operator adds one to their own checkout (deploy and publish jobs, which
name a cloud account, a container registry and deploy hosts), and the
packer omits that directory if it is present. What a fork gets is the gate
set and nothing else.

Build output (`_build/`, `deps/`, `node_modules/`, Rust `target/`
directories) is on the same list defensively; none of it is tracked.

That is the whole list.

### It trips on internal-shaped paths

Some paths used to hold internal material and left the tree on
2026-09-05. If any of them is tracked again the packer refuses the release
and names the path, because the decision was that they leave the
repository, not that a filter hides them:

- `infra/` — deployment topology: Helm values, Terraform, hostnames
- `.specify/` — spec-kit working state and operations notes
- `design/` — UI design briefs and design-tool source (the UI's design
  tokens now live at `ui/design-tokens.json`, which is published)
- `docs/superpowers/` — agent-plugin working state and plans
- `HANDOFF.md` — internal handoff notes
- `r5e-PRD.md` — internal product planning
- `tmp/` — scratch

### It searches every published byte

After the omissions are applied, every byte that would be published is
searched for the strings that identify this operator's own infrastructure
— a cloud account id and internal hostnames — and a hit fails the
release. Binary files are searched too. The patterns are not in this
repository: they live in `.release-forbidden`, which is omitted (see
above). A fork therefore gets the mechanism and an empty list, and the
packer says so in its output rather than leaving anyone believing a gate
ran. Add your own file to arm it.

## What this means for a reader

- If a document in this tree cites a path, the path is here.
- `specs/` holds the specification and plan this release is built from
  (`010-gateway-api-group`, `012-compose-quickstart`) and, for the earlier
  features, their `contracts/` and `fixtures/`: wire contracts and test
  inputs that shipped code and the CI gates read. The rest of the working
  record for those features is not in this repository.
- The genesis verification record's header line keeps its absolute path.
  It is quoted as a record, and editing a record to make it tidier is the
  one thing this project does not do.
