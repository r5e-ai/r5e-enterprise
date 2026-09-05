# Contributing to r5e-enterprise

r5e-enterprise is licensed AGPL-3.0-only. r5e Inc. also offers it under commercial terms; that is
what the contributor agreement makes possible. Contributions are accepted under two things:

- the Developer Certificate of Origin — sign every commit with `git commit -s`; and
- the r5e Contributor License Agreement in `CLA.md` — agreed once. You keep your copyright;
  the agreement lets r5e Inc. distribute your contribution under AGPL and under other terms.
  Read it, send the completed signature form privately to
  <thomas@runr5e.ai>, and open a merge
  request adding a line to `CLA-SIGNERS.md` (account, version, text hash, date). A maintainer
  countersigns. Nothing personal goes into public history.

A CI job checks both on every merge request and tells you exactly what is missing and the
command that fixes it.

Every source file you add carries an SPDX header on its first comment line:
`SPDX-License-Identifier: AGPL-3.0-only`. Most existing files do not have one — the licence is
stated once in `LICENSE.md` and in each `mix.exs` rather than stamped onto every file — so a
header is required on new files only.

How a change is reviewed. A maintainer reviews it, and one independent reviewer (a person or
a model that did not write it) attacks it under two lenses: literally, for technical claims;
for intended purpose, for the charter's principles. Tests and vectors that pin the change
land with it; a claim in a README that the code does not support is a defect. Recurse's own
admission pipeline will carry contributions once the project's release chain is public; this
file will say when that changes.

Where to start: `docs/` for the reader-facing pages; `docs/release/execution-surfaces.md`
for the known, documented limits of this release; issues labelled `good-first` once they exist.

Issues, questions, and forks are welcome without any of the above.
