# Admission storage and recovery

The standalone release keeps its admission log, content-addressed evidence,
origin and signing keys in the Compose `kernel` volume. Preserve that state
as one recovery unit. The enterprise database contains a separate ledger
projection; restoring that database does not restore kernel admission history.

Writable startup refuses a malformed log or missing/corrupt event payloads.
It also refuses a missing or empty log when a history marker, persisted origin
or content-addressed objects survive. The first durable append persists the
history marker before returning its acknowledgement. A fresh directory with
only a preprovisioned node key remains supported.

A missing node key is not generated over a nonempty log. Once a node has
endorsed a locally managed role, missing or substituted role keys cause
refusal. Bindings issued by a predecessor remain binding after legitimate
node succession. Automatically generating a new role key is only a first-use
operation; replacing an established role identity needs an explicit recovery
or rotation procedure, which this release does not automate.

After a refusal, keep the failed state for diagnosis and restore a consistent
backup. Do not remove the history marker, origin or evidence objects to make
the old identity boot with an empty log. A deliberately new data directory
starts a new history; it does not continue the old one.

Retain exported checkpoints outside the writer and use the core verifier's
`--prior` comparison when inspecting a later export. Local loss checks cannot
establish that a party controlling the whole filesystem preserved its state,
or detect a rollback that removes every local trace of later acknowledgements.
The [fold evidence guide](../fold-evidence.md) gives the export and comparison
commands and the report's evidence boundaries.

Validation: `test/history_identity_persistence_test.exs` and
`test/signer_persistence_test.exs` in the `r5e-kernel` repository of the
coordinated source distribution, and the release Compose restart/export smoke
(`scripts/smoke-release-compose.sh`).
