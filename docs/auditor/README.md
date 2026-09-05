# Auditor documentation

For an auditor handed an evidence export zip who needs a pass or fail verdict on a machine with no access to the gateway that produced it.

| Page | Answers |
|---|---|
| [Verification walkthrough](verification_walkthrough.md) | how to run `recurse-verify`, what each step checks, the exit codes, and what to look at on a failure |
| [What a receipt proves](../what-a-receipt-proves.md) | what the signed envelope and the predicate body commit to, and what they do not |

`recurse-verify` and `verify-bundled-merkle` in this directory are the verifier. `bin/r5e evidence export` at the repository root produces a zip to run them on.
