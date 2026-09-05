# What a receipt proves

For a reader receiving evidence from the standalone gateway. First identify the format: the authoritative kernel admission chain and the legacy enterprise audit projection have different records and verifiers.

## Kernel admission evidence

The gateway signs a request with its delegated fold key. Kernel admission validates it, applies the policy with jurisdiction, and records its decision durably. The supported proxy requires that decision before sending a model request or releasing executable tool bytes.

A ToolCall admission records the gateway's observed intent and the permission to release it. It does not independently establish that the client executed the tool, that an external side effect succeeded, or that no other activity occurred outside the proxy. Client identity fields extracted from traffic are observations, distinct from the signing key and its authority.

Core's offline verifier checks the exported chain, checkpoint, signatures, authority, referenced objects and policy-evidence bindings. It does not execute Cedar to prove that the recorded decision follows from the policy. A bundled public key verifies a signature; the reader still decides which key to trust. Read the report's complete `checked`, `findings`, Kind scopes and `not checked` blocks together.

The [fold evidence guide](fold-evidence.md) explains export and separate verification.

## Response evidence

For a completed supported response, the parser records the tool intents it recognized and the gateway retains the response bytes within its mandatory evidence limit. Parser failure and unsupported executable content fail closed; an empty tool list by itself is not proof of complete parsing.

Interrupted traffic may leave only a captured response prefix. A connection failure before a response leaves no Completion artifact. Completion denotes retained response bytes and must be interpreted with the LlmResponse outcome and error kind; partial bytes do not establish success.

The request and response hashes cover the captured bytes without JSON canonicalization. Canonicalization applies to structured signed records. Mandatory request evidence is retained before execution; exceeding the configured limit refuses the work. Legacy retention preferences cannot disable that boundary.

## Legacy audit projection

The audit console displays enterprise ledger receipts. Each contains a signed envelope and a referenced canonical predicate, with model/provider coordinates, observed client claims, parser observations, hashes, tool decisions and admission references. A tool denial also produces a child receipt.

The aggregate's single policy hash identifies the opening model admission. Tool receipts bind their own policy versions, which may differ after a cutover. The ledger is a projection; its availability or successful verification does not replace kernel admission.

The older export is a zip containing its envelope, predicate, available payloads, key, Merkle proofs and archived policy source. Its verifier checks those bindings; it does not read a kernel export. See the [legacy verification walkthrough](auditor/verification_walkthrough.md) for that format's result labels and exit codes.

## Scope

The [execution inventory](release/execution-surfaces.md) states which routes are governed, unavailable, or outside model/tool execution. It also records transport capture limits and the boot-time, process-produced nature of engine measurements. These descriptors are not independent attestation of a running process.
