# Developer Documentation

Entry points for engineers picking up work on Recurse Enterprise. The routes the release
exposes are listed in the [execution inventory](../release/execution-surfaces.md); the
system's shape is in [architecture](../architecture.md).

## Index

| Artifact | Purpose | Source task |
|---|---|---|
| [`../../specs/001-api-jido-foundations/contracts/openapi.yaml`](../../specs/001-api-jido-foundations/contracts/openapi.yaml) | The Feature 001 OpenAPI 3.1 artifact that `mix recurse.contracts.validate` checks. It describes the Feature 001 contract surface, not the routes this release serves; see the [execution inventory](../release/execution-surfaces.md) for those. | T049 |
| [`../../specs/001-api-jido-foundations/contracts/gateway_runtime_matrix.md`](../../specs/001-api-jido-foundations/contracts/gateway_runtime_matrix.md) | Where does a new subsystem live? Matrix answers it unambiguously per FR-035. | T069 |
| [`../../specs/001-api-jido-foundations/contracts/completeness_boundary.md`](../../specs/001-api-jido-foundations/contracts/completeness_boundary.md) | Per-protocol L3/L4/L7 accept/drop/attest matrix (FR-043). | T070 |
| [`../../specs/001-api-jido-foundations/contracts/failure_matrix.md`](../../specs/001-api-jido-foundations/contracts/failure_matrix.md) | Fail-open/closed per Provider Interface + ledger condition. Defaults fail-closed for security-affecting paths. | T071 |
| [`../../specs/001-api-jido-foundations/contracts/new_provider_checklist.md`](../../specs/001-api-jido-foundations/contracts/new_provider_checklist.md) | Code-review checklist enforcing FR-004 Provider-Interface Neutrality. Required pre-merge for any new provider impl. | T059 |
| [`../../specs/001-api-jido-foundations/contracts/byo_mtls_integration_matrix.md`](../../specs/001-api-jido-foundations/contracts/byo_mtls_integration_matrix.md) | Customer-agent integration paths per FR-045. Honest verdicts. | T060 |
| [`../../specs/001-api-jido-foundations/contracts/property_test_surface_catalog.md`](../../specs/001-api-jido-foundations/contracts/property_test_surface_catalog.md) | Catalog of property-test cases Feature 002+ MUST cover at minimum per SC-014 / Constitution Principle VI. | T090 |
| [`../../specs/001-api-jido-foundations/contracts/cedar_pin.md`](../../specs/001-api-jido-foundations/contracts/cedar_pin.md) | Three-component content-addressed Cedar pin (FR-039). Upgrade procedure. | T091 |

## Orientation paths

**"I just joined — where do I start?"**
1. [execution-surfaces.md](../release/execution-surfaces.md) — what the release exposes.
2. [architecture.md](../architecture.md) — how the pieces fit.
3. [gateway_runtime_matrix.md](../../specs/001-api-jido-foundations/contracts/gateway_runtime_matrix.md) — where things live.

**"I'm adding a new Provider impl"**
1. [new_provider_checklist.md](../../specs/001-api-jido-foundations/contracts/new_provider_checklist.md) — what's allowed, what's not.
2. [apps/recurse_providers/lib/recurse_providers/](../../apps/recurse_providers/lib/recurse_providers/) — the behaviours.
3. [apps/recurse_providers/test/contract/](../../apps/recurse_providers/test/contract/) — the Mox harness pattern.

**"I'm adding a new endpoint"**
1. [openapi.yaml](../../specs/001-api-jido-foundations/contracts/openapi.yaml) — start there; every existing endpoint is the template.
2. [gateway_runtime_matrix.md](../../specs/001-api-jido-foundations/contracts/gateway_runtime_matrix.md) — place the handler correctly.
3. [error_codes.md](../../specs/001-api-jido-foundations/contracts/error_codes.md) — use the canonical enum.
4. [streaming_policy_matrix.md](../../specs/001-api-jido-foundations/contracts/streaming_policy_matrix.md) — document the streaming kind.

**"I'm touching the attestation envelope"**
1. [attestation.schema.json](../../specs/001-api-jido-foundations/contracts/attestation.schema.json) — the split-envelope schema.
2. [attestation_examples/](../../specs/001-api-jido-foundations/contracts/attestation_examples/) — three worked examples.
3. [property_test_surface_catalog.md](../../specs/001-api-jido-foundations/contracts/property_test_surface_catalog.md) — surfaces A-D are your acceptance bar.
4. [apps/recurse_shared/lib/recurse_shared/attestation/](../../apps/recurse_shared/lib/recurse_shared/attestation/) — the code.

## Build + test

```bash
mix deps.get
mix compile --warnings-as-errors
mix test
mix credo --strict
mix recurse.cedar.stability_check
mix recurse.contracts.validate
```
