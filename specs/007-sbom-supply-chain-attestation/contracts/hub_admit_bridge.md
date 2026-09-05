# Contract: Hub Admit Bridge

**Module**: `Recurse.Gateway.Sbom.HubAdmitBridge`
**Owner phase**: Phase 5 (signing + bridge)
**Consumed by**: Spec A's `Recurse.Runtime.Hub.IntakeWorkflow` (Phase 6 of Spec A — Hub admit-entry)

## Purpose

The single point of contact between Spec A's Hub admit-entry workflow and Spec B's SBOM machinery. Per R-007, Spec A's Hub does NOT reach into Spec B's tables directly — all SBOM verification + ingest + binding goes through this one function call.

## Public API

```elixir
@spec admit_with_sbom(
        hub_entry :: %McpHubEntry{},
        sbom_doc :: binary(),
        signing_context :: signing_context()
      ) :: {:ok, %{sbom_digest: binary(), binding_predicate_id: integer()}}
         | {:error, atom() | %{reason: atom(), details: map()}}

@type signing_context :: %{
  attested_by: :customer | :recurse_managed | :vendor,
  attested_by_subject: String.t(),
  signature: signature_input()
}

@type signature_input ::
        {:dsse_envelope, binary()}              # for :customer
      | :sign_with_recurse_kms                  # for :recurse_managed
      | {:sigstore_bundle, binary()}            # for :vendor
```

## Algorithm

`admit_with_sbom/3` orchestrates:

1. **Cedar gate**: caller principal + `attested_by` → allow/deny (only `hub_admin` for `:recurse_managed`; etc.)
2. **Ingest**: call `Recurse.Gateway.Sbom.IngestPipeline.run/2` with `(sbom_doc, ingest_context)` → produces `{:ok, %SbomPublication{}}` or `{:error, _}`
3. **Bind**: call `Recurse.Gateway.Sbom.BindingEmitter.emit/1` with the publication + signing_context → produces `{:ok, %SbomBindingPredicate{}}` or `{:error, _}`
4. **Update Hub entry** (Spec A's responsibility AFTER this returns): caller updates `hub_entry.sbom_digest` from our return value

If step 2 OR step 3 fails, the WHOLE call fails atomically — no Hub entry is created, no partial state. (Spec A's caller decides what to surface; we just return structured errors.)

If step 2 returns `{:ok, _}` but the publication is a re-ingest (was already in DB), step 3 still runs — the same caller may bind a previously-ingested SBOM (e.g., second admin admitting the same MCP server with a new arch).

## Invariants

- **I-001**: `admit_with_sbom/3` is atomic — either both ingest+bind succeed (and a binding predicate exists) or neither succeeds (no row written, structured error returned).
- **I-002**: The function is idempotent at the binding level — calling it twice with the same `(sbom_digest, attested_by, attested_by_subject)` triple yields the same `binding_predicate_id` on both calls (no duplicate row).
- **I-003**: Cedar policy gate runs FIRST — if the caller is denied, neither ingest nor bind is attempted (no side effects).
- **I-004**: All errors are structured maps — `{:error, %{reason: :sbom_verification_failed, details: %{...}}}`. No bare exceptions.

## Test contracts

- **CT-001**: Happy path — `hub_admin` calls with valid customer-signed CycloneDX SBOM → `{:ok, %{sbom_digest: <bin>, binding_predicate_id: <int>}}`. Verify Hub entry can populate `sbom_digest` from this.
- **CT-002**: Failed verification — caller passes a malformed CycloneDX → `{:error, %{reason: :sbom_verification_failed, ...}}`. Verify NO publication row exists, NO binding row exists, Hub entry is NOT created (Spec A's caller doesn't proceed past this error).
- **CT-003**: Cedar deny — non-hub_admin caller attempts `:recurse_managed` source → `{:error, :cedar_denied}`. No side effects.
- **CT-004**: Re-bind — same SBOM, same caller, same source called twice → both calls return the same `binding_predicate_id`.
- **CT-005**: Multi-arch: same Hub entry, two arch SBOMs (amd64 + arm64) admit-with-sbom in sequence — both succeed, two distinct publication IDs, both binding predicate IDs returned to caller.

## Property tests

- **PT-001**: Atomicity: if ingest succeeds but bind fails (mock binding to fail), the publication row is rolled back via `Ecto.Multi` (no orphan publication).
- **PT-002**: Caller-source-faithful: the Cedar gate properly rejects mismatched (caller_role, attested_by) tuples.

## Failure modes (caller-actionable error categories)

| `error.reason` | Meaning | Spec A's Hub UI guidance |
|----------------|---------|--------------------------|
| `:cedar_denied` | Caller not authorized | "You are not authorized to admit MCP servers with this signing source." |
| `:sbom_verification_failed` | Parse / schema / signature failure | "The SBOM document could not be verified. Please check the signature and format." |
| `:sbom_size_exceeded` | Document larger than tenant cap | "The SBOM exceeds the configured size limit. Contact support to raise it." |
| `:sbom_already_bound_to_other_binary` | Trying to bind an SBOM digest to a different binary identity than its first binding | "This SBOM is already bound to a different binary." |
| `:duplicate_admit_pending` | Concurrent admit-with-sbom for the same Hub entry already in flight | "Another admin is currently admitting this entry. Please retry." |
| `:internal` | Unexpected error (bug — should never reach the caller) | "An internal error occurred. Please report to support." |

## Performance contracts

- **P-001**: `admit_with_sbom/3` p95 < 5s for a typical MCP server SBOM (10-100 components, 1-3 levels deep).
- **P-002**: For a re-admit (idempotent call), p95 < 1s (skips parse + persist, only re-emits the binding predicate idempotently).

## Spec A integration notes

Spec A's `Recurse.Runtime.Hub.IntakeWorkflow.admit_entry/2` will call `HubAdmitBridge.admit_with_sbom/3` somewhere in its admit pipeline. Spec A is responsible for:

- Constructing the `signing_context` from operator input (e.g., the admin chose "vendor-signed" + uploaded a Sigstore Bundle)
- Updating the `McpHubEntry` row's `sbom_digest` field on success
- Surfacing the error reason to the operator UI on failure
- Emitting any Hub-side-specific predicates (the `mcp_hub_admit_completed` event-kind from Spec A) that wrap the binding result

Spec B's bridge does NOT touch the Hub's tables. No coupling between Spec B and `mcp_hub_entries`.

## Dependencies

- `Recurse.Gateway.Sbom.IngestPipeline` — Phase 2
- `Recurse.Gateway.Sbom.BindingEmitter` — Phase 5
- Existing Cedar policy machinery
- Existing `Ecto.Multi` for atomicity
