# Contract: SbomBindingPredicate

**Module**: `Recurse.Shared.Sbom.BindingPredicate` (struct) + `Recurse.Gateway.Sbom.BindingEmitter` (emitter)
**Owner phase**: Phase 1 (struct), Phase 5 (emitter)
**Consumed by**: Phase 5 (Hub admit bridge), Phase 6 (UI), Spec A's Hub (bridge consumer)

## Purpose

Attest "binary X has SBOM Y, attested by source Z" with a single predicate shape across three signing sources (customer / Recurse-managed / vendor). An auditor verifies any source's binding via the same predicate-verify code path (different signing material per `attested_by`).

## Predicate shape (DSSE-wrapped)

The predicate's inner statement (the in-toto attestation):

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "predicateType": "https://recurse.r5e.io/sbom-binding/v1",
  "subject": [{
    "name": "<binary_identity>",
    "digest": {"sha256": "<binary_oci_or_purl_digest>"}
  }],
  "predicate": {
    "sbom_digest": "<sbom_digest_hex>",
    "sbom_spec_version": "1.5",
    "arch": "amd64",
    "attested_by": "customer | recurse_managed | vendor",
    "attested_by_subject": "<spiffe-id-or-cosign-uri>",
    "binding_emitted_at": "<rfc3339-timestamp>",
    "tenant_id": <integer>
  }
}
```

The DSSE envelope (or Sigstore Bundle for `vendor`) wraps the statement with the appropriate signature material per source. (See R-004.)

## Public API (BindingEmitter)

```elixir
@spec emit(
        %{
          tenant_id: integer(),
          sbom_publication: SbomPublication.t(),
          attested_by: :customer | :recurse_managed | :vendor,
          attested_by_subject: String.t(),
          signature_material: signature_material()
        }
      ) :: {:ok, BindingPredicate.t()} | {:error, atom()}

@type signature_material ::
        {:dsse_envelope, binary()}              # for :customer (customer-signed bytes)
      | :sign_with_recurse_kms                  # for :recurse_managed (we sign internally)
      | {:sigstore_bundle, binary()}            # for :vendor (Sigstore Bundle)
```

The emitter:

1. Validates the source matches the caller's identity (Cedar-gated)
2. Constructs the in-toto statement per the schema above
3. For `:customer`: verifies the provided DSSE envelope against the customer's `IdentityProvider` SVID
4. For `:recurse_managed`: signs via the existing KMS-backed DSSE path (`Recurse.Shared.Attestation.DsseSign.sign_with_kms/2`)
5. For `:vendor`: verifies the Sigstore Bundle against embedded cert chain + Rekor entry (offline-verifiable)
6. Inserts `SbomBindingPredicate` row + emits `sbom_binding_attested` event-kind signed predicate (linked via `signed_predicate_run_id`)

## Public API (BindingPredicate struct + verify)

```elixir
@spec by_id(tenant_id :: String.t()                       # ULID per F002 convention, id :: integer()) ::
        {:ok, t()} | {:error, :not_found}

@spec list_for_publication(tenant_id :: String.t()                       # ULID per F002 convention, sbom_publication_id :: integer()) :: [t()]

@spec verify(t()) ::
        {:ok, %{verified_at: DateTime.t(), source: atom(), subject: String.t()}}
      | {:error, %{reason: atom(), details: map()}}
```

`verify/1` returns the verification outcome by re-checking the signature material:

- For `:customer` and `:recurse_managed`: DSSE envelope verified against the public key of `attested_by_subject` (resolved via `IdentityProvider`)
- For `:vendor`: Sigstore Bundle verified against embedded cert + Rekor entry (no network call required for offline-bundle verification)

The result is also written back to the row (`verified_at`, `verification_status`).

## Invariants

- **I-001**: A single SBOM publication CAN have multiple binding predicates with different `attested_by` values. The customer + Recurse + vendor can all attest the same SBOM independently.
- **I-002**: A given `(sbom_publication_id, attested_by, attested_by_subject)` triple is unique — re-emitting from the same source for the same SBOM is idempotent.
- **I-003**: `verify/1` is pure — re-running on the same row yields the same verification outcome (assuming signing key hasn't been revoked).
- **I-004**: `attested_by = :customer` with `attested_by_subject` not matching the calling principal's SPIFFE ID is REJECTED at emit time (Cedar deny).
- **I-005**: `attested_by = :recurse_managed` requires the caller principal to have the `hub_admin` or `platform_operator` role — only Recurse-side principals can emit Recurse-managed bindings.
- **I-006**: `attested_by = :vendor` requires the caller to provide a complete Sigstore Bundle (cert chain + Rekor entry). The emitter does NOT contact Sigstore servers; verification is offline-only.

## Test contracts

- **CT-001**: Customer-source binding round-trip — customer signs DSSE envelope with their KMS, emit succeeds, `verify/1` returns `:ok`.
- **CT-002**: Recurse-managed binding round-trip — caller is `hub_admin`, emitter signs internally, `verify/1` returns `:ok`.
- **CT-003**: Vendor-source binding round-trip — Sigstore Bundle from a known fixture (e.g., a published Anthropic MCP server image), emit succeeds, `verify/1` returns `:ok` with offline verification.
- **CT-004**: Three sources for the same SBOM — emit customer, Recurse-managed, and vendor bindings in sequence; all three rows persist; `list_for_publication/2` returns all three.
- **CT-005**: Tampered envelope — modify the DSSE payload after emit; `verify/1` returns `{:error, %{reason: :signature_mismatch, ...}}`.

## Property tests

- **PT-001**: Verifier-trust equivalence: for the same SBOM, three valid bindings from different sources produce verification material that an auditor with public verification keys can independently verify to the same correctness conclusion (the SBOM's digest hashes the body the same way regardless of who attested it).
- **PT-002**: Cedar-deny invariant: a customer principal cannot emit a `:recurse_managed` binding (StreamData gen of (caller_role, attested_by) tuples; assert appropriate Cedar denials).
- **PT-003**: Subject-faithful: the predicate's `attested_by` ALWAYS matches the actual signer of the inner DSSE/cosign signature (no source-impersonation surface).

## Failure modes

| Error | Trigger | Handling |
|-------|---------|----------|
| `:cedar_denied` | Caller principal not authorized for the requested `attested_by` source | Return `{:error, :cedar_denied}`; emit `sbom_binding_attested` predicate with `outcome: :rejected`, no row created |
| `:signature_mismatch` | DSSE envelope or Sigstore Bundle signature fails verification | Return `{:error, _}`; predicate-emit-with-rejected-outcome |
| `:invalid_envelope_format` | DSSE envelope is malformed or Sigstore Bundle is incomplete | Same |
| `:no_such_publication` | `sbom_publication_id` doesn't exist for tenant | Same |
| `:duplicate_binding` | `(sbom_publication_id, attested_by, attested_by_subject)` already exists | Return `{:ok, existing_binding}` (idempotent); emit predicate with `outcome: :already_existed` |
| `:rekor_proof_invalid` | `:vendor` source: Rekor inclusion proof in Sigstore Bundle fails offline verification | Return `{:error, _}` |

## Sigstore Bundle (vendor) verification details

Per R-004, vendor-source bindings use Sigstore Bundle (offline-verifiable Sigstore format). Verification:

1. Parse Bundle: extract `verification_material` (cert chain, Rekor entry, tlog inclusion proof) and `dsseEnvelope`
2. Verify the cert chain against the embedded Sigstore root (offline)
3. Verify the Rekor inclusion proof using the embedded log checkpoint (offline)
4. Verify the DSSE signature against the cert's public key
5. If all four pass: emit binding with `verification_status: :verified`

The `cosign` Rust crate or equivalent Elixir/Erlang impl handles steps 1–4. We do NOT shell out to the `cosign` CLI binary on hot path; verification is in-process.

## Lockstep notes

`sbom_binding_attested` is added as a new event-kind in this spec. Lockstep updates:

- `apps/recurse_shared/lib/recurse_shared/attestation/signed_predicate.ex` `@event_kinds`
- `apps/recurse_gateway/lib/recurse_gateway/admin/browser_auth/ui_receipts.ex` `@allowed_event_kinds`
- DB CHECK migration `20260506000006_event_kinds_sbom_ingested_and_binding_attested.exs`

All in the same MR (Principle VII).

## Dependencies

- `jose` — DSSE signing/verifying (existing)
- `ex_aws_kms` — KMS-backed signing for `:recurse_managed` source (existing)
- `Recurse.Providers.IdentityProvider` — for resolving `attested_by_subject` to public key material (existing)
- `:cosign_ex` (NEW) — Sigstore Bundle parsing and offline verification. If no mature Hex.pm impl exists, we wrap a Rust crate via Rustler. Decision deferred to Phase 5 implementation; flag as research in research.md Q-A.
