# Deliverable K — Policy Bundle Distribution Contract

**Source FRs**: FR-039 (policy bundle distribution + canonical AST hash +
Cedar version pin), FR-052 (air-gap policy bundle distribution path).
Related: FR-021 (attestation fields referencing `policy_canonical_hash`),
FR-046 (constitutional-grade durability pattern this contract borrows from),
FR-049 (Playground + Discovery-to-Policy flows that write bundles).
**Cedar engine**: committed per Constitution v1.3.0 Principle V; pinned version
in `apps/recurse_shared/priv/test_fixtures/cedar_stability/cedar_version.txt`.

This contract specifies **how Cedar policy bundles move from authoring to
production**, across the three online deployment shapes (Managed SaaS, VPC
Runner, Standalone Gateway) AND the offline shape (Air-Gapped Appliance).
One Provider Interface — `PolicyProvider` — covers both paths behind the same
set of callbacks; the online/offline distinction is a capability flag.

---

## 1. Bundle format

A Cedar policy bundle is a **content-addressable archive** containing:

1. One or more `*.cedar` policy source files.
2. A manifest (`manifest.json`) enumerating the included files, their
   relative paths, and a SHA-256 per file.
3. The bundle-level `cedar_version` pin (must match the Gateway's pinned
   Cedar version exactly — mismatch is a hard-fail at load).

The bundle's **distribution-time identity** is its **OCI digest** (SHA-256 of
the OCI manifest). The bundle's **evaluation-time identity** is its
**`policy_canonical_hash`** — `SHA-256(JCS(PolicySet::to_json()))` per
FR-039, computed by `Recurse.Cedar.canonical_hash/1` (the T042 NIF). The two
digests differ: the OCI digest covers bytes-on-the-wire; the canonical hash
is invariant to whitespace/comments/key-ordering and is what attestations
reference.

Both identities appear in every attestation:
- `policy_bundle_digest` — OCI digest of the bundle that produced the
  evaluation (bytes-on-the-wire provenance).
- `policy_canonical_hash` — canonical AST hash (semantics-stable identity).

Attestation schema field references live in
`contracts/attestation.schema.json` per FR-021.

---

## 2. Online distribution — OCI Artifacts

**Media type**: `application/vnd.cedar.policy.v1`.
**Source**: Phase-1 research recommendation 1 (OCI Artifacts for policy bundle
distribution — industry-standard, ECR/GHCR/Harbor-compatible, mature tooling).

### Push (publish)

Authoring side (typically the Governance Plane's `publish` flow per FR-049):

1. `PolicyProvider.publish/2` receives the new bundle (raw bytes + Cedar
   source files).
2. Provider serializes the manifest, wraps as OCI, pushes to the configured
   registry (per Tier Configuration `policy_registry_url`).
3. Provider computes the OCI digest (`sha256:...`) — this is the new
   bundle's distribution-time identity.
4. Provider returns `{ok, %{digest: digest, canonical_hash: hash}}`.

### Pull (fetch)

Enforcement side (Gateway policy cache):

1. On startup or on supersede notification, `PolicyProvider.fetch_active_bundle/1`
   is called.
2. Provider reads the registry tag `active` (or equivalent), resolves to a
   digest, pulls bytes.
3. Provider returns `{ok, %{digest, bytes, canonical_hash}}`.
4. Gateway's policy cache stores the parsed `PolicySet` indexed by both
   `digest` (for supersede tracking) and `canonical_hash` (for attestation
   emission).

For receipt verification (auditor flow), old bundles must remain retrievable
by digest — see §4 (old-bundle retention) below.

### Supersede semantics

OCI registries are immutable at the digest level; a supersede is the
promotion of a new digest to the `active` tag. Supersede notification
mechanics:

- **Webhook**: OCI registry pushes to
  `PolicyProvider`'s configured webhook URL (where supported — ECR, Harbor,
  GHCR all support webhooks). Gateway's provider subscribes via
  `subscribe_supersede_notifications/2` and re-fetches on event receipt.
- **Poll**: fallback for registries without webhooks. Gateway provider polls
  the `active` tag every 60s (configurable); digest change triggers re-fetch.
- **Manual SIGHUP**: operator can force a reload via admin endpoint or
  SIGHUP signal.

Hot-swap is atomic: Gateway loads the new bundle in parallel, swaps the
active reference under a single lock, then releases the old bundle's
in-memory `PolicySet`. In-flight evaluations that started under the old
bundle continue under the old bundle (evaluation is synchronous and fast;
no long-running state to migrate).

---

## 3. Offline distribution — signed manifest (FR-052)

For Air-Gapped Appliance deployments without a reachable OCI registry,
`PolicyProvider` MUST support an offline distribution path.

### Install-time bundle

The Appliance binary ships pre-loaded with a baseline policy bundle in
`/var/lib/recurse/policies/bundles/<digest>/`. This satisfies the zero-network
first-boot case.

### Update drop

Updates arrive as **signed manifest files** (USB-droppable, or via the
customer's existing offline update channel — `scp`, signed-email, whatever
the customer's operational pattern supports).

A signed manifest is a DSSE envelope (see §3.1) whose payload is a JSON
document of shape:

```json
{
  "predicateType": "application/vnd.recurse.policy-bundle-manifest.v1",
  "predicate": {
    "bundle_digest": "sha256:def456...",
    "canonical_hash": "44ea666a2c953505b19b2f197d9128f9c4914149cd7a94f6db06833171cb5542",
    "cedar_version": "4.9.1",
    "issued_at": "2026-04-22T12:00:00Z",
    "bundle_bytes_path": "bundles/def456.tar.gz",
    "bundle_bytes_sha256": "abc789..."
  }
}
```

The manifest file itself is delivered alongside the bundle bytes (a tarball
at `bundles/<digest>.tar.gz`). `PolicyProvider` watches the drop directory
(fs-watch or periodic scan); on new manifest:

1. Parse the DSSE envelope.
2. Verify the signature against the customer-provided trust root (configured
   at install time — `/etc/recurse/policy_trust_root.pem` or equivalent).
3. Verify the bundle bytes SHA-256 matches `bundle_bytes_sha256`.
4. Verify `cedar_version` matches the Appliance's pinned Cedar version;
   mismatch fails the update.
5. Atomically swap the `active` symlink to the new bundle directory.
6. Retain the old bundle (§4).

### 3.1 Why DSSE over PGP / Sigstore-Bundle

The v1.0 attestation format (FR-021) is DSSE + in-toto predicate. Reusing
DSSE here means:

- **One verification library** across attestations AND policy bundles — the
  auditor's off-platform verifier doesn't need two signing toolchains.
- **Customer-provided trust root is a simple x509 or JWK** — the same
  key-format surface the customer already manages for the Gateway's
  document-signing key per FR-046.
- **PAE encoding** (Pre-Authenticated Encoding) mitigates
  signature-substitution attacks across both surfaces.

Alternatives considered:

| Format             | Rejected because                                                                 |
|--------------------|----------------------------------------------------------------------------------|
| PGP / OpenPGP      | Separate trust model, separate tooling, no industry supply-chain momentum.        |
| Raw detached X.509 | No payload-type binding; risk of misinterpretation between payload kinds.         |
| Sigstore Bundle    | Adds Rekor-transparency requirement — incompatible with air-gap (no public log). |

DSSE is a neutral wire format — it's what Sigstore Bundles wrap, but we use
bare DSSE here because the Rekor log isn't available offline. If the customer
also runs an internal transparency log, they can layer Sigstore Bundle on top
as a Phase-2 option.

---

## 4. Old-bundle retention (constitutional-grade durability)

Per FR-052 and FR-046-analog: **old bundles MUST remain retrievable for
receipt verification, even after supersede.**

### Why

A receipt issued at time T0 carries `policy_canonical_hash` = `h0`. An
auditor verifying that receipt at T0+1 year needs to retrieve the bundle
that produced `h0` to replay the Cedar evaluation. If the bundle was garbage
collected at supersede, the receipt is unverifiable — this breaks the
long-horizon non-repudiation contract.

### Retention guarantees

- **Online path (OCI)**: bundles are retained for the lifetime of the
  Recurse deployment. OCI digests are immutable; deletion of a digest is
  forbidden by `PolicyProvider` policy and enforced at the registry level
  via retention rules (e.g., ECR `image-tag-mutability: IMMUTABLE`, Harbor
  retention policies).
- **Offline path (Appliance)**: bundle directories are never deleted by
  `PolicyProvider`. Disk-space operator procedures are documented in
  operator runbooks (Feature 003+); they copy bundles to cold storage before
  removing from the Appliance's active directory, with a cold-storage manifest
  the provider reads on retrieval miss.

### Retrieval API

`PolicyProvider.fetch_bundle/2` takes a digest and returns the bundle bytes
+ canonical hash. This is the receipt-verification entry point:

1. Auditor loads the Export Evidence zip (per FR-048 surface 2, Deliverable J).
2. The zip contains the attestation's `policy_bundle_digest`.
3. Auditor calls the Audit Plane's public verification endpoint (or pulls
   from the `policy_bundle/<digest>.tar.gz` included in the zip — Export
   Evidence bundles include the policy bundle specifically to make verification
   possible disconnected).
4. Auditor replays the Cedar evaluation locally; expected canonical hash
   matches `policy_canonical_hash` in the receipt.

---

## 5. PolicyProvider operations (summary)

Full Elixir signatures live in
`contracts/provider_interfaces/policy_provider.ex`. This section summarizes the
callbacks relevant to this contract.

| Callback                                | Purpose                                                                                                 |
|-----------------------------------------|---------------------------------------------------------------------------------------------------------|
| `fetch_active_bundle/1`                 | Gateway startup + supersede trigger. Returns current bundle digest + bytes + canonical hash.            |
| `fetch_bundle/2`                        | Retrieve a specific historical bundle by digest. Backs receipt verification.                            |
| `subscribe_supersede_notifications/2`   | Subscribe to supersede events. Push via webhook (online) or fs-watch (offline).                         |
| `simulate/3`                            | Cedar Playground evaluation (FR-049 surface 1).                                                         |
| `blast_radius/4`                        | Historical replay against candidate policy (FR-049 surface 3).                                          |
| `propose_from_event/2`                  | Discovery-to-Policy proposal from a flagged event (FR-049 surface 2).                                   |
| `capabilities/1`                        | Capability flags: `:oci_distribution`, `:offline_signed_manifest`, `:supersede_notifications`, `:simulation`, `:blast_radius`, `:propose_from_event`. |
| `healthcheck/1`                         | Provider liveness. Feeds `/healthz`.                                                                    |

### Reference implementations (Feature 002+)

- `OciPolicyProvider` — pulls from OCI registries (ECR, GHCR, Harbor, Quay).
  Capabilities: `[:oci_distribution, :supersede_notifications, :simulation,
  :blast_radius, :propose_from_event]`.
- `OfflineSignedPolicyProvider` — accepts manifest-driven offline bundle drops.
  Capabilities: `[:offline_signed_manifest, :supersede_notifications, :simulation,
  :blast_radius, :propose_from_event]`. (`:supersede_notifications` flips to
  fs-watch backing rather than webhook.)

Both providers share an in-memory `PolicySet` cache keyed by `canonical_hash`
to service receipt verification without re-parsing on every hit.

---

## 6. `publish` capability — not a Phase-1 Provider-Interface callback

The FR-049 UI surfaces (Playground + Discovery-to-Policy) describe a
"Publish" button that pushes new bundles. **The publish operation is NOT a
`PolicyProvider` callback in v1.0.**

Rationale:

- The authoring side (Governance Plane) and the enforcement side (Gateway
  policy cache) both implement `PolicyProvider` as readers; only the
  authoring side needs publish.
- Different deployment shapes publish via different paths: Managed SaaS
  publishes via `docker push` against the managed ECR; VPC Runner publishes
  via customer's own registry; Appliance publishes via the offline signed
  manifest drop path.
- Pre-allocating a single `publish/2` callback would bake in a uniform
  publish protocol we don't yet have operational data to design — the same
  principle as FR-051 (deleted in v6.1 per `feedback_no_premature_metaapi.md`).

Phase-1 publish runs through deployment-shape-specific flows documented in
the Governance Plane admin guide (Feature 003+). When the publish path
stabilizes in Phase-2, a `publish/2` callback will be added to
`PolicyProvider` at that time with signatures informed by real publish
implementations.

---

## 7. Cross-references

- `policy_author_ux.md` — Deliverable P (the three FR-049 surfaces).
- `policy_author_ux_examples/wiz_pattern_walkthrough.md` — SC-019 worked example.
- `contracts/provider_interfaces/policy_provider.ex` — the behaviour.
- `contracts/attestation.schema.json` — where `policy_bundle_digest` and
  `policy_canonical_hash` appear in the signed predicate.
- `apps/recurse_shared/priv/test_fixtures/cedar_stability/` — Cedar version
  pin + stability fixture; any bundle push under a mismatched Cedar version
  is rejected per §2.
- `apps/recurse_shared/priv/policy_templates/` — starter templates that feed
  initial bundle publishes (T084).
