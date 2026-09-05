# Contract: F002 Provider Interface Reference Implementations

**Feature**: F002 | **Spec**: FRs 012–020 | **Constitution**: Principle V | **Research**: D1, D5

This contract defines the seven concrete implementations of F001's Provider Interface behaviours that land in F002. Each impl lives under `apps/recurse_providers/lib/recurse_providers/impls/`. Business logic in `apps/recurse_gateway/` and `apps/recurse_broker/` MUST NOT import any vendor SDK named below — all calls go through the behaviours. The `Recurse.Credo.ProviderNeutrality` check enforces this at PR time.

---

## `OpenAiLlmProvider` — `LLMProvider`

**Module**: `Recurse.Providers.Impls.OpenAiLlmProvider`

**Satisfies**: F001 `Recurse.Providers.LlmProvider` behaviour (`complete/1` for sync, `stream/2` for SSE).

**Configuration** (via Tier Configuration YAML):
```yaml
llm_provider:
  kind: openai
  base_url: https://api.openai.com/v1    # configurable for OpenAI-compatible endpoints
  api_key_ref: secrets://openai_api_key    # resolved via SecretsProvider
  timeout_ms: 30000
  finch_pool: :openai_pool
  http2: true
```

**Deps**: `req ~> 0.5` (transitively `finch ~> 0.18`).

**Hot-path implementation** (per research D3):
- Sync: `Req.post!(base_url <> "/chat/completions", json: request, headers: [...], finch: :openai_pool)` → parse JSON → return upstream body.
- Stream: `Req.post!(url, json: request, headers: [...], finch: :openai_pool, into: fn {:data, chunk}, acc -> ...  end)` — the `:into` callback is invoked synchronously in the caller process for each chunk; the caller (Gateway SseProxy) passes each chunk to the downstream client via `Plug.Conn.chunk/2` AND accumulates `delta.content` for reassembly.

**Failure semantics**:
- Upstream 5xx → return `{:upstream_error, status, body, headers}` — Gateway surfaces as FR-016b pass-through.
- Timeout → `{:upstream_error, :timeout, nil, []}`.
- Connection failure → `{:upstream_error, :connection, reason, []}`.

**Property tests**: none unique (exercises through Gateway integration tests against a mocked OpenAI endpoint); contract test via Mox verifies behaviour conformance.

---

## `PostgresMerkleLedger` — `LedgerProvider`

**Module**: `Recurse.Providers.Impls.PostgresMerkleLedger`

**Satisfies**: F001 `Recurse.Providers.LedgerProvider` behaviour — exact callback list per the behaviour source (NOT the names originally listed in this contract):
- `init/1`, `capabilities/1`, `healthcheck/1`, `terminate/2` — lifecycle.
- `commit_epoch/4(state, session_id, epoch_index, epoch_root)` — narrow: given a PRE-COMPUTED epoch root, append to the global tree.
- `inclusion_proof/3`, `consistency_proof/3`, `current_root/1` — RFC 9162-shaped proof + root queries.

**Additionally exposes as PUBLIC MODULE-LEVEL methods** (NOT behaviour callbacks, per the AD-001 c' precedent — both public methods and behaviour callbacks coexist on the same module; F001's behaviour surface is unchanged; the rich entry points are callable directly by Gateway code):
- `commit_attestation(envelope, opts \\ []) :: {:ok, %{run_id, verification_level, session_chain_root, global_inclusion_proof}} | {:error, reason}` — the full 10-step rich commit flow for F002's per-traversal attestation path. Delegates internally to `commit_epoch/4` for the global-append step so callbacks and public method share one implementation of the global-tree walk.
- `query_by_run_id/1` — Audit Plane basic query.
- `force_commit_for_run_ids(run_ids, opts)` — F002 FR-017 on-demand commit for `/v1/audit/export`.

**Why this split**: F001's behaviour was designed around "append a pre-computed root to the global tree" — minimal surface, portable across backends (Trillian, Postgres-Merkle). F002 needs a richer entry point (full envelope → leaf hash → per-session Merkle writes → attestation row → verification_level advancement → PubSub broadcast). Adding those to the behaviour would force every alternative provider to implement them; keeping them as Postgres-Merkle-specific public methods preserves Principle V neutrality. Alternative providers that don't need the rich path stick to `commit_epoch/4`; callers that need the rich path call the public method directly.

**Configuration**:
```yaml
ledger_provider:
  kind: postgres_merkle
  database_url_ref: secrets://database_url
  interim_commit_event_count: 10000      # F001 FR-037 default
  interim_commit_threshold_minutes: 60
```

**Deps**: `ecto_sql ~> 3.12`, `postgrex ~> 0.19`.

**Schemas**: see `data-model.md` — `attestations`, `session_epochs`, `global_ledger_entries`, `merkle_nodes`, `signing_keys`, `payload_outbox`.

**Commit flow** (hot path):
1. Insert `attestations` row (`verification_level: :signed`).
2. Insert leaf into `merkle_nodes` under `tree_id = "session_#{sid}_epoch_#{idx}"`.
3. Recompute + insert ancestor nodes up to epoch root.
4. Update `session_epochs.epoch_root`.
5. Update `attestations.verification_level = :local_inclusion_verified` + `session_chain_root`.
6. Publish `recurse:attestation_first_committed` on Phoenix.PubSub.
7. Under 1-run-1-session (F002): immediately trigger the epoch-close path → insert `global_ledger_entries` row → update `attestations.verification_level = :global_inclusion_verified`. Publishing happens once, at step 6 (not re-fired at step 7) per FR-024's "one SIEM event per attestation" rule.

All six commit-path DB mutations happen in a single `Ecto.Multi` / `SERIALIZABLE` transaction for atomicity.

**`force_commit_for_run_ids/2` flow** (AD-001 c'):
1. For each `run_id`, query current state.
2. If already `:global_inclusion_verified`, include in response as such (no-op).
3. Otherwise, close the session's current epoch in a `SERIALIZABLE` transaction, commit to `global_ledger_entries`, advance `verification_level` — return `:committed`.

Under 1-run-1-session, most run_ids will already be `:global_inclusion_verified` at export time; this method is mainly a safety net.

**Property test**: Surface R.

---

## `S3StorageProvider` — `StorageProvider`

**Module**: `Recurse.Providers.Impls.S3StorageProvider`

**Satisfies**: F001 `Recurse.Providers.StorageProvider` behaviour (`put/3`, `get/1`, `head/1`).

**Configuration**:
```yaml
storage_provider:
  kind: s3
  bucket: my-recurse-payloads
  region: us-east-1
  finch_pool: :s3_pool
  kms_encryption: true
  object_lock_compliance_days: 2555       # 7 years
  lifecycle_transitions:
    - to_storage_class: STANDARD_IA
      after_days: 30
    - to_storage_class: GLACIER_INSTANT_RETRIEVAL
      after_days: 365
```

**Deps**: `ex_aws ~> 2.6`, `ex_aws_s3 ~> 2.5` (HTTP client override to Finch).

**Key operations**:
- `put(run_id, payload_bytes, metadata)` — writes to `s3://<bucket>/tenants/<tid>/runs/<yyyymmdd>/<run_id>.json` per FR-019; enforces Object Lock retention header.
- `get(payload_uri)` — streams via `:body` stream for large payloads.
- `head(payload_uri)` — HEAD only; used by `recurse-verify` to confirm object exists without downloading.

**Failure semantics**: transient S3 errors surface `{:error, :transient, reason}` (caller retries via FR-032 outbox); permission errors surface `{:error, :permanent, reason}` (caller fails hard).

---

## `AwsKmsSecretsProvider` — `SecretsProvider`

**Module**: `Recurse.Providers.Impls.AwsKmsSecretsProvider`

**Satisfies**: F001 `Recurse.Providers.SecretsProvider` behaviour (`sign/2`, `get_public_key/1`, `describe_key/1`, `resolve_ref/1`).

**Configuration**:
```yaml
secrets_provider:
  kind: aws_kms
  key_arn: arn:aws:kms:us-east-1:123456789012:key/abcd-...
  algorithm: ECDSA_SHA_256           # per research D4 (ES256)
  region: us-east-1
  finch_pool: :kms_pool
  refs:                                  # non-signing secrets resolved via AWS Secrets Manager
    openai_api_key: arn:aws:secretsmanager:...
    database_url: arn:aws:secretsmanager:...
```

**Deps**: `ex_aws ~> 2.6`, `ex_aws_kms ~> 2.5`.

**Hot-path implementation** (per research D1): `ExAws.KMS.sign/3` called directly from the request-scoped Plug process — no GenServer gating. Retry per FR-034.

**Public key cache**: `:persistent_term` keyed by `{key_arn, key_version}`. Populated at Gateway boot via `ExAws.KMS.get_public_key/1` + on detected rotation (polling LoopServer, 60s interval per research D1).

---

## `StandaloneIdentityProvider` — `IdentityProvider` (no-op stub)

**Module**: `Recurse.Providers.Impls.StandaloneIdentityProvider`

**Satisfies**: F001 `Recurse.Providers.IdentityProvider` behaviour with no-op impl (Standalone has no Recurse-managed SPIFFE).

**Behaviour**:
- `fetch_svid/0` → `{:not_applicable, :standalone_gateway}` — documented return; callers in Standalone don't invoke this (netns path doesn't exist).
- `rotate_svid/0` → same.

**Purpose**: behaviour-conformant stub keeps Constitution Principle V invariants (every dependency fronted by a Provider Interface) intact; no dead code; no accidental SPIFFE-lookup from the Gateway.

---

## `JwtPrincipalProvider` — `PrincipalProvider`

**Module**: `Recurse.Providers.Impls.JwtPrincipalProvider`

**Satisfies**: F001 `Recurse.Providers.PrincipalProvider` behaviour (`validate_and_extract/1`).

**Behaviour**:
- `validate_and_extract(jwt_string)` — validates `X-Observed-Identity` JWT per F001 FR-017 + F002 FR-007 (via `Recurse.Gateway.Identity.JwtValidator`, which wraps `jose`), extracts the `principal` custom claim (FR-009 shape), returns `{:ok, %Recurse.Shared.Principal{...}}` or `{:error, reason}`.

**Integration**: Gateway's `IdentityContext.Builder` calls this at request ingress.

**Deps**: `jose ~> 1.11` (already in F001 tree).

**Property test**: Surface N.

---

## `FilesystemPolicyProvider` — `PolicyProvider`

**Module**: `Recurse.Providers.Impls.FilesystemPolicyProvider`

**Satisfies**: F001 `Recurse.Providers.PolicyProvider` behaviour (`load_bundle/1`, `canonical_hash/1`, `evaluate/3`).

**Configuration**:
```yaml
policy_provider:
  kind: filesystem
  bundle_path: /etc/recurse/policy/bundle.cedar
  entity_schema_path: /etc/recurse/cedar/schema.cedarschema.json
  reload_on_sighup: true
```

**Behaviour**:
- `load_bundle/1` — reads bundle file + entity-schema file; parses via Cedar NIF (F001 scaffold); returns `{:ok, %PolicyBundleRef{}}` or `{:error, :parse_failure, details}`.
- `canonical_hash/1` — passes through to F001's `Recurse.Cedar.Scaffold.canonical_hash/1`.
- `evaluate/3` — `evaluate(bundle_ref, entities, request)` invokes the NIF; returns `{:ok, :allow | :deny, matched_policies}`.

**Integration**: Gateway's `BundleLoader` GenServer owns the active `PolicyBundleRef`; handles SIGHUP reloads; provides per-request snapshots per FR-010.

**Property test**: Surface S.

---

## Summary: Provider-Interface Neutrality check surface

Running `mix credo --strict --check Recurse.Credo.ProviderNeutrality` MUST report 0 violations after F002 merge. The check's allowlist (from F001) grants:
- `Recurse.*` (first-party).
- `Ecto.*`, `Postgrex.*`, `ExAws.*`, `Jose.*`, `Req.*`, `Finch.*`, `Plug.*`, `Bandit.*`, `Phoenix.PubSub.*`, `StreamData.*`, `Mox.*` (approved framework primitives).

Vendor SDKs named in this contract (`ExAws.KMS`, `ExAws.S3`) are allowlisted only within `apps/recurse_providers/lib/recurse_providers/impls/` — anywhere else is a violation.
