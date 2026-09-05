# Contract: Recurse MCP Hub Registry

**Modules**: `Recurse.Runtime.Hub.Registry` + `Recurse.Runtime.Hub.IntakeWorkflow` + `Recurse.Runtime.Hub.TrustDial` + `Recurse.Runtime.Hub.CveResponseWorker`
**Phase**: 6 (MCP Hub)

## Purpose

Attested, curated registry of MCP servers customers can pull from. Each entry: versioned image, attested SBOM (consumed from Spec B at integration time), Recurse-vouched DSSE predicate, CVE feed status, lifecycle stage. Per-tenant trust dial controls which sources of MCP servers are pullable.

## API surface

```elixir
defmodule Recurse.Runtime.Hub.Registry do
  @doc "Admit a new MCP server to the Hub."
  @spec admit_entry(server_name, server_version, image_uri, sbom_digest, vouched_predicate) ::
          {:ok, %McpHubEntry{}} | {:error, term()}

  @doc "List entries the tenant can pull (filtered by trust dial)."
  @spec list_for_tenant(tenant_id) :: [%McpHubEntry{}]

  @doc "Look up an entry by name + version. Returns full record + image fetch info."
  @spec get_entry(server_name, server_version) :: {:ok, %McpHubEntry{}} | {:error, :not_found}

  @doc "Mark an entry deprecated (no immediate takedown; warns rolled tenants)."
  @spec deprecate_entry(server_name, server_version, reason) :: :ok | {:error, term()}

  @doc "Take down an entry (CVE critical no-patch, etc.). Affected tenants notified."
  @spec takedown_entry(server_name, server_version, reason) :: :ok | {:error, term()}

  @doc "Record that a tenant pulled a Hub entry. Used for CVE fan-out."
  @spec record_pull(tenant_id, server_name, server_version, developer_id, opts) :: :ok
end

defmodule Recurse.Runtime.Hub.TrustDial do
  @type setting :: :recurse_vouched_only | :recurse_vouched_plus_customer_approved | :any_with_attested_sbom

  @doc "Get the tenant's current trust dial setting."
  @spec get(tenant_id) :: setting()

  @doc "Update tenant's trust dial. Cedar-policy-gated by tenant_admin role. Emits trust_dial_changed predicate."
  @spec set(tenant_id, setting, principal) :: :ok | {:error, :unauthorized | term()}

  @doc "Check whether tenant can pull a specific entry under current dial."
  @spec can_pull?(tenant_id, %McpHubEntry{}) :: boolean()
end

defmodule Recurse.Runtime.Hub.IntakeWorkflow do
  @doc "File an intake request for a new MCP server. Customer-facing endpoint on the vendor's own site."
  @spec file_request(tenant_id, requestor_principal, server_name, image_uri, business_justification) ::
          {:ok, %McpHubIntakeRequest{}} | {:error, term()}

  @doc "Triage state transition: filed → in_review → approved/rejected/expired."
  @spec triage(request_id, new_state, opts) :: {:ok, %McpHubIntakeRequest{}} | {:error, term()}
end

defmodule Recurse.Runtime.Hub.CveResponseWorker do
  use Oban.Worker, queue: :hub_cve_response, max_attempts: 5

  @doc "Periodic poll of CveAdvisoryProvider; fan-out flagged entries to affected tenants."
  @impl true
  def perform(%Oban.Job{args: %{"trigger" => "scheduled_poll"}}) do
    # 1. CveAdvisoryProvider.fetch_advisories_since(last_poll_at)
    # 2. For each advisory: match against mcp_hub_entries by ecosystem + package + version
    # 3. For each affected entry: query mcp_hub_pulls for tenants pulling that version
    # 4. For each affected tenant: emit cve_advisory_processed predicate; if customer policy allows auto-roll AND patched_versions exists, advance the tenant's pull to the patched version
    # 5. If no patched version exists AND severity = critical: emit hub_entry_takedown predicate, notify customer
  end
end
```

## Trust dial enforcement

At MCP intercept entry (Phase 3) AND at MCP server hosting spawn (Phase 4):

1. Resolve `server_name` to a Hub entry
2. Call `TrustDial.can_pull?(tenant_id, entry)` — boolean
3. If false: reject with structured error (logged + attested as failed pull)
4. If true: proceed

For `recurse_vouched_plus_customer_approved`, the `customer_approved_pulls` list is consulted as a fallback when the entry is not Recurse-vouched.

For `any_with_attested_sbom`, the entry MUST have a non-NULL `sbom_digest` (proof that an attested SBOM exists).

## CVE response flow

```
[scheduled poll fires every N minutes]
        ↓
[CveAdvisoryProvider.fetch_advisories_since(last_poll_at)]
        ↓
[for each advisory: match against mcp_hub_entries]
        ↓
[for each affected entry:]
        ↓
        [update entry.cve_status]
        ↓
        [query mcp_hub_pulls for affected tenants]
        ↓
        [emit cve_advisory_processed predicate per affected tenant]
        ↓
        [if patched_versions exists:]
                [for each tenant with auto_roll_to_latest=true: advance their pull to patched version]
                [for each tenant with auto_roll=false: notify via tenant admin alert]
        ↓
        [if no patched_versions AND severity=critical:]
                [takedown_entry: lifecycle_stage = takedown]
                [emit hub_entry_takedown predicate]
                [notify all affected tenants — they MUST manually pin a deprecated version with explicit policy override OR remove the dependency]
```

## Customer intake workflow

```
[customer admin files request via the vendor's own site]
        ↓ (filed)
[Recurse triage queue: SBOM scan, license check, security review]
        ↓
        ↙          ↘
   (in_review) → (approved) → admit_entry: create mcp_hub_entries row + Recurse-vouched predicate
                              ↓
                              entry visible in tenant's Hub catalog
   (in_review) → (rejected) → notify customer with rejection_reason
   (filed) → (expired) → after N days with no triage activity, mark expired
```

## Tests required

**Contract**:
- Full Hub round-trip: admit → list → detail → record pull → takedown
- Trust dial enforcement: every cross-trust-level pull is denied
- CVE fan-out: simulated advisory entering feed → affected tenants flagged within 5min (per SC-006)
- Auto-roll fires only for tenants opted in
- Intake workflow state transitions are valid

**Property tests**:
- Trust dial decisions are deterministic for any (tenant, entry) combination
- CVE fan-out: count of `cve_advisory_processed` predicates equals count of affected tenants

**Integration**:
- Stand up the Hub starter set (5 entries: github, linear, datadog, slack, gitlab)
- Tenant pulls each → record_pull row
- Simulate a CVE on `github` entry → all pulling tenants flagged + (if opted in) auto-rolled

## Constitution alignment

- **Principle I** (Air-Gap Native): CVE fan-out via `CveAdvisoryProvider` (Provider Interface) — connected, air-gapped, sovereign all supported via different impls.
- **Principle III**: every Hub action (admit, takedown, pull, CVE-process, trust-dial-change) emits a predicate.
- **Principle IV**: Hub artifacts (image, SBOM, vouched predicate) live in S3; registry rows reference by digest only.
- **Principle V**: NEW `CveAdvisoryProvider` PI introduced (Constitution v1.5.0 amendment); USES existing `StorageProvider` for artifact storage.
- **Principle VII**: Trust dial enforcement is the SECOND consumer of Cedar policy gating beyond capability execution; the gating logic is consolidated into a single helper rather than re-implemented at intercept + hosting + hub layers.
