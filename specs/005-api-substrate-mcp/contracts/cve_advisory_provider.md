# Contract: CveAdvisoryProvider (NEW Provider Interface)

**Module**: `Recurse.Providers.CveAdvisory.Behaviour`
**Phase**: 6 (MCP Hub) — but Constitution v1.5.0 amendment required FIRST (separate spec)

## Purpose

Bring CVE advisory data into Recurse for Hub CVE response automation. Different deployment tiers have fundamentally different feed sources:

- **Connected** (Mode A managed SaaS, Mode B/C connected customer-hosted): GitHub Advisory Database (or Snyk, NVD, OSV) via REST API
- **Air-gapped** (Discovery + VPC Runner + Air-Gapped Appliance): offline JSON bundles dropped at a configured staging path (sneakernet)
- **Sovereign**: customer-managed advisory feed (e.g., a national CERT feed)

Same Provider Interface pattern as the existing 7 PIs: single behaviour, multiple implementations, swap via configuration without code change.

## Behaviour

```elixir
defmodule Recurse.Providers.CveAdvisory.Behaviour do
  @doc """
  Fetch advisories published since the given timestamp. Returns a list
  of advisories ordered by published_at ascending.

  Implementations MAY rate-limit and return partial results — caller
  is responsible for re-calling with the latest published_at to drain
  remaining advisories.
  """
  @callback fetch_advisories_since(timestamp :: DateTime.t()) ::
              {:ok, [advisory()]} | {:error, term()}

  @doc """
  Subscribe to real-time advisory deliveries. Returns a subscription
  reference. Implementations MAY return {:error, :not_supported} if
  real-time delivery is not available (e.g., offline bundle impl).
  """
  @callback subscribe_realtime(callback :: pid() | (advisory() -> any())) ::
              {:ok, subscription_ref()} | {:error, :not_supported}

  @doc """
  Cancel a real-time subscription. Idempotent.
  """
  @callback unsubscribe(subscription_ref()) :: :ok

  @type advisory :: %{
          id: String.t(),
          severity: :critical | :high | :medium | :low,
          published_at: DateTime.t(),
          affected: [%{
            ecosystem: String.t(),     # e.g. "npm", "pypi", "cargo"
            name: String.t(),          # e.g. "@modelcontextprotocol/server-github"
            versions: [String.t()]     # affected version specs (e.g. ["<1.4.3", "1.5.0-1.5.2"])
          }],
          patched_versions: [%{
            ecosystem: String.t(),
            name: String.t(),
            versions: [String.t()]
          }] | nil,                    # nil means no patch path exists
          summary: String.t(),
          references: [String.t()]     # URLs to advisory details
        }

  @type subscription_ref :: term()
end
```

## Implementations

### `Recurse.Providers.CveAdvisory.GithubAdvisoryDb`

Connected impl. Uses GitHub's `https://api.github.com/advisories` endpoint (REST). Polls periodically via Oban scheduled task; optionally subscribes to webhook deliveries for real-time.

Configuration:
```elixir
config :recurse_providers, :cve_advisory,
  impl: Recurse.Providers.CveAdvisory.GithubAdvisoryDb,
  poll_interval_seconds: 300,        # every 5 min
  github_token_env: "GITHUB_API_TOKEN"  # for higher rate limits
```

### `Recurse.Providers.CveAdvisory.OfflineBundle`

Air-gapped impl. Watches a staging path (e.g., `/var/lib/r5e/cve-bundles/`) for new JSON bundle files; ingests them. Customer ops manually deposits bundles via approved sneakernet path.

Configuration:
```elixir
config :recurse_providers, :cve_advisory,
  impl: Recurse.Providers.CveAdvisory.OfflineBundle,
  staging_path: "/var/lib/r5e/cve-bundles/",
  ingest_interval_seconds: 60        # check for new bundles every minute
```

### `Recurse.Providers.CveAdvisory.Mock`

Test impl. Mox-friendly. Used in unit + integration tests.

## Tests required

**Contract**:
- Each implementation's `fetch_advisories_since/1` returns valid `advisory()` shapes
- Each implementation's `subscribe_realtime/1` either delivers advisories OR returns `:not_supported`

**Property tests**:
- Advisory shape validation: every emitted advisory has all required fields with valid types
- Idempotent ingestion: re-fetching the same time window produces the same set of advisories

**Integration**:
- `GithubAdvisoryDb` against a sandbox GitHub Advisory feed
- `OfflineBundle` ingests a known bundle and emits the expected advisories
- `Mock` produces deterministic test data

## Constitution alignment

- **Principle I** (Air-Gap Native): a hardcoded GitHub feed would lock out air-gapped deployments. The Provider Interface enables them.
- **Principle V** (Provider-Interface Neutrality): brings PI count 7→8. Requires constitution v1.5.0 amendment (sibling spec).

## Constitution amendment dependency

This Provider Interface CANNOT land before the Constitution v1.5.0 amendment that adds it to the canonical 8-PI set. Amendment spec lives at `specs/006-constitution-amendment-cve-advisory-provider/` (sibling to this spec). Per amendment procedure: small spec, one PI added, no other principle altered, requires explicit human approval before merge.

Phase 6 (Hub CVE response) is the ONLY phase that depends on this Provider Interface. Phases 1-5 ship without it.
