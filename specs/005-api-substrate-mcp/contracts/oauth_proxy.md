# Contract: OAuth Proxy + Token Vault

**Modules**: `Recurse.Gateway.OAuth.ProxyRouter` + `Recurse.Gateway.OAuth.FlowOrchestrator` + `Recurse.Runtime.OAuth.TokenVault` + `Recurse.Runtime.OAuth.TokenRefresher` + `Recurse.Runtime.OAuth.GrantLifecycle`
**Phase**: 5 (OAuth proxy)

## Purpose

Customer developers' first connection to an OAuth-requiring MCP server triggers a browser-based OAuth flow handled by Recurse. Resulting tokens stored KMS-encrypted in a per-(tenant, developer, service) vault. Refresh handled automatically. Cedar policy governs token minting (which principals can mint with which scopes).

## OAuth dance flow

```
[developer's MCP client invokes a tool requiring OAuth]
        ↓
[MCP intercept detects auth needed]
        ↓
[returns MCP error: {"code": -32602, "message": "Auth required", "data": {"oauth_initiate_url": "..."}}]
        ↓
[client opens oauth_initiate_url in browser]
        ↓
[FlowOrchestrator: generate state, store mint decision intent, redirect to upstream auth URL]
        ↓
[developer authenticates upstream + grants scopes]
        ↓
[upstream redirects to /v1/oauth/callback with code + state]
        ↓
[FlowOrchestrator: validate state, exchange code for tokens]
        ↓
[Cedar gate: principal × service × scopes_granted → allow/deny]
        ↓ allow
        ↓
[TokenVault: KMS-encrypt + store tokens]
        ↓
[emit oauth_grant_minted predicate]
        ↓
[FlowOrchestrator returns success page; client retries original tool call]
        ↓
[MCP intercept now finds vault entry, injects token, forwards to upstream]
```

## API surface

```elixir
defmodule Recurse.Gateway.OAuth.ProxyRouter do
  # Plug routes:
  # POST /v1/oauth/initiate   — start OAuth dance for (developer, service)
  # GET  /v1/oauth/callback   — upstream redirect target
  # POST /v1/oauth/revoke     — revoke a grant
  # GET  /v1/oauth/grants     — list grants (tenant-admin scoped)
end

defmodule Recurse.Runtime.OAuth.TokenVault do
  @doc "Store encrypted tokens for a (tenant, developer, service) tuple. Idempotent — replaces existing."
  @spec store(tenant_id, developer_id, service_id, tokens, ttl) :: :ok | {:error, term()}

  @doc "Retrieve tokens for injection. Decrypts on the customer's BEAM via per-tenant KMS CMK."
  @spec retrieve(tenant_id, developer_id, service_id) ::
          {:ok, %{access_token: String.t(), refresh_token: String.t() | nil, expires_at: DateTime.t()}}
          | {:error, :not_found | :revoked | :expired}

  @doc "Mark a grant revoked. Zero out token material; preserve grant metadata for audit."
  @spec revoke(tenant_id, developer_id, service_id, reason :: String.t()) :: :ok
end

defmodule Recurse.Runtime.OAuth.TokenRefresher do
  use Oban.Worker, queue: :oauth_refresh, max_attempts: 3
  # Periodically scans oauth_grants WHERE state = 'active' AND expires_at < now() + interval '5 minutes'
  # Refreshes tokens before expiry. Updates state machine.
end
```

## Per-service config (data, not behaviour)

Per-upstream-service OAuth config lives in `apps/recurse_providers/lib/recurse/providers/oauth/service_config.ex`:

```elixir
defmodule Recurse.Providers.OAuth.ServiceConfig do
  @services %{
    "github" => %{
      authorize_url: "https://github.com/login/oauth/authorize",
      token_url: "https://github.com/login/oauth/access_token",
      default_scopes: ["repo", "read:org"],
      strategy: Assent.Strategy.Github,
      client_id_env: "GITHUB_OAUTH_CLIENT_ID",
      client_secret_secrets_key: "github/oauth/client_secret"
    },
    "linear" => %{
      authorize_url: "https://linear.app/oauth/authorize",
      token_url: "https://api.linear.app/oauth/token",
      default_scopes: ["read", "write"],
      strategy: Assent.Strategy.OAuth2,
      client_id_env: "LINEAR_OAUTH_CLIENT_ID",
      client_secret_secrets_key: "linear/oauth/client_secret"
    },
    # ... datadog, slack, gitlab
  }

  def get(service_id), do: Map.fetch(@services, service_id)
  def list_services(), do: Map.keys(@services)
end
```

Client IDs come from env (per-tenant config); client secrets from existing `SecretsProvider`.

This is data, NOT a Provider Interface — the OAuth machinery itself is one implementation; the per-service config is parameters to that implementation.

## State machine

Per the OAuth grant state diagram (data-model.md Entity 7):

```
       initiate
          ↓
       [pending]
          ↓ token exchange success
          ↓ Cedar allow
       [active]
       ↙       ↘
[refreshing]  [expired]
   ↓             ↓
[active]      (re-auth required)
                 ↓
             [pending]
   ↓
[revoked] (terminal)

Any state → [error] (terminal, requires manual intervention)
```

State transitions are property-tested.

## Cedar policy at token-mint

Cedar resource path: `oauth_grant::<service_id>`
Cedar action: `mint`
Cedar context: `scopes_requested`, `principal`, `tenant_id`

Example policy:
```cedar
permit(
  principal in Group::"engineering",
  action == Action::"mint",
  resource is OauthGrant
) when {
  resource.service in ["github", "linear"]
};

forbid(
  principal,
  action == Action::"mint",
  resource is OauthGrant
) when {
  resource.service == "github" &&
  context.scopes_requested.contains("repo:write") &&
  !(principal in Group::"senior-engineering")
};
```

Mint decisions emit `oauth_token_mint_decision` predicate regardless of allow/deny — the substrate predicate per-op model.

## KMS encryption

- Per-tenant KMS CMK (existing F002 pattern)
- Envelope encryption: data key encrypts the token; data key is itself encrypted by the CMK
- Stored as `bytea` columns: `access_token_kms_blob`, `refresh_token_kms_blob`
- Decryption only happens on the customer's BEAM at injection time

## Tests required

**Contract**:
- Full OAuth dance for a known mock upstream service end-to-end
- Cedar deny at mint blocks token storage (no row in oauth_grants)
- Token refresh transparently rolls forward; developer not re-prompted
- Revoke marks state revoked; subsequent retrieve returns `{:error, :revoked}`

**Property tests**:
- OAuth state machine: every state has a defined exit; no token leaked through transitions; refresh during refresh is idempotent (mutex)
- Per-(tenant, developer, service) isolation: cross-tenant retrieve is impossible

**Integration**:
- GitHub OAuth flow against a sandbox app: token retrieved + stored + injected + refreshed + revoked

## Constitution alignment

- **Principle III**: every grant lifecycle event emits a predicate.
- **Principle IV** (Detached Payloads / Privacy-First): tokens are KMS-encrypted; deletion zeroes material; audit trail of grant decisions persists independently.
- **Principle V** (Provider-Interface Neutrality): NO new Provider Interface (per-service config is data); USES existing `SecretsProvider`.
- **Principle VI**: state machine property-tested.
