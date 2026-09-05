# Contract: Token Vault (KMS-encrypted OAuth grant storage)

**Module**: `Recurse.Runtime.OAuth.TokenVault`
**Phase**: 5 (OAuth proxy)

## Purpose

Per-(tenant, developer, service) OAuth grant storage with KMS envelope encryption. Tokens are decrypted only at injection time on the customer's BEAM via the per-tenant CMK. Token revocation zeroes material; grant audit metadata persists independently.

This contract is the **storage primitive** for OAuth grants. The OAuth proxy (separate contract) is the **flow primitive** that USES this vault.

## API surface

```elixir
defmodule Recurse.Runtime.OAuth.TokenVault do
  @doc """
  Store encrypted tokens for a (tenant, developer, service) tuple.
  Idempotent — replaces existing grant entry. Triggers state transition
  to :active. KMS-encrypts via the tenant's CMK.
  """
  @spec store(
          tenant_id :: String.t(),
          developer_id :: String.t(),
          service_id :: String.t(),
          tokens :: %{
            access_token: String.t(),
            refresh_token: String.t() | nil,
            expires_at: DateTime.t() | nil
          },
          opts :: keyword()
        ) :: {:ok, %OauthGrant{}} | {:error, term()}

  @doc """
  Retrieve tokens for injection. Decrypts on the customer's BEAM.
  Updates last_used_at. Returns :revoked or :expired structured errors
  rather than masking with :not_found.
  """
  @spec retrieve(tenant_id, developer_id, service_id) ::
          {:ok, %{access_token: String.t(), refresh_token: String.t() | nil, expires_at: DateTime.t() | nil}}
          | {:error, :not_found | :revoked | :expired | :error_state}

  @doc """
  Mark a grant as :refreshing (mutex). Returns the current refresh_token
  for use by the caller. Transitions back to :active on success or
  :error on failure.
  """
  @spec begin_refresh(tenant_id, developer_id, service_id) ::
          {:ok, refresh_token :: String.t()} | {:error, :not_found | :already_refreshing}

  @doc """
  Complete a refresh — store new tokens, transition to :active.
  """
  @spec complete_refresh(tenant_id, developer_id, service_id, new_tokens) :: :ok

  @doc """
  Mark a grant revoked. Zero out token material; preserve grant
  metadata (state, scopes, timestamps) for audit. Idempotent.
  """
  @spec revoke(tenant_id, developer_id, service_id, reason :: String.t(), revoking_principal_id :: String.t()) :: :ok

  @doc """
  List grants for tenant admin UI. Returns metadata only — never
  exposes token material (KMS blobs not decrypted).
  """
  @spec list_for_tenant_admin(tenant_id) :: [
          %{
            developer_id: String.t(),
            service_id: String.t(),
            scopes_granted: [String.t()],
            state: atom(),
            granted_at: DateTime.t(),
            last_used_at: DateTime.t() | nil
          }
        ]
end
```

## KMS envelope encryption

```
For each token to store:
  1. Generate a random 256-bit AES data key
  2. AES-256-GCM-encrypt the token plaintext using the data key
  3. KMS-encrypt the data key using the tenant's CMK
  4. Concatenate: [encrypted_data_key_length][encrypted_data_key][nonce][ciphertext][auth_tag]
  5. Store the concatenated blob in oauth_grants.access_token_kms_blob (or refresh_token_kms_blob)

For each token to retrieve:
  1. Read the blob
  2. Parse: encrypted_data_key_length → encrypted_data_key, nonce, ciphertext, auth_tag
  3. KMS-decrypt the data key using the tenant's CMK
  4. AES-256-GCM-decrypt the token using the data key, nonce, auth_tag
  5. Return plaintext (held in memory only for the duration of one HTTP request)
```

KMS key rotation (annual, automatic for AWS KMS) doesn't affect existing blobs (KMS handles the key version transparently).

## Failure modes

| Failure | Behavior |
|---------|----------|
| KMS unavailable (AWS outage) | Retry with exponential backoff; if persistent, mark grant `:error` and surface to tenant admin |
| KMS access denied (IAM misconfigured) | Same as unavailable — surface to tenant admin |
| Decryption fails (corrupted blob) | Mark grant `:error`; surface to tenant admin; require re-auth |
| Refresh token expired upstream | TokenRefresher detects on refresh attempt; mark grant `:expired`; surface to developer agent on next request |
| Concurrent refresh attempts | `begin_refresh/3` uses DB row-level lock + state machine to prevent double-refresh |

## Tests required

**Contract**:
- Store + retrieve round-trip: tokens stored encrypted, retrieved decrypted, plaintext matches original
- Revoke zeros material: `oauth_grants.access_token_kms_blob` is NULL after revoke; metadata fields preserved
- `list_for_tenant_admin/1` never exposes token material

**Property tests**:
- Cross-tenant isolation: store as tenant A → retrieve as tenant B fails (KMS access denied at decryption)
- State machine: every transition is property-tested; no token leaks through transitions

**Integration**:
- Full end-to-end with AWS KMS: store, retrieve, revoke

## Constitution alignment

- **Principle III** (Cryptographic Provenance): `oauth_grant_minted/_refreshed/_revoked` predicates emitted by the OAuth proxy (separate contract) — vault is the storage primitive, the proxy is the operational layer.
- **Principle IV** (Detached Payloads / Privacy-First): tokens are encrypted at rest with per-tenant CMK; decryption only at injection time; revocation zeroes material.
- **Principle V** (Provider-Interface Neutrality): uses existing AWS KMS path via `ex_aws_kms`; no new vendor abstraction.
