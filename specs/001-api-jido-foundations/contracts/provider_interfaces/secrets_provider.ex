defmodule Recurse.Providers.SecretsProvider do
  @moduledoc """
  Provider Interface — SecretsProvider.

  Spec source: FR-003. Two distinct responsibilities (intentionally co-located in one interface
  because both involve a secret-management backend like KMS/Vault):

  1. **Long-lived document-signing key release** per FR-046 — Gateway authenticates with its
     transport SVID, gets a long-lived (quarterly-rotated) signing key for receipt envelopes.

  2. **Downstream-service credential cache for RFC 8693 token exchange** per FR-047 —
     stores user OIDC tokens mathematically linked to agent SPIFFE IDs; mints downstream-scoped
     OBO tokens for injection into MCP-server upstream calls.

  Reference implementations:
  - `VaultSecrets` — HashiCorp Vault
  - `KmsSecrets` — AWS KMS (Managed SaaS reference)
  - `LocalHsmSecrets` — bundled HSM-equivalent (Air-Gapped Appliance reference)

  **No Phase-2-forward-compat hooks for intent-aware JIT minting** are pre-allocated.
  When that capability ships in Phase 2, this interface will be extended with concrete
  signatures informed by Phase-2 implementation experience (FR-051 DELETED in v6.1 per
  `feedback_no_premature_metaapi.md`).
  """

  alias Recurse.Shared.IdentityContext

  @type config :: map()
  @type state :: term()

  @type signing_key_handle :: %{
          key_id: String.t(),
          key_version: non_neg_integer(),
          algorithm: :ed25519 | :ecdsa_p256 | :rsa_pss_2048
        }

  @type oidc_token :: String.t()
  @type downstream_service_id :: String.t()
  @type scoped_token :: %{
          token: String.t(),
          expires_at: DateTime.t(),
          scope: [String.t()]
        }

  @callback init(config) :: {:ok, state} | {:error, term()}

  # --- Document-signing key release (FR-046) ---

  @doc """
  Get the current active signing key for this Gateway tenant. Used at attestation-emit time.

  The Gateway authenticates to the SecretsProvider using its transport SVID; the SecretsProvider
  returns a handle to a long-lived signing key (NOT the key material itself — signing happens
  via the impl's `sign/3` callback, which keeps key material in KMS).
  """
  @callback active_signing_key(state) :: {:ok, signing_key_handle} | {:error, term()}

  @doc """
  Sign a payload using the specified key. Key material never leaves the SecretsProvider backend
  (KMS-backed implementations); the signing operation happens in KMS.
  """
  @callback sign(state, signing_key_handle, payload :: binary()) ::
              {:ok, signature :: binary()} | {:error, term()}

  @doc """
  Get the public key for an archived signing key. Used by the audit broker to populate
  Evidence Zip exports (FR-046 / FR-048) so offline auditors can verify historical receipts.
  """
  @callback public_key(state, signing_key_handle) :: {:ok, public_key_pem :: String.t()} | {:error, term()}

  # --- Downstream credential cache (FR-047) ---

  @doc """
  Store a user's OIDC token mathematically linked to the agent's SPIFFE ID.
  Called when an agent session is spawned (Runtime side); the token is then available
  to the Gateway for RFC 8693 token exchange when the agent makes downstream calls.
  """
  @callback store_user_token(state, IdentityContext.t(), oidc_token, ttl_seconds :: pos_integer()) ::
              :ok | {:error, term()}

  @doc """
  Mint a downstream-service-scoped OBO token via RFC 8693 exchange.
  The Gateway invokes this just before injecting `Authorization: Bearer` into the MCP-server
  upstream call to a downstream service (Jira, Confluence, etc.).
  Token never returns to the agent — Gateway/MCP-server boundary only.
  """
  @callback exchange_for_downstream_token(
              state,
              IdentityContext.t(),
              downstream_service_id,
              requested_scope :: [String.t()]
            ) :: {:ok, scoped_token} | {:error, term()}

  @callback capabilities(state) :: [
              :sign | :public_key_export | :token_exchange | :user_token_storage | :hsm_backed
            ]

  @callback healthcheck(state) :: :ok | {:degraded, term()} | {:down, term()}

  @callback terminate(state, term()) :: :ok
end
