defmodule Recurse.Providers.StorageProvider do
  @moduledoc """
  Provider Interface — StorageProvider.

  Spec source: FR-003. Stores **detached payloads** per Constitution Principle IV (the
  ledger NEVER stores payloads; this interface does). Customer-controlled storage —
  S3, Splunk HEC, MinIO, or equivalent — so payloads can be deleted (GDPR Article 17 / DSA Right-to-be-Forgotten)
  without breaking the ledger's audit chain.

  Reference implementations:
  - `S3Storage` — AWS S3 (Managed SaaS reference per `gtm_sequencing.md`)
  - `SplunkHECStorage` — Splunk HTTP Event Collector
  - `MinIOStorage` — on-prem S3-compatible object store (Air-Gapped Appliance reference)
  """

  alias Recurse.Shared.IdentityContext

  @type config :: map()
  @type state :: term()
  @type payload_uri :: String.t()
  @type payload_hash :: binary()

  @callback init(config) :: {:ok, state} | {:error, term()}

  @doc """
  Store a detached payload. Returns a URI that the Audit Payload Broker (FR-030)
  uses to retrieve the payload, and the SHA-256 hash that goes into the attestation
  envelope's `payload_hash` field (FR-021).

  The IdentityContext is used for tenancy scoping at storage time.
  """
  @callback put_payload(state, payload :: binary(), IdentityContext.t()) ::
              {:ok, %{uri: payload_uri, hash: payload_hash}} | {:error, term()}

  @doc """
  Retrieve a detached payload by URI. Used by the Audit Payload Broker (FR-030).

  The IdentityContext represents the auditor's identity; the broker authorizes via Cedar
  before invoking this, so impls MAY skip auth checks (defense-in-depth recommended).
  """
  @callback get_payload(state, payload_uri, IdentityContext.t()) ::
              {:ok, binary()} | {:error, term()}

  @doc """
  Delete a payload. Supports GDPR Article 17 / DSA Right-to-be-Forgotten.

  Constitutional contract: deletion MUST NOT break the ledger or other receipts. The
  ledger holds only the hash; deleting the payload makes future hash-comparison impossible
  for THIS payload but does not invalidate the receipt's signature or inclusion proofs.
  """
  @callback delete_payload(state, payload_uri, IdentityContext.t()) :: :ok | {:error, term()}

  @callback capabilities(state) :: [:put | :get | :delete | :streaming | :versioned]

  @callback healthcheck(state) :: :ok | {:degraded, term()} | {:down, term()}

  @callback terminate(state, term()) :: :ok
end
