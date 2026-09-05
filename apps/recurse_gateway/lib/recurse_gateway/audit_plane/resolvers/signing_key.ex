defmodule Recurse.Gateway.AuditPlane.Resolvers.SigningKey do
  @moduledoc """
  Pure archive lookup for the public-key PEM that verifies an
  attestation's DSSE signature, given the attestation's
  `(kms_key_id, key_version)` pair.

  ## Why this module exists (Issue #29 / Constitution Principle VII)

  Before this module landed, FOUR consumers had their own version of
  the archive query:

    * `EvidenceZipBuilder.fetch_signing_key/2` (lines 175-201) —
      archive lookup + a 2-tier fallback (live SecretsProvider, then
      broker PEM at `:internal_jwt.signing_key_path` for
      `observed://...` synthetic signers).
    * `LocalVerifyHandler.fetch_signing_key_pem/2` (lines 576-590) —
      archive only; no fallback, fail-hard.
    * `ReceiptsHandler.fetch_signing_key_pem/1` (lines 677-692) —
      archive only; nil-punning return.
    * The held MR !30 fix would have been a fourth — same archive
      query plus the same fallback chain copied from
      `EvidenceZipBuilder`.

  Three different error policies, four different implementations of
  the same Ecto query. The s4 survey flagged this as the Principle-VII
  smoking gun.

  ## Scope discipline (per s4 survey finding)

  This module implements ONLY the archive lookup. The fallback chain
  (live KMS provider, broker PEM) is **consumer-specific resilience
  policy** and lives either in each caller's wrapper or in the sibling
  `Recurse.Gateway.AuditPlane.Resolvers.SigningKey.Fallback` module
  (see "Sibling: Fallback" below):

    * `EvidenceZipBuilder` keeps its 2-tier fallback (export needs to
      ship even if the archive is empty — operator UX); delegates the
      dispatch + I/O to `SigningKey.Fallback`.
    * `LocalVerifyHandler` falls back to `SigningKey.Fallback` so
      observed-tier receipts (whose synthetic `observed://` signer
      never appears in the archive) verify against the broker's local
      PEM. Re-landed in F7 after MR !31 inadvertently dropped it.
    * `ReceiptsHandler` returns nil/empty signature_present indicator
      (decoration only — nothing to verify against in the list view;
      MUST stay archive-only to avoid broker-PEM file I/O per row).

  Bundling the fallback into this module would force every caller into
  the same resilience policy, which is wrong (specifically, it would
  pull `ReceiptsHandler` into broker-PEM file I/O on every list-row
  decoration). The fallback chain is extracted into a separate sibling
  module so its two callers (`EvidenceZipBuilder` + `LocalVerifyHandler`)
  share the dispatch shape without imposing it on `ReceiptsHandler`.

  ## Sibling: Fallback

  See `Recurse.Gateway.AuditPlane.Resolvers.SigningKey.Fallback` for
  the source-of-truth fallback resolution (`observed://` synthetic
  signers via broker local PEM; real KMS ARNs via
  `SecretsProvider.public_key/2`).

  ## Iron Law

  Pure module. No process. Runs on the request process.

  ## Return shape

  Includes a `source` discriminator (`:archive` only — this module
  doesn't fall back) so callers that wrap with their own fallback can
  thread the source through to audit-trail emitters. See the
  charter's "preserve provenance" requirement.
  """

  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.SigningKey
  alias Recurse.Providers.Repo

  import Ecto.Query, only: [from: 2]

  require Logger

  @type source :: :archive

  @doc """
  Look up the signing-key PEM for `(kms_key_id, key_version)` from the
  `signing_keys` archive (single-row read, indexed-unique).

  Returns:
    * `{:ok, pem, :archive}` on hit.
    * `{:error, :not_found}` on miss OR on any rescued failure
      (rescue path emits a `Logger.warning` — the caller's wrapper
      decides whether to escalate or fall back).
  """
  @spec fetch_from_archive(kms_key_id :: String.t(), key_version :: String.t()) ::
          {:ok, public_key_pem :: binary(), source()}
          | {:error, :not_found}
  def fetch_from_archive(kms_key_id, key_version) do
    case fetch_record_from_archive(kms_key_id, key_version) do
      {:ok, %{public_key_pem: pem}, :archive} -> {:ok, pem, :archive}
      {:error, :not_found} = miss -> miss
    end
  end

  @typedoc "The archive row fields a verifier needs: the PEM and what it signs with."
  @type record :: %{public_key_pem: binary(), algorithm: atom() | nil}

  @doc """
  Like `fetch_from_archive/2`, but also returns the archived `algorithm`
  (`:ecdsa_p256` / `:ed25519` / `:rsa_pss_2048`, per the
  `signing_keys` enum) so a verifier can dispatch on it instead of
  assuming ES256. Same single-row query; `fetch_from_archive/2` is a
  projection of this.
  """
  @spec fetch_record_from_archive(kms_key_id :: String.t(), key_version :: String.t()) ::
          {:ok, record(), source()} | {:error, :not_found}
  def fetch_record_from_archive(kms_key_id, key_version)
      when is_binary(kms_key_id) and is_binary(key_version) do
    query =
      from(sk in SigningKey,
        where: sk.kms_key_id == ^kms_key_id and sk.key_version == ^key_version,
        select: %{public_key_pem: sk.public_key_pem, algorithm: sk.algorithm},
        limit: 1
      )

    case Repo.one(query) do
      %{public_key_pem: pem} = record when is_binary(pem) -> {:ok, record, :archive}
      _ -> {:error, :not_found}
    end
  rescue
    err ->
      Logger.warning(fn ->
        "SigningKeyResolver archive lookup raised: " <>
          "#{inspect(err)} (kms_key_id=#{inspect(kms_key_id)}, " <>
          "key_version=#{inspect(key_version)})"
      end)

      {:error, :not_found}
  end

  def fetch_record_from_archive(_, _), do: {:error, :not_found}
end
