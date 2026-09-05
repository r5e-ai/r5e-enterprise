defmodule Recurse.Gateway.AuditPlane.Resolvers.SigningKey.Fallback do
  @moduledoc """
  Source-of-truth fallback resolution for an attestation's signing-key
  PEM, used when the `signing_keys` archive lookup misses.

  ## Why this module exists (Issue #29 / Constitution Principle VII)

  Sibling resolver to `Recurse.Gateway.AuditPlane.Resolvers.SigningKey`,
  which is intentionally archive-only. The archive lookup is a single
  pure read; the **fallback chain** (live SecretsProvider) carries
  I/O, dispatch, and operator-UX concerns that the archive resolver
  explicitly declines to bundle (per its `@moduledoc` "Scope discipline"
  section).

  Two existing consumers had the same fallback shape:

    * `EvidenceZipBuilder.fetch_signing_key_via_provider/2` (in-tree
      since MR !28; provenance-tagged 3-tuple return for manifest
      audit-trail).
    * `LocalVerifyHandler.fetch_signing_key_pem_via_provider/2` (held
      in dangling commit c11a16c, lost in the MR !31 audit-pass
      refactor that extracted the archive resolver out of
      LocalVerifyHandler).

  Re-landing the LocalVerifyHandler fallback as a second inline copy
  would produce the third copy of the same dispatch shape. Constitution
  Principle VII forbids that. This module is the extraction; both
  consumers call into it.

  `ReceiptsHandler` deliberately does NOT call into here — its
  signing-key lookup is decoration-only on a list/detail view (per
  s4 finding) and must stay archive-only to avoid SecretsProvider
  round-trips per row. That asymmetry is the exact reason the
  fallback chain doesn't belong on the archive resolver itself.

  ## Dispatch

  Function-head pattern match on the `kms_key_id`:

    * `"observed://" <> _` — synthetic-marker signer stamped onto
      observed-tier attestations by the boot-time provider bootstrap
      (`Recurse.Gateway.Config.EnvProviderRegistry`, e.g.
      `"observed://gateway"`). The marker does NOT identify which
      key actually signed the receipt — the real signer is whatever
      key the configured `SecretsProvider.active_signing_key/1`
      currently advertises (verified live on audit-dev: a real KMS
      ARN under `runr5e-core-beam-signing`).

      Resolution: ask the SecretsProvider for its active signing
      key handle, then ask the same provider for that handle's
      public PEM. This is the same compose pattern used at attestation
      EMIT time in `Recurse.Gateway.Attestation.EnvelopeBuilder` —
      ensuring the PEM we verify against is byte-equivalent to the
      key whose private half signed.

    * any other (real KMS ARN) — call
      `SecretsProvider.public_key/2` via `ProviderRegistry` directly.
      The provider implementation handles its own caching (e.g. lazy
      KMS `GetPublicKey` + `:persistent_term`).

  ## Why broker JWT PEM is NOT the answer for observed:// (F7 trilogy)

  An earlier F7 fix tried to resolve the `observed://` synthetic
  marker by reading `:internal_jwt.signing_key_path` (the broker's
  OIDC/JWT signing key). That key has nothing to do with attestation
  signing — receipts are signed by whatever key
  `SecretsProvider.active_signing_key/1` returns at envelope-build
  time. On audit-dev that's the AWS KMS alias
  `runr5e-core-beam-signing`. Loading the broker JWT PEM produced a
  well-formed verify against the WRONG public key →
  `:signature_mismatch`. Fix: ask the SecretsProvider, not the
  broker. (See trilogy: MR !60 sibling extraction, MR !62 DSSE DER
  acceptance, this MR for the actual signer lookup.)

  ## Return shape

  Returns `{:ok, pem, source}` on success where `source` is one of:

    * `:provider` — fetched via `SecretsProvider.public_key/2`.
      The same atom is used for both the real-KMS-ARN arm and the
      observed:// arm because BOTH ultimately resolve through the
      provider — the only difference is whether the handle came
      from the attestation row (real ARN) or from
      `active_signing_key/1` (synthetic marker case).

  or `{:error, :not_found}` on miss / I/O failure.

  Source provenance threads through `EvidenceZipBuilder`'s manifest
  emission so auditors can see the PEM came from a SecretsProvider
  round-trip rather than the immutable archive.

  ## Iron Law

  Pure module. No process. Runs on the request process.
  """

  alias Recurse.Gateway.ProviderRegistry

  require Logger

  @type source :: :provider

  @doc """
  Resolve the signing-key PEM via the source-of-truth fallback chain.

  See `@moduledoc` for the dispatch + return-shape contract.
  """
  @spec fetch(kms_key_id :: String.t(), key_version :: String.t()) ::
          {:ok, public_key_pem :: binary(), source()} | {:error, :not_found}
  def fetch("observed://" <> _ = kms_key_id, key_version)
      when is_binary(key_version) do
    fetch_active_signing_key_public_pem(kms_key_id, key_version)
  end

  def fetch(kms_key_id, key_version)
      when is_binary(kms_key_id) and is_binary(key_version) do
    fetch_kms_public_key(kms_key_id, key_version)
  end

  def fetch(_, _), do: {:error, :not_found}

  # ---------------------------------------------------------------------------
  # Dispatch arms
  # ---------------------------------------------------------------------------

  defp fetch_kms_public_key(kms_key_id, key_version) do
    {mod, state} = ProviderRegistry.secrets_provider()

    case mod.public_key(state, %{key_id: kms_key_id, key_version: key_version}) do
      {:ok, pem} when is_binary(pem) ->
        {:ok, pem, :provider}

      {:ok, malformed} ->
        Logger.warning(fn ->
          "SigningKey.Fallback got non-binary :ok PEM from secrets provider: " <>
            "#{inspect(malformed)} " <>
            "(kms_key_id=#{inspect(kms_key_id)}, key_version=#{inspect(key_version)})"
        end)

        {:error, :not_found}

      {:error, reason} ->
        Logger.warning(fn ->
          "SigningKey.Fallback kms public_key fetch failed: #{inspect(reason)} " <>
            "(kms_key_id=#{inspect(kms_key_id)}, key_version=#{inspect(key_version)})"
        end)

        {:error, :not_found}
    end
  end

  # The `observed://` synthetic-marker arm. The marker is opaque
  # provenance (which deployment stamped it), NOT a key reference —
  # the actual signer is whatever `SecretsProvider.active_signing_key/1`
  # currently returns. Compose: get the active handle, then resolve
  # its public PEM through the same provider.
  defp fetch_active_signing_key_public_pem(kms_key_id, key_version) do
    {mod, state} = ProviderRegistry.secrets_provider()

    with {:ok, handle} <- active_signing_key(mod, state, kms_key_id, key_version),
         {:ok, pem} <- public_key(mod, state, handle, kms_key_id, key_version) do
      {:ok, pem, :provider}
    end
  end

  defp active_signing_key(mod, state, kms_key_id, key_version) do
    case mod.active_signing_key(state) do
      {:ok, %{key_id: _, key_version: _} = handle} ->
        {:ok, handle}

      {:ok, malformed} ->
        Logger.warning(fn ->
          "SigningKey.Fallback got malformed handle from active_signing_key: " <>
            "#{inspect(malformed)} " <>
            "(observed_marker=#{inspect(kms_key_id)}, " <>
            "attestation_key_version=#{inspect(key_version)})"
        end)

        {:error, :not_found}

      {:error, reason} ->
        Logger.warning(fn ->
          "SigningKey.Fallback active_signing_key fetch failed: #{inspect(reason)} " <>
            "(observed_marker=#{inspect(kms_key_id)}, " <>
            "attestation_key_version=#{inspect(key_version)})"
        end)

        {:error, :not_found}
    end
  end

  defp public_key(mod, state, handle, kms_key_id, key_version) do
    case mod.public_key(state, handle) do
      {:ok, pem} when is_binary(pem) ->
        {:ok, pem}

      {:ok, malformed} ->
        Logger.warning(fn ->
          "SigningKey.Fallback got non-binary :ok PEM from secrets provider: " <>
            "#{inspect(malformed)} " <>
            "(observed_marker=#{inspect(kms_key_id)}, " <>
            "active_handle=#{inspect(handle)}, " <>
            "attestation_key_version=#{inspect(key_version)})"
        end)

        {:error, :not_found}

      {:error, reason} ->
        Logger.warning(fn ->
          "SigningKey.Fallback observed:// public_key fetch failed: " <>
            "#{inspect(reason)} " <>
            "(observed_marker=#{inspect(kms_key_id)}, " <>
            "active_handle=#{inspect(handle)}, " <>
            "attestation_key_version=#{inspect(key_version)})"
        end)

        {:error, :not_found}
    end
  end
end
