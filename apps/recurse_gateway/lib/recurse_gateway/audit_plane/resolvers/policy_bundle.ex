defmodule Recurse.Gateway.AuditPlane.Resolvers.PolicyBundle do
  @moduledoc """
  Resolves the Cedar bundle bytes that produced an attestation's policy
  decision, given the receipt's `policy_canonical_hash`.

  ## Why this module exists (Issue #29 / Constitution Principle VII)

  Two consumers carry their own (subtly different) implementations:

    * `EvidenceZipBuilder.fetch_policy_bundle/2` (lines 282-322) —
      raw-SQL archive lookup against `policy_bundles` table → fall back
      to `Active.current/0` with hash-drift warning. Returns
      `{:ok, bytes}` or error tuple.

    * `LocalVerifyHandler.check_policy_against_bundle/1` (lines
      445-477) — calls `Active.current/0` directly, compares against
      TWO canonicalization rules (the JCS canonical hash AND a
      SHA-256-of-bytes fallback for F002 backward-compat). Doesn't
      query the archive.

  Future consumers (any new endpoint that wants to render the policy
  active when a receipt was emitted) would reproduce the chain. This
  module is the single source.

  ## Two functions

    * `resolve/1` — returns the bundle bytes for a given canonical
      hash, with `source` discriminator (`:archive | :loader_match |
      :loader_drift`). Used by the export path.

    * `match_against_bundle/2` — given a receipt's hash + a candidate
      bundle, runs both canonicalization rules and reports which one
      (if any) matches. Used by the verify-checklist path.

  Splitting keeps each function single-purpose.

  ## Iron Law

  Pure module. No process. The underlying `Active` reader is a
  `:persistent_term` lookup; the loaders that populate it are
  GenServers (filesystem `BundleLoader`, OCI `OciBundleManager`),
  but this module only reads via `Active.current/0`.
  """

  alias Recurse.Gateway.Policy.Active
  alias Recurse.Providers.Repo

  require Logger

  @type source :: :archive | :loader_match | :loader_drift

  @doc """
  Resolve the bundle for a `policy_canonical_hash`. Tries the
  `policy_bundles` archive first, falls back to `BundleLoader`'s
  in-memory cache.

  Returns:

    * `{:ok, bytes, :archive, hash}` — archive hit; `hash` equals input.
    * `{:ok, bytes, :loader_match, hash}` — archive miss, BundleLoader's
       canonical_hash matches input.
    * `{:ok, bytes, :loader_drift, current_hash}` — archive miss,
       BundleLoader has SOMETHING but its hash differs from the
       receipt's. Logs a warning. The `current_hash` is the loader's,
       not the receipt's — caller should record both for audit-trail.
    * `{:error, :not_found}` — neither archive nor loader has anything.

  The `:loader_drift` case is what MR !29 added (the bug where
  dogfood receipts referenced a hash neither the archive nor the
  current loader could match cleanly). We preserve that operational
  behavior — return SOMETHING rather than 500 — but track the drift
  via the source discriminator.
  """
  @spec resolve(policy_canonical_hash :: binary()) ::
          {:ok, bundle_bytes :: binary(), source(), resolved_hash :: binary()}
          | {:error, :not_found}
  def resolve(policy_canonical_hash) when is_binary(policy_canonical_hash) do
    case archive_lookup(policy_canonical_hash) do
      {:ok, bytes} -> {:ok, bytes, :archive, policy_canonical_hash}
      :miss -> loader_fallback(policy_canonical_hash)
    end
  end

  def resolve(_), do: {:error, :not_found}

  @doc """
  Given the receipt's canonical hash and a bundle (either fresh from
  the loader or fetched from the archive), check whether either
  canonicalization rule matches:

    1. `BundleLoader`'s canonical_hash equals the receipt's hash —
       this is the post-F002 JCS rule.
    2. SHA-256 of the raw bundle bytes equals the receipt's hash —
       this is the F002 backward-compat rule.

  Returns:

    * `{:ok, "BundleLoader canonical_hash via JCS(PolicySet::to_json())"}`
      on rule 1 match.
    * `{:ok, "SHA-256 of bundle bytes (F002 compat)"}` on rule 2 match.
    * `{:error, :no_match, %{loader_canonical: ..., bytes_sha: ...}}`
      when neither rule matches — the caller renders both candidates
      so the auditor can diagnose the drift.

  This function is what replaces the inline two-rule comparison in
  `LocalVerifyHandler.check_policy_against_bundle/1`.
  """
  @spec match_against_bundle(receipt_hash :: binary(), %{
          canonical_hash: binary(),
          bundle_bytes: binary()
        }) ::
          {:ok, kind_label :: String.t()}
          | {:error, :no_match, %{loader_canonical: binary(), bytes_sha: binary()}}
  def match_against_bundle(receipt_hash, %{
        canonical_hash: loader_canonical,
        bundle_bytes: bundle_bytes
      })
      when is_binary(receipt_hash) and is_binary(loader_canonical) and is_binary(bundle_bytes) do
    if receipt_hash == loader_canonical do
      {:ok, "BundleLoader canonical_hash via JCS(PolicySet::to_json())"}
    else
      bytes_sha = :crypto.hash(:sha256, bundle_bytes)

      if receipt_hash == bytes_sha do
        {:ok, "SHA-256 of bundle bytes (F002 compat)"}
      else
        {:error, :no_match, %{loader_canonical: loader_canonical, bytes_sha: bytes_sha}}
      end
    end
  end

  defp archive_lookup(policy_canonical_hash) do
    sql = "SELECT bundle_bytes FROM policy_bundles WHERE policy_canonical_hash = $1 LIMIT 1"

    case Repo.query(sql, [policy_canonical_hash]) do
      {:ok, %{rows: [[bytes]]}} when is_binary(bytes) -> {:ok, bytes}
      {:ok, %{rows: []}} -> :miss
      {:error, _} -> :miss
    end
  rescue
    err ->
      Logger.warning(fn ->
        "PolicyBundleResolver archive lookup raised: #{inspect(err)}"
      end)

      :miss
  end

  defp loader_fallback(policy_canonical_hash) do
    case Active.current() do
      {:ok, %Active{bundle: %{bundle_bytes: bytes, canonical_hash: ^policy_canonical_hash}}} ->
        {:ok, bytes, :loader_match, policy_canonical_hash}

      {:ok, %Active{bundle: %{bundle_bytes: bytes, canonical_hash: current_hash}}} ->
        Logger.warning(fn ->
          "PolicyBundleResolver: archive miss + loader hash drift " <>
            "(receipt=#{Base.encode16(policy_canonical_hash, case: :lower)}, " <>
            "loader=#{Base.encode16(current_hash, case: :lower)}) — " <>
            "returning loader bundle (issue #28)."
        end)

        {:ok, bytes, :loader_drift, current_hash}

      {:error, _reason} ->
        {:error, :not_found}
    end
  end
end
