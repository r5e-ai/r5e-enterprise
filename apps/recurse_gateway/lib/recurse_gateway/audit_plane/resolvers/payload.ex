defmodule Recurse.Gateway.AuditPlane.Resolvers.Payload do
  @moduledoc """
  Pure storage fetch for an attestation's detached payload bytes,
  given a `payload_uri` and an identity context.

  ## Why this module exists (Issue #29 / Constitution Principle VII)

  FOUR consumers had their own version of the StorageProvider call:

    * `EvidenceZipBuilder.fetch_payload/4` (lines 143-164) — checks
      predicate-only URI scheme inline, then calls StorageProvider.
    * `LocalVerifyHandler.fetch_payload_bytes/2` (lines 553-561) — same.
    * `PayloadBroker.fetch_payload/2` (lines 175-183) — same, used in
      the verify-side payload-tab fetch.
    * `ReceiptsHandler` for any payload-shaped fetch.

  Each had subtly different error-classification logic. The s4 survey
  flagged this as a four-instance Principle-VII violation that the
  charter under-counted (it had identified three).

  ## Scope discipline

  This module fetches storage bytes ONLY. It does NOT detect the
  predicate-only URI scheme — that's `PredicateOnlyUri.match?/1`'s
  job, called by the consumer BEFORE this resolver, so the consumer
  can short-circuit with the appropriate response shape (a JSON
  marker for the broker, an inline marker for the export zip, a
  payload-skip for the verify check).

  Bundling predicate-only detection into this resolver would couple
  it to the "system event" concept and force every caller to handle
  the same response shape — which they don't (per s4 finding).

  ## Iron Law

  Pure module. No process. Calls `ProviderRegistry.storage_provider/0`
  + the provider's `get_payload/3` callback.
  """

  alias Recurse.Gateway.ProviderRegistry

  require Logger

  @doc """
  Store `bytes` in the configured StorageProvider and return the URI the
  provider addresses them by (spec 012 S6b). The mirror of `fetch/2`:
  the third `put_payload/3` consumer (after `ChatCompletionsHandler` and
  `OutboxReconciler`) — the emitter's predicate-body and payload
  retention — lands here rather than as a third inline copy
  (Constitution Principle VII).

  The provider's returned hash is checked against SHA-256 of `bytes`;
  a provider that reports a different hash did not store these bytes
  under that URI, so the put is reported as failed. Every failure shape
  (`{:error, reason}`, `{:error, class, reason}`, a raise) normalises
  to `{:error, {:put_failed, reason}}` — callers decide whether the
  failure is fatal; for receipt retention it never is.
  """
  @spec store(bytes :: binary(), ctx :: map()) ::
          {:ok, uri :: String.t()} | {:error, {:put_failed, reason :: term()}}
  def store(bytes, ctx) when is_binary(bytes) and is_map(ctx) do
    {storage_mod, storage_state} = ProviderRegistry.storage_provider()
    expected = :crypto.hash(:sha256, bytes)

    case storage_mod.put_payload(storage_state, bytes, ctx) do
      {:ok, %{uri: uri, hash: ^expected}} when is_binary(uri) ->
        {:ok, uri}

      {:ok, %{uri: uri, hash: other}} ->
        {:error, {:put_failed, {:hash_mismatch, uri, other}}}

      {:error, _class, reason} ->
        {:error, {:put_failed, reason}}

      {:error, reason} ->
        {:error, {:put_failed, reason}}

      other ->
        {:error, {:put_failed, {:unexpected_reply, other}}}
    end
  rescue
    error -> {:error, {:put_failed, {:raised, error}}}
  end

  @doc """
  Fetch payload bytes from the configured StorageProvider for a given
  `payload_uri`. The `ctx` (typically an `IdentityContext` or a map
  with `:tenant_id`/`:correlation_id`) is forwarded to the provider
  for tenant scoping + audit-trail emission.

  Error envelope is normalized to `{:error, {:fetch_failed, reason}}`
  regardless of which error shape the provider returns
  (`{:error, _class, reason}` or `{:error, reason}` — both seen in
  the codebase). Callers don't need to handle the variation.
  """
  @spec fetch(payload_uri :: String.t(), ctx :: map()) ::
          {:ok, bytes :: binary()}
          | {:error, {:fetch_failed, reason :: term()}}
  def fetch(payload_uri, ctx) when is_binary(payload_uri) and is_map(ctx) do
    {storage_mod, storage_state} = ProviderRegistry.storage_provider()

    case storage_mod.get_payload(storage_state, payload_uri, ctx) do
      {:ok, bytes} when is_binary(bytes) -> {:ok, bytes}
      {:error, _class, reason} -> {:error, {:fetch_failed, reason}}
      {:error, reason} -> {:error, {:fetch_failed, reason}}
    end
  end
end
