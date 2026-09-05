defmodule Recurse.Providers.Support.MockSecretsProvider do
  @moduledoc """
  Fixed-data stub implementation of `Recurse.Providers.SecretsProvider`
  (T065).

  Returns a canonical signing-key handle (`:ed25519`, `key_version: 1`)
  and a deterministic 64-byte "signature" (SHA-512 of the payload
  truncated to 64 bytes — NOT cryptographically meaningful, just
  round-trippable).

  Also returns a canned RFC 8693 token-exchange response — an
  Ed25519-shaped JWT string prefix + a fixed expiry. Real KMS / Vault
  impls ship in Feature 002+.
  """

  @behaviour Recurse.Providers.SecretsProvider

  @impl true
  def init(_config), do: {:ok, %{backend: :in_memory}}

  @impl true
  def active_signing_key(_state) do
    {:ok,
     %{
       key_id: "mock-signing-key-001",
       key_version: 1,
       algorithm: :ed25519
     }}
  end

  @impl true
  def sign(_state, _handle, payload) when is_binary(payload) do
    {:ok, :crypto.hash(:sha512, payload)}
  end

  @impl true
  def public_key(_state, _handle) do
    {:ok,
     "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAmockmockmockmockmockmockmockmockmockmockmockmo=\n-----END PUBLIC KEY-----\n"}
  end

  @impl true
  def store_user_token(_state, _identity_ctx, _token, _ttl), do: :ok

  @impl true
  def exchange_for_downstream_token(_state, _identity_ctx, service_id, requested_scope) do
    {:ok,
     %{
       token: "mock-rfc8693-token-for-" <> service_id,
       expires_at: DateTime.add(DateTime.utc_now(), 3600, :second),
       scope: requested_scope
     }}
  end

  @impl true
  def capabilities(_state), do: [:sign, :public_key_export, :token_exchange, :user_token_storage]

  @impl true
  def healthcheck(_state), do: :ok

  @impl true
  def terminate(_state, _reason), do: :ok
end
