defmodule Recurse.Gateway.Test.StubSecretsProvider do
  @moduledoc """
  Inline stub `Recurse.Providers.SecretsProvider` for EnvelopeBuilder +
  any test that needs a signing-key handle + deterministic "signature"
  without booting AWS KMS.

  Returns a canonical `stub-signing-key-001` Ed25519 handle (key_version
  1) and a 64-byte SHA-512 digest of the payload as the signature. Not
  cryptographically meaningful; structural round-trip is what we verify
  (Dsse.verify/2 in Phase-1 is a structural shell per F001).

  Lives in `test/support/` so the test elixirc path (`:test` env only)
  compiles it ahead of every test module under `apps/recurse_gateway/
  test/`. Mirrors `MockSecretsProvider` in `apps/recurse_providers/test/
  support/`; the duplication is intentional — we do not want test
  modules in one app to depend on `:test` artifacts from a sibling app.
  """
  @behaviour Recurse.Providers.SecretsProvider

  @impl true
  def init(_config), do: {:ok, %{backend: :stub}}

  @impl true
  def active_signing_key(_state) do
    {:ok, %{key_id: "stub-signing-key-001", key_version: 1, algorithm: :ed25519}}
  end

  @impl true
  def sign(_state, _handle, payload) when is_binary(payload) do
    {:ok, :crypto.hash(:sha512, payload)}
  end

  @impl true
  def public_key(_state, _handle),
    do: {:ok, "-----BEGIN PUBLIC KEY-----\nSTUB\n-----END PUBLIC KEY-----\n"}

  @impl true
  def store_user_token(_state, _ctx, _tok, _ttl), do: :ok

  @impl true
  def exchange_for_downstream_token(_s, _c, _id, _scope),
    do: {:error, :not_implemented_in_test}

  @impl true
  def capabilities(_state), do: [:sign, :public_key_export]

  @impl true
  def healthcheck(_state), do: :ok

  @impl true
  def terminate(_state, _reason), do: :ok
end

defmodule Recurse.Gateway.Test.ActiveSigningKeyFailureProvider do
  @moduledoc """
  Test double that fails at `active_signing_key/1` with the reason
  carried in the state slot. Used by EnvelopeBuilderTest to exercise
  the `{:error, {:active_signing_key, reason}}` path.
  """
  @behaviour Recurse.Providers.SecretsProvider

  @impl true
  def init(_config), do: {:ok, %{}}

  @impl true
  def active_signing_key(reason), do: {:error, reason}

  @impl true
  def sign(_state, _handle, _payload),
    do: raise("unreachable — active_signing_key failed first")

  @impl true
  def public_key(_state, _handle), do: {:error, :not_implemented_in_test}
  @impl true
  def store_user_token(_state, _ctx, _tok, _ttl), do: :ok
  @impl true
  def exchange_for_downstream_token(_s, _c, _id, _scope),
    do: {:error, :not_implemented_in_test}

  @impl true
  def capabilities(_state), do: []
  @impl true
  def healthcheck(_state), do: :ok
  @impl true
  def terminate(_state, _reason), do: :ok
end

defmodule Recurse.Gateway.Test.SignFailureProvider do
  @moduledoc """
  Test double that returns a valid signing handle, then fails at
  `sign/3` with the reason carried in the state slot. Used by
  EnvelopeBuilderTest to exercise the `{:error, {:sign, reason}}` path.
  """
  @behaviour Recurse.Providers.SecretsProvider

  @impl true
  def init(_config), do: {:ok, %{}}

  @impl true
  def active_signing_key(_state) do
    {:ok, %{key_id: "test-key", key_version: 1, algorithm: :ed25519}}
  end

  @impl true
  def sign(reason, _handle, _payload), do: {:error, reason}
  @impl true
  def public_key(_state, _handle), do: {:error, :not_implemented_in_test}
  @impl true
  def store_user_token(_state, _ctx, _tok, _ttl), do: :ok
  @impl true
  def exchange_for_downstream_token(_s, _c, _id, _scope),
    do: {:error, :not_implemented_in_test}

  @impl true
  def capabilities(_state), do: []
  @impl true
  def healthcheck(_state), do: :ok
  @impl true
  def terminate(_state, _reason), do: :ok
end
