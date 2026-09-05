defmodule Recurse.Gateway.AuditPlane.Resolvers.SigningKey.FallbackTest do
  @moduledoc """
  Unit tests for the source-of-truth fallback resolver
  (`Recurse.Gateway.AuditPlane.Resolvers.SigningKey.Fallback`).

  This module is the consolidation extraction landed for F7 — it owns
  the `observed://` vs real-KMS-ARN dispatch + I/O that was previously
  duplicated between `EvidenceZipBuilder` and (in dangling commit
  c11a16c) `LocalVerifyHandler`. These tests cover both dispatch arms
  directly so the F7 demo path (observed-tier receipt → archive empty →
  SecretsProvider active key → DSSE verify passes) regression-guards
  explicitly.

  ## What this guards (F7 trilogy correction)

  An earlier F7 fix routed `observed://` markers to the broker JWT PEM
  at `:internal_jwt.signing_key_path`. That was the WRONG key — the
  broker JWT key signs OIDC/login tokens, not attestations. Live
  diagnosis on audit-dev showed receipts are signed by whatever key
  `SecretsProvider.active_signing_key/1` advertises (a real KMS ARN
  under `runr5e-core-beam-signing` in production). The synthetic
  `observed://...` value is an opaque provenance marker stamped by
  the boot-time provider bootstrap
  (`Recurse.Gateway.Config.EnvProviderRegistry`); it does NOT identify
  the actual signer.

  The corrected fallback composes `active_signing_key/1` and
  `public_key/2` on the SAME provider — exactly the compose pattern
  used at attestation-EMIT time in `EnvelopeBuilder` — so verify
  resolves the same byte sequence whose private half signed.

  This file tests:

    * Observed:// arm: marker → `active_signing_key/1` → `public_key/2`
      → returned PEM, `:provider` source.
    * Observed:// arm: `active_signing_key/1` failure paths translate
      to `:not_found`.
    * Observed:// arm: `public_key/2` failure paths translate to
      `:not_found`.
    * Real-KMS-ARN arm: unchanged — delegates to `public_key/2` with
      the attestation-row key handle.
    * Degenerate inputs: nil / non-binary returns `:not_found`.

  Pure module under test — no GenServer, no SQL Sandbox; ProviderRegistry
  is the only piece of global state.
  """

  use ExUnit.Case, async: false

  alias Recurse.Gateway.AuditPlane.Resolvers.SigningKey.Fallback
  alias Recurse.Gateway.ProviderRegistry

  import Mox

  setup :verify_on_exit!

  setup do
    on_exit(fn -> ProviderRegistry.uninstall() end)
    install_mock_secrets_provider!()
    :ok
  end

  describe "fetch/2 — observed:// arm" do
    test "composes active_signing_key + public_key and tags source :provider" do
      handle = %{
        key_id: "arn:aws:kms:us-west-2:111122223333:alias/runr5e-core-beam-signing",
        key_version: 1,
        algorithm: :ecdsa_p256
      }

      pem = "-----BEGIN PUBLIC KEY-----\nFAKE\n-----END PUBLIC KEY-----\n"

      expect(Recurse.Gateway.Test.Mocks.SecretsProvider, :active_signing_key, fn _state ->
        {:ok, handle}
      end)

      expect(Recurse.Gateway.Test.Mocks.SecretsProvider, :public_key, fn _state, asked ->
        assert asked == handle
        {:ok, pem}
      end)

      assert {:ok, ^pem, :provider} = Fallback.fetch("observed://gateway", "v1")
    end

    test "matches any observed:// suffix via prefix dispatch (not hardcoded suffix)" do
      handle = %{key_id: "k", key_version: 1, algorithm: :ecdsa_p256}
      pem = "-----BEGIN PUBLIC KEY-----\nA\n-----END PUBLIC KEY-----\n"

      expect(Recurse.Gateway.Test.Mocks.SecretsProvider, :active_signing_key, 2, fn _ ->
        {:ok, handle}
      end)

      expect(Recurse.Gateway.Test.Mocks.SecretsProvider, :public_key, 2, fn _, _ -> {:ok, pem} end)

      assert {:ok, ^pem, :provider} = Fallback.fetch("observed://gateway", "v1")
      assert {:ok, ^pem, :provider} = Fallback.fetch("observed://gateway/us2-test", "v1")
    end

    test "returns :not_found when active_signing_key returns an error" do
      expect(Recurse.Gateway.Test.Mocks.SecretsProvider, :active_signing_key, fn _ ->
        {:error, :provider_unavailable}
      end)

      assert {:error, :not_found} = Fallback.fetch("observed://gateway", "v1")
    end

    test "returns :not_found when active_signing_key returns a malformed handle" do
      expect(Recurse.Gateway.Test.Mocks.SecretsProvider, :active_signing_key, fn _ ->
        {:ok, %{not_a_handle: true}}
      end)

      assert {:error, :not_found} = Fallback.fetch("observed://gateway", "v1")
    end

    test "returns :not_found when public_key returns an error" do
      handle = %{key_id: "k", key_version: 1, algorithm: :ecdsa_p256}

      expect(Recurse.Gateway.Test.Mocks.SecretsProvider, :active_signing_key, fn _ ->
        {:ok, handle}
      end)

      expect(Recurse.Gateway.Test.Mocks.SecretsProvider, :public_key, fn _, _ ->
        {:error, :kms_unavailable}
      end)

      assert {:error, :not_found} = Fallback.fetch("observed://gateway", "v1")
    end

    test "treats a non-binary :ok PEM as :not_found (defense-in-depth)" do
      handle = %{key_id: "k", key_version: 1, algorithm: :ecdsa_p256}

      expect(Recurse.Gateway.Test.Mocks.SecretsProvider, :active_signing_key, fn _ ->
        {:ok, handle}
      end)

      expect(Recurse.Gateway.Test.Mocks.SecretsProvider, :public_key, fn _, _ ->
        {:ok, ~c"not a binary"}
      end)

      assert {:error, :not_found} = Fallback.fetch("observed://gateway", "v1")
    end
  end

  describe "fetch/2 — real KMS ARN arm" do
    test "delegates to SecretsProvider.public_key/2 and tags source :provider" do
      kms_key_id = "arn:aws:kms:us-east-1:111122223333:key/real-key"
      key_version = "v3"
      pem = "-----BEGIN PUBLIC KEY-----\nFAKE\n-----END PUBLIC KEY-----\n"

      expect(Recurse.Gateway.Test.Mocks.SecretsProvider, :public_key, fn _state, handle ->
        assert handle == %{key_id: kms_key_id, key_version: key_version}
        {:ok, pem}
      end)

      assert {:ok, ^pem, :provider} = Fallback.fetch(kms_key_id, key_version)
    end

    test "translates SecretsProvider error into :not_found" do
      expect(Recurse.Gateway.Test.Mocks.SecretsProvider, :public_key, fn _state, _handle ->
        {:error, :kms_unavailable}
      end)

      assert {:error, :not_found} =
               Fallback.fetch("arn:aws:kms:us-east-1:111122223333:key/abc", "v1")
    end

    test "treats a non-binary :ok return as :not_found (defense-in-depth)" do
      expect(Recurse.Gateway.Test.Mocks.SecretsProvider, :public_key, fn _state, _handle ->
        {:ok, ~c"not a binary"}
      end)

      assert {:error, :not_found} =
               Fallback.fetch("arn:aws:kms:us-east-1:111122223333:key/x", "v1")
    end
  end

  describe "fetch/2 — degenerate inputs" do
    test "returns :not_found for non-binary kms_key_id" do
      assert {:error, :not_found} = Fallback.fetch(nil, "v1")
      assert {:error, :not_found} = Fallback.fetch(123, "v1")
    end

    test "returns :not_found for non-binary key_version" do
      assert {:error, :not_found} = Fallback.fetch("arn:aws:kms:...", nil)
    end
  end

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  defp install_mock_secrets_provider! do
    # `Recurse.Gateway.Test.Mocks.SecretsProvider` is defined in
    # test_helper.exs against the SecretsProvider behaviour. Install it
    # via ProviderRegistry so the Fallback's
    # `ProviderRegistry.secrets_provider/0` call resolves to the mock.
    ProviderRegistry.install_raw!(%{
      llm: {Recurse.Gateway.Test.Mocks.LLMProvider, %{}},
      ledger: {Recurse.Gateway.Test.Mocks.LedgerProvider, %{}},
      storage: {Recurse.Gateway.Test.Mocks.StorageProvider, %{}},
      secrets: {Recurse.Gateway.Test.Mocks.SecretsProvider, %{}},
      tenant_id: "01HQZN5K7J8M9N0P1Q2R3S4T5V",
      signer: "observed://gateway/fallback-test"
    })

    # Mox: allow the test process to set expectations directly.
    Mox.set_mox_global()
    :ok
  end
end
