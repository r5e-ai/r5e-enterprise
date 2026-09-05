defmodule Recurse.Providers.Impls.LocalPemSecretsProviderTest do
  @moduledoc """
  Real-impl tests for `Recurse.Providers.Impls.LocalPemSecretsProvider`
  (spec 012 S1, shortname `local_pem`).

  Both algorithms are exercised: ES256 (default) verifies through the
  same `Dsse.verify_es256/4` primitive the `LocalVerifyHandler` and the
  export path use, so a receipt signed by this provider is verifiable by
  the existing tooling. Ed25519 verifies through OTP `:public_key`
  against the exported SPKI PEM.
  """

  use ExUnit.Case, async: true

  alias Recurse.Providers.Impls.LocalPemSecretsProvider, as: Provider
  alias Recurse.Shared.Attestation.Dsse

  import Bitwise, only: [&&&: 2]

  @payload_type "application/recurse.signed-predicate+jcs"

  setup do
    dir =
      Path.join(
        System.tmp_dir!(),
        "local_pem_test_#{System.unique_integer([:positive])}"
      )

    on_exit(fn -> File.rm_rf!(dir) end)
    {:ok, key_path: Path.join(dir, "nested/local-signing-key.pem")}
  end

  describe "init/1 — ES256 (default)" do
    test "generates a P-256 key on first boot, mode 0600, and reports an ecdsa_p256 handle",
         %{key_path: key_path} do
      refute File.exists?(key_path)

      assert {:ok, state} = Provider.init(%{key_path: key_path})
      assert state.algorithm == :es256
      assert File.regular?(key_path)
      assert (File.stat!(key_path).mode &&& 0o777) == 0o600
      assert File.read!(key_path) =~ "PRIVATE KEY"

      assert {:ok, %{key_id: "local-pem-es256-" <> fp, key_version: 1, algorithm: :ecdsa_p256}} =
               Provider.active_signing_key(state)

      assert byte_size(fp) == 12
      assert Provider.capabilities(state) == [:sign, :public_key_export]
      assert Provider.healthcheck(state) == :ok
    end

    test "signatures verify with Dsse.verify_es256/4 (the production verifier path)",
         %{key_path: key_path} do
      {:ok, state} = Provider.init(%{key_path: key_path})
      {:ok, handle} = Provider.active_signing_key(state)
      {:ok, pem} = Provider.public_key(state, handle)

      predicate = ~s({"hello":"receipt"})
      pae = Dsse.pae(@payload_type, predicate)

      assert {:ok, sig} = Provider.sign(state, handle, pae)
      # `:public_key.sign/3` emits DER, same as KMS.
      assert <<0x30, _::binary>> = sig
      assert byte_size(sig) in 70..72

      assert :ok = Dsse.verify_es256(@payload_type, predicate, sig, pem)

      assert {:error, :signature_mismatch} =
               Dsse.verify_es256(@payload_type, ~s({"hello":"tampered"}), sig, pem)
    end

    test "reloads the same key across restarts (stable key_id + public key)",
         %{key_path: key_path} do
      {:ok, first} = Provider.init(%{key_path: key_path})
      {:ok, second} = Provider.init(%{key_path: key_path})

      assert first.public_pem == second.public_pem
      assert Provider.active_signing_key(first) == Provider.active_signing_key(second)
    end

    test "a rotated (regenerated) key yields a different key_id", %{key_path: key_path} do
      {:ok, first} = Provider.init(%{key_path: key_path})
      File.rm!(key_path)
      {:ok, second} = Provider.init(%{key_path: key_path})

      {:ok, %{key_id: id1}} = Provider.active_signing_key(first)
      {:ok, %{key_id: id2}} = Provider.active_signing_key(second)
      refute id1 == id2
    end
  end

  describe "init/1 — Ed25519" do
    test "generates an Ed25519 key and reports an :ed25519 handle", %{key_path: key_path} do
      assert {:ok, state} = Provider.init(%{key_path: key_path, algorithm: :ed25519})
      assert state.algorithm == :ed25519

      assert {:ok, %{key_id: "local-pem-ed25519-" <> _, key_version: 1, algorithm: :ed25519}} =
               Provider.active_signing_key(state)
    end

    test "accepts the env-var string form, case-insensitively", %{key_path: key_path} do
      assert {:ok, %{algorithm: :ed25519}} =
               Provider.init(%{key_path: key_path, algorithm: "ED25519"})
    end

    test "raw 64-byte signatures verify against the exported SPKI PEM", %{key_path: key_path} do
      {:ok, state} = Provider.init(%{key_path: key_path, algorithm: :ed25519})
      {:ok, handle} = Provider.active_signing_key(state)
      {:ok, pem} = Provider.public_key(state, handle)

      pae = Dsse.pae(@payload_type, "predicate")
      assert {:ok, sig} = Provider.sign(state, handle, pae)
      assert byte_size(sig) == 64

      assert {:ok, otp_key} = Dsse.pem_to_public_key(pem)
      assert :public_key.verify(pae, :none, sig, otp_key)
      refute :public_key.verify(pae <> "x", :none, sig, otp_key)
    end

    test "reloads the persisted Ed25519 key", %{key_path: key_path} do
      {:ok, first} = Provider.init(%{key_path: key_path, algorithm: :ed25519})
      {:ok, second} = Provider.init(%{key_path: key_path, algorithm: :ed25519})
      assert first.public_pem == second.public_pem
    end
  end

  describe "init/1 — failure modes" do
    test "rejects an unknown algorithm before touching the filesystem", %{key_path: key_path} do
      assert {:error, {:unsupported_algorithm, "rsa"}} =
               Provider.init(%{key_path: key_path, algorithm: "rsa"})

      refute File.exists?(key_path)
    end

    test "refuses to use a PEM whose key type does not match the requested algorithm",
         %{key_path: key_path} do
      {:ok, _} = Provider.init(%{key_path: key_path, algorithm: :es256})

      assert {:error, {:key_algorithm_mismatch, details}} =
               Provider.init(%{key_path: key_path, algorithm: :ed25519})

      assert details[:expected] == :ed25519
      assert details[:found] == {"EC", "P-256"}
    end

    test "rejects garbage at the key path", %{key_path: key_path} do
      File.mkdir_p!(Path.dirname(key_path))
      File.write!(key_path, "not a pem")

      assert {:error, {:invalid_key_pem, ^key_path}} = Provider.init(%{key_path: key_path})
    end

    test "healthcheck degrades when the key file disappears", %{key_path: key_path} do
      {:ok, state} = Provider.init(%{key_path: key_path})
      File.rm!(key_path)
      assert {:degraded, {:signing_key_file_missing, ^key_path}} = Provider.healthcheck(state)
    end
  end

  describe "key material is not inspectable" do
    test "inspect(state) carries neither the ECDSA scalar nor the Ed25519 seed",
         %{key_path: key_path} do
      for alg <- Provider.algorithms() do
        path = "#{key_path}.#{alg}"
        {:ok, state} = Provider.init(%{key_path: path, algorithm: alg})

        # The secret as it sits on disk: the JWK `d` member.
        {_, %{"d" => d_b64}} = path |> JOSE.JWK.from_pem_file() |> JOSE.JWK.to_map()
        secret = Base.url_decode64!(d_b64, padding: false)
        rendered = inspect(state, limit: :infinity, printable_limit: :infinity)

        assert is_function(state.signer, 1)
        refute rendered =~ "ECPrivateKey", "#{alg}"
        # `<<155, 36, ...>>` — how the bare key bytes rendered before the fix.
        refute rendered =~ inspect(secret, limit: :infinity), "#{alg}"
        refute rendered =~ d_b64, "#{alg}"
        refute rendered =~ Base.encode16(secret, case: :lower), "#{alg}"

        # ...and the closure still signs.
        {:ok, handle} = Provider.active_signing_key(state)
        assert {:ok, sig} = Provider.sign(state, handle, "payload")
        assert is_binary(sig)
      end
    end

    test "a signing failure reports the exception type, not the arguments", %{key_path: key_path} do
      {:ok, state} = Provider.init(%{key_path: key_path})
      broken = %{state | signer: fn _payload -> raise ArgumentError, "boom" end}
      {:ok, handle} = Provider.active_signing_key(state)
      assert {:error, {:sign_failed, ArgumentError}} = Provider.sign(broken, handle, "payload")
    end
  end

  describe "Dsse.public_key_algorithm/1 on the exported PEM" do
    test "names the algorithm the LocalVerifyHandler must dispatch on", %{key_path: key_path} do
      {:ok, es} = Provider.init(%{key_path: key_path <> ".es256", algorithm: :es256})
      {:ok, ed} = Provider.init(%{key_path: key_path <> ".ed25519", algorithm: :ed25519})

      assert {:ok, :ecdsa_p256} = Dsse.public_key_algorithm(es.public_pem)
      assert {:ok, :ed25519} = Dsse.public_key_algorithm(ed.public_pem)
      assert {:error, :invalid_pem} = Dsse.public_key_algorithm("not a pem")
    end
  end

  describe "FR-047 surface" do
    test "token exchange is not supported by a local signer", %{key_path: key_path} do
      {:ok, state} = Provider.init(%{key_path: key_path})
      assert :ok = Provider.store_user_token(state, nil, "tok", 60)

      assert {:error, :not_supported} =
               Provider.exchange_for_downstream_token(state, nil, "jira", [])

      assert :ok = Provider.terminate(state, :normal)
    end
  end
end
