defmodule Recurse.Shared.Attestation.DsseVerifyEs256Test do
  @moduledoc """
  Issue #29 / B5. Tests for the `verify_es256/4` primitive lifted from
  `LocalVerifyHandler.verify_dsse_signature/3` into recurse_shared so any
  verifier can use it without re-implementing the ECDSA P-256 + ASN.1 +
  PEM-decode plumbing.

  Verifies the round-trip: encode (which signs PAE) → extract raw r||s
  signature → verify_es256 against the matching public-key PEM.
  """

  use ExUnit.Case, async: true

  alias Recurse.Shared.Attestation.Dsse

  @payload_type "application/recurse.signed-predicate+jcs"

  describe "verify_es256/4 — round-trip with JOSE-generated key pair" do
    setup do
      # Generate a fresh EC P-256 keypair per test (async-safe).
      jwk = JOSE.JWK.generate_key({:ec, "P-256"})
      public_jwk = JOSE.JWK.to_public(jwk)
      {_module, public_pem} = JOSE.JWK.to_pem(public_jwk)
      {:ok, jwk: jwk, public_pem: public_pem}
    end

    test "verifies a valid signature against the matching public key", %{
      jwk: jwk,
      public_pem: pem
    } do
      payload = "predicate-bytes-go-here"

      envelope = Dsse.encode(@payload_type, payload, jwk, "key-test")

      [%{"sig" => sig_b64}] = envelope["signatures"]
      sig_raw = Base.decode64!(sig_b64)

      assert :ok = Dsse.verify_es256(@payload_type, payload, sig_raw, pem)
    end

    test "rejects when the signature is mutated", %{jwk: jwk, public_pem: pem} do
      payload = "the-payload"
      envelope = Dsse.encode(@payload_type, payload, jwk, "key-1")
      [%{"sig" => sig_b64}] = envelope["signatures"]
      sig_raw = Base.decode64!(sig_b64)

      mutated = mutate_random_byte(sig_raw)

      assert {:error, _} = Dsse.verify_es256(@payload_type, payload, mutated, pem)
    end

    test "rejects when the payload is mutated", %{jwk: jwk, public_pem: pem} do
      payload = "original"
      envelope = Dsse.encode(@payload_type, payload, jwk, "key-1")
      [%{"sig" => sig_b64}] = envelope["signatures"]
      sig_raw = Base.decode64!(sig_b64)

      assert {:error, :signature_mismatch} =
               Dsse.verify_es256(@payload_type, "different-payload", sig_raw, pem)
    end

    test "rejects when the public key is from a different keypair", %{
      jwk: jwk
    } do
      payload = "x"
      envelope = Dsse.encode(@payload_type, payload, jwk, "key-a")
      [%{"sig" => sig_b64}] = envelope["signatures"]
      sig_raw = Base.decode64!(sig_b64)

      # Use a fresh, unrelated keypair's public PEM.
      other_jwk = JOSE.JWK.generate_key({:ec, "P-256"})
      other_public_jwk = JOSE.JWK.to_public(other_jwk)
      {_module, other_pem} = JOSE.JWK.to_pem(other_public_jwk)

      assert {:error, :signature_mismatch} =
               Dsse.verify_es256(@payload_type, payload, sig_raw, other_pem)
    end
  end

  describe "verify_es256/4 — DER-encoded signature path (F7 follow-up)" do
    setup do
      # Generate a fresh EC P-256 keypair per test (async-safe).
      jwk = JOSE.JWK.generate_key({:ec, "P-256"})
      {_, otp_priv_key} = JOSE.JWK.to_key(jwk)
      public_jwk = JOSE.JWK.to_public(jwk)
      {_module, public_pem} = JOSE.JWK.to_pem(public_jwk)
      {:ok, otp_priv_key: otp_priv_key, public_pem: public_pem}
    end

    test "verifies a DER-encoded signature (production receipt shape)", %{
      otp_priv_key: otp_priv_key,
      public_pem: pem
    } do
      payload = "predicate-bytes-from-kms"

      # `:public_key.sign/3` returns DER directly — this is what KMS / the
      # broker produce on audit-dev, and what was failing pre-fix with
      # `:invalid_signature_format`.
      pae_bytes = Dsse.pae(@payload_type, payload)
      der_sig = :public_key.sign(pae_bytes, :sha256, otp_priv_key)

      # Confirm we actually generated a DER signature (sanity check).
      assert <<0x30, _rest::binary>> = der_sig
      assert byte_size(der_sig) in 8..72

      assert :ok = Dsse.verify_es256(@payload_type, payload, der_sig, pem)
    end

    test "rejects a DER signature when the payload is mutated", %{
      otp_priv_key: otp_priv_key,
      public_pem: pem
    } do
      pae_bytes = Dsse.pae(@payload_type, "original-payload")
      der_sig = :public_key.sign(pae_bytes, :sha256, otp_priv_key)

      assert {:error, :signature_mismatch} =
               Dsse.verify_es256(@payload_type, "tampered-payload", der_sig, pem)
    end
  end

  describe "verify_es256/4 — deterministic encoding regressions" do
    setup do
      # Public point for the test-only private scalar d = 1 (P-256's generator).
      jwk =
        JOSE.JWK.from_map(%{
          "kty" => "EC",
          "crv" => "P-256",
          "x" =>
            hex_coordinate("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"),
          "y" =>
            hex_coordinate("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
        })

      {_, pem} = JOSE.JWK.to_pem(jwk)
      {:ok, public_pem: pem}
    end

    test "verifies a fixed 69-byte DER signature and its raw equivalent", %{public_pem: pem} do
      # ECDSA over PAE(type, payload), d = 1, nonce k = 278. The s integer
      # needs only 31 bytes. No random search is needed to exercise this case.
      der =
        Base.decode16!(
          "304302207c53cbed04c48186aae30f51aa74dc31b04939146fc7156c4128b41f9ade187f" <>
            "021f07f857dfd18fccc46c6f328d5c023d01518b5df3089679d1798892a1b87f68",
          case: :lower
        )

      <<0x30, 67, 0x02, 32, r::binary-size(32), 0x02, 31, s::binary-size(31)>> = der
      raw = r <> <<0>> <> s
      assert byte_size(der) == 69
      assert :ok = Dsse.verify_es256(@payload_type, "fixed-es256-regression", der, pem)
      assert :ok = Dsse.verify_es256(@payload_type, "fixed-es256-regression", raw, pem)

      assert {:error, :signature_mismatch} =
               Dsse.verify_es256(@payload_type, "tampered", der, pem)
    end

    test "verifies fixed raw bytes starting with the DER sequence tag", %{public_pem: pem} do
      # Same payload and d = 1, nonce k = 31. The first raw byte is 0x30.
      raw =
        Base.decode16!(
          "301d9e502dc7e05da85da026a7ae9aa0fac9db7d52a95b3e3e3f9aa0a1b45b8b" <>
            "a2fb674822cb045d2bb79748149e11f4f3746ffffed729d2884f21735dd62db0",
          case: :lower
        )

      assert byte_size(raw) == 64
      assert :ok = Dsse.verify_es256(@payload_type, "fixed-es256-regression", raw, pem)
    end

    test "64 bytes always use the raw path even with a malformed DER prefix", %{public_pem: pem} do
      assert {:error, :signature_mismatch} =
               Dsse.verify_es256(@payload_type, "p", <<0x30, 0::size(504)>>, pem)
    end

    test "accepts the minimum DER structure for cryptographic checking", %{public_pem: pem} do
      assert {:error, :signature_mismatch} =
               Dsse.verify_es256(@payload_type, "p", <<0x30, 6, 2, 1, 1, 2, 1, 1>>, pem)
    end

    test "rejects malformed or noncanonical DER before cryptographic verification", %{
      public_pem: pem
    } do
      valid_shape = <<0x30, 6, 2, 1, 1, 2, 1, 1>>

      malformed = [
        <<0x30, 7, 2, 1, 1, 2, 1, 1>>,
        <<0x30, 5, 2, 1, 1, 2, 1, 1>>,
        valid_shape <> <<0>>,
        <<0x30, 0x81, 6, 2, 1, 1, 2, 1, 1>>,
        <<0x30, 0x80, 2, 1, 1, 2, 1, 1, 0, 0>>,
        <<0x30, 6, 3, 1, 1, 2, 1, 1>>,
        <<0x30, 6, 2, 1, 1, 3, 1, 1>>,
        <<0x30, 6, 2, 0, 2, 2, 1, 1>>,
        <<0x30, 6, 2, 1, 0, 2, 1, 1>>,
        <<0x30, 6, 2, 1, 0x80, 2, 1, 1>>,
        <<0x30, 7, 2, 2, 0, 1, 2, 1, 1>>,
        <<0x30, 9, 2, 1, 1, 2, 1, 1, 2, 1, 1>>,
        <<0x30, 38, 2, 33, 1, 0::size(256), 2, 1, 1>>,
        <<0x30, 68, 0::size(544)>>,
        <<0x30, 69, 0::size(552)>>,
        <<0x30, 70, 0::size(560)>>
      ]

      for signature <- malformed do
        assert {:error, :invalid_signature_format} =
                 Dsse.verify_es256(@payload_type, "p", signature, pem)
      end
    end
  end

  describe "verify_es256/4 — input shape errors" do
    test "invalid PEM returns :invalid_pem" do
      assert {:error, :invalid_pem} =
               Dsse.verify_es256(@payload_type, "p", <<0, 0, 0>>, "not-a-pem")
    end

    test "wrong-length signature returns :invalid_signature_format" do
      jwk = JOSE.JWK.generate_key({:ec, "P-256"})
      public_jwk = JOSE.JWK.to_public(jwk)
      {_, pem} = JOSE.JWK.to_pem(public_jwk)

      # This is neither raw r||s nor a DER sequence.
      bad_sig = :binary.copy(<<1>>, 32)

      assert {:error, :invalid_signature_format} =
               Dsse.verify_es256(@payload_type, "p", bad_sig, pem)
    end

    test "garbage 50-byte signature returns :invalid_signature_format" do
      jwk = JOSE.JWK.generate_key({:ec, "P-256"})
      public_jwk = JOSE.JWK.to_public(jwk)
      {_, pem} = JOSE.JWK.to_pem(public_jwk)

      # Malformed 50-byte input must reject without
      # crashing in `:public_key.verify/4`. F7 follow-up regression case.
      bad_sig = :binary.copy(<<1>>, 50)

      assert {:error, :invalid_signature_format} =
               Dsse.verify_es256(@payload_type, "p", bad_sig, pem)
    end

    test "DER-shaped signature with wrong size returns :invalid_signature_format" do
      jwk = JOSE.JWK.generate_key({:ec, "P-256"})
      public_jwk = JOSE.JWK.to_public(jwk)
      {_, pem} = JOSE.JWK.to_pem(public_jwk)

      # 0x30-prefixed but larger than any P-256 DER signature.
      # Don't let coincidental DER prefix bypass length-bounding.
      bad_sig = <<0x30>> <> :binary.copy(<<1>>, 99)

      assert {:error, :invalid_signature_format} =
               Dsse.verify_es256(@payload_type, "p", bad_sig, pem)
    end
  end

  describe "raw_to_ecdsa_der/2 — the underlying helper" do
    test "valid 64-byte input produces DER bytes" do
      sig = :crypto.strong_rand_bytes(64)
      der = Dsse.raw_to_ecdsa_der(sig, 32)
      assert is_binary(der)
      assert <<0x30, _len, 0x02, _r_len, _r::binary>> = der
    end

    test "non-64-byte input returns nil" do
      assert Dsse.raw_to_ecdsa_der(<<>>, 32) == nil
      assert Dsse.raw_to_ecdsa_der(<<1, 2, 3>>, 32) == nil
      assert Dsse.raw_to_ecdsa_der(:crypto.strong_rand_bytes(96), 32) == nil
    end
  end

  describe "pem_to_public_key/1" do
    test "decodes a valid SubjectPublicKeyInfo PEM" do
      jwk = JOSE.JWK.generate_key({:ec, "P-256"})
      public_jwk = JOSE.JWK.to_public(jwk)
      {_module, pem} = JOSE.JWK.to_pem(public_jwk)

      assert {:ok, otp_key} = Dsse.pem_to_public_key(pem)
      assert is_tuple(otp_key)
    end

    test "returns :invalid_pem for malformed input" do
      assert {:error, :invalid_pem} = Dsse.pem_to_public_key("not pem")
    end
  end

  defp hex_coordinate(hex) do
    hex |> Base.decode16!(case: :lower) |> Base.url_encode64(padding: false)
  end

  defp mutate_random_byte(bin) do
    pos = :rand.uniform(byte_size(bin)) - 1
    <<head::binary-size(pos), b::8, tail::binary>> = bin
    flipped = b |> Bitwise.bxor(0x01)
    <<head::binary, flipped::8, tail::binary>>
  end
end
