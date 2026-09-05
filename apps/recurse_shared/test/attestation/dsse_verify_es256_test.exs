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
      assert byte_size(der_sig) in 70..72

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

  describe "verify_es256/4 — input shape errors" do
    test "invalid PEM returns :invalid_pem" do
      assert {:error, :invalid_pem} =
               Dsse.verify_es256(@payload_type, "p", <<0, 0, 0>>, "not-a-pem")
    end

    test "wrong-length signature returns :invalid_signature_format" do
      jwk = JOSE.JWK.generate_key({:ec, "P-256"})
      public_jwk = JOSE.JWK.to_public(jwk)
      {_, pem} = JOSE.JWK.to_pem(public_jwk)

      # 32 bytes is neither raw r||s (64) nor DER (70-72) — should reject.
      bad_sig = :crypto.strong_rand_bytes(32)

      assert {:error, :invalid_signature_format} =
               Dsse.verify_es256(@payload_type, "p", bad_sig, pem)
    end

    test "garbage 50-byte signature returns :invalid_signature_format" do
      jwk = JOSE.JWK.generate_key({:ec, "P-256"})
      public_jwk = JOSE.JWK.to_public(jwk)
      {_, pem} = JOSE.JWK.to_pem(public_jwk)

      # 50 bytes — neither raw (64) nor DER (70-72) — must reject without
      # crashing in `:public_key.verify/4`. F7 follow-up regression case.
      bad_sig = :crypto.strong_rand_bytes(50)

      assert {:error, :invalid_signature_format} =
               Dsse.verify_es256(@payload_type, "p", bad_sig, pem)
    end

    test "DER-shaped signature with wrong size returns :invalid_signature_format" do
      jwk = JOSE.JWK.generate_key({:ec, "P-256"})
      public_jwk = JOSE.JWK.to_public(jwk)
      {_, pem} = JOSE.JWK.to_pem(public_jwk)

      # 0x30-prefixed but 100 bytes (outside 70-72 valid P-256 DER range).
      # Don't let coincidental DER prefix bypass length-bounding.
      bad_sig = <<0x30>> <> :crypto.strong_rand_bytes(99)

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

  defp mutate_random_byte(bin) do
    pos = :rand.uniform(byte_size(bin)) - 1
    <<head::binary-size(pos), b::8, tail::binary>> = bin
    flipped = b |> Bitwise.bxor(0x01)
    <<head::binary, flipped::8, tail::binary>>
  end
end
