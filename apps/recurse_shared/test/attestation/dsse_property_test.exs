defmodule Recurse.Shared.Attestation.DssePropertyTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Recurse.Shared.Attestation.Dsse

  describe "pae/2" do
    property "PAE is byte-stable under re-encoding (same inputs → same bytes)" do
      check all(
              type <- StreamData.string(:alphanumeric, min_length: 1, max_length: 64),
              payload <- StreamData.binary(min_length: 0, max_length: 256)
            ) do
        assert Dsse.pae(type, payload) == Dsse.pae(type, payload)
      end
    end

    property "PAE encodes correct lengths per DSSE spec" do
      check all(
              type <- StreamData.string(:alphanumeric, min_length: 1, max_length: 32),
              payload <- StreamData.binary(min_length: 0, max_length: 128)
            ) do
        pae = Dsse.pae(type, payload)
        # "DSSEv1 <tl> <type> <pl> <payload>" — check prefix form.
        assert String.starts_with?(pae, "DSSEv1 ")

        type_len_str = Integer.to_string(byte_size(type))
        expected_prefix = "DSSEv1 " <> type_len_str <> " " <> type <> " "
        assert String.starts_with?(pae, expected_prefix)

        # And the payload bytes live at the tail.
        assert binary_part(pae, byte_size(pae) - byte_size(payload), byte_size(payload)) ==
                 payload
      end
    end
  end

  describe "encode/4 → decode/1" do
    property "round-trip returns identical payload bytes" do
      check all(
              payload <- StreamData.binary(min_length: 1, max_length: 256),
              payload_type <-
                StreamData.one_of([
                  StreamData.constant("application/vnd.in-toto+json"),
                  StreamData.constant("application/vnd.recurse.attestation+json;version=1.0")
                ]),
              key_id <- StreamData.string(:alphanumeric, min_length: 1, max_length: 32),
              max_runs: 40
            ) do
        jwk = JOSE.JWK.generate_key({:okp, :Ed25519})
        envelope = Dsse.encode(payload_type, payload, jwk, key_id)

        assert %{"payloadType" => ^payload_type, "payload" => _, "signatures" => [_]} = envelope

        {:ok, decoded} = Dsse.decode(envelope)
        assert decoded.payload == payload
        assert decoded.payload_type == payload_type
        assert [%{key_id: ^key_id, sig: sig}] = decoded.signatures
        assert byte_size(sig) > 0
      end
    end

    # Regression guard for speckit-pr-review iteration-2 F001: the DSSE
    # signature MUST be computed over raw PAE bytes (per ITE-5 §2),
    # NOT over the JWS signing input (base64url(header) || "." ||
    # base64url(payload)). A round-trip test encode→decode can mask
    # this bug because we encode and decode consistently wrong. The
    # only way to catch it is to independently verify the emitted sig
    # against the raw PAE using a third-party primitive.
    #
    # Iteration-3 F006 flagged that we lacked this test.
    property "signature verifies against raw PAE bytes (not JWS signing input)" do
      check all(
              payload <- StreamData.binary(min_length: 1, max_length: 256),
              payload_type <- StreamData.constant("application/vnd.in-toto+json"),
              key_id <- StreamData.string(:alphanumeric, min_length: 1, max_length: 16),
              max_runs: 30
            ) do
        jwk = JOSE.JWK.generate_key({:okp, :Ed25519})
        envelope = Dsse.encode(payload_type, payload, jwk, key_id)
        {:ok, decoded} = Dsse.decode(envelope)
        [%{sig: sig}] = decoded.signatures

        # Reconstruct the raw PAE the way DSSE spec says to sign it.
        pae = Dsse.pae(payload_type, payload)

        # Extract Ed25519 public key from the JWK and verify the sig
        # is over `pae` directly using :crypto — independent of JOSE.
        {_, %{"d" => _, "x" => x_b64, "kty" => "OKP", "crv" => "Ed25519"}} =
          JOSE.JWK.to_map(jwk)

        pub = Base.url_decode64!(x_b64, padding: false)

        assert :crypto.verify(:eddsa, :none, pae, sig, [pub, :ed25519]),
               "signature did not verify against raw PAE — likely signed the JWS signing input " <>
                 "(base64url(hdr)||.||base64url(payload)) instead of raw PAE bytes (iteration-2 F001)"
      end
    end
  end
end
