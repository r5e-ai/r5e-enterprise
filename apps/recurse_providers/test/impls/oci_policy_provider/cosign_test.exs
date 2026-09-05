defmodule Recurse.Providers.Impls.OciPolicyProvider.CosignTest do
  @moduledoc """
  Real-impl tests for `Recurse.Providers.Impls.OciPolicyProvider.Cosign`.

  ## Test strategy

  Cosign verification has two supported wire formats:

    * cosign 2.x — "simplesigning" — exercised here with an in-process
      EC keypair from `:crypto.generate_key/2` + the `:ECPrivateKey`
      record idiom established by the F004 integration tests.
    * cosign 3.x — "sigstore Bundle v0.3" with DSSE envelope — exercised
      with the same EC keypair (algorithm dispatch is by key SHAPE so
      one happy-path EC test covers both wire formats' ECDSA branch).
      A separate RSA test covers the RSA-PSS branch end-to-end.

  External KMS dependencies are stubbed via the
  `:cosign_kms_pubkey_fetcher` Application env, which is set + restored
  per-test in the `setup` block.

  The `:persistent_term` cache is process-global, so every test uses a
  unique `kms_key_arn` (derived from `make_ref/0`) — keeps the suite
  `async: true` safe.
  """

  use ExUnit.Case, async: true

  alias Recurse.Providers.Impls.OciPolicyProvider.Cosign
  alias Recurse.Shared.Attestation.Dsse

  @cosign_signature_annotation "dev.cosignproject.cosign/signature"
  @cosign_simplesigning_media_type "application/vnd.dev.cosign.simplesigning.v1+json"
  @cosign_payload_type "cosign container image signature"
  @sigstore_bundle_v0_3_media_type "application/vnd.dev.sigstore.bundle.v0.3+json"
  @in_toto_statement_v1 "https://in-toto.io/Statement/v1"
  @dsse_payload_type "application/vnd.in-toto+json"

  describe "verify/3 — simplesigning happy path" do
    test "verifies a well-formed cosign 2.x signature against the configured KMS key" do
      ctx = build_simplesigning_artifact()

      assert :ok =
               Cosign.verify(ctx.manifest_bytes, ctx.sig_artifact, ctx.kms_key_arn)
    end

    test "second verify against the same key hits the persistent_term cache" do
      ctx = build_simplesigning_artifact()

      assert Recurse.Providers.Impls.OciPolicyProvider.Cosign.TestPubkeyFetcher.call_count(
               ctx.kms_key_arn
             ) == 0

      assert :ok =
               Cosign.verify(ctx.manifest_bytes, ctx.sig_artifact, ctx.kms_key_arn)

      assert Recurse.Providers.Impls.OciPolicyProvider.Cosign.TestPubkeyFetcher.call_count(
               ctx.kms_key_arn
             ) == 1

      manifest_bytes2 = JSON.encode!(%{"different" => "manifest", "n" => 2})

      sig_artifact2 =
        build_simplesigning_artifact(manifest_bytes: manifest_bytes2, private_key: ctx.private_key)
        |> Map.fetch!(:sig_artifact)

      assert :ok = Cosign.verify(manifest_bytes2, sig_artifact2, ctx.kms_key_arn)

      assert Recurse.Providers.Impls.OciPolicyProvider.Cosign.TestPubkeyFetcher.call_count(
               ctx.kms_key_arn
             ) == 1
    end
  end

  describe "verify/3 — simplesigning payload digest mismatch" do
    test "returns {:error, :payload_digest_mismatch} when payload claims a different digest" do
      ctx = build_simplesigning_artifact()

      tampered_manifest_bytes = ctx.manifest_bytes <> <<0xAB>>

      assert {:error, :payload_digest_mismatch} =
               Cosign.verify(
                 tampered_manifest_bytes,
                 ctx.sig_artifact,
                 ctx.kms_key_arn
               )
    end
  end

  describe "verify/3 — simplesigning tampered signature" do
    test "returns {:error, :signature_mismatch} when signature bytes are flipped" do
      ctx = build_simplesigning_artifact()

      tampered_sig_b64 = flip_one_bit(ctx.signature_b64)

      tampered_layer =
        Map.update!(ctx.sig_artifact.layer, "annotations", fn ann ->
          Map.put(ann, @cosign_signature_annotation, tampered_sig_b64)
        end)

      tampered_sig_artifact = %{ctx.sig_artifact | layer: tampered_layer}

      assert {:error, reason} =
               Cosign.verify(
                 ctx.manifest_bytes,
                 tampered_sig_artifact,
                 ctx.kms_key_arn
               )

      assert reason in [:signature_mismatch] or
               match?({:verify_raised, _}, reason)
    end
  end

  describe "verify/3 — wrong KMS public key" do
    test "returns {:error, :signature_mismatch} when configured KMS key is wrong" do
      ctx = build_simplesigning_artifact()

      {wrong_pem, _wrong_priv} = generate_ec_keypair_pem()
      wrong_arn = unique_kms_arn()

      Recurse.Providers.Impls.OciPolicyProvider.Cosign.TestPubkeyFetcher.put_pem(
        wrong_arn,
        wrong_pem
      )

      assert {:error, :signature_mismatch} =
               Cosign.verify(ctx.manifest_bytes, ctx.sig_artifact, wrong_arn)
    end
  end

  describe "verify/3 — malformed simplesigning inputs" do
    test "returns {:error, _} when blob bytes aren't JSON" do
      ctx = build_simplesigning_artifact()

      bad_artifact = %{ctx.sig_artifact | layer_blob_bytes: "<not-json>"}

      assert {:error, {:malformed_cosign_payload, _}} =
               Cosign.verify(ctx.manifest_bytes, bad_artifact, ctx.kms_key_arn)
    end

    test "returns {:error, {:unknown_signature_format, _}} when layer mediaType is unrecognised" do
      ctx = build_simplesigning_artifact()

      bad_layer = Map.put(ctx.sig_artifact.layer, "mediaType", "application/x-not-cosign")
      bad_artifact = %{ctx.sig_artifact | layer: bad_layer}

      assert {:error, {:unknown_signature_format, "application/x-not-cosign"}} =
               Cosign.verify(ctx.manifest_bytes, bad_artifact, ctx.kms_key_arn)
    end

    test "returns {:error, :signature_annotation_missing} when annotation is absent" do
      ctx = build_simplesigning_artifact()

      stripped_layer = Map.put(ctx.sig_artifact.layer, "annotations", %{})
      bad_artifact = %{ctx.sig_artifact | layer: stripped_layer}

      assert {:error, :signature_annotation_missing} =
               Cosign.verify(ctx.manifest_bytes, bad_artifact, ctx.kms_key_arn)
    end
  end

  describe "verify/3 — KMS fetch failures" do
    test "returns {:error, reason} when the fetcher errors" do
      ctx = build_simplesigning_artifact()
      failing_arn = unique_kms_arn()

      Recurse.Providers.Impls.OciPolicyProvider.Cosign.TestPubkeyFetcher.put_error(
        failing_arn,
        :kms_unreachable
      )

      assert {:error, :kms_unreachable} =
               Cosign.verify(ctx.manifest_bytes, ctx.sig_artifact, failing_arn)
    end
  end

  # =========================================================================
  # cosign 3.x — sigstore Bundle v0.3 (DSSE envelope)
  # =========================================================================

  describe "verify/3 — sigstore Bundle v0.3 happy path (ECDSA P-256)" do
    test "verifies a well-formed v0.3 bundle with ECDSA-P256 KMS key" do
      ctx = build_v0_3_artifact_ec()

      assert :ok =
               Cosign.verify(ctx.manifest_bytes, ctx.sig_artifact, ctx.kms_key_arn)
    end
  end

  describe "verify/3 — sigstore Bundle v0.3 happy path (RSA-PSS)" do
    @tag timeout: :timer.seconds(60)
    test "verifies a well-formed v0.3 bundle with RSA-PSS-SHA256 KMS key" do
      ctx = build_v0_3_artifact_rsa(:pss)

      assert :ok =
               Cosign.verify(ctx.manifest_bytes, ctx.sig_artifact, ctx.kms_key_arn)
    end
  end

  describe "verify/3 — sigstore Bundle v0.3 happy path (RSA PKCS#1 v1.5)" do
    @tag timeout: :timer.seconds(60)
    test "verifies a well-formed v0.3 bundle with RSASSA_PKCS1_V1_5_SHA_256 KMS key" do
      # Pinned: cosign 3.x's default RSA-via-KMS signer uses PKCS#1 v1.5
      # (verified 2026-05-08 against the real eddy_smoke bundle via
      # `openssl dgst -verify`). The verifier MUST accept this branch;
      # regression here means production cosign verify on RSA-signed
      # bundles will fail with `:signature_mismatch`.
      ctx = build_v0_3_artifact_rsa(:pkcs1_v1_5)

      assert :ok =
               Cosign.verify(ctx.manifest_bytes, ctx.sig_artifact, ctx.kms_key_arn)
    end
  end

  describe "verify/3 — sigstore Bundle v0.3 subject digest mismatch" do
    test "returns {:error, :payload_digest_mismatch} when bundle's subject doesn't match manifest" do
      ctx = build_v0_3_artifact_ec()
      tampered_manifest_bytes = ctx.manifest_bytes <> <<0xAB>>

      assert {:error, :payload_digest_mismatch} =
               Cosign.verify(tampered_manifest_bytes, ctx.sig_artifact, ctx.kms_key_arn)
    end
  end

  describe "verify/3 — sigstore Bundle v0.3 tampered signature" do
    test "returns {:error, :signature_mismatch} when DSSE signature is flipped" do
      ctx = build_v0_3_artifact_ec()

      bundle = JSON.decode!(ctx.sig_artifact.layer_blob_bytes)
      orig_sig_b64 = get_in(bundle, ["dsseEnvelope", "signatures", Access.at(0), "sig"])
      tampered_sig_b64 = flip_one_bit(orig_sig_b64)

      tampered_bundle =
        put_in(bundle, ["dsseEnvelope", "signatures"], [%{"sig" => tampered_sig_b64}])

      tampered_artifact = %{
        ctx.sig_artifact
        | layer_blob_bytes: JSON.encode!(tampered_bundle)
      }

      assert {:error, reason} =
               Cosign.verify(ctx.manifest_bytes, tampered_artifact, ctx.kms_key_arn)

      assert reason in [:signature_mismatch] or match?({:verify_raised, _}, reason)
    end
  end

  describe "verify/3 — sigstore Bundle v0.3 malformed inputs" do
    test "returns {:error, _} when bundle JSON is invalid" do
      ctx = build_v0_3_artifact_ec()

      bad_artifact = %{ctx.sig_artifact | layer_blob_bytes: "<not-json>"}

      assert {:error, {:malformed_sigstore_bundle, _}} =
               Cosign.verify(ctx.manifest_bytes, bad_artifact, ctx.kms_key_arn)
    end

    test "returns {:error, :sigstore_bundle_missing_dsse_envelope} when bundle has no envelope" do
      ctx = build_v0_3_artifact_ec()

      bundle = JSON.decode!(ctx.sig_artifact.layer_blob_bytes)
      bad_bundle = Map.delete(bundle, "dsseEnvelope")

      bad_artifact = %{ctx.sig_artifact | layer_blob_bytes: JSON.encode!(bad_bundle)}

      assert {:error, :sigstore_bundle_missing_dsse_envelope} =
               Cosign.verify(ctx.manifest_bytes, bad_artifact, ctx.kms_key_arn)
    end

    test "returns {:error, _} when the in-toto Statement type is wrong" do
      ctx = build_v0_3_artifact_ec()

      bundle = JSON.decode!(ctx.sig_artifact.layer_blob_bytes)
      orig_payload_b64 = get_in(bundle, ["dsseEnvelope", "payload"])
      orig_statement = orig_payload_b64 |> Base.decode64!() |> JSON.decode!()
      bad_statement = Map.put(orig_statement, "_type", "https://malicious.example/Statement/v0")
      bad_payload_b64 = bad_statement |> JSON.encode!() |> Base.encode64()

      bad_bundle =
        put_in(bundle, ["dsseEnvelope", "payload"], bad_payload_b64)

      bad_artifact = %{ctx.sig_artifact | layer_blob_bytes: JSON.encode!(bad_bundle)}

      assert {:error, {:unexpected_in_toto_statement_type, _}} =
               Cosign.verify(ctx.manifest_bytes, bad_artifact, ctx.kms_key_arn)
    end
  end

  # =========================================================================
  # Fixtures
  # =========================================================================

  setup do
    previous = Application.get_env(:recurse_providers, :cosign_kms_pubkey_fetcher)

    Application.put_env(
      :recurse_providers,
      :cosign_kms_pubkey_fetcher,
      Recurse.Providers.Impls.OciPolicyProvider.Cosign.TestPubkeyFetcher
    )

    on_exit(fn ->
      if previous do
        Application.put_env(:recurse_providers, :cosign_kms_pubkey_fetcher, previous)
      else
        Application.delete_env(:recurse_providers, :cosign_kms_pubkey_fetcher)
      end
    end)

    :ok
  end

  # ---- simplesigning fixture ------------------------------------------------

  defp build_simplesigning_artifact(opts \\ []) do
    {pem, private_key} =
      case Keyword.get(opts, :private_key) do
        nil -> generate_ec_keypair_pem()
        priv -> {ec_pem_from_private_key(priv), priv}
      end

    manifest_bytes =
      Keyword.get_lazy(opts, :manifest_bytes, fn ->
        JSON.encode!(%{
          "schemaVersion" => 2,
          "mediaType" => "application/vnd.oci.image.manifest.v1+json",
          "artifactType" => "application/vnd.cedar.policy.v1",
          "layers" => [
            %{"mediaType" => "application/vnd.cedar.policy.bundle", "size" => 42}
          ]
        })
      end)

    payload_bytes =
      build_cosign_payload(manifest_bytes, "registry.example.com/cedar-policies/test")

    sig_der = :public_key.sign(payload_bytes, :sha256, private_key)
    sig_b64 = Base.encode64(sig_der)

    sig_manifest = build_simplesigning_manifest(payload_bytes, sig_b64)
    layer = hd(sig_manifest["layers"])

    sig_artifact = %{
      manifest: sig_manifest,
      layer: layer,
      layer_blob_bytes: payload_bytes
    }

    kms_key_arn =
      case Keyword.get(opts, :kms_key_arn) do
        nil ->
          arn = unique_kms_arn()

          Recurse.Providers.Impls.OciPolicyProvider.Cosign.TestPubkeyFetcher.put_pem(arn, pem)

          arn

        arn ->
          arn
      end

    %{
      manifest_bytes: manifest_bytes,
      payload_bytes: payload_bytes,
      private_key: private_key,
      pem: pem,
      kms_key_arn: kms_key_arn,
      signature_b64: sig_b64,
      sig_artifact: sig_artifact
    }
  end

  defp build_cosign_payload(manifest_bytes, docker_reference) do
    digest = "sha256:" <> Base.encode16(:crypto.hash(:sha256, manifest_bytes), case: :lower)

    JSON.encode!(%{
      "critical" => %{
        "identity" => %{"docker-reference" => docker_reference},
        "image" => %{"docker-manifest-digest" => digest},
        "type" => @cosign_payload_type
      },
      "optional" => %{}
    })
  end

  defp build_simplesigning_manifest(payload_bytes, sig_b64) do
    %{
      "schemaVersion" => 2,
      "mediaType" => "application/vnd.oci.image.manifest.v1+json",
      "config" => %{
        "mediaType" => "application/vnd.oci.image.config.v1+json",
        "size" => 0
      },
      "layers" => [
        %{
          "mediaType" => @cosign_simplesigning_media_type,
          "size" => byte_size(payload_bytes),
          "digest" =>
            "sha256:" <> Base.encode16(:crypto.hash(:sha256, payload_bytes), case: :lower),
          "annotations" => %{
            @cosign_signature_annotation => sig_b64
          }
        }
      ]
    }
  end

  # ---- v0.3 sigstore Bundle fixture (ECDSA P-256) ---------------------------

  defp build_v0_3_artifact_ec do
    {pem, private_key} = generate_ec_keypair_pem()
    build_v0_3_artifact_with_key(pem, private_key, &sign_ec/2)
  end

  defp sign_ec(pae_bytes, private_key),
    do: :public_key.sign(pae_bytes, :sha256, private_key)

  # ---- v0.3 sigstore Bundle fixture (RSA, both algorithms) ----------------

  defp build_v0_3_artifact_rsa(algorithm) do
    # RSA-2048 keeps the test fast; algorithm dispatch in the verifier
    # is by key SHAPE, not size, so this exercises the same branch as
    # production's RSA-4096.
    rsa_private = :public_key.generate_key({:rsa, 2048, 65_537})

    pem =
      :public_key.pem_encode([
        :public_key.pem_entry_encode(
          :SubjectPublicKeyInfo,
          extract_rsa_public_from_private(rsa_private)
        )
      ])

    sign_fn =
      case algorithm do
        :pss -> &sign_rsa_pss/2
        :pkcs1_v1_5 -> &sign_rsa_pkcs1_v1_5/2
      end

    build_v0_3_artifact_with_key(pem, rsa_private, sign_fn)
  end

  defp extract_rsa_public_from_private({:RSAPrivateKey, _v, mod, exp, _, _, _, _, _, _, _}),
    do: {:RSAPublicKey, mod, exp}

  defp sign_rsa_pkcs1_v1_5(pae_bytes, rsa_private) do
    # AWS KMS `RSASSA_PKCS1_V1_5_SHA_256` — cosign 3.x default for
    # RSA-via-KMS signing as of 2026-05-08. No padding opts ⇒ OTP
    # defaults to PKCS#1 v1.5, matching what cosign emits.
    :public_key.sign(pae_bytes, :sha256, rsa_private)
  end

  defp sign_rsa_pss(pae_bytes, rsa_private) do
    # `-1` = salt length equal to digest length (32 bytes for SHA-256),
    # matching AWS KMS's `RSASSA_PSS_SHA_256` algorithm exactly. The
    # verify side uses the same value — keep them in lockstep.
    :public_key.sign(pae_bytes, :sha256, rsa_private,
      rsa_padding: :rsa_pkcs1_pss_padding,
      rsa_pss_saltlen: -1,
      rsa_mgf1_md: :sha256
    )
  end

  # ---- v0.3 fixture builder (algorithm-agnostic) ----------------------------

  defp build_v0_3_artifact_with_key(pem, private_key, sign_fn) do
    manifest_bytes =
      JSON.encode!(%{
        "schemaVersion" => 2,
        "mediaType" => "application/vnd.oci.image.manifest.v1+json",
        "artifactType" => "application/vnd.cedar.policy.v1",
        "layers" => [
          %{"mediaType" => "application/vnd.cedar.policy.bundle", "size" => 42}
        ]
      })

    manifest_digest_hex = Base.encode16(:crypto.hash(:sha256, manifest_bytes), case: :lower)

    statement = %{
      "_type" => @in_toto_statement_v1,
      "subject" => [
        %{
          "digest" => %{"sha256" => manifest_digest_hex},
          "annotations" => %{}
        }
      ],
      "predicateType" => "https://sigstore.dev/cosign/sign/v1",
      "predicate" => %{}
    }

    payload_bytes = JSON.encode!(statement)
    pae_bytes = Dsse.pae(@dsse_payload_type, payload_bytes)
    sig_bytes = sign_fn.(pae_bytes, private_key)

    bundle = %{
      "mediaType" => @sigstore_bundle_v0_3_media_type,
      "verificationMaterial" => %{
        "publicKey" => %{"hint" => "test-key-hint"}
      },
      "dsseEnvelope" => %{
        "payloadType" => @dsse_payload_type,
        "payload" => Base.encode64(payload_bytes),
        "signatures" => [%{"sig" => Base.encode64(sig_bytes)}]
      }
    }

    bundle_bytes = JSON.encode!(bundle)

    layer = %{
      "mediaType" => @sigstore_bundle_v0_3_media_type,
      "size" => byte_size(bundle_bytes),
      "digest" => "sha256:" <> Base.encode16(:crypto.hash(:sha256, bundle_bytes), case: :lower)
    }

    sig_manifest = %{
      "schemaVersion" => 2,
      "mediaType" => "application/vnd.oci.image.manifest.v1+json",
      "artifactType" => @sigstore_bundle_v0_3_media_type,
      "layers" => [layer]
    }

    sig_artifact = %{
      manifest: sig_manifest,
      layer: layer,
      layer_blob_bytes: bundle_bytes
    }

    kms_key_arn = unique_kms_arn()
    Recurse.Providers.Impls.OciPolicyProvider.Cosign.TestPubkeyFetcher.put_pem(kms_key_arn, pem)

    %{
      manifest_bytes: manifest_bytes,
      pem: pem,
      private_key: private_key,
      kms_key_arn: kms_key_arn,
      sig_artifact: sig_artifact
    }
  end

  # ---- shared key + util helpers -------------------------------------------

  defp generate_ec_keypair_pem do
    {pub_raw, priv_raw} = :crypto.generate_key(:ecdh, :secp256r1)

    private_key =
      {:ECPrivateKey, 1, priv_raw, {:namedCurve, :secp256r1}, pub_raw, :asn1_NOVALUE}

    pem = ec_pem_from_private_key(private_key)

    {pem, private_key}
  end

  defp ec_pem_from_private_key(private_key) do
    jwk = JOSE.JWK.from_key(private_key)
    pub_jwk = JOSE.JWK.to_public(jwk)
    {_mod, pem} = JOSE.JWK.to_pem(pub_jwk)
    pem
  end

  defp unique_kms_arn do
    suffix = :erlang.ref_to_list(make_ref()) |> to_string()
    "arn:aws:kms:us-west-2:123456789012:key/test-#{Base.encode16(suffix, case: :lower)}"
  end

  # Flip one bit in the *middle* of a base64-decoded blob.
  defp flip_one_bit(b64) do
    {:ok, bytes} = Base.decode64(b64)
    middle = div(byte_size(bytes), 2)
    <<lead::binary-size(middle), b, rest::binary>> = bytes
    flipped = <<lead::binary, Bitwise.bxor(b, 0x01)::8, rest::binary>>
    Base.encode64(flipped)
  end
end
