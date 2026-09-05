defmodule Recurse.Providers.Impls.OciPolicyProvider.Cosign do
  @moduledoc """
  Cosign signature verification against a KMS-backed public key.

  ## Two supported wire formats

  Cosign's signature wire format changed in cosign 3.x. Both shapes
  are supported here; the verifier sniffs the `.sig` artifact's
  layer mediaType to dispatch.

  ### A. cosign 2.x — "simplesigning"

      mediaType: application/vnd.dev.cosign.simplesigning.v1+json

  The `.sig` manifest carries one layer whose blob is a small JSON
  payload:

      {
        "critical": {
          "identity":  {"docker-reference": "<registry>/<repo>"},
          "image":     {"docker-manifest-digest": "sha256:<hex>"},
          "type":      "cosign container image signature"
        },
        "optional": {}
      }

  The layer descriptor's `annotations[\"dev.cosignproject.cosign/signature\"]`
  carries the base64-encoded signature. Algorithm is ECDSA P-256 / SHA-256
  for our profile (KMS keys with `KeyUsage=SIGN_VERIFY`,
  `SigningAlgorithm=ECDSA_SHA_256`); the signature bytes are DER-encoded
  ASN.1 `SEQUENCE { INTEGER r, INTEGER s }` directly consumable by
  `:public_key.verify/4`. Verification is over the **raw simplesigning
  payload bytes** (no PAE).

  ### B. cosign 3.x — "sigstore Bundle v0.3"

      mediaType: application/vnd.dev.sigstore.bundle.v0.3+json

  The `.sig` manifest carries one layer whose blob is a sigstore Bundle
  v0.3 JSON document:

      {
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "verificationMaterial": { "publicKey": { "hint": "<base64>" } },
        "dsseEnvelope": {
          "payload": "<base64 in-toto Statement v1 JSON>",
          "payloadType": "application/vnd.in-toto+json",
          "signatures": [{"sig": "<base64 raw signature>"}]
        }
      }

  The base64-decoded `dsseEnvelope.payload` is an in-toto Statement v1:

      {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"digest": {"sha256": "<hex>"}, "annotations": {}}],
        "predicateType": "https://sigstore.dev/cosign/sign/v1",
        "predicate": {}
      }

  The signed bytes are the **DSSE PAE encoding** of `(payloadType,
  payload_bytes)`:

      DSSEv1 SP LEN(payloadType) SP payloadType SP LEN(payload) SP payload

  Algorithm detection is from the OTP public-key record returned by
  `:public_key.pem_entry_decode/1` — see `verify_signature/4` for the
  per-algorithm `:public_key.verify/4` invocation. Our cosign CMK is
  RSA-4096 with `SigningAlgorithm=RSASSA_PSS_SHA_256` per the
  audit-dev / audit-demo deploy comments; the verifier handles both
  RSA-PSS-SHA-256 and ECDSA-P256-SHA-256 transparently so the same
  primitive works against the platform-roles bundle (ECDSA P-256 if
  ever published) and the eddy_smoke fixture (RSA-4096 PSS).

  ## Subject-digest binding (both formats)

  Both formats carry a "claimed manifest digest" inside the signed
  payload. The verifier asserts it matches the SHA-256 of the actual
  bundle manifest bytes BEFORE the cryptographic verify, so an attacker
  who flips the manifest content (without a matching new signature)
  fails the verify regardless of whether they could re-sign.

    * simplesigning: `payload.critical.image.docker-manifest-digest`
    * v0.3 bundle:   `dsseEnvelope.payload.subject[0].digest.sha256`

  ## KMS public-key cache

  Stored in `:persistent_term` keyed by
  `{:cosign_kms_pubkey, kms_key_arn}` as
  `{otp_public_key_record, fetched_at_ms_monotonic}`. TTL is one hour;
  on TTL expiry OR on a verification failure (could be a key rotation)
  we drop the cache entry and refetch on the next call.

  Persistent-term is the right primitive here: the cache is
  read-without-copy on the BEAM, written once per refresh, and
  cosign keys are stable across the artifact's lifetime. ETS would
  force a copy on every cross-process read on a hot path.

  ## Test injection

  Production fetches the KMS public key via `ExAws.KMS.get_public_key/1`
  through the normal `ex_aws` retry/timeout machinery. Tests override
  the fetcher module via the application env key
  `:cosign_kms_pubkey_fetcher` (a module exporting
  `fetch_public_key_der/1` returning `{:ok, der_bytes} | {:error, term()}`).
  """

  @behaviour Recurse.Providers.Impls.OciPolicyProvider.CosignBehaviour

  alias Recurse.Providers.Impls.OciPolicyProvider.FetcherBehaviour
  alias Recurse.Shared.Attestation.Dsse

  require Logger

  @cache_ttl_ms :timer.hours(1)

  # cosign 2.x layer mediaType
  @cosign_simplesigning_media_type "application/vnd.dev.cosign.simplesigning.v1+json"
  @cosign_signature_annotation "dev.cosignproject.cosign/signature"
  @cosign_payload_type "cosign container image signature"

  # cosign 3.x sigstore Bundle v0.3 layer mediaType
  @sigstore_bundle_v0_3_media_type "application/vnd.dev.sigstore.bundle.v0.3+json"
  @in_toto_statement_v1 "https://in-toto.io/Statement/v1"

  @type kms_pubkey_fetcher :: module()

  @doc """
  Verify a cosign signature artifact against the KMS-backed public key.
  See @moduledoc for the two supported wire formats and the
  per-format verification pipelines.
  """
  @impl true
  @spec verify(
          manifest_bytes :: binary(),
          sig_artifact :: FetcherBehaviour.signature_artifact(),
          kms_key_arn :: String.t()
        ) :: :ok | {:error, term()}
  def verify(manifest_bytes, sig_artifact, kms_key_arn)
      when is_binary(manifest_bytes) and is_map(sig_artifact) and is_binary(kms_key_arn) do
    with {:ok, layer} <- fetch_layer(sig_artifact),
         {:ok, blob_bytes} <- fetch_blob(sig_artifact),
         {:ok, format} <- detect_format(layer) do
      case format do
        :simplesigning ->
          verify_simplesigning(manifest_bytes, layer, blob_bytes, kms_key_arn)

        :sigstore_bundle_v0_3 ->
          verify_sigstore_bundle_v0_3(manifest_bytes, blob_bytes, kms_key_arn)
      end
    end
  end

  # --- artifact-tuple plucking ----------------------------------------------

  defp fetch_layer(%{layer: layer}) when is_map(layer), do: {:ok, layer}
  defp fetch_layer(_), do: {:error, :sig_artifact_missing_layer}

  defp fetch_blob(%{layer_blob_bytes: bytes}) when is_binary(bytes), do: {:ok, bytes}
  defp fetch_blob(_), do: {:error, :sig_artifact_missing_layer_blob}

  @spec detect_format(map()) ::
          {:ok, :simplesigning | :sigstore_bundle_v0_3} | {:error, term()}
  defp detect_format(%{"mediaType" => @cosign_simplesigning_media_type}),
    do: {:ok, :simplesigning}

  defp detect_format(%{"mediaType" => @sigstore_bundle_v0_3_media_type}),
    do: {:ok, :sigstore_bundle_v0_3}

  defp detect_format(%{"mediaType" => other}),
    do: {:error, {:unknown_signature_format, other}}

  defp detect_format(_), do: {:error, :signature_layer_missing_media_type}

  # --- A. cosign 2.x simplesigning verifier ---------------------------------

  defp verify_simplesigning(manifest_bytes, layer, blob_bytes, kms_key_arn) do
    with {:ok, sig_bytes} <- extract_simplesigning_signature(layer),
         :ok <- assert_simplesigning_payload_digest(blob_bytes, manifest_bytes),
         {:ok, public_key} <- fetch_public_key(kms_key_arn),
         :ok <- verify_signature(blob_bytes, sig_bytes, public_key, kms_key_arn) do
      :ok
    end
  end

  defp extract_simplesigning_signature(%{"annotations" => %{} = annotations}) do
    case Map.get(annotations, @cosign_signature_annotation) do
      nil ->
        {:error, :signature_annotation_missing}

      sig_b64 when is_binary(sig_b64) ->
        case Base.decode64(sig_b64) do
          {:ok, sig} -> {:ok, sig}
          :error -> {:error, :signature_annotation_not_base64}
        end

      _ ->
        {:error, :signature_annotation_not_a_string}
    end
  end

  defp extract_simplesigning_signature(_), do: {:error, :signature_annotation_missing}

  defp assert_simplesigning_payload_digest(payload_bytes, manifest_bytes) do
    expected = "sha256:" <> Base.encode16(:crypto.hash(:sha256, manifest_bytes), case: :lower)

    with {:ok, payload} <- decode_json_object(payload_bytes, :malformed_cosign_payload),
         {:ok, claimed} <- pluck_simplesigning_claimed_digest(payload),
         {:ok, type} <- pluck_simplesigning_payload_type(payload),
         :ok <- assert_simplesigning_payload_type(type) do
      if claimed == expected do
        :ok
      else
        {:error, :payload_digest_mismatch}
      end
    end
  end

  defp pluck_simplesigning_claimed_digest(%{
         "critical" => %{"image" => %{"docker-manifest-digest" => digest}}
       })
       when is_binary(digest),
       do: {:ok, digest}

  defp pluck_simplesigning_claimed_digest(_), do: {:error, :payload_missing_manifest_digest}

  defp pluck_simplesigning_payload_type(%{"critical" => %{"type" => type}}) when is_binary(type),
    do: {:ok, type}

  defp pluck_simplesigning_payload_type(_), do: {:error, :payload_missing_type}

  defp assert_simplesigning_payload_type(@cosign_payload_type), do: :ok
  defp assert_simplesigning_payload_type(other), do: {:error, {:unexpected_payload_type, other}}

  # --- B. cosign 3.x sigstore Bundle v0.3 verifier --------------------------

  defp verify_sigstore_bundle_v0_3(manifest_bytes, bundle_bytes, kms_key_arn) do
    with {:ok, bundle} <- decode_json_object(bundle_bytes, :malformed_sigstore_bundle),
         :ok <- assert_bundle_media_type(bundle),
         {:ok, envelope} <- pluck_dsse_envelope(bundle),
         {:ok, payload_bytes} <- decode_dsse_payload(envelope),
         {:ok, payload_type} <- pluck_dsse_payload_type(envelope),
         {:ok, sig_bytes} <- decode_dsse_signature(envelope),
         :ok <- assert_v0_3_subject_digest(payload_bytes, manifest_bytes),
         {:ok, public_key} <- fetch_public_key(kms_key_arn),
         pae_bytes = Dsse.pae(payload_type, payload_bytes),
         :ok <- verify_signature(pae_bytes, sig_bytes, public_key, kms_key_arn) do
      :ok
    end
  end

  defp assert_bundle_media_type(%{"mediaType" => @sigstore_bundle_v0_3_media_type}), do: :ok

  defp assert_bundle_media_type(%{"mediaType" => other}),
    do: {:error, {:unexpected_bundle_media_type, other}}

  # The bundle JSON's top-level mediaType is a defense-in-depth check
  # (the layer mediaType already passed this discriminator); a missing
  # field is non-fatal because some implementations omit it.
  defp assert_bundle_media_type(_), do: :ok

  defp pluck_dsse_envelope(%{"dsseEnvelope" => %{} = env}), do: {:ok, env}
  defp pluck_dsse_envelope(_), do: {:error, :sigstore_bundle_missing_dsse_envelope}

  defp decode_dsse_payload(%{"payload" => payload_b64}) when is_binary(payload_b64) do
    case Base.decode64(payload_b64) do
      {:ok, bytes} -> {:ok, bytes}
      :error -> {:error, :dsse_payload_not_base64}
    end
  end

  defp decode_dsse_payload(_), do: {:error, :dsse_envelope_missing_payload}

  defp pluck_dsse_payload_type(%{"payloadType" => type}) when is_binary(type), do: {:ok, type}
  defp pluck_dsse_payload_type(_), do: {:error, :dsse_envelope_missing_payload_type}

  # The DSSE wire format permits multiple signatures (multi-key
  # attestation). For cosign-sign output there's exactly one — we
  # take the first and reject any other shape.
  defp decode_dsse_signature(%{"signatures" => [%{"sig" => sig_b64} | _]})
       when is_binary(sig_b64) do
    case Base.decode64(sig_b64) do
      {:ok, sig} -> {:ok, sig}
      :error -> {:error, :dsse_signature_not_base64}
    end
  end

  defp decode_dsse_signature(_), do: {:error, :dsse_envelope_missing_signature}

  defp assert_v0_3_subject_digest(payload_bytes, manifest_bytes) do
    expected_hex = Base.encode16(:crypto.hash(:sha256, manifest_bytes), case: :lower)

    with {:ok, statement} <- decode_json_object(payload_bytes, :malformed_in_toto_statement),
         :ok <- assert_in_toto_statement_type(statement),
         {:ok, claimed_hex} <- pluck_v0_3_subject_digest(statement) do
      if claimed_hex == expected_hex do
        :ok
      else
        {:error, :payload_digest_mismatch}
      end
    end
  end

  defp assert_in_toto_statement_type(%{"_type" => @in_toto_statement_v1}), do: :ok

  defp assert_in_toto_statement_type(%{"_type" => other}),
    do: {:error, {:unexpected_in_toto_statement_type, other}}

  defp assert_in_toto_statement_type(_), do: {:error, :in_toto_statement_missing_type}

  defp pluck_v0_3_subject_digest(%{
         "subject" => [%{"digest" => %{"sha256" => hex}} | _]
       })
       when is_binary(hex) do
    {:ok, String.downcase(hex)}
  end

  defp pluck_v0_3_subject_digest(_),
    do: {:error, :in_toto_statement_missing_subject_digest}

  # --- shared: JSON helpers --------------------------------------------------

  defp decode_json_object(bytes, error_tag) do
    case JSON.decode(bytes) do
      {:ok, %{} = map} -> {:ok, map}
      {:ok, _other} -> {:error, {error_tag, :not_a_map}}
      {:error, reason} -> {:error, {error_tag, reason}}
    end
  end

  # --- shared: KMS public-key cache + algorithm-aware verify ---------------

  @spec fetch_public_key(String.t()) :: {:ok, term()} | {:error, term()}
  defp fetch_public_key(kms_key_arn) do
    cache_key = cache_key(kms_key_arn)
    now_ms = System.monotonic_time(:millisecond)

    case :persistent_term.get(cache_key, :miss) do
      {public_key, fetched_at_ms} when now_ms - fetched_at_ms <= @cache_ttl_ms ->
        {:ok, public_key}

      _ ->
        fetch_and_cache_public_key(kms_key_arn, cache_key)
    end
  end

  defp fetch_and_cache_public_key(kms_key_arn, cache_key) do
    fetcher = pubkey_fetcher_module()

    case fetcher.fetch_public_key_der(kms_key_arn) do
      {:ok, der_bytes} when is_binary(der_bytes) ->
        case decode_spki_der(der_bytes) do
          {:ok, public_key} ->
            :persistent_term.put(cache_key, {public_key, System.monotonic_time(:millisecond)})

            Logger.info("OciPolicyProvider.Cosign cached KMS public key for #{kms_key_arn}")

            {:ok, public_key}

          {:error, reason} = err ->
            Logger.warning(
              "OciPolicyProvider.Cosign failed to decode KMS public key for #{kms_key_arn}: #{inspect(reason)}"
            )

            err
        end

      {:ok, _other} ->
        {:error, {:kms_response_malformed, :public_key_not_binary}}

      {:error, reason} = err ->
        Logger.warning(
          "OciPolicyProvider.Cosign failed to fetch KMS public key for #{kms_key_arn}: #{inspect(reason)}"
        )

        err
    end
  end

  # KMS returns the SubjectPublicKeyInfo as DER. Convert to the
  # decoded `:public_key`-record OTP wants for `:public_key.verify/4`.
  # Accept a PEM directly (test fixtures sometimes pass PEM).
  @spec decode_spki_der(binary()) :: {:ok, term()} | {:error, term()}
  defp decode_spki_der(<<"-----BEGIN", _rest::binary>> = pem) do
    Dsse.pem_to_public_key(pem)
  end

  defp decode_spki_der(der_bytes) when is_binary(der_bytes) do
    pem_entry = {:SubjectPublicKeyInfo, der_bytes, :not_encrypted}
    {:ok, :public_key.pem_entry_decode(pem_entry)}
  rescue
    err -> {:error, {:spki_decode_raised, err}}
  end

  defp cache_key(kms_key_arn), do: {:cosign_kms_pubkey, kms_key_arn}

  defp pubkey_fetcher_module do
    Application.get_env(
      :recurse_providers,
      :cosign_kms_pubkey_fetcher,
      __MODULE__.DefaultKmsPubkeyFetcher
    )
  end

  # --- shared: signature verify with key-shape dispatch --------------------

  # Algorithm dispatch via the OTP public-key record's tuple shape:
  #
  #   * `{:RSAPublicKey, _modulus, _exponent}` — RSA-4096 key (our cosign
  #     CMK profile). KMS signs these with `RSASSA_PSS_SHA_256`; verify
  #     with `:public_key.verify/4`'s PSS opts. Signature bytes are the
  #     raw PSS output (no DER wrapping).
  #
  #   * `{{:ECPoint, _point}, {:namedCurve, _oid}}` — ECDSA on a named
  #     curve (typically secp256r1 / P-256 for cosign). KMS signs these
  #     with `ECDSA_SHA_256`; signature bytes are ASN.1 DER-encoded
  #     `SEQUENCE { INTEGER r, INTEGER s }` directly consumable by
  #     `:public_key.verify/4` with no algorithm opts.
  #
  # On verify failure we drop the cached public key for `kms_key_arn` —
  # a verify-fail is most often a malformed signature OR a wrong-key
  # condition, but it can also signal a KMS-side rotation we missed.
  # The next call refetches.
  @spec verify_signature(binary(), binary(), term(), String.t()) ::
          :ok | {:error, term()}
  defp verify_signature(signed_bytes, sig_bytes, public_key, kms_key_arn) do
    case do_verify_signature(signed_bytes, sig_bytes, public_key) do
      :ok ->
        :ok

      {:error, _reason} = err ->
        :persistent_term.erase(cache_key(kms_key_arn))
        err
    end
  end

  defp do_verify_signature(signed_bytes, sig_bytes, {:RSAPublicKey, _, _} = public_key) do
    # AWS KMS RSA keys (`KeyUsage=SIGN_VERIFY`, key spec RSA_*) support
    # BOTH `RSASSA_PKCS1_V1_5_SHA_*` and `RSASSA_PSS_SHA_*` signing
    # algorithms. Cosign 3.x's default RSA-via-KMS signer chose PKCS#1
    # v1.5 when signing the eddy_smoke fixture (verified empirically
    # 2026-05-08 via `openssl dgst -verify`: PSS rejected with `last
    # octet invalid`; PKCS#1 v1.5 returned `Verified OK`).
    #
    # We try PKCS#1 v1.5 first (cosign 3.x default + the algorithm
    # actually in use on our cosign CMK as of this writing) and fall
    # back to PSS-SHA256 (saltlen = digest length, MGF1 = SHA-256, the
    # AWS KMS PSS profile) on mismatch. This keeps the verifier
    # compatible with both algorithm choices without hard-coding
    # which one is in use — important because the KMS key supports
    # both and the same primitive may need to handle bundles signed
    # by `AwsKmsSecretsProvider` (which signs with PSS per the
    # audit-dev.yaml `KMS_ALGORITHM=RSASSA_PSS_SHA_256` comment) at
    # some future date.
    case :public_key.verify(signed_bytes, :sha256, sig_bytes, public_key) do
      true ->
        :ok

      false ->
        # PSS fallback. `-1` is the OTP sentinel meaning "salt = digest
        # length" — matches AWS KMS's `RSASSA_PSS_SHA_256` profile.
        case :public_key.verify(signed_bytes, :sha256, sig_bytes, public_key,
               rsa_padding: :rsa_pkcs1_pss_padding,
               rsa_pss_saltlen: -1,
               rsa_mgf1_md: :sha256
             ) do
          true -> :ok
          false -> {:error, :signature_mismatch}
        end
    end
  rescue
    err -> {:error, {:verify_raised, err}}
  end

  defp do_verify_signature(signed_bytes, sig_bytes, {{:ECPoint, _}, _} = public_key) do
    case :public_key.verify(signed_bytes, :sha256, sig_bytes, public_key) do
      true -> :ok
      false -> {:error, :signature_mismatch}
    end
  rescue
    err -> {:error, {:verify_raised, err}}
  end

  defp do_verify_signature(_signed, _sig, public_key) do
    {:error, {:unsupported_public_key_shape, key_shape_summary(public_key)}}
  end

  # Don't include the full key (potentially leaks bits) — just the
  # outer tuple shape so operators can identify what algorithm path
  # is missing.
  defp key_shape_summary(tuple) when is_tuple(tuple) do
    case elem(tuple, 0) do
      atom when is_atom(atom) -> atom
      _ -> :unknown_tuple_head
    end
  end

  defp key_shape_summary(_), do: :unknown_term

  defmodule DefaultKmsPubkeyFetcher do
    @moduledoc """
    Production fetcher for `Recurse.Providers.Impls.OciPolicyProvider.Cosign`'s
    KMS public-key cache. Calls `kms:GetPublicKey` via ex_aws and base64-decodes
    the `PublicKey` field into raw DER `SubjectPublicKeyInfo` bytes.

    ## Region resolution

    The KMS region is parsed FROM the input `kms_key_arn` (which is
    always a fully-qualified ARN like
    `arn:aws:kms:us-west-2:123456789012:alias/r5e-cosign` per the
    OciPolicyProvider's `R5E_CEDAR_COSIGN_KEY_ARN` env contract).
    Region is then passed explicitly as an `ExAws.request/2` opt.

    Why explicit instead of relying on ExAws's default chain
    (`AWS_REGION` env -> Application config -> profile -> default):
    audit-dev's pod has `AWS_REGION=us-west-2` set, but ExAws's
    request-building doesn't always pick that up cleanly when the
    KMS API is invoked from a Provider-init context where ExAws has
    not yet been "warmed" by other AWS calls in the same BEAM. The
    observed failure mode was `NotFoundException: Invalid arn
    us-west-2` — KMS hit the WRONG region's endpoint and refused the
    `us-west-2`-scoped alias ARN. Parsing region from the ARN
    sidesteps the resolution race and is also the right shape: an
    ARN is self-describing about its region.

    Tests override the whole fetcher module via the Application env
    key `:cosign_kms_pubkey_fetcher`, so this region-from-ARN logic
    is exercised only in production.
    """

    @doc """
    Fetch the DER-encoded SubjectPublicKeyInfo for `kms_key_arn`. Returns
    raw DER bytes (base64 already stripped).
    """
    @spec fetch_public_key_der(String.t()) :: {:ok, binary()} | {:error, term()}
    def fetch_public_key_der(kms_key_arn) when is_binary(kms_key_arn) do
      with {:ok, region} <- parse_region_from_arn(kms_key_arn) do
        kms_key_arn
        |> ExAws.KMS.get_public_key()
        |> ExAws.request(region: region)
        |> case do
          {:ok, %{"PublicKey" => der_b64}} when is_binary(der_b64) ->
            decode_public_key(der_b64)

          {:ok, body} ->
            {:error, {:kms_response_malformed, body}}

          {:error, reason} ->
            {:error, reason}
        end
      end
    end

    defp decode_public_key(der_b64) do
      case Base.decode64(der_b64) do
        {:ok, der_bytes} -> {:ok, der_bytes}
        :error -> {:error, {:kms_response_malformed, :public_key_not_base64}}
      end
    end

    # ARN shape: arn:aws:kms:<region>:<account>:<key-or-alias>/<id>
    # The 4th colon-separated field is the region. We deliberately do
    # NOT accept bare key IDs / alias names — the OciPolicyProvider
    # contract is full-ARN only (validated upstream), so a non-ARN
    # input here is a contract violation worth surfacing.
    @spec parse_region_from_arn(String.t()) :: {:ok, String.t()} | {:error, term()}
    defp parse_region_from_arn(arn) do
      case String.split(arn, ":", parts: 6) do
        ["arn", "aws", "kms", region, _account, _resource]
        when is_binary(region) and region != "" ->
          {:ok, region}

        _ ->
          {:error, {:kms_arn_malformed, arn}}
      end
    end
  end
end
