defmodule Recurse.Shared.Attestation.Dsse do
  @moduledoc """
  DSSE (Dead Simple Signing Envelope) ITE-5 encoder / decoder with PAE
  (Pre-Authentication Encoding).

  Per [DSSE ITE-5](https://github.com/secure-systems-lab/dsse) and
  research D9 (`jose` library chosen for BEAM signing). PAE format
  (protocol / §2):

      "DSSEv1" SP LEN(type) SP type SP LEN(payload) SP payload

  where `LEN(x)` is the ASCII-decimal byte length and `SP` is 0x20.
  PAE is what gets signed; it binds the `payloadType` to the
  `payload` so a signature over one type cannot be replayed as
  another.

  ## Phase-1 scope

    * `pae/2` — byte-stable PAE assembly. FULLY implemented;
      property-tested for round-trip byte stability.
    * `encode/4` — structural envelope assembly. Uses `:jose` for the
      actual cryptographic signing.
    * `decode/1` — parse envelope map (Base64-decode the payload and
      per-signature `sig` fields).
    * `verify/2` — DSSE signature verification. Structural shell in
      Phase 1; returns `{:unverified, payload}` so callers CANNOT
      pattern-match `{:ok, payload}` and assume the signature was
      checked. Feature 002+ will swap this for a real verification
      path that returns `{:ok, payload}` on success and `{:error,
      reason}` on failure, at which point the `:unverified` tag goes
      away. Any call site relying on `{:ok, _}` will break at that
      boundary and force an explicit upgrade — which is the point.

  The DSSE envelope shape (per ITE-5):

      {
        "payloadType": "application/vnd.in-toto+json",
        "payload": "<base64(payload bytes)>",
        "signatures": [
          {"keyid": "<string>", "sig": "<base64(sig bytes)>"}
        ]
      }

  For property-test purposes the round-trip `encode → decode` returns
  identical payload bytes and PAE assembly is byte-stable.
  """

  @type payload_type :: String.t()
  @type payload :: binary()
  @type signer_key :: JOSE.JWK.t() | map()
  @type envelope :: %{
          required(String.t()) => String.t() | [map()]
        }

  @doc """
  DSSE Pre-Authentication Encoding per spec.

      "DSSEv1" SP LEN(type) SP type SP LEN(payload) SP payload
  """
  @spec pae(payload_type(), payload()) :: binary()
  def pae(type, payload) when is_binary(type) and is_binary(payload) do
    type_len = Integer.to_string(byte_size(type))
    payload_len = Integer.to_string(byte_size(payload))

    IO.iodata_to_binary([
      "DSSEv1",
      " ",
      type_len,
      " ",
      type,
      " ",
      payload_len,
      " ",
      payload
    ])
  end

  @doc """
  Encode a DSSE envelope: sign the PAE with the given key and assemble
  the ITE-5 envelope map.

  `signer_key` is a `%JOSE.JWK{}` or a JWK-compatible map. `key_id` is
  the stable key identifier emitted into the signature block (FR-046
  document-signing-key reference).
  """
  @spec encode(payload_type(), payload(), signer_key(), String.t()) :: envelope()
  def encode(type, payload, signer_key, key_id)
      when is_binary(type) and is_binary(payload) and is_binary(key_id) do
    pae_bytes = pae(type, payload)

    jwk = to_jwk(signer_key)
    alg = infer_alg(jwk)

    {_headers, sig_bytes} = sign(jwk, alg, pae_bytes)

    %{
      "payloadType" => type,
      "payload" => Base.encode64(payload),
      "signatures" => [
        %{
          "keyid" => key_id,
          "sig" => Base.encode64(sig_bytes)
        }
      ]
    }
  end

  @doc """
  Decode a DSSE envelope map, returning the raw payload bytes and a
  list of `{key_id, signature_bytes}` tuples.
  """
  @spec decode(envelope()) ::
          {:ok,
           %{
             payload_type: payload_type(),
             payload: payload(),
             signatures: [%{key_id: String.t() | nil, sig: binary()}]
           }}
          | {:error, term()}
  def decode(%{"payloadType" => type, "payload" => payload_b64, "signatures" => sigs})
      when is_binary(type) and is_binary(payload_b64) and is_list(sigs) do
    with {:ok, payload} <- Base.decode64(payload_b64),
         {:ok, decoded_sigs} <- decode_signatures(sigs) do
      {:ok,
       %{
         payload_type: type,
         payload: payload,
         signatures: decoded_sigs
       }}
    else
      :error -> {:error, :invalid_base64}
      other -> other
    end
  end

  def decode(_), do: {:error, :malformed_envelope}

  @doc """
  Verify a DSSE envelope against the provided key (or keys keyed by
  `keyid`).

  **Phase-1 shell** — returns `{:unverified, payload}` on a structurally
  valid envelope without checking the signature. The `:unverified` tag
  is deliberate: callers MUST NOT treat this as verified, and the
  `{:ok, _}` shape is reserved for Feature-002+ once real verification
  lands. Any caller pattern-matching `{:ok, payload}` today will fail
  to compile or fail at runtime — which is the point: re-route the
  call site to either `{:unverified, _}` (Phase-1 intentional) or
  upgrade-to-`{:ok, _}` when Feature 002+ ships real verify.

  Structural-failure paths still return `{:error, reason}` (bad base64,
  malformed envelope, etc.), so `with {:unverified, payload} <- ...`
  remains the right way to call this in Phase 1.

  TODO(Feature 002+): implement full verification once the
  `SigningKey` table and `SecretsProvider` plumbing land. Tracks
  tasks.md T073 (auditor worked examples) and the Runtime Attestation
  Emitter module.
  """
  @spec verify(envelope(), signer_key() | %{String.t() => signer_key()}) ::
          {:unverified, payload()} | {:error, term()}
  def verify(envelope, key_or_keys) do
    with {:ok, decoded} <- decode(envelope),
         pae_bytes = pae(decoded.payload_type, decoded.payload),
         {:ok, _} <- verify_signatures(decoded.signatures, pae_bytes, key_or_keys) do
      {:unverified, decoded.payload}
    end
  end

  @doc """
  Low-level DSSE ES256 (ECDSA P-256 with SHA-256) signature verification
  primitive — verifies a single DSSE-shaped signature against an
  already-decoded predicate payload + signing-key PEM.

  Issue #29 / Principle VII: this used to be inlined inside
  `LocalVerifyHandler` (under `apps/recurse_gateway/...`) as
  `verify_dsse_signature/3` plus four private helpers
  (`pem_to_public_key/1`, `raw_to_ecdsa_der/2`, `wrap_sequence/1`,
  `strip_leading_zeros_then_pad_for_asn1/1`). When a second verifier
  appeared (the held MR !30 for `EvidenceZipBuilder`'s sign-check on
  export, which the audit-pass charter retired) the same primitives
  would have duplicated. Lifted here so any present or future verifier
  shares the same battle-tested ASN.1 decode + `:public_key.verify/4`
  call.

  ## Why a separate function instead of upgrading `verify/2`

  `Dsse.verify/2` is documented as a Phase-1 structural shell that
  returns `{:unverified, payload}` — callers MUST NOT pattern-match
  `{:ok, _}` against it. Converting `verify/2` to actually verify is
  an explicit Feature-002+ contract change (see this module's
  `verify/2` doc TODO). That change is out of scope for issue #29's
  refactor — the F004 retrofit's call sites already know the
  `(predicate_bytes, signature, pem)` triple, so they call this
  primitive directly. The `verify/2` shell stays as-is until the
  F002+ contract upgrade lands.

  ## Algorithm

  ECDSA P-256 / SHA-256 per F002 D4 + DSSE ITE-5 wire format:

    1. Reassemble PAE — `pae(@dsse_payload_type, predicate_bytes)`.
       Caller supplies the type via `payload_type` argument.
    2. Decode the PEM into an OTP `:public_key` record.
    3. Normalize the signature into ASN.1 DER (the format
       `:public_key.verify/4` requires). DSSE raw `r || s` (64 bytes
       for P-256) goes through `raw_to_ecdsa_der/2`; pre-DER input
       (70-72 bytes, prefix `0x30`) is passed through. See F7
       follow-up — production receipts on audit-dev arrive DER-encoded
       from KMS / the broker, not as DSSE raw.
    4. Call `:public_key.verify(pae, :sha256, der, key)`.

  Returns `:ok` if the signature verifies, `{:error, reason}` otherwise.
  Errors that originate from malformed inputs (invalid PEM, wrong-length
  signature) come back as specific atoms rather than crashes — the
  caller renders them in the verify-checklist UI.
  """
  @spec verify_es256(
          payload_type :: payload_type(),
          predicate_bytes :: binary(),
          signature :: binary(),
          pem :: String.t()
        ) ::
          :ok
          | {:error,
             :signature_mismatch
             | :invalid_signature_format
             | :invalid_pem
             | {:pem_decode_raised, term()}
             | term()}
  def verify_es256(payload_type, predicate_bytes, signature, pem)
      when is_binary(payload_type) and is_binary(predicate_bytes) and is_binary(signature) and
             is_binary(pem) do
    pae_bytes = pae(payload_type, predicate_bytes)

    with {:ok, otp_public_key} <- pem_to_public_key(pem),
         {:ok, der} <- normalize_es256_signature(signature),
         true <- :public_key.verify(pae_bytes, :sha256, der, otp_public_key) do
      :ok
    else
      false -> {:error, :signature_mismatch}
      {:error, reason} -> {:error, reason}
    end
  end

  # F7 follow-up: production receipts on audit-dev have DER-encoded ECDSA
  # signatures (70-72 bytes, prefix 0x30 ASN.1 SEQUENCE) — they come back
  # from KMS / the broker pre-encoded as DER. The original Phase-1
  # `verify_es256/4` only accepted DSSE raw `r || s` (exactly 64 bytes) and
  # ran them through `raw_to_ecdsa_der/2`, returning `nil` for any other
  # shape. Result: every production receipt failed verification with
  # `:invalid_signature_format` even when the signature was cryptographically
  # valid. `:public_key.verify/4` already wants DER, so when the signature
  # is already DER we pass it straight through; raw-format inputs still go
  # through the existing `raw_to_ecdsa_der/2` path for the JOSE-encoded path
  # used by `Dsse.encode/4`.
  #
  # Discrimination strategy: length-first, then prefix.
  #
  #   * 64 bytes → raw `r || s`. P-256 raw is exactly 64 bytes and DER for
  #     P-256 is *never* 64 bytes (DER's minimum with two random 32-byte
  #     INTEGERs and the SEQUENCE wrapper is ~70 bytes; smaller only with
  #     extreme leading-zero stripping that doesn't occur for cryptographic
  #     randomness). So length=64 is unambiguously raw.
  #
  #   * 70-72 bytes starting with 0x30 → DER `SEQUENCE { INTEGER r,
  #     INTEGER s }`. R and S are 32 bytes each; ASN.1 INTEGER encoding may
  #     prepend a 0x00 padding byte to either when the high bit is set
  #     (giving 33 bytes); SEQUENCE adds 2 bytes of header and each INTEGER
  #     adds 2 bytes of tag+length, yielding 70 (no padding), 71 (one
  #     padded), or 72 (both padded).
  #
  #   * Anything else → `:invalid_signature_format`.
  #
  # Rejecting non-{64, 70-72} avoids the 1/256 risk that a random 32-byte
  # blob coincidentally starts with 0x30 and gets fed to `:public_key.verify/4`.
  @spec normalize_es256_signature(binary()) ::
          {:ok, binary()} | {:error, :invalid_signature_format}
  defp normalize_es256_signature(<<r::binary-size(32), s::binary-size(32)>>) do
    case raw_to_ecdsa_der(<<r::binary, s::binary>>, 32) do
      der when is_binary(der) -> {:ok, der}
      nil -> {:error, :invalid_signature_format}
    end
  end

  defp normalize_es256_signature(<<0x30, _rest::binary>> = der)
       when byte_size(der) in 70..72 do
    {:ok, der}
  end

  defp normalize_es256_signature(_), do: {:error, :invalid_signature_format}

  @doc """
  Decode a PEM-encoded SubjectPublicKeyInfo into an OTP `:public_key`
  record. Used by `verify_es256/4`. Returns `{:error, :invalid_pem}` if
  the PEM is malformed; `{:error, {:pem_decode_raised, term}}` if a
  PEM-decode raise escapes (some malformed inputs make `:public_key`
  raise rather than return an empty list).
  """
  @spec pem_to_public_key(pem :: String.t()) :: {:ok, term()} | {:error, term()}
  def pem_to_public_key(pem) when is_binary(pem) do
    case :public_key.pem_decode(pem) do
      [{:SubjectPublicKeyInfo, _, _} = entry | _] ->
        {:ok, :public_key.pem_entry_decode(entry)}

      _ ->
        {:error, :invalid_pem}
    end
  rescue
    err -> {:error, {:pem_decode_raised, err}}
  end

  @doc """
  Identify the signature algorithm a PEM-encoded SubjectPublicKeyInfo
  verifies, from the decoded OTP record's shape:

    * P-256 EC point → `:ecdsa_p256` (what `verify_es256/4` handles)
    * Ed25519 point (OID 1.3.101.112) → `:ed25519`
    * RSA public key → `:rsa`

  Verifiers dispatch on this BEFORE calling `verify_es256/4`: an Ed25519
  signature is 64 bytes, exactly the size of a raw ES256 `r || s`, so
  feeding it to `verify_es256/4` yields a well-formed but false
  `:signature_mismatch` (spec 012 S1 review). The atoms match the
  `signing_keys.algorithm` enum where both exist.
  """
  @spec public_key_algorithm(pem :: String.t()) ::
          {:ok, :ecdsa_p256 | :ed25519 | :rsa} | {:error, term()}
  def public_key_algorithm(pem) when is_binary(pem) do
    with {:ok, otp_public_key} <- pem_to_public_key(pem) do
      case otp_public_key do
        {{:ECPoint, _}, {:namedCurve, curve}}
        when curve in [{1, 2, 840, 10_045, 3, 1, 7}, :secp256r1, :prime256v1] ->
          {:ok, :ecdsa_p256}

        {{:ECPoint, _}, {:namedCurve, curve}} when curve in [{1, 3, 101, 112}, :"id-Ed25519"] ->
          {:ok, :ed25519}

        {:RSAPublicKey, _, _} ->
          {:ok, :rsa}

        {{:ECPoint, _}, {:namedCurve, other}} ->
          {:error, {:unsupported_curve, other}}

        other when is_tuple(other) ->
          {:error, {:unsupported_public_key_shape, elem(other, 0)}}

        _ ->
          {:error, :unsupported_public_key_shape}
      end
    end
  end

  @doc """
  Convert a raw `r || s` DSSE-format ECDSA signature (64 bytes for
  P-256) into ASN.1 DER `SEQUENCE { INTEGER r, INTEGER s }` — the
  shape `:public_key.verify/4` expects. Inverse of
  `ecdsa_der_to_raw/2` (the sign-side helper used by `encode/4`).

  Returns `nil` for any signature that isn't the expected raw shape,
  letting the caller's `with` chain surface
  `{:error, :invalid_signature_format}` rather than crashing.
  """
  @spec raw_to_ecdsa_der(signature :: binary(), component_size :: pos_integer()) ::
          binary() | nil
  def raw_to_ecdsa_der(<<r::binary-size(32), s::binary-size(32)>>, 32) do
    r_int = strip_leading_zeros_then_pad_for_asn1(r)
    s_int = strip_leading_zeros_then_pad_for_asn1(s)

    <<0x02, byte_size(r_int)::8, r_int::binary, 0x02, byte_size(s_int)::8, s_int::binary>>
    |> wrap_sequence()
  end

  def raw_to_ecdsa_der(_other, _size), do: nil

  defp wrap_sequence(body) do
    <<0x30, byte_size(body)::8, body::binary>>
  end

  # ASN.1 INTEGER cannot have a high-bit set without a leading 0x00
  # padding byte (else it's interpreted negative). Likewise a leading
  # 0x00 must be stripped if not needed for sign disambiguation.
  defp strip_leading_zeros_then_pad_for_asn1(<<>>), do: <<0>>

  defp strip_leading_zeros_then_pad_for_asn1(<<0, rest::binary>> = bin) do
    case strip_leading_zeros_then_pad_for_asn1(rest) do
      stripped when byte_size(stripped) > 0 -> stripped
      <<>> -> bin
    end
  end

  defp strip_leading_zeros_then_pad_for_asn1(<<first, _::binary>> = bin) when first >= 0x80 do
    <<0>> <> bin
  end

  defp strip_leading_zeros_then_pad_for_asn1(bin), do: bin

  # --- internals ---

  defp decode_signatures(list) do
    Enum.reduce_while(list, {:ok, []}, fn
      %{"sig" => sig_b64} = entry, {:ok, acc} ->
        case Base.decode64(sig_b64) do
          {:ok, sig_bytes} ->
            {:cont, {:ok, [%{key_id: Map.get(entry, "keyid"), sig: sig_bytes} | acc]}}

          :error ->
            {:halt, {:error, :invalid_signature_base64}}
        end

      _, _ ->
        {:halt, {:error, :malformed_signature_entry}}
    end)
    |> case do
      {:ok, acc} -> {:ok, Enum.reverse(acc)}
      other -> other
    end
  end

  defp to_jwk(%JOSE.JWK{} = k), do: k
  defp to_jwk(map) when is_map(map), do: JOSE.JWK.from_map(map)

  defp infer_alg(jwk) do
    # Previously defaulted to "EdDSA" for unknown keys (speckit-pr-review
    # iteration-3 F007): that silently picked the Ed25519 signing path
    # for any key we didn't pattern-match, which either (a) raised in
    # sign_raw/3 with a confusing error, or (b) produced garbage
    # signatures against non-Ed25519 keys. Raising here surfaces the
    # misconfiguration immediately with a clear message.
    case JOSE.JWK.to_map(jwk) do
      {_, %{"kty" => "OKP", "crv" => "Ed25519"}} ->
        "EdDSA"

      {_, %{"kty" => "EC", "crv" => "P-256"}} ->
        "ES256"

      {_, %{"kty" => "RSA"}} ->
        "PS256"

      {_, other} ->
        raise ArgumentError,
              "DSSE infer_alg: unsupported JWK shape — " <>
                "expected OKP/Ed25519, EC/P-256, or RSA; got #{inspect(other)}"
    end
  end

  # DSSE ITE-5 §2: `Sign(PAE(type, payload), K) -> sig`. The signature
  # MUST be computed over the raw PAE bytes. JOSE.JWS.sign internally
  # signs the JWS signing input (base64url(header) || "." ||
  # base64url(payload)) NOT the raw bytes, so external DSSE verifiers —
  # sigstore-cli, in-toto-go, etc. — reject envelopes produced that way
  # (speckit-pr-review iteration-2 F001, PR #1).
  #
  # We drop to the raw crypto primitive per algorithm so the signature
  # target is exactly `pae_bytes`.
  defp sign(jwk, alg, pae_bytes) do
    {alg, sign_raw(jwk, alg, pae_bytes)}
  end

  defp sign_raw(jwk, "EdDSA", pae_bytes) do
    # Ed25519: the private key lives in JOSE's OKP form as `d` (base64url).
    {_, %{"d" => d_b64, "kty" => "OKP", "crv" => "Ed25519"}} = JOSE.JWK.to_map(jwk)
    priv = Base.url_decode64!(d_b64, padding: false)
    :crypto.sign(:eddsa, :none, pae_bytes, [priv, :ed25519])
  end

  defp sign_raw(jwk, "ES256", pae_bytes) do
    # ECDSA P-256 with SHA-256. JOSE hands us an EC JWK; convert to the
    # :public_key OTP record via JOSE.JWK.to_key/1.
    {_, otp_priv_key} = JOSE.JWK.to_key(jwk)
    # :public_key returns DER-encoded ASN.1; DSSE uses raw r||s concat.
    der = :public_key.sign(pae_bytes, :sha256, otp_priv_key)
    ecdsa_der_to_raw(der, 32)
  end

  defp sign_raw(jwk, "PS256", pae_bytes) do
    # RSA-PSS-SHA256
    {_, otp_priv_key} = JOSE.JWK.to_key(jwk)

    :public_key.sign(pae_bytes, :sha256, otp_priv_key,
      rsa_padding: :rsa_pkcs1_pss_padding,
      rsa_mgf1_md: :sha256,
      rsa_pss_saltlen: -1
    )
  end

  defp sign_raw(_jwk, alg, _pae_bytes) do
    raise ArgumentError,
          "DSSE sign: unsupported algorithm #{inspect(alg)} (expected EdDSA | ES256 | PS256)"
  end

  # ECDSA in X.509 DER form is SEQUENCE { INTEGER r, INTEGER s }; DSSE
  # expects the raw r || s concatenation with each integer left-padded
  # to `size` bytes. Decode the DER manually; this is a tight parser.
  defp ecdsa_der_to_raw(<<0x30, _len, 0x02, r_len, rest::binary>>, size) do
    <<r::binary-size(r_len), 0x02, s_len, s_rest::binary>> = rest
    <<s::binary-size(s_len), _::binary>> = s_rest
    pad(strip_leading_zero(r), size) <> pad(strip_leading_zero(s), size)
  end

  defp strip_leading_zero(<<0x00, rest::binary>>) when byte_size(rest) > 0, do: rest
  defp strip_leading_zero(other), do: other

  defp pad(bin, size) when byte_size(bin) == size, do: bin

  defp pad(bin, size) when byte_size(bin) < size do
    :binary.copy(<<0>>, size - byte_size(bin)) <> bin
  end

  # Verification stub: returns :ok for now. See moduledoc TODO.
  defp verify_signatures(_signatures, _pae_bytes, _key_or_keys), do: {:ok, :unverified}
end
