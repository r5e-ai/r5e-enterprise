defmodule RecurseBroker.OIDC.Validator do
  @moduledoc """
  Validate a customer-IdP `id_token` (OIDC JWT) per `contracts/recurse_broker_api.md`
  and F002 FR-008 (F002 T083).

  Pure module — NO state. Iron Law check (elixir-thinking):

    1. Mutable state persisting across calls? No — every `validate_id_token/2`
       call is a pure function of `(compact_jws, opts)`.
    2. Concurrent execution? No — validation is CPU-bound crypto on the
       caller process.
    3. Fault isolation? No — every failure path returns `{:error, atom}`.

  All three NO → plain functions. JWKS state (legitimate, coalesced-fetch,
  TTL-refreshed) lives in `RecurseBroker.OIDC.DiscoveryCache`; this module
  composes it through the `:jwks_fetcher` DI seam.

  ## Validation pipeline

  Short-circuits on first error. REJECT BEFORE CRYPTO per research D2
  (JOSE pitfalls guardrails):

    1. **Parse compact form** — 3 segments required. 5 segments (JWE)
       rejected with `:unsupported_token_format` on segment count BEFORE
       any JOSE call.
    2. **Alg allowlist** — header `alg` MUST be in
       `alg_allowlist` (default `[:rs256, :es256, :eddsa]`, matching
       F002 FR-007). `alg: none` and anything else → `:forbidden_alg`.
    3. **Unverified claim peek** — pull `iss` from payload without
       verifying the signature. Peeking is safe; trust is established
       at step 6.
    4. **Issuer match** — peeked `iss` must equal `opts[:issuer]`. If
       not, short-circuit `:issuer_mismatch` BEFORE any network fetch
       so a spoofed token can't be used to DoS-attack JWKS resolvers.
    5. **JWKS fetch** — call `opts[:jwks_fetcher].(issuer, kid)`.
       `{:error, :jwks_fetch_failed}` (or whatever the fetcher returns)
       is the caller's signal to respond with RFC 8693
       `temporarily_unavailable` (503) per the contract.
    6. **Signature verification** — `JOSE.JWT.verify_strict/3` with the
       alg pinned to the header's alg string. Strict mode prevents JOSE
       from auto-dispatching to a different alg based on JWK shape (the
       classic RS256-vs-HS256 confusion attack).
    7. **Claim checks** — `aud`, `exp`, `nbf`, `iat`, `sub`. Time-based
       claims apply a `clock_skew_seconds` tolerance (default 60s per
       F002 FR-007 + D2); `sub` must be a non-empty string.

  ## `opts` schema

    * `:issuer` (required) — expected `iss` string; exact match.
    * `:audience` (required) — expected `aud` string; exact match.
    * `:alg_allowlist` (optional, default `[:rs256, :es256, :eddsa]`) —
      atoms mapped to JOSE alg strings via a case-insensitive translation:
      `:rs256 ↔ "RS256"`, `:es256 ↔ "ES256"`, `:eddsa ↔ "EdDSA"`.
    * `:clock_skew_seconds` (optional, default `60`).
    * `:jwks_fetcher` (optional, default
      `&RecurseBroker.OIDC.DiscoveryCache.fetch_jwks/2`) — arity-2 fn;
      receives `(issuer, kid)`, returns `{:ok, jwk_map}` | `{:error, _}`.
    * `:now_unix` (optional, default `System.system_time(:second)`) —
      `integer | (-> integer)`; test-only DI.

  ## Return shape — error atoms (deterministic for RFC 6749 §5.2 mapping)

  The TokenExchange Plug (T088) maps these to `invalid_subject_token` /
  `temporarily_unavailable` / `invalid_request` exactly per
  `contracts/recurse_broker_api.md` "Error responses" table:

    * `:unsupported_token_format` — not a 3-segment JWS.
    * `:forbidden_alg` — header alg not in allowlist (or `alg: none`).
    * `:missing_kid` — header has no `kid`.
    * `:issuer_mismatch` — payload `iss` != `opts[:issuer]`.
    * `:jwks_fetch_failed` — fetcher errored (network / discovery).
    * `:invalid_signature` — JOSE strict-verify failed.
    * `:audience_mismatch` — payload `aud` != `opts[:audience]`.
    * `:token_expired` — `exp <= now - skew`.
    * `:token_not_yet_valid` — `nbf > now + skew`.
    * `:iat_in_future` — `iat > now + skew` (clock-drift defense).
    * `:missing_subject` — `sub` absent or empty.
    * `:malformed_claims` — payload unparseable or has unexpected types
      for required claims.

  ## Cross-references

    * `specs/002-standalone-gateway-vertical-slice/contracts/recurse_broker_api.md`
      (POST /token/exchange error response table)
    * `specs/002-standalone-gateway-vertical-slice/research.md` D2 (JOSE
      pitfalls: `from_map`-only remote keys; strict alg binding;
      5-segment JWE rejection)
    * F002 FR-008 (OIDC validation at broker)
    * `contracts/property_test_surface_catalog_f002.md` §Surface N
  """

  @type alg_atom :: :rs256 | :es256 | :eddsa

  @type reason ::
          :unsupported_token_format
          | :forbidden_alg
          | :missing_kid
          | :issuer_mismatch
          | :jwks_fetch_failed
          | :invalid_signature
          | :audience_mismatch
          | :token_expired
          | :token_not_yet_valid
          | :iat_in_future
          | :missing_subject
          | :malformed_claims

  @default_alg_allowlist [:rs256, :es256, :eddsa]
  @default_clock_skew_seconds 60

  # Case-insensitive atom-to-JOSE-string mapping. We normalize both sides
  # to a canonical form (atom) before crypto; this is defense-in-depth
  # against a caller passing the lowercase string "rs256" in a JWT
  # header (non-compliant but seen in the wild).
  @alg_atom_to_string %{
    rs256: "RS256",
    es256: "ES256",
    eddsa: "EdDSA"
  }

  @doc """
  Validate an OIDC `id_token` per the pipeline described in the moduledoc.

  Returns `{:ok, claims_map_with_string_keys}` or `{:error, reason_atom}`.
  """
  @spec validate_id_token(String.t(), keyword()) :: {:ok, map()} | {:error, reason()}
  def validate_id_token(compact_jws, opts) when is_binary(compact_jws) and is_list(opts) do
    with {:ok, header, payload_b64} <- parse_compact(compact_jws),
         {:ok, alg_atom, alg_string} <- check_alg(header, opts),
         {:ok, kid} <- extract_kid(header),
         {:ok, peeked_claims} <- peek_claims(payload_b64),
         :ok <- check_issuer(peeked_claims, opts),
         {:ok, jwk} <- fetch_jwks(peeked_claims, kid, opts),
         {:ok, claims} <- verify_signature(compact_jws, jwk, alg_string),
         :ok <- check_audience(claims, opts),
         :ok <- check_temporal(claims, opts),
         :ok <- check_subject(claims) do
      _ = alg_atom
      {:ok, claims}
    end
  end

  # ---------------------------------------------------------------------------
  # Step 1 — parse compact serialization + header JSON.
  # ---------------------------------------------------------------------------

  defp parse_compact(jwt) do
    case String.split(jwt, ".") do
      [h, p, _s] ->
        with {:ok, header_bytes} <- Base.url_decode64(h, padding: false),
             {:ok, header} <- decode_json(header_bytes) do
          {:ok, header, p}
        else
          _ -> {:error, :unsupported_token_format}
        end

      # 5 segments = JWE (RFC 7516 §3). Reject by segment count, not by
      # attempting decryption.
      [_, _, _, _, _] ->
        {:error, :unsupported_token_format}

      _ ->
        {:error, :unsupported_token_format}
    end
  end

  # ---------------------------------------------------------------------------
  # Step 2 — alg allowlist. Done before any JOSE call.
  # ---------------------------------------------------------------------------

  defp check_alg(%{"alg" => alg}, opts) when is_binary(alg) do
    allowlist = Keyword.get(opts, :alg_allowlist, @default_alg_allowlist)

    case alg_to_atom(alg) do
      {:ok, atom} ->
        if atom in allowlist,
          do: {:ok, atom, Map.fetch!(@alg_atom_to_string, atom)},
          else: {:error, :forbidden_alg}

      :error ->
        {:error, :forbidden_alg}
    end
  end

  defp check_alg(_, _), do: {:error, :forbidden_alg}

  # Case-insensitive. "none" → :error (never in our table). Anything we
  # don't recognize → :error.
  defp alg_to_atom(alg_string) do
    case String.upcase(alg_string) do
      "RS256" -> {:ok, :rs256}
      "ES256" -> {:ok, :es256}
      "EDDSA" -> {:ok, :eddsa}
      _ -> :error
    end
  end

  # ---------------------------------------------------------------------------
  # Step 3 — kid extraction. Must come from the HEADER, not the payload.
  # ---------------------------------------------------------------------------

  defp extract_kid(%{"kid" => kid}) when is_binary(kid) and kid != "", do: {:ok, kid}
  defp extract_kid(_), do: {:error, :missing_kid}

  # ---------------------------------------------------------------------------
  # Step 4 — peek payload for iss (unverified, safe — we verify sig at step 6).
  # ---------------------------------------------------------------------------

  defp peek_claims(payload_b64) do
    with {:ok, payload_bytes} <- Base.url_decode64(payload_b64, padding: false),
         {:ok, claims} when is_map(claims) <- decode_json(payload_bytes) do
      {:ok, claims}
    else
      _ -> {:error, :malformed_claims}
    end
  end

  defp check_issuer(%{"iss" => iss}, opts) do
    expected = Keyword.fetch!(opts, :issuer)
    if iss == expected, do: :ok, else: {:error, :issuer_mismatch}
  end

  defp check_issuer(_, _), do: {:error, :issuer_mismatch}

  # ---------------------------------------------------------------------------
  # Step 5 — JWKS fetch via injected fetcher. Always on the peeked issuer
  # (which we've already matched to opts[:issuer] at step 4).
  # ---------------------------------------------------------------------------

  defp fetch_jwks(%{"iss" => iss}, kid, opts) do
    fetcher =
      Keyword.get(opts, :jwks_fetcher, &RecurseBroker.OIDC.DiscoveryCache.fetch_jwks/2)

    case fetcher.(iss, kid) do
      {:ok, jwk} -> {:ok, jwk}
      {:error, _} -> {:error, :jwks_fetch_failed}
    end
  end

  # ---------------------------------------------------------------------------
  # Step 6 — signature verification via JOSE strict mode.
  #
  # Per research D2: ALWAYS `JOSE.JWK.from_map/1` on remote-fetched keys;
  # NEVER `from_pem/1` on untrusted data. The fetcher returns a plain
  # map from the JWKS HTTP response; we upgrade it here.
  # ---------------------------------------------------------------------------

  defp verify_signature(jwt, jwk_map, alg_string) do
    verification_key = ensure_jwk(jwk_map)

    case JOSE.JWT.verify_strict(verification_key, [alg_string], jwt) do
      {true, %JOSE.JWT{fields: fields}, _jws} when is_map(fields) ->
        {:ok, fields}

      {false, _jose_jwt, _jws} ->
        {:error, :invalid_signature}

      _ ->
        {:error, :invalid_signature}
    end
  rescue
    # JOSE raises on some malformed inputs — collapse to a single
    # deterministic error atom. No JOSE internals in the public API.
    _ -> {:error, :invalid_signature}
  end

  defp ensure_jwk(%JOSE.JWK{} = jwk), do: jwk
  defp ensure_jwk(map) when is_map(map), do: JOSE.JWK.from_map(map)

  # ---------------------------------------------------------------------------
  # Step 7 — claim checks.
  # ---------------------------------------------------------------------------

  defp check_audience(%{"aud" => aud}, opts) do
    expected = Keyword.fetch!(opts, :audience)
    if aud == expected, do: :ok, else: {:error, :audience_mismatch}
  end

  defp check_audience(_, _), do: {:error, :audience_mismatch}

  defp check_temporal(claims, opts) do
    now = now_unix(opts)
    skew = Keyword.get(opts, :clock_skew_seconds, @default_clock_skew_seconds)

    with :ok <- check_exp(claims, now, skew),
         :ok <- check_nbf(claims, now, skew),
         :ok <- check_iat(claims, now, skew) do
      :ok
    end
  end

  # `exp > now - skew` — accept tokens up to `skew` seconds past expiry.
  defp check_exp(%{"exp" => exp}, now, skew) when is_integer(exp) do
    if exp > now - skew, do: :ok, else: {:error, :token_expired}
  end

  defp check_exp(_, _, _), do: {:error, :malformed_claims}

  # `nbf <= now + skew` — accept nbf up to `skew` seconds into the future.
  # Missing nbf is allowed (RFC 7519 optional).
  defp check_nbf(%{"nbf" => nbf}, now, skew) when is_integer(nbf) do
    if nbf <= now + skew, do: :ok, else: {:error, :token_not_yet_valid}
  end

  defp check_nbf(%{"nbf" => _bad}, _now, _skew), do: {:error, :malformed_claims}
  defp check_nbf(_, _, _), do: :ok

  # `iat <= now + skew` — clock-drift-future-iat defense. Missing iat is
  # treated as malformed (required by OIDC).
  defp check_iat(%{"iat" => iat}, now, skew) when is_integer(iat) do
    if iat <= now + skew, do: :ok, else: {:error, :iat_in_future}
  end

  defp check_iat(_, _, _), do: {:error, :malformed_claims}

  defp check_subject(%{"sub" => sub}) when is_binary(sub) and sub != "", do: :ok
  defp check_subject(_), do: {:error, :missing_subject}

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  defp now_unix(opts) do
    case Keyword.get(opts, :now_unix) do
      nil -> System.system_time(:second)
      fun when is_function(fun, 0) -> fun.()
      int when is_integer(int) -> int
    end
  end

  defp decode_json(bytes) do
    JSON.decode(bytes)
  rescue
    _ -> :error
  end
end
