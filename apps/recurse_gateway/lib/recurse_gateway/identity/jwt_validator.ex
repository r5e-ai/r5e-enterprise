defmodule Recurse.Gateway.Identity.JwtValidator do
  @moduledoc """
  Validate an `X-Observed-Identity` JWT minted by the Standalone Identity
  Broker per F002 FR-007 + `contracts/recurse_broker_api.md`.

  Pure module — NO state. The Iron Law check (elixir-thinking):

    1. Mutable state persisting across calls? No — every call is a pure
       function of `(jwt, opts)`.
    2. Concurrent execution? No — verification is CPU-bound crypto on the
       caller process.
    3. Fault isolation? No — validation failure is `{:error, _}`, not a
       crash.

  All three NO → plain functions. State (JWKS cache, replay cache) is
  owned by other processes (`JwksCache` GenServer, Postgres table) and
  injected via `opts`.

  ## Validation pipeline

  Short-circuits on first error. Ordered per research D2 (JOSE pitfalls
  guardrails — structural + algorithm checks before any crypto work):

    1. **Parse** — compact serialization; 3 segments required. 5 segments
       (JWE) rejected with `:unsupported_token_format`.
    2. **Alg allowlist** — header `alg` MUST be one of
       `RS256 | ES256 | EdDSA` (F002 FR-007). `alg: none` and every other
       value → `:forbidden_alg` BEFORE any `JOSE.JWT.verify*` call is
       made (defense-in-depth; JOSE has its own `alg: none` guard but
       we don't rely on it).
    3. **Kid resolution** — header `kid` looked up in `opts[:known_kids]`.
       Supports three shapes (see `:known_kids` below); miss →
       `:unknown_kid`.
    4. **Signature verification** — `JOSE.JWT.verify_strict/3` with the
       single resolved `kid`'s JWK + the allowlisted `alg` only. Strict
       mode prevents JOSE from auto-dispatching to a different `alg`
       based on JWK contents (the classic "RS256 vs HS256" confusion
       attack).
    5. **Claim checks** — `exp`, `nbf`, `iat`, `aud`, `iss` with 60s clock
       skew per research D2. `iat` must be `≤ now + skew` to defend
       against clock-drift-future-iat.
    6. **Replay** — `jti` checked via `opts[:jti_check]` callable; noop
       when absent.

  ## `opts` keys

    * `:audience` (required) — expected `aud` claim. String equality.
    * `:issuer` (optional) — expected `iss` claim. Absent = any issuer
      accepted (useful for test harnesses that use multiple issuers).
    * `:known_kids` (required) — key resolver. Three supported shapes:

        - `[{kid_binary, %JOSE.JWK{}}, ...]` — static list.
        - `%{kid_binary => %JOSE.JWK{}}` — static map.
        - `{:cache, JwksCacheModule}` — calls
          `JwksCacheModule.fetch_jwk(issuer, kid)` on-demand. Enables
          `kid`-miss refresh per research D2.

    * `:seen_jtis` (optional) — a list or `MapSet` of previously-seen
      jtis; validator reports `:token_replayed` if the jti is a member.
      Convenience for test fixtures; production uses `:jti_check`.
    * `:jti_check` (optional) — callable of arity 1 invoked with the
      decoded `jti` string. Returns `:ok` on first-seen,
      `{:error, :token_replayed}` on replay. Backed by the
      `jwt_jti_cache` Postgres table in production.
    * `:clock_skew_seconds` (optional, default `60`) — tolerance applied
      to `exp`, `nbf`, `iat` checks per F002 FR-007 (matches broker-side
      tolerance for clock-drift resistance).
    * `:now` (optional) — override current UNIX seconds; test-only seam.

  ## Return shape

    * `{:ok, claims_map}` — map with string keys, the decoded payload
      (including the `principal` custom claim). Callers should read
      `claims["principal"]` to materialize a
      `Recurse.Shared.Principal.t()`.
    * `{:error, reason_atom}` — one of:
      `:unsupported_token_format | :forbidden_alg | :unknown_kid |
       :invalid_signature | :token_expired | :token_not_yet_valid |
       :invalid_audience | :invalid_issuer | :token_replayed |
       :malformed_claims`.

  ## Cross-references

    * `specs/002-standalone-gateway-vertical-slice/contracts/recurse_broker_api.md` (minted JWT shape)
    * `specs/002-standalone-gateway-vertical-slice/research.md` D2 (JOSE pitfalls)
    * `contracts/property_test_surface_catalog_f002.md` §Surface N
    * F002 FR-007 (alg allowlist), FR-009 (principal claim shape)
    * `apps/recurse_gateway/test/identity/jwt_validator_property_test.exs` (1000-iter property test pinning this API)
  """

  @type reason ::
          :unsupported_token_format
          | :forbidden_alg
          | :unknown_kid
          | :invalid_signature
          | :token_expired
          | :token_not_yet_valid
          | :invalid_audience
          | :invalid_issuer
          | :token_replayed
          | :malformed_claims

  # Allowlisted JOSE `alg` strings per F002 FR-007. `alg: none` is NOT in
  # this list — rejected at step 2 before any crypto call.
  @allowed_algs ["RS256", "ES256", "EdDSA"]

  @default_clock_skew_seconds 60

  @doc """
  Validate a JWT against the configured audience / issuer / key set.

  See moduledoc for `opts` schema + ordered-check semantics. Returns
  `{:ok, claims_map}` or `{:error, reason_atom}`.
  """
  @spec validate(String.t(), map()) :: {:ok, map()} | {:error, reason()}
  def validate(jwt, opts) when is_binary(jwt) and is_map(opts) do
    with {:ok, header, payload_b64, sig_b64} <- parse_compact(jwt),
         {:ok, alg} <- check_alg(header),
         {:ok, kid} <- extract_kid(header),
         {:ok, jwk} <- resolve_kid(kid, payload_b64, opts),
         {:ok, claims} <- verify_signature(jwt, jwk, alg, header, payload_b64, sig_b64),
         :ok <- check_temporal_claims(claims, opts),
         :ok <- check_audience(claims, opts),
         :ok <- check_issuer(claims, opts),
         :ok <- check_replay(claims, opts) do
      {:ok, claims}
    end
  end

  # ---------------------------------------------------------------------------
  # Step 1: parse the compact serialization.
  #
  # 3 segments = JWS (what we accept). 5 segments = JWE (reject explicitly per
  # FR-007). Anything else = malformed. This guard runs BEFORE any JOSE call
  # because we don't trust JOSE to refuse a non-JWS compactly-serialized input
  # — we want a definite `:unsupported_token_format` atom.
  # ---------------------------------------------------------------------------

  defp parse_compact(jwt) do
    case String.split(jwt, ".") do
      [h, p, s] ->
        with {:ok, header_bytes} <- Base.url_decode64(h, padding: false),
             {:ok, header} <- decode_json(header_bytes) do
          {:ok, header, p, s}
        else
          _ -> {:error, :unsupported_token_format}
        end

      # 5 segments is explicitly JWE per RFC 7516 §3; we reject on segment
      # count rather than attempting to decrypt (the validator is JWS-only).
      [_, _, _, _, _] ->
        {:error, :unsupported_token_format}

      _ ->
        {:error, :unsupported_token_format}
    end
  end

  # ---------------------------------------------------------------------------
  # Step 2: alg allowlist.
  #
  # Done BEFORE any JOSE.JWT.verify* call so `alg: none` or HS256 never
  # reaches crypto primitives. Defense-in-depth: JOSE has its own allowlist,
  # but we don't rely on it.
  # ---------------------------------------------------------------------------

  defp check_alg(%{"alg" => alg}) when alg in @allowed_algs, do: {:ok, alg}
  defp check_alg(_), do: {:error, :forbidden_alg}

  # ---------------------------------------------------------------------------
  # Step 3: kid extraction.
  # ---------------------------------------------------------------------------

  defp extract_kid(%{"kid" => kid}) when is_binary(kid), do: {:ok, kid}
  defp extract_kid(_), do: {:error, :unknown_kid}

  # ---------------------------------------------------------------------------
  # Step 3b: kid resolution against the three supported :known_kids shapes.
  #
  # For the `{:cache, Mod}` form we need the issuer to scope the cache
  # lookup — per F002 the JwksCache is keyed `{issuer, kid}`. The issuer
  # is in the payload (claim `iss`), so we peek at it without verifying
  # the signature yet (peeking is safe; trust is established at step 4).
  # ---------------------------------------------------------------------------

  defp resolve_kid(kid, payload_b64, %{known_kids: {:cache, cache_module}}) do
    with {:ok, issuer} <- peek_issuer(payload_b64),
         {:ok, jwk} <- cache_module.fetch_jwk(issuer, kid) do
      {:ok, jwk}
    else
      _ -> {:error, :unknown_kid}
    end
  end

  defp resolve_kid(kid, _payload_b64, %{known_kids: known_kids}) when is_list(known_kids) do
    case List.keyfind(known_kids, kid, 0) do
      {^kid, jwk} -> {:ok, jwk}
      _ -> {:error, :unknown_kid}
    end
  end

  defp resolve_kid(kid, _payload_b64, %{known_kids: known_kids}) when is_map(known_kids) do
    case Map.fetch(known_kids, kid) do
      {:ok, jwk} -> {:ok, jwk}
      :error -> {:error, :unknown_kid}
    end
  end

  defp resolve_kid(_kid, _payload_b64, _opts), do: {:error, :unknown_kid}

  # ---------------------------------------------------------------------------
  # Step 4: signature verification via JOSE strict mode.
  #
  # Strict mode binds a specific allowlist of algs to the verification call,
  # so JOSE won't promiscuously try to verify with an alg derived from the
  # JWK contents. We already checked alg is in our @allowed_algs set, so we
  # pass a singleton allowlist — the exact header alg — to JOSE.
  #
  # If the JWK we resolved is a plain map (e.g. straight from a JWKS HTTP
  # response), we upgrade it via JOSE.JWK.from_map/1 per research D2 (only
  # ever call `from_map/1` — never `from_pem/1` — on remote-fetched keys).
  # ---------------------------------------------------------------------------

  defp verify_signature(jwt, jwk, alg, _header, _payload_b64, _sig_b64) do
    verification_key = ensure_jwk(jwk)

    case JOSE.JWT.verify_strict(verification_key, [alg], jwt) do
      {true, jose_jwt, _jws} ->
        claims = extract_claims(jose_jwt)
        {:ok, claims}

      {false, _jose_jwt, _jws} ->
        {:error, :invalid_signature}

      # Defensive — JOSE raises or returns `{:error, ...}` shapes on
      # malformed crypto material; we collapse them all to
      # `:invalid_signature` to avoid leaking JOSE internals to callers
      # (per FR-010 "fail closed; no internals leak").
      _ ->
        {:error, :invalid_signature}
    end
  rescue
    _ -> {:error, :invalid_signature}
  end

  defp ensure_jwk(%JOSE.JWK{} = jwk), do: jwk
  defp ensure_jwk(map) when is_map(map), do: JOSE.JWK.from_map(map)

  defp extract_claims(%JOSE.JWT{fields: fields}) when is_map(fields), do: fields

  # ---------------------------------------------------------------------------
  # Step 5: claim checks — exp, nbf, iat, aud, iss.
  # ---------------------------------------------------------------------------

  defp check_temporal_claims(claims, opts) do
    now = Map.get(opts, :now, System.system_time(:second))
    skew = Map.get(opts, :clock_skew_seconds, @default_clock_skew_seconds)

    with :ok <- check_exp(claims, now, skew),
         :ok <- check_nbf(claims, now, skew),
         :ok <- check_iat(claims, now, skew) do
      :ok
    end
  end

  # `exp > now - skew` — the token expires `exp` seconds from epoch; we
  # accept up to `skew` seconds into the past (broker-to-validator clock
  # drift). If `exp` is missing we reject as malformed (required claim
  # per recurse_broker_api.md).
  defp check_exp(%{"exp" => exp}, now, skew) when is_integer(exp) do
    if exp > now - skew, do: :ok, else: {:error, :token_expired}
  end

  defp check_exp(_claims, _now, _skew), do: {:error, :malformed_claims}

  # `nbf < now + skew` — not-before; we accept up to `skew` seconds in the
  # future (drift-tolerant). Missing nbf is acceptable (RFC 7519 optional).
  defp check_nbf(%{"nbf" => nbf}, now, skew) when is_integer(nbf) do
    if nbf < now + skew, do: :ok, else: {:error, :token_not_yet_valid}
  end

  defp check_nbf(_claims, _now, _skew), do: :ok

  # `iat ≤ now + skew` — issued-at. Per the task spec this is a
  # clock-drift-future-iat defense: a token issued "in the future"
  # beyond skew tolerance is rejected with `:token_not_yet_valid`
  # (not `:token_expired` — the broker hasn't issued it yet from
  # the validator's POV). If missing we treat as malformed.
  defp check_iat(%{"iat" => iat}, now, skew) when is_integer(iat) do
    if iat <= now + skew, do: :ok, else: {:error, :token_not_yet_valid}
  end

  defp check_iat(_claims, _now, _skew), do: {:error, :malformed_claims}

  # `:audience` is optional — mirrors the `:issuer` semantics below.
  # When absent from opts the validator accepts any aud (or missing
  # aud entirely; some IdPs like WorkOS User Management don't emit
  # the `aud` claim on their access_tokens). When present, exact
  # string equality.
  defp check_audience(claims, opts) do
    case Map.fetch(opts, :audience) do
      :error ->
        :ok

      {:ok, expected} ->
        case Map.fetch(claims, "aud") do
          {:ok, ^expected} -> :ok
          _ -> {:error, :invalid_audience}
        end
    end
  end

  # `:issuer` is optional — when absent the validator accepts any iss
  # (useful for test harnesses spanning multiple broker issuers). When
  # present, exact string equality per recurse_broker_api.md.
  defp check_issuer(claims, opts) do
    case Map.fetch(opts, :issuer) do
      :error ->
        :ok

      {:ok, expected} ->
        case Map.fetch(claims, "iss") do
          {:ok, ^expected} -> :ok
          _ -> {:error, :invalid_issuer}
        end
    end
  end

  # ---------------------------------------------------------------------------
  # Step 6: replay.
  #
  # Two knobs: `:seen_jtis` (list / MapSet) for fixture tests, and
  # `:jti_check` (fn) for production. `:jti_check` is preferred because it
  # encapsulates the Postgres-backed jwt_jti_cache atomic insert.
  # ---------------------------------------------------------------------------

  defp check_replay(claims, opts) do
    jti = Map.get(claims, "jti")

    with :ok <- check_seen_jtis(jti, Map.get(opts, :seen_jtis)),
         :ok <- check_jti_callback(jti, Map.get(opts, :jti_check)) do
      :ok
    end
  end

  defp check_seen_jtis(_jti, nil), do: :ok

  defp check_seen_jtis(jti, %MapSet{} = set) do
    if MapSet.member?(set, jti), do: {:error, :token_replayed}, else: :ok
  end

  defp check_seen_jtis(jti, list) when is_list(list) do
    if jti in list, do: {:error, :token_replayed}, else: :ok
  end

  defp check_jti_callback(_jti, nil), do: :ok

  defp check_jti_callback(jti, fun) when is_function(fun, 1) do
    case fun.(jti) do
      :ok -> :ok
      {:error, reason} -> {:error, reason}
      # Any non-ok return from the user callback is treated as replay —
      # fail closed per FR-010.
      _ -> {:error, :token_replayed}
    end
  end

  # ---------------------------------------------------------------------------
  # Payload peek — decode the payload segment WITHOUT verifying the signature.
  # Used only for issuer-scoped cache lookup before step 4; trust is still
  # established at step 4. Safe by construction — we return `:error` if the
  # payload doesn't parse, which short-circuits to `:unknown_kid`.
  # ---------------------------------------------------------------------------

  defp peek_issuer(payload_b64) do
    with {:ok, payload_bytes} <- Base.url_decode64(payload_b64, padding: false),
         {:ok, %{"iss" => iss}} when is_binary(iss) <- decode_json(payload_bytes) do
      {:ok, iss}
    else
      _ -> :error
    end
  end

  # JSON module arrived in Elixir 1.18+ and is the preferred decoder per
  # elixir-thinking. `decode/1` returns `{:ok, term} | {:error, reason}`.
  defp decode_json(bytes) do
    JSON.decode(bytes)
  rescue
    _ -> :error
  end
end
