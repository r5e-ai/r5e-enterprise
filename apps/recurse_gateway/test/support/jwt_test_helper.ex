defmodule Recurse.Gateway.Test.JwtTestHelper do
  @moduledoc """
  Mint test `X-Observed-Identity` JWTs without booting the real
  `:recurse_broker` (F002 T027).

  Gateway integration tests need a working JWT for the
  `Authorization: Bearer <JWT>` header — but spinning up the broker
  for every test is slow and couples Gateway tests to broker-impl
  progress. This helper mints JWTs via JOSE over a deterministic
  per-test-run keypair, and exposes the matching public JWK so
  Gateway's `JwksCache` fixtures can be populated directly.

  ## Keypair caching

  Per-algorithm keypairs are generated once per BEAM run and cached
  in `:persistent_term` keyed `{__MODULE__, alg}`. Tests that mint
  with the same `:alg` share the same keypair; different algs each
  get their own. `:persistent_term` is the right store for this
  (rarely-written, frequently-read per otp-thinking) and avoids a
  test-only GenServer.

  The keypair is **not** read from disk — it's freshly generated
  per BEAM run to avoid checking cryptographic material into the
  repo. Downstream `public_jwk/1` callers must run in the same
  BEAM instance as `mint_test_jwt/1`, which holds for all in-tree
  ExUnit tests. (If we later need cross-process determinism, the
  task allows checking in `apps/recurse_gateway/test/support/fixtures/jwt_test_key.pem`
  and swapping this module's backing store without changing its
  public API.)

  ## Algorithm support

  Three JOSE algs per `contracts/recurse_broker_api.md` allowlist:
  `:rs256`, `:es256`, `:eddsa`. Default is `:rs256` (broadest
  verifier compatibility; matches F002 FR-007's RS256/ES256/EdDSA
  validator allowlist).

  ## Cross-references

    * `specs/002-standalone-gateway-vertical-slice/contracts/recurse_broker_api.md`
    * `specs/002-standalone-gateway-vertical-slice/tasks.md` T027, T031
    * F002 FR-007 (alg allowlist)
  """

  @type alg :: :rs256 | :es256 | :eddsa

  @default_issuer "https://test-broker.example.invalid"
  @default_audience "recurse-gateway-test"
  @default_ttl_seconds 900
  @default_subject "user-0001"
  @default_recurse_role "caller"
  @default_alg :rs256

  @doc """
  Mint a test `X-Observed-Identity` JWT.

  Options:

    * `:subject` — JWT `sub` claim (default `"user-0001"`).
    * `:recurse_role` — the `principal.recurse_role` custom claim.
      Pass `"platform_operator"` or `"tenant_auditor"` to test
      Audit-Plane auth, `"caller"` (default) for Data-Plane.
    * `:ttl_seconds` — time between `iat` and `exp` (default `900`,
      matches the broker's 15-min default).
    * `:issuer` — JWT `iss` claim (default a reserved `.invalid` URL).
    * `:audience` — JWT `aud` claim (default `"recurse-gateway-test"`).
    * `:alg` — signing algorithm; one of `:rs256 | :es256 | :eddsa`
      (default `:rs256`).
    * `:iat` — override issue time (UNIX seconds). Defaults to now.
      Useful for generating expired-class tokens (Surface N
      property test).
    * `:jti` — override the `jti` claim. Default UUIDv4-ish (random
      128 bits hex). Useful for replay-class tokens.
    * `:principal_overrides` — map merged into the `principal`
      custom claim after defaults are applied.

  Returns a compact JWS serialization string.
  """
  @spec mint_test_jwt(keyword()) :: String.t()
  def mint_test_jwt(opts \\ []) do
    alg = Keyword.get(opts, :alg, @default_alg)
    subject = Keyword.get(opts, :subject, @default_subject)
    recurse_role = Keyword.get(opts, :recurse_role, @default_recurse_role)
    ttl_seconds = Keyword.get(opts, :ttl_seconds, @default_ttl_seconds)
    issuer = Keyword.get(opts, :issuer, @default_issuer)
    audience = Keyword.get(opts, :audience, @default_audience)
    iat = Keyword.get(opts, :iat, System.system_time(:second))
    jti = Keyword.get(opts, :jti, random_jti())
    principal_overrides = Keyword.get(opts, :principal_overrides, %{})

    principal =
      Map.merge(
        %{
          "kind" => "obo_human",
          "issuer" => issuer,
          "subject" => subject,
          "display_name" => "Test User",
          "groups" => [],
          "recurse_role" => recurse_role
        },
        principal_overrides
      )

    claims = %{
      "iss" => issuer,
      "sub" => subject,
      "aud" => audience,
      "iat" => iat,
      "nbf" => iat,
      "exp" => iat + ttl_seconds,
      "jti" => jti,
      "principal" => principal
    }

    {jwk, jws_header} = signing_material(alg)

    {_, compact} =
      jwk
      |> JOSE.JWT.sign(jws_header, claims)
      |> JOSE.JWS.compact()

    compact
  end

  @doc """
  Return the public JWK matching the keypair used to sign tokens
  under `alg` (default `:rs256`).

  The returned map is a JOSE JWK in plain-map form — the same shape a
  broker would publish via `GET /oidc/jwks` — and can be fed straight
  into `JOSE.JWK.from_map/1` by validator-side caches.

  Includes `"kid"` set to `"test-key-<alg>"` so downstream tests can
  populate a JWKS cache keyed consistently with the tokens this module
  emits.
  """
  @spec public_jwk(alg()) :: map()
  def public_jwk(alg \\ @default_alg) do
    alg
    |> keypair()
    |> elem(1)
    |> JOSE.JWK.to_map()
    |> elem(1)
    |> Map.put("kid", kid_for(alg))
    |> Map.put("use", "sig")
    |> Map.put("alg", jose_alg_string(alg))
  end

  @doc """
  Return the JWS `alg` string for the given atom — useful for test
  assertions that need to compare against a decoded header.
  """
  @spec jose_alg_string(alg()) :: String.t()
  def jose_alg_string(:rs256), do: "RS256"
  def jose_alg_string(:es256), do: "ES256"
  def jose_alg_string(:eddsa), do: "EdDSA"

  # Internal: return (private_jwk_for_signing, jws_header_with_kid_and_alg).
  defp signing_material(alg) do
    {private_jwk, _public_jwk} = keypair(alg)

    header = %{
      "alg" => jose_alg_string(alg),
      "kid" => kid_for(alg),
      "typ" => "JWT"
    }

    {private_jwk, header}
  end

  # Persist-per-BEAM keypair cache. :persistent_term is the right store
  # here per otp-thinking ("Storage Options" → :persistent_term for
  # rarely-written, frequently-read static config).
  defp keypair(alg) do
    key = {__MODULE__, :keypair, alg}

    case :persistent_term.get(key, :undefined) do
      :undefined ->
        pair = generate_keypair(alg)
        :persistent_term.put(key, pair)
        pair

      pair ->
        pair
    end
  end

  defp generate_keypair(:rs256) do
    jwk = JOSE.JWK.generate_key({:rsa, 2048})
    {jwk, JOSE.JWK.to_public(jwk)}
  end

  defp generate_keypair(:es256) do
    jwk = JOSE.JWK.generate_key({:ec, "P-256"})
    {jwk, JOSE.JWK.to_public(jwk)}
  end

  defp generate_keypair(:eddsa) do
    jwk = JOSE.JWK.generate_key({:okp, :Ed25519})
    {jwk, JOSE.JWK.to_public(jwk)}
  end

  defp kid_for(alg), do: "test-key-#{alg}"

  defp random_jti, do: 16 |> :crypto.strong_rand_bytes() |> Base.encode16(case: :lower)
end
