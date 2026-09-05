defmodule Recurse.Gateway.Identity.JwtValidatorPropertyTest do
  @moduledoc """
  Surface N — `X-Observed-Identity` JWT validation (F002 T031).

  Per `contracts/property_test_surface_catalog_f002.md` §Surface N, the
  Gateway's JWT validator MUST accept exactly the valid class and emit
  the correct error category for each of 9 invalid classes:

    | Class                      | Error atom                  |
    |----------------------------|-----------------------------|
    | valid                      | `{:ok, claims}`             |
    | `:token_expired`           | `:token_expired`            |
    | `:token_not_yet_valid`     | `:token_not_yet_valid`      |
    | `:invalid_audience`        | `:invalid_audience`         |
    | `:invalid_issuer`          | `:invalid_issuer`           |
    | `:forbidden_alg`           | `:forbidden_alg`            |
    | `:invalid_signature`       | `:invalid_signature`        |
    | `:token_replayed`          | `:token_replayed`           |
    | `:unknown_kid`             | `:unknown_kid`              |
    | `:unsupported_token_format`| `:unsupported_token_format` |

  ## Pending status

  T041 (the `Recurse.Gateway.Identity.JwtValidator` implementation) has
  not landed. Per the surface catalog's "test-first" discipline this
  property test is written now as a skeleton that T041's implementer
  un-pends by deleting `@moduletag :pending` below. Generators +
  assertions are real — only the target module is stubbed.

  When T041 lands, the implementer will:
    1. Remove the `@moduletag :pending` line.
    2. Alias the real `Recurse.Gateway.Identity.JwtValidator`.
    3. Replace the two `flunk/1`s in `validate_under_test/2` with
       calls to the real validator + `JwksCache` fixture setup.

  ## Shrinking discipline (stream-data-thinking skill)

  All 9 invalid-class generators emit **structurally-valid** invalid
  JWTs — i.e. the only defect is the one the class name names. A
  generator that emitted arbitrarily-garbled bytes would shrink to
  trivial garbage (e.g. `""`) and hide the interesting failure modes.
  We use `StreamData.bind` over `member_of/1` the class enum, never
  `.filter/2`, because `.filter/2` discards candidates silently and
  corrupts shrinking.

  ## Iterations

  `max_runs: 1000` per surface catalog (security-critical per
  Constitution SC-014).

  ## Cross-references

    * `specs/002-standalone-gateway-vertical-slice/contracts/property_test_surface_catalog_f002.md` §Surface N
    * `specs/002-standalone-gateway-vertical-slice/contracts/recurse_broker_api.md` — Minted JWT shape
    * `specs/002-standalone-gateway-vertical-slice/tasks.md` T031, T041, T042
    * F002 FR-007 (alg allowlist: RS256/ES256/EdDSA; rejects `none`)
    * F001 FR-017 (X-Observed-Identity claim shape)
  """
  use ExUnit.Case, async: true
  use ExUnitProperties

  # T041 landed — property test is live. Covers Surface N at 1000 iters
  # per Constitution SC-014.

  alias Recurse.Gateway.Identity.JwtValidator
  alias Recurse.Gateway.Test.JwtTestHelper

  @audience "recurse-gateway-test"
  @issuer "https://test-broker.example.invalid"
  # Matches kids produced by JwtTestHelper for its three supported algs.
  @known_kids ["test-key-rs256", "test-key-es256", "test-key-eddsa"]

  describe "Surface N: Gateway JWT validator" do
    property "accepts valid JWTs with populated principal claims" do
      check all(
              subject <- subject_gen(),
              role <- role_gen(),
              alg <- alg_gen(),
              max_runs: 1000
            ) do
        jwt = mint_valid(subject: subject, recurse_role: role, alg: alg)

        assert {:ok, claims} = validate_under_test(jwt, known_kids: @known_kids)
        assert claims["sub"] == subject
        assert claims["aud"] == @audience
        assert claims["iss"] == @issuer
        assert is_map(claims["principal"])
        assert claims["principal"]["recurse_role"] == role
      end
    end

    property "rejects each invalid class with the exact error atom" do
      check all(
              class <- invalid_class_gen(),
              alg <- alg_gen(),
              {jwt, expected_error} = build_invalid(class, alg),
              max_runs: 1000
            ) do
        # One-to-one mapping per surface invariant: generator emits
        # exactly the class named, validator emits exactly the matching
        # error atom.
        assert {:error, ^expected_error} =
                 validate_under_test(jwt,
                   known_kids: @known_kids,
                   seen_jtis: seen_jtis_for(class, jwt)
                 )
      end
    end
  end

  # ---------------------------------------------------------------------------
  # Scalar generators — feed bind/gen-all.
  # ---------------------------------------------------------------------------

  defp subject_gen, do: StreamData.string(:alphanumeric, min_length: 1, max_length: 32)

  defp role_gen,
    do: StreamData.member_of(["platform_operator", "tenant_auditor", "caller"])

  defp alg_gen, do: StreamData.member_of([:rs256, :es256, :eddsa])

  # Enum of the 9 invalid classes. `member_of/1` shrinks toward the first
  # element — we put `:token_expired` first because it's the cheapest to
  # shrink/reproduce, not because it's the most important.
  defp invalid_class_gen do
    StreamData.member_of([
      :token_expired,
      :token_not_yet_valid,
      :invalid_audience,
      :invalid_issuer,
      :forbidden_alg,
      :invalid_signature,
      :token_replayed,
      :unknown_kid,
      :unsupported_token_format
    ])
  end

  # ---------------------------------------------------------------------------
  # Valid-class mint.
  # ---------------------------------------------------------------------------

  defp mint_valid(opts) do
    JwtTestHelper.mint_test_jwt(
      Keyword.merge(
        [
          issuer: @issuer,
          audience: @audience,
          ttl_seconds: 900
        ],
        opts
      )
    )
  end

  # ---------------------------------------------------------------------------
  # Invalid-class builders — each returns {jwt_string, expected_error_atom}.
  # Classes are structurally-valid-except-for-one-thing, so shrinking
  # reveals informative counterexamples (per stream-data-thinking skill).
  # ---------------------------------------------------------------------------

  defp build_invalid(:token_expired, alg) do
    # iat 2h ago, ttl 1h → exp = iat + 3600 = 1h ago. Well outside the
    # 60s skew tolerance per FR-007.
    now = System.system_time(:second)

    jwt =
      JwtTestHelper.mint_test_jwt(
        alg: alg,
        issuer: @issuer,
        audience: @audience,
        iat: now - 7200,
        ttl_seconds: 3600
      )

    {jwt, :token_expired}
  end

  defp build_invalid(:token_not_yet_valid, alg) do
    # iat 10 min in the future → nbf also 10 min in the future (helper
    # sets nbf = iat). Validator enforces nbf ≤ now + skew.
    now = System.system_time(:second)

    jwt =
      JwtTestHelper.mint_test_jwt(
        alg: alg,
        issuer: @issuer,
        audience: @audience,
        iat: now + 600,
        ttl_seconds: 900
      )

    {jwt, :token_not_yet_valid}
  end

  defp build_invalid(:invalid_audience, alg) do
    jwt =
      JwtTestHelper.mint_test_jwt(
        alg: alg,
        issuer: @issuer,
        audience: "not-the-gateway"
      )

    {jwt, :invalid_audience}
  end

  defp build_invalid(:invalid_issuer, alg) do
    jwt =
      JwtTestHelper.mint_test_jwt(
        alg: alg,
        issuer: "https://imposter.example.invalid",
        audience: @audience
      )

    {jwt, :invalid_issuer}
  end

  defp build_invalid(:forbidden_alg, _alg) do
    # JOSE intentionally refuses to sign with `alg: none`, so the helper
    # cannot produce this class. We hand-craft the compact serialization
    # per RFC 7519 §6.1 (Unsecured JWS): 3 segments, empty signature
    # segment, `alg: none` header.
    now = System.system_time(:second)

    header = %{"alg" => "none", "kid" => "test-key-rs256", "typ" => "JWT"}

    payload = %{
      "iss" => @issuer,
      "sub" => "user-none",
      "aud" => @audience,
      "iat" => now,
      "nbf" => now,
      "exp" => now + 900,
      "jti" => random_hex(16),
      "principal" => base_principal("caller")
    }

    h_b64 = b64url(JSON.encode!(header))
    p_b64 = b64url(JSON.encode!(payload))
    # Empty signature segment is RFC-legal for `alg: none` but MUST be
    # rejected by the validator per F002 FR-007 + F001 FR-017.
    jwt = "#{h_b64}.#{p_b64}."
    {jwt, :forbidden_alg}
  end

  defp build_invalid(:invalid_signature, alg) do
    # Mint a valid JWT, flip exactly one byte in the signature segment.
    # Header + payload remain valid; only the signature fails crypto
    # verification. Shrinking preserves "well-formed JWT with broken
    # sig" — the interesting counterexample shape.
    jwt = mint_valid(alg: alg, subject: "user-sig")
    [h, p, s] = String.split(jwt, ".", parts: 3)

    sig_bytes = Base.url_decode64!(s, padding: false)
    flipped = flip_one_byte(sig_bytes)
    s2 = Base.url_encode64(flipped, padding: false)

    {"#{h}.#{p}.#{s2}", :invalid_signature}
  end

  defp build_invalid(:token_replayed, alg) do
    # Fixed jti → first validate should succeed; second (with the jti
    # recorded in the replay cache) MUST be `:token_replayed`. The
    # property assertion feeds the replay-cache fixture the pre-seen jti
    # via `seen_jtis_for/2` below — equivalent to the validator seeing
    # the same token twice.
    jti = "replayed-" <> random_hex(8)
    jwt = mint_valid(alg: alg, subject: "user-replay", jti: jti)
    {jwt, :token_replayed}
  end

  defp build_invalid(:unknown_kid, alg) do
    # Construct a JWT with a `kid` that is NOT in @known_kids — validator
    # must short-circuit on kid-miss with `:unknown_kid` per FR-007 +
    # T042's JwksCache contract. We sign with a throwaway keypair so the
    # signature would also fail if kid-miss didn't short-circuit (that's
    # negative assurance, not the assertion).
    throwaway = generate_throwaway_jwk(alg)
    now = System.system_time(:second)

    header = %{
      "alg" => JwtTestHelper.jose_alg_string(alg),
      "kid" => "unknown-" <> random_hex(8),
      "typ" => "JWT"
    }

    payload = %{
      "iss" => @issuer,
      "sub" => "user-unknown-kid",
      "aud" => @audience,
      "iat" => now,
      "nbf" => now,
      "exp" => now + 900,
      "jti" => random_hex(16),
      "principal" => base_principal("caller")
    }

    {_, compact} =
      throwaway
      |> JOSE.JWT.sign(header, payload)
      |> JOSE.JWS.compact()

    {compact, :unknown_kid}
  end

  defp build_invalid(:unsupported_token_format, _alg) do
    # A JWE in compact serialization has 5 segments (header, encrypted
    # key, iv, ciphertext, tag) per RFC 7516 §3. The validator processes
    # JWS (3 segments) only — per F002 FR-007 + recurse_broker_api.md
    # "5-segment tokens (JWE) rejected". We synthesize a syntactically
    # well-formed JWE-shaped token; the validator rejects on segment
    # count without attempting to decrypt.
    header = %{"alg" => "dir", "enc" => "A256GCM", "kid" => "test-key-rs256"}

    segments = [
      b64url(JSON.encode!(header)),
      # encrypted_key (empty for `dir` but we fill with bytes for realism)
      b64url(:crypto.strong_rand_bytes(32)),
      # iv
      b64url(:crypto.strong_rand_bytes(12)),
      # ciphertext (empty protected payload allowed; bytes for realism)
      b64url(:crypto.strong_rand_bytes(64)),
      # auth tag
      b64url(:crypto.strong_rand_bytes(16))
    ]

    {Enum.join(segments, "."), :unsupported_token_format}
  end

  # ---------------------------------------------------------------------------
  # Replay-cache fixture helper — only the :token_replayed class needs a
  # pre-seeded cache; all other classes get `[]` so the validator's own
  # jti-extraction path is exercised.
  # ---------------------------------------------------------------------------

  defp seen_jtis_for(:token_replayed, jwt) do
    # Decode just the payload to pull jti (no sig verification needed;
    # this is the test harness seeding its OWN replay cache, not the
    # SUT doing validation).
    [_h, p, _s] = String.split(jwt, ".", parts: 3)
    claims = p |> Base.url_decode64!(padding: false) |> JSON.decode!()
    [claims["jti"]]
  end

  defp seen_jtis_for(_class, _jwt), do: []

  # ---------------------------------------------------------------------------
  # Forward reference to T041. When T041 lands, the implementer replaces
  # the body below with a call to Recurse.Gateway.Identity.JwtValidator.
  # The signature here is the one T041 is expected to expose; writing
  # against it now keeps T031 + T041 in sync.
  # ---------------------------------------------------------------------------

  defp validate_under_test(jwt, opts) do
    JwtValidator.validate(jwt, %{
      known_kids: jwk_lookup(opts[:known_kids]),
      audience: @audience,
      issuer: @issuer,
      seen_jtis: opts[:seen_jtis] || []
    })
  end

  # Translate the property-test's known-kid name list into the
  # `[{kid, JWK}]` shape the validator expects. JwtTestHelper caches one
  # keypair per alg in `:persistent_term`, so the JWKs below are stable
  # across iterations — the validator sees exactly the keypair that
  # signed each minted token.
  defp jwk_lookup(known_kids) when is_list(known_kids) do
    Enum.map(known_kids, fn
      "test-key-rs256" -> {"test-key-rs256", JwtTestHelper.public_jwk(:rs256)}
      "test-key-es256" -> {"test-key-es256", JwtTestHelper.public_jwk(:es256)}
      "test-key-eddsa" -> {"test-key-eddsa", JwtTestHelper.public_jwk(:eddsa)}
    end)
  end

  # ---------------------------------------------------------------------------
  # Utilities.
  # ---------------------------------------------------------------------------

  defp b64url(bin), do: Base.url_encode64(bin, padding: false)

  defp random_hex(bytes),
    do: bytes |> :crypto.strong_rand_bytes() |> Base.encode16(case: :lower)

  defp base_principal(role) do
    %{
      "kind" => "obo_human",
      "issuer" => @issuer,
      "subject" => "user-test",
      "display_name" => "Test User",
      "groups" => [],
      "recurse_role" => role
    }
  end

  defp flip_one_byte(<<b, rest::binary>>) do
    <<Bitwise.bxor(b, 0x01), rest::binary>>
  end

  defp generate_throwaway_jwk(:rs256), do: JOSE.JWK.generate_key({:rsa, 2048})
  defp generate_throwaway_jwk(:es256), do: JOSE.JWK.generate_key({:ec, "P-256"})
  defp generate_throwaway_jwk(:eddsa), do: JOSE.JWK.generate_key({:okp, :Ed25519})
end
