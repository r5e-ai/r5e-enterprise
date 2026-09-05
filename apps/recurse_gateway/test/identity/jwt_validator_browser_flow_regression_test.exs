defmodule Recurse.Gateway.Identity.JwtValidatorBrowserFlowRegressionTest do
  @moduledoc """
  F004 T039 — regression test for the existing F002 JwtValidator
  against JWTs minted via the F004 browser flow.

  ## What this test asserts

  Per `specs/004-audit-console/tasks.md` T039: the F004 browser flow
  (per `contracts/browser_oidc_flow.md`) ultimately minted JWTs go
  through the same RFC 8693 token-exchange path that direct API
  callers use (per F002 `recurse_broker_api.md`). Both paths emit
  identical-shape JWTs:

    * Header — `alg \u2208 {RS256, ES256, EdDSA}`, `kid`, `typ: JWT`.
    * Claims — `iss`, `sub`, `aud`, `iat`, `nbf`, `exp`, `jti`,
      `principal: {kind, issuer, subject, ...}`.

  The validator is therefore expected to handle browser-flow JWTs
  WITHOUT extension. F004 contributes no new claim-shape validation
  rules. This regression test pins that contract: if a future
  refactor of the validator (say, tightening allowed `kind` values
  or adding a custom claim) accidentally rejects a browser-flow
  JWT, this test fails.

  ## elixir-thinking notes

  Pure data assertions over a pure function — no GenServer, no
  test fixture cleanup needed. Validator + JwtTestHelper both run
  on the test process. Iron Law triple-NO satisfied.

  ## Cross-references

    * `apps/recurse_gateway/lib/recurse_gateway/identity/jwt_validator.ex`
    * `apps/recurse_gateway/test/support/jwt_test_helper.ex`
    * `specs/004-audit-console/contracts/browser_oidc_flow.md` Step 5
      (RFC 8693 token-exchange path, identical to F002's direct-API
      path)
    * `specs/002-standalone-gateway-vertical-slice/contracts/recurse_broker_api.md`
      \u00a7"Minted JWT shape"
  """
  use ExUnit.Case, async: true

  alias Recurse.Gateway.Identity.JwtValidator
  alias Recurse.Gateway.Test.JwtTestHelper

  @audience "recurse-gateway-prod"
  @issuer "https://test-broker.example.invalid"

  describe "browser-flow JWT regression" do
    test "platform_operator JWT minted as if from /admin/login/callback validates" do
      # Models the cookie payload's `jwt` field: a freshly-minted
      # X-Observed-Identity for a platform_operator who just
      # completed the OIDC dance per browser_oidc_flow.md Step 4.5
      # (the broker's RFC 8693 path, audience `recurse-gateway-prod`).
      jwt =
        JwtTestHelper.mint_test_jwt(
          alg: :rs256,
          issuer: @issuer,
          audience: @audience,
          subject: "alice@corp",
          recurse_role: "platform_operator",
          principal_overrides: %{
            "display_name" => "Alice Operator",
            "groups" => ["operators", "audit-readers"]
          }
        )

      assert {:ok, claims} =
               JwtValidator.validate(jwt, %{
                 audience: @audience,
                 issuer: @issuer,
                 known_kids: known_kids()
               })

      # Pin the claim shape — this is what BrowserSessionPlug will
      # later read out of the lifted Authorization header.
      assert claims["sub"] == "alice@corp"
      assert claims["aud"] == @audience
      assert claims["iss"] == @issuer
      assert is_integer(claims["iat"])
      assert is_integer(claims["exp"])
      assert claims["exp"] > claims["iat"]
      assert is_binary(claims["jti"])

      principal = claims["principal"]
      assert principal["kind"] == "obo_human"
      assert principal["subject"] == "alice@corp"
      assert principal["recurse_role"] == "platform_operator"
      assert principal["display_name"] == "Alice Operator"
      assert principal["groups"] == ["operators", "audit-readers"]
    end

    test "tenant_auditor JWT minted as if from /admin/login/callback validates" do
      # Same shape under the second valid F004 console role.
      jwt =
        JwtTestHelper.mint_test_jwt(
          alg: :es256,
          issuer: @issuer,
          audience: @audience,
          subject: "bob@corp",
          recurse_role: "tenant_auditor"
        )

      assert {:ok, claims} =
               JwtValidator.validate(jwt, %{
                 audience: @audience,
                 issuer: @issuer,
                 known_kids: known_kids()
               })

      assert claims["principal"]["recurse_role"] == "tenant_auditor"
    end

    test "all three F002-allowlisted algs round-trip through the browser-flow audience" do
      # F002 FR-007 allowlist: RS256, ES256, EdDSA. Browser flow
      # inherits the allowlist unchanged. Validating each here pins
      # that the F004 audience value (`recurse-gateway-prod`)
      # composes correctly with each alg.
      for alg <- [:rs256, :es256, :eddsa] do
        jwt =
          JwtTestHelper.mint_test_jwt(
            alg: alg,
            issuer: @issuer,
            audience: @audience,
            subject: "carol@corp",
            recurse_role: "platform_operator"
          )

        assert {:ok, claims} =
                 JwtValidator.validate(jwt, %{
                   audience: @audience,
                   issuer: @issuer,
                   known_kids: known_kids()
                 }),
               "alg #{inspect(alg)} failed to validate; F002 allowlist regression"

        assert claims["sub"] == "carol@corp"
      end
    end

    test "browser-flow JWT 60s clock-skew tolerance still applies" do
      # The validator's 60s skew is a F002 FR-007 contract; browser
      # flow inherits it. A token minted with `iat` 30s in the
      # future (within skew) MUST validate.
      now = System.system_time(:second)

      jwt =
        JwtTestHelper.mint_test_jwt(
          alg: :rs256,
          issuer: @issuer,
          audience: @audience,
          subject: "dave@corp",
          recurse_role: "tenant_auditor",
          iat: now + 30
        )

      assert {:ok, _claims} =
               JwtValidator.validate(jwt, %{
                 audience: @audience,
                 issuer: @issuer,
                 known_kids: known_kids()
               })
    end
  end

  # ---------------------------------------------------------------------------
  # Test fixture: the public JWKs for every alg JwtTestHelper supports.
  # The validator's `:known_kids` opt accepts a `[{kid, %JOSE.JWK{}}]` list;
  # we derive both from JwtTestHelper so the keypair the helper signs with
  # is the keypair the validator verifies against.
  # ---------------------------------------------------------------------------

  defp known_kids do
    Enum.map([:rs256, :es256, :eddsa], fn alg ->
      jwk = JwtTestHelper.public_jwk(alg)
      {jwk["kid"], jwk}
    end)
  end
end
