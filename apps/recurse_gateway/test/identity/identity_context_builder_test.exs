defmodule Recurse.Gateway.Identity.IdentityContextBuilderTest do
  @moduledoc """
  Contract tests for `Recurse.Gateway.Identity.IdentityContextBuilder` (F002 T043).

  Covers:

    * Happy path — valid JWT populates every IdentityContext field.
    * Missing / malformed Authorization headers.
    * Validator errors propagated (expired, invalid_audience, etc.).
    * Correlation-ID resolution — ULID / foreign / absent.
    * Principal-claim shape mismatch → `:malformed_principal`.

  `async: true` — pure functions under test; no global state.
  """

  use ExUnit.Case, async: true

  alias Recurse.Gateway.Identity.IdentityContextBuilder
  alias Recurse.Gateway.Test.JwtTestHelper
  alias Recurse.Shared.CorrelationId
  alias Recurse.Shared.IdentityContext
  alias Recurse.Shared.Principal
  alias Recurse.Shared.Ulid

  @tenant_id "01HQZN5K7J8M9N0P1Q2R3S4T5V"
  @audience "recurse-gateway-test"
  @issuer "https://test-broker.example.invalid"

  defp validator_opts do
    [
      audience: @audience,
      issuer: @issuer,
      known_kids: [
        {"test-key-rs256", JwtTestHelper.public_jwk(:rs256)},
        {"test-key-es256", JwtTestHelper.public_jwk(:es256)},
        {"test-key-eddsa", JwtTestHelper.public_jwk(:eddsa)}
      ]
    ]
  end

  describe "build/3 — happy path" do
    test "populates IdentityContext fields from a valid JWT" do
      jwt =
        JwtTestHelper.mint_test_jwt(
          subject: "alice",
          recurse_role: "platform_operator",
          issuer: @issuer,
          audience: @audience
        )

      headers = [{"authorization", "Bearer " <> jwt}]

      assert {:ok, %IdentityContext{} = ctx} =
               IdentityContextBuilder.build(headers, @tenant_id, validator_opts())

      assert ctx.tenant_id == @tenant_id
      assert %Principal{kind: :obo_human, subject: "alice", issuer: @issuer} = ctx.principal

      assert {:observed_jwt_subject, %{observed_jwt_subject: "alice", issuer: @issuer}} =
               ctx.machine_identity

      assert is_integer(ctx.resolved_at_usec) and ctx.resolved_at_usec > 0
      # Correlation ID was minted (no X-Correlation-ID header supplied).
      assert Ulid.valid?(ctx.correlation_id)
    end

    test "preserves an inbound canonical ULID correlation_id" do
      jwt = JwtTestHelper.mint_test_jwt(audience: @audience, issuer: @issuer)
      correlation_id = Ulid.generate()

      headers = [
        {"authorization", "Bearer " <> jwt},
        {CorrelationId.header_name(), correlation_id}
      ]

      assert {:ok, ctx} = IdentityContextBuilder.build(headers, @tenant_id, validator_opts())
      assert ctx.correlation_id == correlation_id
    end

    test "accepts a foreign correlation_id (e.g., W3C traceparent) unchanged" do
      jwt = JwtTestHelper.mint_test_jwt(audience: @audience, issuer: @issuer)
      # 32-hex Jaeger-ish trace-id — `CorrelationId.validate/1` returns
      # `{:ok, :foreign, original}` per its printable-ASCII rule.
      foreign = "abcdef0123456789abcdef0123456789"

      headers = [
        {"authorization", "Bearer " <> jwt},
        {CorrelationId.header_name(), foreign}
      ]

      assert {:ok, ctx} = IdentityContextBuilder.build(headers, @tenant_id, validator_opts())
      assert ctx.correlation_id == foreign
    end

    test "mints a fresh correlation_id when the header is empty or unprintable" do
      jwt = JwtTestHelper.mint_test_jwt(audience: @audience, issuer: @issuer)

      headers = [
        {"authorization", "Bearer " <> jwt},
        {CorrelationId.header_name(), ""}
      ]

      assert {:ok, ctx} = IdentityContextBuilder.build(headers, @tenant_id, validator_opts())
      assert Ulid.valid?(ctx.correlation_id)
    end
  end

  describe "build/3 — authorization header handling" do
    test "returns :missing_authorization when header absent" do
      assert {:error, :missing_authorization} =
               IdentityContextBuilder.build([], @tenant_id, validator_opts())
    end

    test "returns :missing_authorization when scheme is not Bearer" do
      headers = [{"authorization", "Basic dXNlcjpwYXNz"}]

      assert {:error, :missing_authorization} =
               IdentityContextBuilder.build(headers, @tenant_id, validator_opts())
    end

    test "returns :missing_authorization when Bearer value is empty" do
      headers = [{"authorization", "Bearer "}]

      assert {:error, :missing_authorization} =
               IdentityContextBuilder.build(headers, @tenant_id, validator_opts())
    end

    test "accepts lowercase bearer scheme" do
      jwt = JwtTestHelper.mint_test_jwt(audience: @audience, issuer: @issuer)
      headers = [{"authorization", "bearer " <> jwt}]

      assert {:ok, _ctx} =
               IdentityContextBuilder.build(headers, @tenant_id, validator_opts())
    end
  end

  describe "build/3 — validator error propagation" do
    test "propagates :token_expired unchanged" do
      now = System.system_time(:second)

      jwt =
        JwtTestHelper.mint_test_jwt(
          audience: @audience,
          issuer: @issuer,
          iat: now - 7200,
          ttl_seconds: 3600
        )

      headers = [{"authorization", "Bearer " <> jwt}]

      assert {:error, :token_expired} =
               IdentityContextBuilder.build(headers, @tenant_id, validator_opts())
    end

    test "propagates :invalid_audience unchanged" do
      jwt = JwtTestHelper.mint_test_jwt(audience: "wrong-aud", issuer: @issuer)
      headers = [{"authorization", "Bearer " <> jwt}]

      assert {:error, :invalid_audience} =
               IdentityContextBuilder.build(headers, @tenant_id, validator_opts())
    end

    test "propagates :invalid_issuer unchanged" do
      jwt = JwtTestHelper.mint_test_jwt(audience: @audience, issuer: "https://imposter.example")
      headers = [{"authorization", "Bearer " <> jwt}]

      assert {:error, :invalid_issuer} =
               IdentityContextBuilder.build(headers, @tenant_id, validator_opts())
    end
  end

  describe "build/3 — malformed principal claim" do
    test "returns :malformed_principal when principal.kind missing" do
      jwt =
        JwtTestHelper.mint_test_jwt(
          audience: @audience,
          issuer: @issuer,
          principal_overrides: %{"kind" => "unknown_shape"}
        )

      headers = [{"authorization", "Bearer " <> jwt}]

      assert {:error, :malformed_principal} =
               IdentityContextBuilder.build(headers, @tenant_id, validator_opts())
    end
  end
end
