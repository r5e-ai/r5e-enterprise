defmodule Recurse.Gateway.LlmProxy.PrincipalExtractorTest do
  @moduledoc """
  Unit tests for `Recurse.Gateway.LlmProxy.PrincipalExtractor`.

  Spec source of truth:
    * `specs/009-llm-api-proxy/research.md` R-001 (Codex auth + JWT shape)
    * `specs/009-llm-api-proxy/research.md` R-014 (login flow)
    * `specs/009-llm-api-proxy/spec.md` FR-002 (OAuth flow preservation)

  ## What this validates

  The proxy peeks at the JWT payload — WITHOUT signature verification —
  to extract audit-identity claims (`sub`, `chatgpt_account_id`).
  Upstream `chatgpt.com` does the actual authN; we observe.

  Five surfaces:

    * happy path — ChatGPT-Enterprise JWT shape extracts sub +
      chatgpt_account_id + classifies as :obo_human
    * service-account JWT classifies as :service_account
    * missing Authorization header → {:error, :no_authorization}
    * malformed JWT (not 3 segments / bad base64) →
      {:error, :malformed_jwt}
    * missing sub claim → {:error, :missing_sub_claim}
    * missing chatgpt_account_id (some non-Enterprise tokens) →
      ok with chatgpt_account_id: nil
  """

  use ExUnit.Case, async: true

  alias Recurse.Gateway.LlmProxy.PrincipalExtractor

  # ---------------------------------------------------------------------------
  # Helpers — mint a JWT-shaped string. We do NOT need a valid signature
  # because PrincipalExtractor decodes WITHOUT verifying. The signature
  # segment can be any bytes; the header + payload must be valid base64-
  # url-encoded JSON.
  # ---------------------------------------------------------------------------

  defp encode_segment(map) do
    map
    |> Jason.encode!()
    |> Base.url_encode64(padding: false)
  end

  defp build_jwt(payload, header \\ %{"alg" => "RS256", "typ" => "JWT"}) do
    encode_segment(header) <> "." <> encode_segment(payload) <> ".signature_bytes"
  end

  # Canonical ChatGPT-Enterprise JWT shape per research.md R-001.
  # `chatgpt_account_id` is the org-tenant ID Codex CLI sets as a
  # request header.
  defp chatgpt_enterprise_payload do
    %{
      "iss" => "https://auth.openai.com",
      "sub" => "user-abc123",
      "chatgpt_account_id" => "acct_eddy_corp_42",
      "aud" => "chatgpt.com",
      "exp" => 9_999_999_999,
      "iat" => 1_700_000_000,
      "scope" => "openai-api"
    }
  end

  describe "extract_from_headers/1 — happy path" do
    test "ChatGPT-Enterprise JWT yields :obo_human + sub + chatgpt_account_id" do
      jwt = build_jwt(chatgpt_enterprise_payload())

      headers = [{"authorization", "Bearer " <> jwt}, {"content-type", "application/json"}]

      assert {:ok, principal} = PrincipalExtractor.extract_from_headers(headers)
      assert principal.principal_id == "user-abc123"
      assert principal.principal_kind == :obo_human
      assert principal.chatgpt_account_id == "acct_eddy_corp_42"
      assert principal.claims["iss"] == "https://auth.openai.com"
      assert principal.claims["aud"] == "chatgpt.com"
    end

    test "case-insensitive Authorization header lookup" do
      jwt = build_jwt(chatgpt_enterprise_payload())

      headers = [{"Authorization", "Bearer " <> jwt}]
      assert {:ok, _} = PrincipalExtractor.extract_from_headers(headers)

      headers = [{"AUTHORIZATION", "Bearer " <> jwt}]
      assert {:ok, _} = PrincipalExtractor.extract_from_headers(headers)
    end

    test "headers as a map (not a list) also works" do
      jwt = build_jwt(chatgpt_enterprise_payload())
      headers = %{"authorization" => "Bearer " <> jwt}

      assert {:ok, principal} = PrincipalExtractor.extract_from_headers(headers)
      assert principal.principal_id == "user-abc123"
    end
  end

  describe "extract_from_headers/1 — principal_kind classification" do
    test "service_account when token_use claim is service" do
      payload = %{
        "sub" => "service-account-xyz",
        "token_use" => "service",
        "chatgpt_account_id" => "acct_corp"
      }

      jwt = build_jwt(payload)
      headers = [{"authorization", "Bearer " <> jwt}]

      assert {:ok, principal} = PrincipalExtractor.extract_from_headers(headers)
      assert principal.principal_kind == :service_account
    end

    test "autonomous when claims indicate spiffe identity" do
      payload = %{
        "sub" => "spiffe://example.org/agent",
        "token_use" => "autonomous"
      }

      jwt = build_jwt(payload)
      headers = [{"authorization", "Bearer " <> jwt}]

      assert {:ok, principal} = PrincipalExtractor.extract_from_headers(headers)
      assert principal.principal_kind == :autonomous
    end

    test "default :obo_human when no classifying claim present" do
      payload = %{"sub" => "user-default", "chatgpt_account_id" => "acct_x"}
      jwt = build_jwt(payload)
      headers = [{"authorization", "Bearer " <> jwt}]

      assert {:ok, principal} = PrincipalExtractor.extract_from_headers(headers)
      assert principal.principal_kind == :obo_human
    end
  end

  describe "extract_from_headers/1 — missing chatgpt_account_id" do
    test "non-Enterprise token (no chatgpt_account_id claim) returns nil" do
      payload = %{"sub" => "user-plus", "iss" => "https://auth.openai.com"}
      jwt = build_jwt(payload)
      headers = [{"authorization", "Bearer " <> jwt}]

      assert {:ok, principal} = PrincipalExtractor.extract_from_headers(headers)
      assert principal.principal_id == "user-plus"
      assert principal.chatgpt_account_id == nil
    end

    test "account_id alias claim (some legacy tokens)" do
      payload = %{
        "sub" => "user-legacy",
        "account_id" => "acct_legacy_alias"
      }

      jwt = build_jwt(payload)
      headers = [{"authorization", "Bearer " <> jwt}]

      assert {:ok, principal} = PrincipalExtractor.extract_from_headers(headers)
      assert principal.chatgpt_account_id == "acct_legacy_alias"
    end
  end

  describe "extract_from_headers/1 — error paths" do
    test "no Authorization header at all" do
      headers = [{"content-type", "application/json"}]
      assert {:error, :no_authorization} = PrincipalExtractor.extract_from_headers(headers)
    end

    test "Authorization without Bearer scheme" do
      headers = [{"authorization", "Basic dXNlcjpwYXNz"}]
      assert {:error, :no_authorization} = PrincipalExtractor.extract_from_headers(headers)
    end

    test "malformed JWT — not three segments" do
      headers = [{"authorization", "Bearer not.a.jwt.at.all"}]
      assert {:error, :malformed_jwt} = PrincipalExtractor.extract_from_headers(headers)

      headers = [{"authorization", "Bearer onlyone"}]
      assert {:error, :malformed_jwt} = PrincipalExtractor.extract_from_headers(headers)
    end

    test "malformed JWT — payload not base64" do
      headers = [{"authorization", "Bearer aaaa.!!!!.zzzz"}]
      assert {:error, :malformed_jwt} = PrincipalExtractor.extract_from_headers(headers)
    end

    test "malformed JWT — payload not JSON" do
      bad_payload = Base.url_encode64("not-json-at-all", padding: false)
      jwt = "header." <> bad_payload <> ".sig"
      headers = [{"authorization", "Bearer " <> jwt}]
      assert {:error, :malformed_jwt} = PrincipalExtractor.extract_from_headers(headers)
    end

    test "missing sub claim" do
      payload = %{"chatgpt_account_id" => "acct_x", "iss" => "https://auth.openai.com"}
      jwt = build_jwt(payload)
      headers = [{"authorization", "Bearer " <> jwt}]

      assert {:error, :missing_sub_claim} = PrincipalExtractor.extract_from_headers(headers)
    end

    test "empty sub claim" do
      payload = %{"sub" => ""}
      jwt = build_jwt(payload)
      headers = [{"authorization", "Bearer " <> jwt}]

      assert {:error, :missing_sub_claim} = PrincipalExtractor.extract_from_headers(headers)
    end
  end

  # ---------------------------------------------------------------------------
  # Spec 012 S4 — Claude Code: opaque OAuth bearer + metadata.user_id
  # ---------------------------------------------------------------------------

  describe "extract_from_request/2 (Claude Code)" do
    @account "0f2f0a2e-4b7a-4c8f-9d5e-000000000abc"
    @user_id Jason.encode!(%{
               "device_id" => String.duplicate("0", 64),
               "account_uuid" => "0f2f0a2e-4b7a-4c8f-9d5e-000000000abc",
               "session_id" => "ecdcbccc-ecb4-40f4-bbb1-db3ad3b16bca"
             })

    test "opaque sk-ant-oat01 bearer + metadata.user_id → claude-code:<account_uuid>, obo_human" do
      headers = [{"authorization", "Bearer sk-ant-oat01-" <> String.duplicate("x", 100)}]
      params = %{"model" => "claude-haiku-4-5-20251001", "metadata" => %{"user_id" => @user_id}}

      assert {:ok, principal} = PrincipalExtractor.extract_from_request(headers, params)
      assert principal.principal_id == "claude-code:" <> @account
      assert principal.principal_kind == :obo_human
      assert principal.chatgpt_account_id == nil
      assert principal.claims["account_uuid"] == @account
      assert principal.claims["session_id"] == "ecdcbccc-ecb4-40f4-bbb1-db3ad3b16bca"
      assert principal.claims["source"] == "claude_code_metadata"
      assert principal.principal_source == :client_metadata
    end

    test "the JWT path reports principal_source :jwt" do
      headers = [{"authorization", "Bearer " <> build_jwt(chatgpt_enterprise_payload())}]
      assert {:ok, %{principal_source: :jwt}} = PrincipalExtractor.extract_from_headers(headers)

      assert {:ok, %{principal_source: :jwt}} =
               PrincipalExtractor.extract_from_request(headers, %{})
    end

    test "an account_uuid that is not a UUID makes the bearer opaque (S4 review)" do
      headers = [{"authorization", "Bearer sk-ant-oat01-" <> String.duplicate("x", 100)}]

      for account <- [
            ~s(x"y),
            "a\\b",
            "0f2f0a2e-4b7a-4c8f-9d5e-000000000abc\n",
            String.duplicate("a", 300),
            "abc",
            "0f2f0a2e4b7a4c8f9d5e000000000abc",
            "",
            42
          ] do
        params = %{"metadata" => %{"user_id" => Jason.encode!(%{"account_uuid" => account})}}

        assert {:error, :opaque_bearer} = PrincipalExtractor.extract_from_request(headers, params),
               "expected opaque for #{inspect(account)}"

        refute PrincipalExtractor.valid_account_uuid?(account)
      end
    end

    test "the account uuid is lower-cased so hex case cannot fork a principal" do
      headers = [{"authorization", "Bearer sk-ant-oat01-" <> String.duplicate("x", 100)}]
      upper = String.upcase(@account)
      params = %{"metadata" => %{"user_id" => Jason.encode!(%{"account_uuid" => upper})}}

      assert {:ok, principal} = PrincipalExtractor.extract_from_request(headers, params)
      assert principal.principal_id == "claude-code:" <> @account
      assert principal.claims["account_uuid"] == @account
      assert PrincipalExtractor.valid_account_uuid?(upper)
      assert PrincipalExtractor.valid_account_uuid?("00000000-0000-0000-0000-000000000000")
    end

    test "principal_source_to_string/1 never reports an unknown source as stronger than anonymous" do
      assert PrincipalExtractor.principal_source_to_string(:jwt) == "jwt"
      assert PrincipalExtractor.principal_source_to_string(:client_metadata) == "client_metadata"
      assert PrincipalExtractor.principal_source_to_string(:mtls_svid) == "mtls_svid"
      assert PrincipalExtractor.principal_source_to_string("client_metadata") == "client_metadata"
      assert PrincipalExtractor.principal_source_to_string(:anonymous) == "anonymous"
      assert PrincipalExtractor.principal_source_to_string("verified") == "anonymous"
      assert PrincipalExtractor.principal_source_to_string(nil) == "anonymous"
    end

    test "metadata is consulted only when the bearer is not a JWT; the JWT path is unchanged" do
      jwt = build_jwt(%{"sub" => "user-jwt", "chatgpt_account_id" => "acct"})
      headers = [{"authorization", "Bearer " <> jwt}]
      params = %{"metadata" => %{"user_id" => @user_id}}

      assert {:ok, %{principal_id: "user-jwt", chatgpt_account_id: "acct"}} =
               PrincipalExtractor.extract_from_request(headers, params)
    end

    test "opaque bearer without usable metadata → :opaque_bearer" do
      headers = [{"authorization", "Bearer sk-ant-api03-key"}]
      assert {:error, :opaque_bearer} = PrincipalExtractor.extract_from_request(headers, %{})
      assert {:error, :opaque_bearer} = PrincipalExtractor.extract_from_request(headers, nil)

      assert {:error, :opaque_bearer} =
               PrincipalExtractor.extract_from_request(headers, %{
                 "metadata" => %{"user_id" => "not json"}
               })

      assert {:error, :opaque_bearer} =
               PrincipalExtractor.extract_from_request(headers, %{
                 "metadata" => %{"user_id" => Jason.encode!(%{"session_id" => "s"})}
               })
    end

    test "a JWT-shaped bearer that fails to decode still reports :malformed_jwt" do
      headers = [{"authorization", "Bearer a.b.c"}]
      assert {:error, :malformed_jwt} = PrincipalExtractor.extract_from_request(headers, %{})
    end

    test "no Authorization header → :no_authorization even with metadata" do
      params = %{"metadata" => %{"user_id" => @user_id}}
      assert {:error, :no_authorization} = PrincipalExtractor.extract_from_request([], params)
    end
  end
end
