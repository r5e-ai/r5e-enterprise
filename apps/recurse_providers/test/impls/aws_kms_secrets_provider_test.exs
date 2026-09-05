defmodule Recurse.Providers.Impls.AwsKmsSecretsProviderTest do
  @moduledoc """
  Contract tests for `Recurse.Providers.Impls.AwsKmsSecretsProvider` (F002
  T036 + T037 — real KMS sign + public-key cache).

  ## Test strategy

  KMS calls are intercepted at the `ExAws.Request.HttpClient` boundary via
  `Recurse.Providers.Mocks.ExAwsHttpClient` (Mox). The mock is installed
  into each provider state via the `:http_client` config knob — no global
  `Application.put_env` mutation, `async: true`-safe.

  The `:persistent_term` public-key cache is process-global; tests use a
  unique `key_arn` per test (derived from `make_ref/0`) so concurrent
  tests cannot see each other's cache entries.
  """

  use ExUnit.Case, async: true

  import Mox

  alias Recurse.Providers.Impls.AwsKmsSecretsProvider
  alias Recurse.Providers.Mocks.ExAwsHttpClient, as: HttpClientMock

  setup :set_mox_from_context
  setup :verify_on_exit!

  # A tiny DER-encoded SubjectPublicKeyInfo blob — we don't parse it, we
  # just need to confirm the provider base64-decodes the wire value and
  # wraps it in a PEM envelope.
  @der_bytes :crypto.strong_rand_bytes(91)
  @der_b64 Base.encode64(@der_bytes)

  # Representative ECDSA_SHA_256 signature — 71 bytes of random DER-shaped
  # payload. Same pattern: we assert shape, not crypto validity.
  @sig_bytes :crypto.strong_rand_bytes(71)
  @sig_b64 Base.encode64(@sig_bytes)

  describe "init/1" do
    test "returns {:ok, state} after warming public-key cache" do
      key_arn = unique_key_arn()

      HttpClientMock
      |> expect(:request, 1, fn :post, _url, _body, _headers, _opts ->
        {:ok, ok_response(%{"KeyId" => key_arn, "PublicKey" => @der_b64})}
      end)

      assert {:ok, state} = init_provider(key_arn)
      assert state.key_arn == key_arn
      assert state.algorithm == "ECDSA_SHA_256"
      assert state.key_version == 1
    end

    test "returns {:error, :invalid_config, :key_arn} when key_arn missing" do
      assert {:error, {:invalid_config, :key_arn}} =
               AwsKmsSecretsProvider.init(%{region: "us-east-1"})
    end

    test "returns {:error, :public_key_warmup_failed, _} on KMS 500" do
      key_arn = unique_key_arn()

      HttpClientMock
      |> expect(:request, 3, fn :post, _url, _body, _headers, _opts ->
        {:ok, %{status_code: 500, headers: [], body: "{}"}}
      end)

      assert {:error, {:public_key_warmup_failed, _reason}} = init_provider(key_arn)
    end
  end

  describe "active_signing_key/1" do
    test "returns handle with key_arn, key_version, algorithm" do
      state = warmed_state()

      assert {:ok, %{key_id: key_id, key_version: 1, algorithm: :ecdsa_p256}} =
               AwsKmsSecretsProvider.active_signing_key(state)

      assert is_binary(key_id)
    end
  end

  describe "sign/3" do
    test "returns {:ok, signature_bytes} on mocked KMS 200" do
      state = warmed_state()
      {:ok, handle} = AwsKmsSecretsProvider.active_signing_key(state)

      HttpClientMock
      |> expect(:request, 1, fn :post, _url, body, headers, _opts ->
        assert kms_target(headers) == "TrentService.Sign"
        decoded = JSON.decode!(body)
        assert decoded["KeyId"] == state.key_arn
        assert decoded["SigningAlgorithm"] == "ECDSA_SHA_256"

        {:ok,
         ok_response(%{
           "KeyId" => state.key_arn,
           "Signature" => @sig_b64,
           "SigningAlgorithm" => "ECDSA_SHA_256"
         })}
      end)

      assert {:ok, sig} = AwsKmsSecretsProvider.sign(state, handle, "payload-bytes")
      assert sig == @sig_bytes
    end

    test "returns {:error, :retries_exhausted} after 3 KMS 5xx responses" do
      state = warmed_state()
      {:ok, handle} = AwsKmsSecretsProvider.active_signing_key(state)

      HttpClientMock
      |> expect(:request, 3, fn :post, _url, _body, _headers, _opts ->
        {:ok,
         %{
           status_code: 503,
           headers: [],
           body: ~s({"__type":"ServiceUnavailable","message":"try later"})
         }}
      end)

      assert {:error, :retries_exhausted} =
               AwsKmsSecretsProvider.sign(state, handle, "payload-bytes")
    end

    test "passes raw payload bytes through (no double-base64 on the wire)" do
      state = warmed_state()
      {:ok, handle} = AwsKmsSecretsProvider.active_signing_key(state)
      raw_payload = <<0x00, 0x01, 0x02, 0xFF, "canonical-pae-bytes"::binary>>

      HttpClientMock
      |> expect(:request, 1, fn :post, _url, body, _headers, _opts ->
        decoded = JSON.decode!(body)
        # ex_aws base64-encodes the Message blob on the wire; we verify
        # our provider passed the raw bytes in, not a double-encoded form.
        {:ok, wire_bytes} = Base.decode64(decoded["Message"])
        assert wire_bytes == raw_payload

        {:ok, ok_response(%{"KeyId" => state.key_arn, "Signature" => @sig_b64})}
      end)

      assert {:ok, _sig} = AwsKmsSecretsProvider.sign(state, handle, raw_payload)
    end
  end

  describe "public_key/2" do
    test "first call hits KMS, second call hits :persistent_term cache" do
      key_arn = unique_key_arn()

      # One KMS call for init/warmup + one for the first explicit public_key/2.
      # The SECOND explicit public_key/2 call must NOT hit KMS — asserted
      # by setting the Mox expectation count to exactly 2.
      HttpClientMock
      |> expect(:request, 2, fn :post, _url, _body, _headers, _opts ->
        {:ok, ok_response(%{"KeyId" => key_arn, "PublicKey" => @der_b64})}
      end)

      {:ok, state} = init_provider(key_arn)
      {:ok, handle} = AwsKmsSecretsProvider.active_signing_key(state)

      # First public_key/2 call — cache was written by init but we bust
      # it deliberately to force a real fetch path through the provider.
      :persistent_term.erase({AwsKmsSecretsProvider, :public_key, key_arn, 1})
      assert {:ok, pem1} = AwsKmsSecretsProvider.public_key(state, handle)
      assert String.starts_with?(pem1, "-----BEGIN PUBLIC KEY-----\n")
      assert String.ends_with?(pem1, "-----END PUBLIC KEY-----\n")

      # Second call — must hit cache, NOT the mock. If it hit KMS, Mox
      # would flag "unexpected request" on the THIRD call.
      assert {:ok, ^pem1} = AwsKmsSecretsProvider.public_key(state, handle)
    end

    test "rotation (new key_version) produces cache miss + fresh fetch" do
      key_arn = unique_key_arn()

      # warmup (v1) + explicit v1 after cache-erase + v2 fetch = 3 calls.
      HttpClientMock
      |> expect(:request, 3, fn :post, _url, _body, _headers, _opts ->
        {:ok, ok_response(%{"KeyId" => key_arn, "PublicKey" => @der_b64})}
      end)

      {:ok, state} = init_provider(key_arn)
      handle_v1 = %{key_id: key_arn, key_version: 1, algorithm: :ecdsa_p256}
      handle_v2 = %{key_id: key_arn, key_version: 2, algorithm: :ecdsa_p256}

      # Erase v1 cache then fetch both versions — each is a distinct
      # cache key, so both miss + hit KMS.
      :persistent_term.erase({AwsKmsSecretsProvider, :public_key, key_arn, 1})
      assert {:ok, _pem_v1} = AwsKmsSecretsProvider.public_key(state, handle_v1)
      assert {:ok, _pem_v2} = AwsKmsSecretsProvider.public_key(state, handle_v2)
    end

    test "returns valid PEM envelope with 64-char body lines" do
      state = warmed_state()
      {:ok, handle} = AwsKmsSecretsProvider.active_signing_key(state)

      assert {:ok, pem} = AwsKmsSecretsProvider.public_key(state, handle)

      body_lines =
        pem
        |> String.split("\n", trim: true)
        |> Enum.drop(1)
        |> Enum.drop(-1)

      for line <- Enum.drop(body_lines, -1) do
        assert String.length(line) == 64, "PEM body line not 64 chars: #{inspect(line)}"
      end

      last = List.last(body_lines)
      assert last != nil and String.length(last) <= 64
    end
  end

  describe "capabilities/1" do
    test "advertises :sign, :public_key_export, :hsm_backed" do
      state = warmed_state()
      caps = AwsKmsSecretsProvider.capabilities(state)
      assert :sign in caps
      assert :public_key_export in caps
      assert :hsm_backed in caps
    end
  end

  describe "healthcheck/1" do
    test "returns :ok on KMS 200 DescribeKey" do
      state = warmed_state()

      HttpClientMock
      |> expect(:request, 1, fn :post, _url, _body, headers, _opts ->
        assert kms_target(headers) == "TrentService.DescribeKey"
        {:ok, ok_response(%{"KeyMetadata" => %{"KeyId" => state.key_arn, "Enabled" => true}})}
      end)

      assert :ok = AwsKmsSecretsProvider.healthcheck(state)
    end

    test "returns {:degraded, _} on KMS 5xx" do
      state = warmed_state()

      HttpClientMock
      |> expect(:request, 3, fn :post, _url, _body, _headers, _opts ->
        {:ok, %{status_code: 500, headers: [], body: "{}"}}
      end)

      assert {:degraded, {:kms_5xx, 500}} = AwsKmsSecretsProvider.healthcheck(state)
    end
  end

  describe "Phase-2 deferred RFC 8693 callbacks (unchanged)" do
    test "store_user_token/4 returns :not_implemented_yet" do
      state = warmed_state()
      ctx = build_identity_context()

      assert {:error, :not_implemented_yet} =
               AwsKmsSecretsProvider.store_user_token(state, ctx, "token", 3600)
    end

    test "exchange_for_downstream_token/4 returns :not_implemented_yet" do
      state = warmed_state()
      ctx = build_identity_context()

      assert {:error, :not_implemented_yet} =
               AwsKmsSecretsProvider.exchange_for_downstream_token(state, ctx, "jira", [
                 "read:issues"
               ])
    end
  end

  describe "terminate/2" do
    test "returns :ok and leaves cache intact" do
      state = warmed_state()
      {:ok, handle} = AwsKmsSecretsProvider.active_signing_key(state)
      cache_key = {AwsKmsSecretsProvider, :public_key, state.key_arn, 1}
      cached_before = :persistent_term.get(cache_key, :miss)

      assert :ok = AwsKmsSecretsProvider.terminate(state, :normal)
      assert :persistent_term.get(cache_key, :miss) == cached_before
      # Re-fetch via the API still hits cache (no KMS call expected).
      assert {:ok, _pem} = AwsKmsSecretsProvider.public_key(state, handle)
    end
  end

  # --- Helpers -----------------------------------------------------------

  defp init_provider(key_arn) do
    AwsKmsSecretsProvider.init(%{
      key_arn: key_arn,
      algorithm: :ecdsa_p256,
      region: "us-east-1",
      finch_pool: :kms_pool,
      http_client: HttpClientMock,
      access_key_id: "AKIATESTKEY",
      secret_access_key: "testsecret"
    })
  end

  # Build a state whose public-key cache is already warmed; uses a single
  # Mox expectation to satisfy the warmup fetch.
  defp warmed_state do
    key_arn = unique_key_arn()

    HttpClientMock
    |> expect(:request, 1, fn :post, _url, _body, _headers, _opts ->
      {:ok, ok_response(%{"KeyId" => key_arn, "PublicKey" => @der_b64})}
    end)

    {:ok, state} = init_provider(key_arn)
    state
  end

  defp unique_key_arn do
    ref = :erlang.ref_to_list(make_ref()) |> to_string()
    "arn:aws:kms:us-east-1:123456789012:key/#{Base.encode16(ref, case: :lower)}"
  end

  defp ok_response(body_map) do
    %{
      status_code: 200,
      headers: [{"content-type", "application/x-amz-json-1.0"}],
      body: JSON.encode!(body_map)
    }
  end

  defp kms_target(headers) do
    Enum.find_value(headers, fn
      {"x-amz-target", value} -> value
      {"X-Amz-Target", value} -> value
      _ -> nil
    end)
  end

  defp build_identity_context do
    principal =
      Recurse.Shared.Principal.service_account(%{
        issuer: "https://mock-idp.recurse.test",
        account_id: "impl-test"
      })

    Recurse.Shared.IdentityContext.new(%{
      machine_identity: "spiffe://mock.recurse.test/workload/impl-test",
      principal: principal,
      tenant_id: "tenant-test",
      correlation_id: "01HZZZZZZZZZZZZZZZZZZZZZZZ"
    })
  end
end
