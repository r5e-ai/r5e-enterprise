defmodule Recurse.Providers.Impls.S3StorageProviderTest do
  @moduledoc """
  Contract test for `Recurse.Providers.Impls.S3StorageProvider` (T038 Phase-3).

  Strategy: inject a mock `ExAws.Request.HttpClient` whose FIFO expectation
  queue lives in a per-test supervised `Agent`. Because ExAws resolves
  `http_client` per-request from the config map (no global mutable state
  touched), each test owns its own Agent — the suite stays `async: true`.

  The Agent pid is stashed via `Process.put` ONLY as a pointer (not as the
  state itself). State lives in the supervised Agent so `start_supervised!`
  guarantees cleanup even on test crash, addressing the "process dictionary
  for state" anti-pattern flagged by `elixir-thinking`.
  """

  use ExUnit.Case, async: true

  alias Recurse.Providers.Impls.S3StorageProvider

  # --- Test HTTP client ---------------------------------------------------

  defmodule MockHttpClient do
    @moduledoc """
    Minimal `ExAws.Request.HttpClient` implementation backed by an Agent
    holding the FIFO expectation queue. The Agent pid is looked up from
    the calling test's process dictionary (single pointer, not state).
    Each test populates expectations via
    `Recurse.Providers.Impls.S3StorageProviderTest.expect_request/1` and
    the mock pops them FIFO under `Agent.get_and_update/2`.
    """
    @behaviour ExAws.Request.HttpClient

    @impl true
    def request(method, url, body, headers, _opts) do
      agent =
        Process.get({__MODULE__, :agent}) ||
          raise "MockHttpClient agent not configured for this test"

      case Agent.get_and_update(agent, fn
             [fun | rest] -> {fun, rest}
             [] -> {:none, []}
           end) do
        :none ->
          flunk_from_mock("no expectation registered for #{method} #{url}")

        fun when is_function(fun, 1) ->
          fun.(%{method: method, url: url, body: body, headers: headers})
      end
    end

    defp flunk_from_mock(msg) do
      # ExAws expects {:ok, _} | {:error, _} — surface the unexpected-call
      # as an error so the test fails with a readable message rather than
      # a Mix compilation cascade.
      {:error, %{reason: {:mock_http_client_unexpected_call, msg}}}
    end
  end

  # --- Setup --------------------------------------------------------------

  setup do
    # Per-test supervised Agent owning the FIFO expectation queue. The
    # Agent is auto-stopped by ExUnit's supervisor when the test exits
    # (success or crash), so no manual teardown is needed. The pid is
    # stashed in the test's process dictionary as a pointer ONLY — the
    # state itself lives in the supervised Agent.
    agent = start_supervised!({Agent, fn -> [] end})
    Process.put({MockHttpClient, :agent}, agent)

    {:ok, state} =
      S3StorageProvider.init(%{
        bucket: "my-recurse-payloads",
        region: "us-east-1",
        kms_encryption: true,
        object_lock_compliance_days: 2555,
        http_client: MockHttpClient,
        access_key_id: "test-akid",
        secret_access_key: "test-secret",
        endpoint_url: "http://127.0.0.1:1",
        # Disable ExAws's own retry loop inside the provider so each test's
        # single expectation covers the entire call. Production runs with
        # the default exponential-backoff loop; the `payload_outbox`
        # reconciliation (FR-032) sits ABOVE the provider and handles
        # long-horizon retries.
        retries: [max_attempts: 1, base_backoff_in_ms: 0, max_backoff_in_ms: 0]
      })

    %{state: state}
  end

  # --- init/1 -------------------------------------------------------------

  describe "init/1" do
    test "returns {:ok, state} with core fields resolved", %{state: state} do
      assert %{
               bucket: "my-recurse-payloads",
               region: "us-east-1",
               kms_encryption: true,
               object_lock_compliance_days: 2555
             } = state
    end

    test "returns {:error, {:missing_config, :bucket}} when bucket absent" do
      assert {:error, {:missing_config, :bucket}} = S3StorageProvider.init(%{region: "us-east-1"})
    end

    test "returns {:error, {:missing_config, :region}} when region absent" do
      assert {:error, {:missing_config, :region}} = S3StorageProvider.init(%{bucket: "b"})
    end

    test "defaults object_lock_compliance_days to 2555 (7 years)" do
      assert {:ok, %{object_lock_compliance_days: 2555}} =
               S3StorageProvider.init(%{bucket: "b", region: "us-east-1"})
    end

    test "allows operator override of object_lock_compliance_days" do
      assert {:ok, %{object_lock_compliance_days: 42}} =
               S3StorageProvider.init(%{
                 bucket: "b",
                 region: "us-east-1",
                 object_lock_compliance_days: 42
               })
    end
  end

  # --- put_payload/3 ------------------------------------------------------

  describe "put_payload/3" do
    test "issues a PUT to the FR-019 key with Object Lock + SSE-KMS headers", %{state: state} do
      parent = self()
      identity_ctx = build_identity_context("tenant-alpha", ulid())

      expect_request(fn req ->
        send(parent, {:captured_request, req})

        {:ok,
         %{
           status_code: 200,
           headers: [{"etag", "\"abc\""}],
           body: ""
         }}
      end)

      today = format_utc_today()
      run_id = identity_ctx.correlation_id

      assert {:ok, %{uri: uri, hash: hash}} =
               S3StorageProvider.put_payload(state, ~s({"canon":"req"}), identity_ctx)

      assert uri == "s3://my-recurse-payloads/tenants/tenant-alpha/runs/#{today}/#{run_id}.json"
      assert byte_size(hash) == 32

      assert_received {:captured_request, req}
      assert req.method == :put

      assert req.url =~
               "/tenants/tenant-alpha/runs/#{today}/#{run_id}.json"

      headers = normalize_headers(req.headers)

      assert headers["x-amz-object-lock-mode"] == "COMPLIANCE"
      assert headers["x-amz-server-side-encryption"] == "aws:kms"
      assert is_binary(headers["x-amz-object-lock-retain-until-date"])

      # Retain-until must parse as ISO8601 and be ~2555 days in the future.
      {:ok, retain_until, _} =
        DateTime.from_iso8601(headers["x-amz-object-lock-retain-until-date"])

      delta_seconds = DateTime.diff(retain_until, DateTime.utc_now())
      # 2555 days * 86_400 s = 220_752_000 s; allow a 60-second clock skew
      # against the moment we recompute `now`.
      assert_in_delta delta_seconds, 2555 * 86_400, 60
    end

    test "503 from S3 is classified as {:error, :transient, _}", %{state: state} do
      identity_ctx = build_identity_context("tenant-alpha", ulid())

      expect_request(fn _req ->
        {:ok, %{status_code: 503, headers: [], body: "SlowDown"}}
      end)

      assert {:error, :transient, {:http_status, 503, "SlowDown"}} =
               S3StorageProvider.put_payload(state, "payload", identity_ctx)
    end

    test "429 (Throttling) is classified as {:error, :transient, _}", %{state: state} do
      identity_ctx = build_identity_context("tenant-alpha", ulid())

      expect_request(fn _req ->
        {:ok, %{status_code: 429, headers: [], body: "SlowDown"}}
      end)

      assert {:error, :transient, {:http_status, 429, "SlowDown"}} =
               S3StorageProvider.put_payload(state, "payload", identity_ctx)
    end

    test "403 from S3 is classified as {:error, :permanent, _}", %{state: state} do
      identity_ctx = build_identity_context("tenant-alpha", ulid())

      expect_request(fn _req ->
        {:ok, %{status_code: 403, headers: [], body: "AccessDenied"}}
      end)

      assert {:error, :permanent, {:http_status, 403, "AccessDenied"}} =
               S3StorageProvider.put_payload(state, "payload", identity_ctx)
    end

    test "404 (NoSuchBucket) is classified as {:error, :permanent, _}", %{state: state} do
      identity_ctx = build_identity_context("tenant-alpha", ulid())

      expect_request(fn _req ->
        {:ok, %{status_code: 404, headers: [], body: "NoSuchBucket"}}
      end)

      assert {:error, :permanent, {:http_status, 404, _}} =
               S3StorageProvider.put_payload(state, "payload", identity_ctx)
    end

    test "400 (validation) is classified as {:error, :permanent, _}", %{state: state} do
      identity_ctx = build_identity_context("tenant-alpha", ulid())

      expect_request(fn _req ->
        {:ok, %{status_code: 400, headers: [], body: "InvalidArgument"}}
      end)

      assert {:error, :permanent, {:http_status, 400, _}} =
               S3StorageProvider.put_payload(state, "payload", identity_ctx)
    end

    test "connection timeout is classified as {:error, :transient, :timeout}", %{state: state} do
      identity_ctx = build_identity_context("tenant-alpha", ulid())

      expect_request(fn _req -> {:error, %{reason: :timeout}} end)

      assert {:error, :transient, :timeout} =
               S3StorageProvider.put_payload(state, "payload", identity_ctx)
    end

    test "econnrefused is classified as {:error, :transient, :econnrefused}", %{state: state} do
      identity_ctx = build_identity_context("tenant-alpha", ulid())

      expect_request(fn _req -> {:error, %{reason: :econnrefused}} end)

      assert {:error, :transient, :econnrefused} =
               S3StorageProvider.put_payload(state, "payload", identity_ctx)
    end

    test "hash in successful response is SHA-256 of the payload bytes", %{state: state} do
      identity_ctx = build_identity_context("tenant-alpha", ulid())
      payload = "the-exact-bytes-we-hash"

      expect_request(fn _req -> {:ok, %{status_code: 200, headers: [], body: ""}} end)

      assert {:ok, %{hash: hash}} = S3StorageProvider.put_payload(state, payload, identity_ctx)
      assert hash == :crypto.hash(:sha256, payload)
    end

    test "kms_encryption: false omits the SSE header", %{} do
      {:ok, state} =
        S3StorageProvider.init(%{
          bucket: "my-recurse-payloads",
          region: "us-east-1",
          kms_encryption: false,
          http_client: MockHttpClient,
          access_key_id: "test",
          secret_access_key: "test",
          endpoint_url: "http://127.0.0.1:1",
          retries: [max_attempts: 1, base_backoff_in_ms: 0, max_backoff_in_ms: 0]
        })

      parent = self()
      identity_ctx = build_identity_context("tenant-alpha", ulid())

      expect_request(fn req ->
        send(parent, {:captured_request, req})
        {:ok, %{status_code: 200, headers: [], body: ""}}
      end)

      assert {:ok, _} = S3StorageProvider.put_payload(state, "x", identity_ctx)
      assert_received {:captured_request, req}

      headers = normalize_headers(req.headers)
      refute Map.has_key?(headers, "x-amz-server-side-encryption")
      assert headers["x-amz-object-lock-mode"] == "COMPLIANCE"
    end
  end

  # --- get_payload/3 ------------------------------------------------------

  describe "get_payload/3" do
    test "issues a GET to the URI's key and returns the body bytes", %{state: state} do
      parent = self()
      identity_ctx = build_identity_context("tenant-alpha", "01HRUN00000000000000000000")

      uri =
        "s3://my-recurse-payloads/tenants/tenant-alpha/runs/20260423/01HRUN00000000000000000000.json"

      expect_request(fn req ->
        send(parent, {:captured_request, req})
        {:ok, %{status_code: 200, headers: [], body: "the-bytes"}}
      end)

      assert {:ok, "the-bytes"} = S3StorageProvider.get_payload(state, uri, identity_ctx)
      assert_received {:captured_request, req}
      assert req.method == :get

      assert req.url =~
               "/tenants/tenant-alpha/runs/20260423/01HRUN00000000000000000000.json"
    end

    test "rejects a URI whose bucket mismatches the configured bucket", %{state: state} do
      identity_ctx = build_identity_context("tenant-alpha", ulid())
      uri = "s3://other-bucket/tenants/tenant-alpha/runs/20260423/foo.json"

      assert {:error, :permanent, {:bucket_mismatch, %{expected: "my-recurse-payloads"}}} =
               S3StorageProvider.get_payload(state, uri, identity_ctx)
    end

    test "malformed URI is a permanent error", %{state: state} do
      identity_ctx = build_identity_context("tenant-alpha", ulid())

      assert {:error, :permanent, {:malformed_uri, _}} =
               S3StorageProvider.get_payload(state, "not-an-s3-uri", identity_ctx)
    end

    test "503 from S3 is transient", %{state: state} do
      identity_ctx = build_identity_context("tenant-alpha", ulid())
      uri = "s3://my-recurse-payloads/tenants/tenant-alpha/runs/20260423/foo.json"

      expect_request(fn _req -> {:ok, %{status_code: 503, headers: [], body: "x"}} end)

      assert {:error, :transient, {:http_status, 503, _}} =
               S3StorageProvider.get_payload(state, uri, identity_ctx)
    end
  end

  # --- capabilities/1 -----------------------------------------------------

  describe "capabilities/1" do
    test "advertises :put, :get, :streaming, :versioned", %{state: state} do
      caps = S3StorageProvider.capabilities(state)
      assert :put in caps
      assert :get in caps
      assert :streaming in caps
      assert :versioned in caps
    end
  end

  # --- healthcheck/1 ------------------------------------------------------

  describe "healthcheck/1" do
    test "200 from HEAD /bucket → :ok", %{state: state} do
      expect_request(fn _req -> {:ok, %{status_code: 200, headers: [], body: ""}} end)
      assert :ok = S3StorageProvider.healthcheck(state)
    end

    test "503 → {:degraded, _}", %{state: state} do
      expect_request(fn _req -> {:ok, %{status_code: 503, headers: [], body: ""}} end)
      assert {:degraded, {:http_status, 503}} = S3StorageProvider.healthcheck(state)
    end

    test "403 → {:down, _}", %{state: state} do
      expect_request(fn _req -> {:ok, %{status_code: 403, headers: [], body: ""}} end)
      assert {:down, {:http_status, 403}} = S3StorageProvider.healthcheck(state)
    end

    test "connection error → {:down, reason}", %{state: state} do
      expect_request(fn _req -> {:error, %{reason: :econnrefused}} end)
      # ExAws unwraps `%{reason: r}` into a bare atom before surfacing it as
      # `{:error, r}` after retry exhaustion — see `ex_aws/request.ex` :500.
      assert {:down, :econnrefused} = S3StorageProvider.healthcheck(state)
    end
  end

  # --- terminate/2 --------------------------------------------------------

  describe "terminate/2" do
    test "returns :ok", %{state: state} do
      assert :ok = S3StorageProvider.terminate(state, :normal)
    end
  end

  # --- Helpers ------------------------------------------------------------

  @spec expect_request((map() -> {:ok, map()} | {:error, map()})) :: :ok
  defp expect_request(fun) when is_function(fun, 1) do
    agent = Process.get({MockHttpClient, :agent})
    Agent.update(agent, fn existing -> existing ++ [fun] end)
    :ok
  end

  defp normalize_headers(headers) when is_list(headers) do
    Map.new(headers, fn {k, v} -> {String.downcase(to_string(k)), to_string(v)} end)
  end

  defp format_utc_today do
    %{year: y, month: m, day: d} = DateTime.utc_now()
    :io_lib.format("~4..0B~2..0B~2..0B", [y, m, d]) |> IO.iodata_to_binary()
  end

  defp ulid do
    # ULID-ish test fixture: 26-char Crockford base32, always uppercase.
    <<a::40, b::88>> = :crypto.strong_rand_bytes(16)
    Base.encode32(<<a::40, b::88>>, case: :upper, padding: false) |> String.slice(0, 26)
  end

  defp build_identity_context(tenant_id, correlation_id) do
    principal =
      Recurse.Shared.Principal.service_account(%{
        issuer: "https://mock-idp.recurse.test",
        account_id: "impl-test"
      })

    Recurse.Shared.IdentityContext.new(%{
      machine_identity: "spiffe://mock.recurse.test/workload/impl-test",
      principal: principal,
      tenant_id: tenant_id,
      correlation_id: correlation_id
    })
  end
end
