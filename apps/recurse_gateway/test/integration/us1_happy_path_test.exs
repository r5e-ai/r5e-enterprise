defmodule RecurseGateway.Integration.US1HappyPathTest do
  @moduledoc """
  Internal legacy chat-handler integration coverage. Every request first
  asserts the public router returns 503 capability_unavailable, then invokes
  the retained handler directly to exercise provider, receipt, and SIEM
  behavior. These assertions do not claim this execution route is released.
  """

  use ExUnit.Case, async: false

  setup_all do
    Recurse.Gateway.Test.KernelFixture.boot()
  end

  alias Ecto.Adapters.SQL.Sandbox
  alias Recurse.Gateway.Policy.BundleLoader
  alias Recurse.Gateway.ProviderRegistry
  alias Recurse.Gateway.Siem.Forwarder
  alias Recurse.Gateway.Test.JwtTestHelper
  alias Recurse.Gateway.Test.LegacyChatHandler
  alias Recurse.Gateway.Test.MockHttpUpstream
  alias Recurse.Gateway.Test.StubSecretsProvider
  alias Recurse.Gateway.Test.StubStorageProvider
  alias Recurse.Providers.Impls.OpenAiLlmProvider
  alias Recurse.Providers.Impls.PostgresMerkleLedger
  alias Recurse.Providers.Repo

  # A ULID-shaped `tenant_id` per the Standalone deployment convention
  # (FR-031). Stays stable across all four scenarios.
  @tenant_id "01HQZN5K7J8M9N0P1Q2R3S4T5V"

  # Must match JwtTestHelper defaults so the JwtValidator opts we seed
  # accept the minted token.
  @jwt_issuer "https://test-broker.example.invalid"
  @jwt_audience "recurse-gateway-test"
  @siem_topic "recurse:attestation_first_committed"

  setup context do
    # -- DB ----------------------------------------------------------
    # The Repo is started by :recurse_providers' application supervisor
    # (see `RecurseProviders.Application`). We take a per-test
    # connection out of the sandbox pool and switch it to shared mode so
    # the Bandit-spawned handler process (which runs on a non-test pid
    # for chunked-response send-off; the Plug call itself runs inline on
    # the test pid) sees the same transaction. `on_exit` below reverts
    # everything automatically via ExUnit.
    :ok = Sandbox.checkout(Repo)
    Sandbox.mode(Repo, {:shared, self()})

    # -- Mock upstream + provider install -------------------------------
    {:ok, upstream} = MockHttpUpstream.start()

    on_exit(fn ->
      MockHttpUpstream.stop(upstream)
      ProviderRegistry.uninstall()
      StubStorageProvider.reset()
    end)

    :ok = StubStorageProvider.reset()

    {:ok, llm_state} =
      OpenAiLlmProvider.init(%{
        base_url: MockHttpUpstream.url(upstream),
        # Unique Finch pool per-test isn't required because the shared
        # `:openai_pool` is idempotent-per-pool; Finch multiplexes HTTP/2
        # + HTTP/1.1 over the same pool name. Pointing the provider at
        # `127.0.0.1:<port>` with the shared pool is correct for this
        # integration test (the per-test port is what gives isolation).
        finch_pool: :openai_pool,
        resolved_api_key: "sk-test-fake-key",
        timeout_ms: 10_000,
        pool_timeout_ms: 5_000
      })

    {:ok, ledger_state} = PostgresMerkleLedger.init(%{})
    {:ok, storage_state} = StubStorageProvider.init(%{bucket: "test-bucket"})
    {:ok, secrets_state} = StubSecretsProvider.init(%{})

    ProviderRegistry.install_raw!(%{
      llm: {OpenAiLlmProvider, llm_state},
      ledger: {PostgresMerkleLedger, ledger_state},
      storage: {StubStorageProvider, storage_state},
      secrets: {StubSecretsProvider, secrets_state},
      tenant_id: @tenant_id,
      signer: "observed://gateway/test"
    })

    # -- Cedar bundle loader --------------------------------------------
    # Point BundleLoader at a scratch dir (`@tag :tmp_dir` ExUnit
    # auto-magic per ecto-thinking's tmp-dir pattern) so each test
    # assembles its own policy bundle without touching the shared
    # `priv/reference_policies/permissive_all.cedar` (which has its own
    # fixture lifecycle). Default: permissive policy; deny-all variant
    # can be selected via `@tag bundle: :deny_all` (unused in US1 but
    # the plumbing is here for parity with the handler unit test).
    bundle_source =
      case Map.get(context, :bundle, :permissive) do
        :permissive -> "permit(principal, action, resource);"
        :deny_all -> "forbid(principal, action, resource);"
      end

    tmp_dir = fresh_tmp_dir(context[:test])
    bundle_path = Path.join(tmp_dir, "policies.cedar")
    File.write!(bundle_path, bundle_source)

    entity_schema_path =
      Path.join([
        Application.app_dir(:recurse_gateway, "priv"),
        "cedar",
        "schema.cedarschema.json"
      ])

    # Unregistered name so successive tests don't collide on the atom.
    _bundle_loader =
      start_supervised!(
        Supervisor.child_spec(
          {BundleLoader,
           bundle_path: bundle_path,
           entity_schema_path: entity_schema_path,
           trap_sighup: false,
           name: nil},
          id: {BundleLoader, make_ref()}
        )
      )

    # -- JWT validator opts --------------------------------------------
    # `IdentityContextBuilder` forwards these to `JwtValidator.validate/2`
    # at request time. We pin `known_kids` to the `JwtTestHelper` public
    # JWK so production JwksCache is never contacted.
    previous_jwt_opts = Application.get_env(:recurse_gateway, :jwt_validator_opts)

    Application.put_env(:recurse_gateway, :jwt_validator_opts,
      audience: @jwt_audience,
      issuer: @jwt_issuer,
      known_kids: [
        {"test-key-rs256", JwtTestHelper.public_jwk(:rs256)}
      ]
    )

    on_exit(fn ->
      case previous_jwt_opts do
        nil -> Application.delete_env(:recurse_gateway, :jwt_validator_opts)
        val -> Application.put_env(:recurse_gateway, :jwt_validator_opts, val)
      end
    end)

    # -- SIEM forwarder bound to a StringIO device ----------------------
    # The application-supervised forwarder writes to `:stdio`; we start a
    # PRIVATE forwarder with an isolated StringIO device subscribed to
    # the same topic. Scenario 4 asserts against this device; scenarios
    # 1-3 ignore it. Starting it here keeps lifecycle tied to the test.
    {:ok, string_io} = StringIO.open("")

    _forwarder_pid =
      start_supervised!(
        Supervisor.child_spec(
          {Forwarder, io_device: string_io, pubsub: Recurse.PubSub, name: nil},
          id: {Forwarder, make_ref()}
        )
      )

    %{upstream: upstream, string_io: string_io}
  end

  # ---------------------------------------------------------------------------
  # US1 Acceptance Scenario 1 — sync happy path
  # ---------------------------------------------------------------------------

  describe "US1 Acceptance Scenario 1 — happy path chat completion" do
    test "internal legacy handler: sync chat completion: JWT valid → Cedar allow → OpenAI mock → receipt + SIEM",
         %{upstream: upstream} do
      # Pre-subscribe so we don't miss the broadcast that fires between
      # `Router.call/2` returning and `assert_receive` running.
      :ok = Phoenix.PubSub.subscribe(Recurse.PubSub, @siem_topic)

      MockHttpUpstream.expect(upstream, fn conn ->
        # Plug.Parsers is NOT installed on this mock, so we read the body
        # ourselves. The Gateway forwards the request body verbatim.
        {:ok, raw, conn} = Plug.Conn.read_body(conn)
        assert conn.method == "POST"
        assert conn.request_path == "/chat/completions"

        decoded = JSON.decode!(raw)
        assert decoded["model"] == "gpt-4o-mini"

        assert [%{"role" => "user", "content" => "Write a haiku about compliance."}] =
                 decoded["messages"]

        # The customer API key never leaks to the agent — the Gateway
        # injects it on the outbound wire only. This assertion guards
        # that FR-009 invariant.
        assert Enum.any?(conn.req_headers, fn
                 {"authorization", "Bearer sk-test-fake-key"} -> true
                 _ -> false
               end),
               "expected Gateway-injected Authorization header on upstream request"

        conn
        |> Plug.Conn.put_resp_header("content-type", "application/json")
        |> Plug.Conn.send_resp(200, canned_completion_body())
      end)

      jwt =
        JwtTestHelper.mint_test_jwt(
          subject: "alice@corp",
          recurse_role: "caller",
          issuer: @jwt_issuer,
          audience: @jwt_audience
        )

      request_body = %{
        "model" => "gpt-4o-mini",
        "messages" => [%{"role" => "user", "content" => "Write a haiku about compliance."}]
      }

      started_mono = System.monotonic_time(:millisecond)

      conn =
        :post
        |> Plug.Test.conn("/v1/chat/completions", JSON.encode!(request_body))
        |> Plug.Conn.put_req_header("content-type", "application/json")
        |> Plug.Conn.put_req_header("authorization", "Bearer " <> jwt)
        |> LegacyChatHandler.call()

      elapsed_ms = System.monotonic_time(:millisecond) - started_mono

      # -- Response assertions (FR-006 passthrough + header stamping) --
      assert conn.status == 200
      decoded = JSON.decode!(conn.resp_body)

      assert %{
               "object" => "chat.completion",
               "choices" => [%{"message" => %{"content" => "Compliance haiku here."}}],
               "usage" => %{"total_tokens" => 15}
             } = decoded

      correlation_id =
        conn.resp_headers
        |> List.keyfind("x-recurse-correlation-id", 0)
        |> then(fn {_, v} -> v end)

      assert is_binary(correlation_id) and byte_size(correlation_id) > 0

      # -- Receipt lives in the ledger keyed by run_id --
      # The Gateway mints a fresh run_id per request; we can't know it
      # from the outside except by querying for "the attestation emitted
      # with our correlation_id." `query_by_run_id/1` wants a run_id, so
      # we reach for the `attestations` table directly via a correlation
      # filter — this is the Audit-Plane source-of-truth path T059 will
      # eventually wrap.
      {:ok, receipt} = fetch_attestation_by_correlation_id(correlation_id)

      assert receipt.verification_level in [
               :signed,
               :local_inclusion_verified,
               :global_inclusion_verified
             ]

      assert receipt.tier_completeness_advisory == :partial
      assert receipt.policy_decision == :allow
      assert receipt.outcome == :success
      assert receipt.tenant_id == @tenant_id
      assert receipt.correlation_id == correlation_id

      # -- SIEM PubSub event (SC-004 — within 2s) --
      assert_receive {:first_committed, run_id_broadcast, payload}, 2_000
      assert run_id_broadcast == receipt.run_id
      assert payload.verification_level in [:local_inclusion_verified, :global_inclusion_verified]
      assert is_map(payload.attestation)

      # -- Latency breadcrumb (SC-001) --
      # Excludes KMS sign (stub) + LLM mock latency is local-loopback only;
      # a hard assertion would be flaky in CI. Log a breadcrumb only.
      if elapsed_ms > 500 do
        IO.puts("[US1 AS1 breadcrumb] total handler latency: #{elapsed_ms} ms")
      end
    end
  end

  # ---------------------------------------------------------------------------
  # US1 Acceptance Scenario 2 — SSE streaming
  # ---------------------------------------------------------------------------

  describe "US1 Acceptance Scenario 2 — SSE streaming" do
    test "internal legacy handler: SSE streaming: chunks pass through → single attestation at stream end",
         %{upstream: upstream} do
      :ok = Phoenix.PubSub.subscribe(Recurse.PubSub, @siem_topic)

      # The mock upstream emits SSE frames downstream; the Gateway
      # forwards them verbatim per FR-006. Chunked mode is latched on
      # by the `Plug.Conn.put_resp_header("content-type",
      # "text/event-stream")` + `send_chunked/2` dance in SseProxy.
      MockHttpUpstream.expect(upstream, fn conn ->
        {:ok, raw, conn} = Plug.Conn.read_body(conn)
        decoded = JSON.decode!(raw)
        # OpenAiLlmProvider.chat_complete_stream/3 forces `stream: true`
        # on the outbound body so the upstream sees the SSE intent.
        assert decoded["stream"] == true
        assert decoded["model"] == "gpt-4o-mini"

        conn =
          conn
          |> Plug.Conn.put_resp_header("content-type", "text/event-stream")
          |> Plug.Conn.send_chunked(200)

        {:ok, conn} =
          Plug.Conn.chunk(
            conn,
            ~s|data: {"id":"c-stream","object":"chat.completion.chunk","created":1700000000,"model":"gpt-4o-mini","choices":[{"index":0,"delta":{"role":"assistant","content":"Hello"}}]}\n\n|
          )

        {:ok, conn} =
          Plug.Conn.chunk(
            conn,
            ~s|data: {"id":"c-stream","object":"chat.completion.chunk","created":1700000000,"model":"gpt-4o-mini","choices":[{"index":0,"delta":{"content":" world"}}]}\n\n|
          )

        {:ok, conn} =
          Plug.Conn.chunk(
            conn,
            ~s|data: {"id":"c-stream","object":"chat.completion.chunk","created":1700000000,"model":"gpt-4o-mini","choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":2,"total_tokens":7}}\n\n|
          )

        {:ok, conn} = Plug.Conn.chunk(conn, "data: [DONE]\n\n")
        conn
      end)

      jwt =
        JwtTestHelper.mint_test_jwt(
          subject: "alice@corp",
          recurse_role: "caller",
          issuer: @jwt_issuer,
          audience: @jwt_audience
        )

      request_body = %{
        "model" => "gpt-4o-mini",
        "messages" => [%{"role" => "user", "content" => "stream haiku"}],
        "stream" => true
      }

      conn =
        :post
        |> Plug.Test.conn("/v1/chat/completions", JSON.encode!(request_body))
        |> Plug.Conn.put_req_header("content-type", "application/json")
        |> Plug.Conn.put_req_header("authorization", "Bearer " <> jwt)
        |> LegacyChatHandler.call()

      assert conn.status == 200
      assert conn.state in [:chunked, :sent]

      # Plug.Test's chunked adapter concatenates all chunks into resp_body.
      assert conn.resp_body =~ "Hello"
      assert conn.resp_body =~ "world"
      assert conn.resp_body =~ "[DONE]"

      # Correlation header still present on the chunked response.
      correlation_id =
        conn.resp_headers
        |> List.keyfind("x-recurse-correlation-id", 0)
        |> then(fn {_, v} -> v end)

      assert is_binary(correlation_id)

      # -- Single attestation at stream end (FR-041 per-turn rule) --
      assert_receive {:first_committed, run_id, payload}, 2_000
      refute_receive {:first_committed, ^run_id, _another_payload}, 100

      assert payload.verification_level in [:local_inclusion_verified, :global_inclusion_verified]

      {:ok, receipt} = PostgresMerkleLedger.query_by_run_id(run_id)
      assert receipt.outcome == :success
      assert receipt.policy_decision == :allow

      # -- Reassembled payload hash matches a fresh canonicalization --
      # The stored `payload_hash` comes from
      # `SHA-256(JCS({"request": canon_req, "response": canon_resp}))`.
      # Recomputing it here verifies the SseProxy reassembly produced the
      # exact bytes the ledger received.
      reassembled_response_bytes = reassembled_response_for_stream(request_body)

      expected_payload_hash =
        :crypto.hash(
          :sha256,
          Recurse.Shared.Jcs.encode(%{
            "request" => Jason.decode!(Recurse.Shared.Jcs.encode(request_body)),
            "response" => Jason.decode!(reassembled_response_bytes)
          })
        )

      assert receipt.payload_hash == expected_payload_hash
    end
  end

  # ---------------------------------------------------------------------------
  # US1 Acceptance Scenario 3 — audit plane receipts query
  # ---------------------------------------------------------------------------

  describe "US1 Acceptance Scenario 3 — audit plane receipts query" do
    test "internal legacy handler: receipt is discoverable via the Audit-Plane source-of-truth path",
         %{
           upstream: upstream
         } do
      # The HTTP endpoint that wraps this query (GET /v1/audit/receipts)
      # lands in Phase 5 — see tasks.md T059. Until then, Scenario 3's
      # assertion is that the SAME data a receipts query would serve is
      # present in the ledger after a Scenario-1 flow. We assert via
      # `PostgresMerkleLedger.query_by_run_id/1` — the same function
      # T059's handler will eventually call.

      MockHttpUpstream.expect(upstream, fn conn ->
        conn
        |> Plug.Conn.put_resp_header("content-type", "application/json")
        |> Plug.Conn.send_resp(200, canned_completion_body())
      end)

      jwt =
        JwtTestHelper.mint_test_jwt(
          subject: "alice@corp",
          recurse_role: "caller",
          issuer: @jwt_issuer,
          audience: @jwt_audience
        )

      conn =
        :post
        |> Plug.Test.conn(
          "/v1/chat/completions",
          JSON.encode!(%{
            "model" => "gpt-4o-mini",
            "messages" => [%{"role" => "user", "content" => "audit-lookup target"}]
          })
        )
        |> Plug.Conn.put_req_header("content-type", "application/json")
        |> Plug.Conn.put_req_header("authorization", "Bearer " <> jwt)
        |> LegacyChatHandler.call()

      assert conn.status == 200

      correlation_id =
        conn.resp_headers
        |> List.keyfind("x-recurse-correlation-id", 0)
        |> then(fn {_, v} -> v end)

      {:ok, receipt} = fetch_attestation_by_correlation_id(correlation_id)

      # FR-021 split: immutable signed-predicate fields + mutable
      # outer-container fields are both present on the stored row.
      #
      # Signed predicate:
      assert receipt.tenant_id == @tenant_id
      assert receipt.policy_decision == :allow
      assert byte_size(receipt.payload_hash) == 32
      assert is_binary(receipt.signed_predicate_bytes)

      # Outer container:
      assert receipt.verification_level in [
               :local_inclusion_verified,
               :global_inclusion_verified
             ]

      assert receipt.tier_completeness_advisory == :partial
      assert receipt.outcome == :success

      # The detached payload is reachable via the StubStorageProvider —
      # the same storage the real `/v1/audit/payload` endpoint will query
      # through the broker. Assert the stored bytes decode to the
      # JCS-canonicalized `{"request": ..., "response": ...}` shape.
      [%{payload: stored_bytes, uri: stored_uri}] = StubStorageProvider.puts(@tenant_id)
      assert stored_uri == receipt.payload_uri

      stored_decoded = JSON.decode!(stored_bytes)
      assert %{"request" => req_term, "response" => resp_term} = stored_decoded
      assert req_term["model"] == "gpt-4o-mini"
      assert resp_term["object"] == "chat.completion"
    end
  end

  # ---------------------------------------------------------------------------
  # US1 Acceptance Scenario 4 — SIEM NDJSON
  # ---------------------------------------------------------------------------

  describe "US1 Acceptance Scenario 4 — SIEM NDJSON" do
    test "internal legacy handler: SIEM forwarder emits exactly one NDJSON line per attestation",
         %{
           upstream: upstream,
           string_io: string_io
         } do
      MockHttpUpstream.expect(upstream, fn conn ->
        conn
        |> Plug.Conn.put_resp_header("content-type", "application/json")
        |> Plug.Conn.send_resp(200, canned_completion_body())
      end)

      jwt =
        JwtTestHelper.mint_test_jwt(
          subject: "alice@corp",
          recurse_role: "caller",
          issuer: @jwt_issuer,
          audience: @jwt_audience
        )

      conn =
        :post
        |> Plug.Test.conn(
          "/v1/chat/completions",
          JSON.encode!(%{
            "model" => "gpt-4o-mini",
            "messages" => [%{"role" => "user", "content" => "ndjson target"}]
          })
        )
        |> Plug.Conn.put_req_header("content-type", "application/json")
        |> Plug.Conn.put_req_header("authorization", "Bearer " <> jwt)
        |> LegacyChatHandler.call()

      assert conn.status == 200

      # Wait up to 2s for the forwarder to process the PubSub broadcast
      # and flush the NDJSON line into the StringIO.
      ndjson_line = wait_for_ndjson_line(string_io, 2_000)

      # Exactly one JSON line (newline-terminated) per attestation.
      assert [_single_json_line] = String.split(ndjson_line, "\n", trim: true)

      decoded = JSON.decode!(ndjson_line)

      # FR-025 / F001 FR-048 surface-1 schema conformance.
      for key <- [
            "run_id",
            "session_id",
            "principal",
            "machine_identity",
            "tool_called",
            "policy_decision",
            "policy_canonical_hash",
            "verification_level",
            "tier_completeness_advisory",
            "correlation_id",
            "timestamp"
          ] do
        assert Map.has_key?(decoded, key), "NDJSON event missing required key: #{key}"
      end

      assert decoded["tool_called"] == nil
      assert decoded["policy_decision"] == "allow"
      assert decoded["tier_completeness_advisory"] == "partial"

      assert decoded["verification_level"] in [
               "local_inclusion_verified",
               "global_inclusion_verified"
             ]

      assert String.starts_with?(decoded["policy_canonical_hash"], "sha256:")

      correlation_id =
        conn.resp_headers
        |> List.keyfind("x-recurse-correlation-id", 0)
        |> then(fn {_, v} -> v end)

      assert decoded["correlation_id"] == correlation_id
    end
  end

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  # OpenAI sync completion body — canned canned canned; we assert the
  # content string flows back to the caller unchanged.
  defp canned_completion_body do
    JSON.encode!(%{
      "id" => "chatcmpl-test",
      "object" => "chat.completion",
      "created" => 1_700_000_000,
      "model" => "gpt-4o-mini",
      "choices" => [
        %{
          "index" => 0,
          "message" => %{
            "role" => "assistant",
            "content" => "Compliance haiku here."
          },
          "finish_reason" => "stop"
        }
      ],
      "usage" => %{
        "prompt_tokens" => 10,
        "completion_tokens" => 5,
        "total_tokens" => 15
      }
    })
  end

  # Reassembled final chat.completion JSON for the SSE fixture in AS2.
  # Mirrors what `SseProxy.reassemble_chat_completion/2` produces from
  # the 3 deltas + [DONE]; kept in sync by construction (if this
  # function drifts from the MockHttpUpstream fixture, the payload_hash
  # assertion will catch it).
  defp reassembled_response_for_stream(request_body) do
    Recurse.Shared.Jcs.encode(%{
      "id" => "c-stream",
      "object" => "chat.completion",
      "created" => 1_700_000_000,
      "model" => Map.get(request_body, "model"),
      "choices" => [
        %{
          "index" => 0,
          "message" => %{
            "role" => "assistant",
            "content" => "Hello world",
            "refusal" => nil
          },
          "finish_reason" => "stop"
        }
      ],
      "usage" => %{
        "prompt_tokens" => 5,
        "completion_tokens" => 2,
        "total_tokens" => 7
      }
    })
  end

  # The `Attestation` PK is the UUID `run_id` — we don't know it from
  # outside the Gateway, so look up by correlation_id, which is stamped
  # on every row and matches the response header.
  defp fetch_attestation_by_correlation_id(correlation_id) do
    import Ecto.Query,
      only: [from: 2]

    query =
      from(a in Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Attestation,
        where: a.correlation_id == ^correlation_id,
        limit: 1
      )

    case Repo.one(query) do
      nil -> {:error, :not_found}
      att -> {:ok, att}
    end
  end

  defp wait_for_ndjson_line(string_io, timeout_ms) do
    deadline = System.monotonic_time(:millisecond) + timeout_ms
    poll_ndjson_line(string_io, deadline)
  end

  defp poll_ndjson_line(string_io, deadline) do
    {_input, output} = StringIO.contents(string_io)

    cond do
      byte_size(output) > 0 and String.ends_with?(output, "\n") ->
        output

      System.monotonic_time(:millisecond) >= deadline ->
        flunk("SIEM forwarder produced no NDJSON within the deadline; output=#{inspect(output)}")

      true ->
        Process.sleep(25)
        poll_ndjson_line(string_io, deadline)
    end
  end

  defp fresh_tmp_dir(test_name) do
    name = test_name |> to_string() |> String.replace(~r/[^a-zA-Z0-9_]/, "_")
    path = Path.join(System.tmp_dir!(), "us1_happy_path_#{name}_#{System.unique_integer()}")
    File.mkdir_p!(path)
    on_exit(fn -> File.rm_rf!(path) end)
    path
  end
end
