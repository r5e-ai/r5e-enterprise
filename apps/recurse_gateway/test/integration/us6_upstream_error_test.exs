defmodule RecurseGateway.Integration.US6UpstreamErrorTest do
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

  @tenant_id "01HQZN5K7J8M9N0P1Q2R3S4T5V"
  @jwt_issuer "https://test-broker.example.invalid"
  @jwt_audience "recurse-gateway-test"
  @siem_topic "recurse:attestation_first_committed"

  setup context do
    :ok = Sandbox.checkout(Repo)
    Sandbox.mode(Repo, {:shared, self()})

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

    # Permissive policy — Cedar must ALLOW so the upstream branch runs.
    tmp_dir = fresh_tmp_dir(context[:test])
    bundle_path = Path.join(tmp_dir, "policies.cedar")
    File.write!(bundle_path, "permit(principal, action, resource);")

    entity_schema_path =
      Path.join([
        Application.app_dir(:recurse_gateway, "priv"),
        "cedar",
        "schema.cedarschema.json"
      ])

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

  describe "US6 — upstream 5xx pass-through + distinguishable receipt" do
    test "internal legacy handler: 503 from upstream → 503 to client + correlation header + upstream_error receipt",
         %{upstream: upstream, string_io: string_io} do
      :ok = Phoenix.PubSub.subscribe(Recurse.PubSub, @siem_topic)

      # The mock upstream returns a 503 with an OpenAI-shaped error body.
      # This simulates a real OpenAI outage; FR-016b requires the Gateway
      # to pass the status through verbatim.
      upstream_body = ~s|{"error":{"message":"upstream congested","type":"server_error"}}|

      MockHttpUpstream.expect(upstream, fn conn ->
        conn
        |> Plug.Conn.put_resp_header("content-type", "application/json")
        |> Plug.Conn.send_resp(503, upstream_body)
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
        "messages" => [%{"role" => "user", "content" => "will fail upstream"}]
      }

      conn =
        :post
        |> Plug.Test.conn("/v1/chat/completions", JSON.encode!(request_body))
        |> Plug.Conn.put_req_header("content-type", "application/json")
        |> Plug.Conn.put_req_header("authorization", "Bearer " <> jwt)
        |> LegacyChatHandler.call()

      # -- Assertion 1: 503 pass-through (FR-016b) ---------------------
      assert conn.status == 503
      assert conn.resp_body == upstream_body

      # -- Assertion 2: correlation header present on the 503 ---------
      correlation_id =
        conn.resp_headers
        |> List.keyfind("x-recurse-correlation-id", 0)
        |> then(fn {_, v} -> v end)

      assert is_binary(correlation_id) and byte_size(correlation_id) > 0

      # -- Assertion 3: receipt shape ---------------------------------
      # Cedar evaluated BEFORE the upstream was called; policy_decision
      # is :allow. Outcome is :upstream_error, upstream_status_code is
      # 503 verbatim from the upstream. verification_level reached the
      # ledger's terminal Merkle state (:signed acceptable if the ledger
      # commit raced but the broadcast still fired).
      {:ok, receipt} = fetch_attestation_by_correlation_id(correlation_id)

      assert receipt.policy_decision == :allow
      assert receipt.outcome == :upstream_error
      assert receipt.upstream_status_code == 503
      assert receipt.tenant_id == @tenant_id
      assert receipt.correlation_id == correlation_id

      assert receipt.verification_level in [
               :signed,
               :local_inclusion_verified,
               :global_inclusion_verified
             ]

      # -- Assertion 4: SIEM event distinguishable from a deny event --
      # Wait for the forwarder to flush the NDJSON line, then assert the
      # fields that make an upstream error obviously NOT a policy denial:
      #   * `outcome` = "upstream_error"  (deny events emit "success")
      #   * `policy_decision` = "allow"   (deny events emit "deny")
      #   * `upstream_status_code` = 503  (deny events emit null)
      assert_receive {:first_committed, _run_id, _payload}, 2_000

      ndjson_line = wait_for_ndjson_line(string_io, 2_000)
      decoded = JSON.decode!(ndjson_line)

      assert decoded["outcome"] == "upstream_error"
      assert decoded["policy_decision"] == "allow"
      assert decoded["upstream_status_code"] == 503
      assert decoded["correlation_id"] == correlation_id

      # The presence of a distinct `outcome` field — separate from
      # `policy_decision` — is the load-bearing property: a SIEM
      # dashboard grouping on either field alone sees the two classes
      # of failure cleanly partitioned. The triple (allow, upstream_error,
      # 503) cannot occur on a policy-denied event; the contract is that
      # denials come back as (deny, success, null) per the ledger's
      # default outer-container values.
      refute decoded["policy_decision"] == "deny"
      refute decoded["outcome"] == "success"
    end
  end

  # ---------------------------------------------------------------------------
  # Helpers — private copies of the US1 test helpers. Kept local to avoid
  # coupling US1 and US6 setup via a shared support module; each test file
  # owns its own fixture lifecycle.
  # ---------------------------------------------------------------------------

  defp fetch_attestation_by_correlation_id(correlation_id) do
    import Ecto.Query, only: [from: 2]

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
    path = Path.join(System.tmp_dir!(), "us6_upstream_error_#{name}_#{System.unique_integer()}")
    File.mkdir_p!(path)
    on_exit(fn -> File.rm_rf!(path) end)
    path
  end
end
