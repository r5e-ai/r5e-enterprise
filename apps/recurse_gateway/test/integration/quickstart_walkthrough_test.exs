defmodule Recurse.Integration.QuickstartWalkthroughTest do
  @moduledoc """
  Quickstart walkthrough end-to-end test (F002 T099).

  Scripted equivalent of `specs/002-standalone-gateway-vertical-slice/quickstart.md`
  — the 30-minute "`git clone` to first receipted chat completion" flow.
  Proves SC-011: a freshly-provisioned Recurse deployment can issue a
  `/v1/chat/completions`, produce an attestation, retrieve the receipt,
  export it as an evidence zip, and verify the zip cryptographically via
  `docs/auditor/recurse-verify` — all in under 30 seconds of wall-clock
  time in CI (the 30-minute budget in SC-011 is for a human running
  Docker setup, not a scripted test).

  ## What this test covers (and doesn't)

  Covers:

    * Step 4 (`POST /token/exchange`) — via REAL `RecurseBroker.Endpoint`
      driven by `Plug.Test.conn/3` (no Bandit port binding; matches
      `us1_with_real_broker_test.exs` T089 pattern).
    * Step 5 (`POST /v1/chat/completions`) — via REAL
      `Recurse.Gateway.Router.call/2` with a real broker-minted JWT on
      the `Authorization: Bearer ...` header.
    * Step 6 (`GET /v1/audit/receipts?run_id=...`) — via REAL
      `Recurse.Gateway.AuditPlane.ReceiptsHandler.handle/1`.
    * Step 8 (`POST /v1/audit/export` → bytes → `recurse-verify`) —
      via REAL `Recurse.Gateway.AuditPlane.ExportHandler.handle/1` +
      `System.cmd/3` to `docs/auditor/recurse-verify --trust-anchor`.

  Explicitly skipped (scope notes in quickstart.md):

    * Step 1 `git clone` / config write — the test assumes the repo is
      already checked out.
    * Step 2 `docker compose up` / migrations — the test relies on the
      CI Postgres service container + `mix ecto.migrate` having run
      before ExUnit starts. Boots Gateway + Broker via `Application.ensure_all_started`,
      not Docker.
    * Step 3 SIGHUP bundle reload — we load the bundle via
      `BundleLoader.start_link/1` once.
    * Step 7 SIEM event visibility — proven by `us4_vector_forwarder_test.sh`
      (the bash integration test) and by the
      `Phoenix.PubSub.subscribe(@siem_topic)` sub-assertion in
      `us1_with_real_broker_test.exs`. Re-proving it here would be
      redundant.

  ## `@moduletag :quickstart`

  Excluded from default `mix test` via
  `apps/recurse_gateway/test/test_helper.exs`'s
  `ExUnit.start(exclude: [:pending, :quickstart, :soak, :restore_drill])`.
  Run explicitly via:

      mix test --include quickstart \\
        apps/recurse_gateway/test/integration/quickstart_walkthrough_test.exs

  …or with any sibling Phase-10 integration test included via
  `--include quickstart --include soak --include restore_drill`.

  ## `async: false`

  Reuses the reasoning from `us1_with_real_broker_test.exs`: Bandit
  port binding on the mock LLM upstream, Ecto SQL Sandbox, ProviderRegistry
  persistent_term slot, BundleLoader persistent_term slot, plus
  `Application.put_env` mutation for broker config + module-registered
  GenServers for KeyRing + DiscoveryCache. Unambiguous `async: false`.

  ## `elixir:elixir-thinking` compliance

  No GenServers introduced. The test body is a flat sequence of
  `Plug.Test.conn/3` → `Module.call/2` steps plus one `System.cmd/3`
  shell-out. No process state accumulates beyond the (already-supervised)
  Gateway + Broker application trees that `setup/1` boots and tears down.
  Pattern matching on response shape (`200`, `%{"object" => "chat.completion"}`,
  etc.) replaces imperative asserts per the skill rule.

  ## Cross-references

    * `specs/002-standalone-gateway-vertical-slice/quickstart.md`
    * `specs/002-standalone-gateway-vertical-slice/spec.md` SC-011
    * `specs/002-standalone-gateway-vertical-slice/tasks.md` T099
    * `apps/recurse_gateway/test/integration/us1_with_real_broker_test.exs`
    * `apps/recurse_gateway/test/integration/us3_export_verify_test.exs`
    * `docs/auditor/recurse-verify`
  """

  use ExUnit.Case, async: false

  setup_all do
    Recurse.Gateway.Test.KernelFixture.boot()
  end

  @moduletag :quickstart
  @moduletag timeout: :timer.minutes(2)

  alias Ecto.Adapters.SQL.Sandbox
  alias Recurse.Gateway.AuditPlane.ExportHandler
  alias Recurse.Gateway.AuditPlane.ReceiptsHandler
  alias Recurse.Gateway.Policy.BundleLoader
  alias Recurse.Gateway.ProviderRegistry
  alias Recurse.Gateway.Router
  alias Recurse.Gateway.Test.MockHttpUpstream
  alias Recurse.Gateway.Test.StubStorageProvider
  alias Recurse.Providers.Impls.OpenAiLlmProvider
  alias Recurse.Providers.Impls.PostgresMerkleLedger
  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.SigningKey
  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Tenant
  alias Recurse.Providers.Repo
  alias RecurseBroker.Endpoint, as: BrokerEndpoint
  alias RecurseBroker.Test.MockOidcIssuer
  alias RecurseBroker.Test.SupervisorHelper

  @tenant_id "01HQZN5K7J8M9N0P1Q2R3S4T5V"
  @broker_audience "recurse-gateway-quickstart"
  @broker_issuer "https://broker.recurse.test"
  @interactive_aud @broker_audience <> "-interactive"
  @archive_chain_anchor <<0::size(256)>>

  @router_opts Router.init([])
  @broker_endpoint_opts BrokerEndpoint.init([])

  @mapping %{
    group_to_recurse_role: %{
      "cn=recurse-auditors,ou=groups,dc=corp,dc=example" => "tenant_auditor"
    },
    default_recurse_role: "caller",
    role_privilege_order: ["platform_operator", "tenant_auditor", "caller"]
  }

  # Resolve the absolute path to the vendored verifier. Mirrors the
  # candidate-walk strategy from `us3_export_verify_test.exs` so the
  # test works whether invoked from repo root or inside `apps/*`.
  defp recurse_verify_path do
    candidates = [
      Path.expand("../../docs/auditor/recurse-verify", __DIR__),
      Path.expand("../../../docs/auditor/recurse-verify", __DIR__),
      Path.expand("../../../../docs/auditor/recurse-verify", __DIR__)
    ]

    Enum.find(candidates, &File.exists?/1) ||
      flunk(
        "recurse-verify script not found; searched:\n  " <>
          Enum.join(candidates, "\n  ")
      )
  end

  setup do
    # -- DB ---------------------------------------------------------------
    :ok = Sandbox.checkout(Repo)
    Sandbox.mode(Repo, {:shared, self()})

    # Seed tenant row so signing_keys FK inserts succeed.
    Repo.insert!(
      Tenant.changeset(%Tenant{}, %{
        tenant_id: @tenant_id,
        display_name: "Quickstart Tenant",
        tier: :standalone_gateway,
        created_at: DateTime.utc_now()
      }),
      on_conflict: :nothing,
      conflict_target: :tenant_id
    )

    # -- Mock LLM upstream + provider install -----------------------------
    {:ok, upstream} = MockHttpUpstream.start()

    # Mint a fresh ES256 keypair for the SecretsProvider. `recurse-verify`
    # needs a trust-anchor PEM that matches the DSSE signing key the
    # envelope builder uses. We reuse the US3 pattern: generate key,
    # produce a JOSE.JWK wrapper, publish the public PEM to a tmp file
    # that the shell-out will pass to `--trust-anchor`.
    {pub_raw, priv_raw} = :crypto.generate_key(:ecdh, :secp256r1)

    jwk =
      JOSE.JWK.from_key(
        {:ECPrivateKey, 1, priv_raw, {:namedCurve, :secp256r1}, pub_raw, :asn1_NOVALUE}
      )

    {_mod, pub_pem} = jwk |> JOSE.JWK.to_public() |> JOSE.JWK.to_pem()

    tmp_dir = Path.join(System.tmp_dir!(), "quickstart_#{System.unique_integer([:positive])}")
    File.mkdir_p!(tmp_dir)

    anchor_pem_path = Path.join(tmp_dir, "anchor.pem")
    File.write!(anchor_pem_path, pub_pem)

    on_exit(fn ->
      MockHttpUpstream.stop(upstream)
      ProviderRegistry.uninstall()
      StubStorageProvider.reset()
      File.rm_rf!(tmp_dir)
    end)

    :ok = StubStorageProvider.reset()

    # The Gateway's ChatCompletionsHandler commits an attestation whose
    # DSSE signature is made by the SecretsProvider. Use a mock secrets
    # provider that wraps the JOSE.JWK we just generated so the
    # trust-anchor PEM actually corresponds to the signing key. We reuse
    # US3's pattern but inline (kept small; copying is cheaper than
    # promoting this stub to a shared test module).
    {:ok, llm_state} =
      OpenAiLlmProvider.init(%{
        base_url: MockHttpUpstream.url(upstream),
        finch_pool: :openai_pool,
        resolved_api_key: "sk-quickstart-fake-key",
        timeout_ms: 10_000,
        pool_timeout_ms: 5_000
      })

    {:ok, ledger_state} = PostgresMerkleLedger.init(%{})
    {:ok, storage_state} = StubStorageProvider.init(%{bucket: "quickstart-bucket"})
    {:ok, secrets_state} = quickstart_mock_secrets_init(jwk)

    ProviderRegistry.install_raw!(%{
      llm: {OpenAiLlmProvider, llm_state},
      ledger: {PostgresMerkleLedger, ledger_state},
      storage: {StubStorageProvider, storage_state},
      secrets: {__MODULE__.QuickstartSecretsProvider, secrets_state},
      tenant_id: @tenant_id,
      signer: "observed://gateway/quickstart"
    })

    # -- Cedar bundle: use the permissive reference policy from Step 3 --
    bundle_path =
      Path.join([
        Application.app_dir(:recurse_gateway, "priv"),
        "reference_policies",
        "permissive_all.cedar"
      ])

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

    # -- Customer IdP (mock) + broker setup -------------------------------
    mock_issuer = MockOidcIssuer.new()
    jwks_plug = MockOidcIssuer.jwks_plug_fn(mock_issuer)

    SupervisorHelper.stop_auto_started(RecurseBroker.OIDC.DiscoveryCache)
    SupervisorHelper.stop_auto_started(RecurseBroker.JWT.KeyRing)

    start_supervised!({RecurseBroker.JWT.KeyRing, generate_ephemeral?: true})
    start_supervised!({RecurseBroker.OIDC.DiscoveryCache, req_opts: [plug: jwks_plug]})

    previous_broker_env = swap_broker_env(mock_issuer.issuer)
    on_exit(fn -> restore_broker_env(previous_broker_env) end)

    # -- Gateway JwtValidator: populate known_kids from broker's keys ----
    {:ok, broker_keys} = RecurseBroker.JWT.KeyRing.all_active_keys()

    known_kids =
      Enum.map(broker_keys, fn {kid, k} ->
        {_, fields} = k |> JOSE.JWK.to_public() |> JOSE.JWK.to_map()
        {kid, Map.put(fields, "kid", kid)}
      end)

    previous_jwt_opts = Application.get_env(:recurse_gateway, :jwt_validator_opts)

    Application.put_env(:recurse_gateway, :jwt_validator_opts,
      audience: @broker_audience,
      issuer: @broker_issuer,
      known_kids: known_kids
    )

    on_exit(fn ->
      case previous_jwt_opts do
        nil -> Application.delete_env(:recurse_gateway, :jwt_validator_opts)
        val -> Application.put_env(:recurse_gateway, :jwt_validator_opts, val)
      end
    end)

    %{
      upstream: upstream,
      mock_issuer: mock_issuer,
      jwk: jwk,
      pub_pem: pub_pem,
      anchor_pem_path: anchor_pem_path,
      tmp_dir: tmp_dir,
      recurse_verify: recurse_verify_path()
    }
  end

  test "full quickstart: id_token → exchange → chat → receipt → export → recurse-verify",
       %{
         upstream: upstream,
         mock_issuer: mock_issuer,
         pub_pem: pub_pem,
         anchor_pem_path: anchor_pem_path,
         tmp_dir: tmp_dir,
         recurse_verify: recurse_verify
       } do
    start_wall_usec = System.monotonic_time(:microsecond)

    # Expect ONE canned chat completion from the mock upstream.
    MockHttpUpstream.expect(upstream, fn conn ->
      {:ok, _raw, conn} = Plug.Conn.read_body(conn)

      conn
      |> Plug.Conn.put_resp_header("content-type", "application/json")
      |> Plug.Conn.send_resp(200, canned_completion_body())
    end)

    # -- Step 4: Mint id_token from mock IdP ------------------------------
    id_token =
      MockOidcIssuer.mint_id_token(mock_issuer, %{
        "sub" => "auth0|quickstart-auditor",
        "aud" => @interactive_aud,
        "groups" => ["cn=recurse-auditors,ou=groups,dc=corp,dc=example"]
      })

    # -- Step 4: Token exchange against real broker ------------------------
    form_body =
      URI.encode_query(%{
        "grant_type" => "urn:ietf:params:oauth:grant-type:token-exchange",
        "subject_token" => id_token,
        "subject_token_type" => "urn:ietf:params:oauth:token-type:id_token",
        "audience" => @broker_audience
      })

    broker_conn =
      :post
      |> Plug.Test.conn("/token/exchange", form_body)
      |> Plug.Conn.put_req_header("content-type", "application/x-www-form-urlencoded")
      |> BrokerEndpoint.call(@broker_endpoint_opts)

    assert broker_conn.status == 200,
           "broker exchange failed: #{inspect(broker_conn.resp_body)}"

    %{"access_token" => access_token} = JSON.decode!(broker_conn.resp_body)

    # -- Step 5: POST /v1/chat/completions --------------------------------
    request_body = %{
      "model" => "gpt-4o-mini",
      "messages" => [%{"role" => "user", "content" => "quickstart haiku"}]
    }

    chat_conn =
      :post
      |> Plug.Test.conn("/v1/chat/completions", JSON.encode!(request_body))
      |> Plug.Conn.put_req_header("content-type", "application/json")
      |> Plug.Conn.put_req_header("authorization", "Bearer " <> access_token)
      |> Router.call(@router_opts)

    assert chat_conn.status == 200,
           "Gateway rejected the chat completion: status=#{chat_conn.status}"

    %{"object" => "chat.completion"} = JSON.decode!(chat_conn.resp_body)

    correlation_id =
      chat_conn.resp_headers
      |> List.keyfind("x-recurse-correlation-id", 0)
      |> then(fn {_, v} -> v end)

    assert is_binary(correlation_id)

    # -- Step 6: GET /v1/audit/receipts?run_id=... ------------------------
    # The ReceiptsHandler needs the attestation row to exist. Find it by
    # correlation_id (the data-plane handler recorded it).
    {:ok, attestation} = fetch_attestation_by_correlation_id(correlation_id)
    run_id = attestation.run_id

    receipts_conn =
      :get
      |> Plug.Test.conn("/v1/audit/receipts?run_id=" <> run_id)
      |> Plug.Conn.put_req_header("authorization", "Bearer " <> access_token)
      |> ReceiptsHandler.handle()

    assert receipts_conn.status == 200,
           "ReceiptsHandler returned #{receipts_conn.status}: #{inspect(receipts_conn.resp_body)}"

    %{"receipts" => receipts_list} = JSON.decode!(receipts_conn.resp_body)
    assert [_ | _] = receipts_list
    assert Enum.any?(receipts_list, fn r -> Map.get(r, "run_id") == run_id end)

    # -- Step 8: POST /v1/audit/export ------------------------------------
    # Seed signing_keys + policy_bundles so EvidenceZipBuilder can find
    # the PEM + bundle bytes needed by `recurse-verify` Steps 0 + 4.
    {:ok, bundle_ref} = BundleLoader.current_bundle()
    seed_signing_key(pub_pem, attestation)
    seed_policy_bundle(bundle_ref)

    export_conn =
      :post
      |> Plug.Test.conn("/v1/audit/export", JSON.encode!(%{"run_ids" => [run_id]}))
      |> Plug.Conn.put_req_header("content-type", "application/json")
      |> Plug.Conn.put_req_header("authorization", "Bearer " <> access_token)
      |> ExportHandler.handle()

    assert export_conn.status == 200,
           "ExportHandler returned #{export_conn.status}: #{inspect(export_conn.resp_body)}"

    # -- Step 8: recurse-verify shell-out ---------------------------------
    zip_path = Path.join(tmp_dir, "evidence-#{run_id}.zip")
    File.write!(zip_path, export_conn.resp_body)

    {stdout, exit_code} =
      System.cmd(recurse_verify, [
        "--zip",
        zip_path,
        "--trust-anchor",
        anchor_pem_path
      ])

    assert exit_code == 0,
           "recurse-verify failed: exit=#{exit_code}\n#{stdout}"

    assert stdout =~ "VERIFY: PASS (strict, anchored)"

    # -- SC-011 wall-clock sanity -----------------------------------------
    # The SC target is 30 MINUTES for a human doing Docker setup. This
    # scripted test runs in seconds. Assert 30s ceiling so a pathological
    # slowdown (database latency spike, TLS handshake storm) trips a
    # failure rather than a silent budget erosion.
    elapsed_usec = System.monotonic_time(:microsecond) - start_wall_usec
    elapsed_sec = elapsed_usec / 1_000_000

    assert elapsed_sec < 30,
           "quickstart walkthrough exceeded 30s budget: #{Float.round(elapsed_sec, 2)}s"
  end

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  # Two-step stop (terminate+delete child, then belt-and-braces
  # GenServer.stop) lives in
  # `RecurseBroker.Test.SupervisorHelper.stop_auto_started/1`.

  defp quickstart_mock_secrets_init(jwk) do
    __MODULE__.QuickstartSecretsProvider.init(%{jwk: jwk})
  end

  defp canned_completion_body do
    JSON.encode!(%{
      "id" => "chatcmpl-quickstart",
      "object" => "chat.completion",
      "created" => 1_700_000_000,
      "model" => "gpt-4o-mini",
      "choices" => [
        %{
          "index" => 0,
          "message" => %{
            "role" => "assistant",
            "content" => "compliance is a single sentence"
          },
          "finish_reason" => "stop"
        }
      ],
      "usage" => %{"prompt_tokens" => 3, "completion_tokens" => 5, "total_tokens" => 8}
    })
  end

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

  defp seed_signing_key(pub_pem, attestation) do
    now = DateTime.utc_now()

    identity = %{
      tenant_id: @tenant_id,
      kms_key_id: attestation.signer_kms_key_id,
      key_version: attestation.signer_key_version,
      public_key_pem: pub_pem,
      algorithm: :ecdsa_p256,
      first_seen_at: now
    }

    chain_hash =
      :crypto.hash(
        :sha256,
        @archive_chain_anchor <> SigningKey.canonical_row_bytes(identity)
      )

    attrs =
      identity
      |> Map.put(:last_seen_at, now)
      |> Map.put(:chain_hash, chain_hash)
      |> Map.put(:inserted_at, now)

    %SigningKey{}
    |> SigningKey.insert_changeset(attrs)
    |> Repo.insert!(on_conflict: :nothing, conflict_target: [:kms_key_id, :key_version])
  end

  defp seed_policy_bundle(bundle_ref) do
    # Match the us3 test's SQL-insert shape — the policy_bundles schema
    # isn't exposed by `PostgresMerkleLedger.Schemas` yet.
    now = DateTime.utc_now()

    sql = """
    INSERT INTO policy_bundles (id, tenant_id, policy_canonical_hash, bundle_bytes, cedar_version, loaded_at, source)
    VALUES ($1, $2, $3, $4, $5, $6, $7)
    ON CONFLICT DO NOTHING
    """

    {:ok, _} =
      Ecto.Adapters.SQL.query(Repo, sql, [
        Ecto.UUID.bingenerate(),
        @tenant_id,
        bundle_ref.canonical_hash,
        bundle_ref.bytes,
        "4.9.1",
        now,
        "filesystem"
      ])
  end

  defp swap_broker_env(issuer_url) do
    previous = %{
      expected_audience: Application.get_env(:recurse_broker, :expected_audience),
      broker_issuer: Application.get_env(:recurse_broker, :broker_issuer),
      role_mapping: Application.get_env(:recurse_broker, :role_mapping),
      oidc_validator_opts: Application.get_env(:recurse_broker, :oidc_validator_opts)
    }

    Application.put_env(:recurse_broker, :expected_audience, @broker_audience)
    Application.put_env(:recurse_broker, :broker_issuer, @broker_issuer)
    Application.put_env(:recurse_broker, :role_mapping, @mapping)

    Application.put_env(:recurse_broker, :oidc_validator_opts,
      alg_allowlist: [:rs256, :es256, :eddsa],
      issuer: issuer_url,
      audience: @interactive_aud
    )

    previous
  end

  defp restore_broker_env(previous) do
    for {k, v} <- previous do
      case v do
        nil -> Application.delete_env(:recurse_broker, k)
        val -> Application.put_env(:recurse_broker, k, val)
      end
    end

    :ok
  end
end

defmodule Recurse.Integration.QuickstartWalkthroughTest.QuickstartSecretsProvider do
  @moduledoc """
  Quickstart-test-local `SecretsProvider` that signs DSSE PAE bytes with
  a real `JOSE.JWK`-wrapped EC P-256 key. Kept adjacent to the test file
  (colocated with `us3_export_verify_test.exs`'s `US3MockSecretsProvider`
  pattern) because the key lifecycle is tied to the test's `setup/1`
  block — extracting this to a shared helper would invite drift with
  tests that prefer the `StubSecretsProvider` SHA-512 fake.
  """
  @behaviour Recurse.Providers.SecretsProvider

  @key_id "arn:aws:kms:us-east-1:000000000000:key/quickstart-test-key"

  @impl true
  def init(config) when is_map(config), do: {:ok, config}

  @impl true
  def active_signing_key(_state) do
    {:ok, %{key_id: @key_id, key_version: "v1", algorithm: :ecdsa_p256}}
  end

  @impl true
  def sign(%{jwk: jwk}, _handle, pae_bytes) when is_binary(pae_bytes) do
    {_, otp_priv_key} = JOSE.JWK.to_key(jwk)
    der = :public_key.sign(pae_bytes, :sha256, otp_priv_key)
    {:ok, ecdsa_der_to_raw(der, 32)}
  end

  @impl true
  def public_key(%{jwk: jwk}, _handle) do
    pub_jwk = JOSE.JWK.to_public(jwk)
    {_mod, pem} = JOSE.JWK.to_pem(pub_jwk)
    {:ok, pem}
  end

  @impl true
  def store_user_token(_state, _ctx, _tok, _ttl), do: :ok

  @impl true
  def exchange_for_downstream_token(_s, _c, _id, _scope),
    do: {:error, :not_implemented_in_test}

  @impl true
  def capabilities(_state), do: [:sign, :public_key_export]

  @impl true
  def healthcheck(_state), do: :ok

  @impl true
  def terminate(_state, _reason), do: :ok

  defp ecdsa_der_to_raw(<<0x30, _len, 0x02, r_len, rest::binary>>, size) do
    <<r::binary-size(r_len), 0x02, s_len, s_rest::binary>> = rest
    <<s::binary-size(s_len), _::binary>> = s_rest
    pad(strip_leading_zero(r), size) <> pad(strip_leading_zero(s), size)
  end

  defp strip_leading_zero(<<0x00, rest::binary>>) when byte_size(rest) > 0, do: rest
  defp strip_leading_zero(other), do: other

  defp pad(bin, size) when byte_size(bin) == size, do: bin

  defp pad(bin, size) when byte_size(bin) < size do
    :binary.copy(<<0>>, size - byte_size(bin)) <> bin
  end
end
