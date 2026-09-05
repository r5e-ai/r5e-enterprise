defmodule Recurse.Integration.SC012RestoreDrillTest do
  @moduledoc """
  SC-012 — scripted equivalent of the quarterly restore drill (F002 T103).

  Scripted equivalent of the runbook in `docs/operator/restore-drill.md`
  (SA2 T095). The goal: prove that after a catastrophic loss of the
  Gateway's Postgres ledger + S3 payload storage, operators can rebuild
  the deployment from backup and still produce `recurse-verify`-clean
  evidence zips for every historic run_id.

  ## Flow

      1. Emit 5 receipts via 5 chat completions (with real DSSE signing
         so the zips can be verified cryptographically).
      2. Snapshot:
           * ALL F002 ledger table rows via `SELECT *` per table into
             an in-memory map (the sandbox-mode Sandbox.checkout means
             we can't shell out to `pg_dump` — changes aren't committed
             to the real DB. A Sandbox-internal snapshot is the
             semantically equivalent operation).
           * StubStorageProvider state via `:ets.tab2list/1`.
      3. Clear state:
           * TRUNCATE every F002 table (via raw SQL; bypasses Ecto
             constraints).
           * `StubStorageProvider.reset/0`.
           * Sanity-assert the clearance (attestations == 0, stub puts
             == 0).
      4. Restore:
           * Re-insert every snapshotted row via `INSERT` (using the
             sandbox connection).
           * Re-insert every snapshotted ETS row into the stub storage
             table.
      5. For each of the 5 run_ids:
           a. Call `ExportHandler.handle/1` → zip bytes.
           b. Write the bytes to a tmp file.
           c. `System.cmd/3` `docs/auditor/recurse-verify --trust-anchor`.
           d. Assert exit_code == 0.

  ## Why this doesn't use real `pg_dump` / `pg_restore`

  Under `Ecto.Adapters.SQL.Sandbox` the test process holds an open
  transaction that is rolled back at test end — nothing is persisted to
  the actual Postgres tables. Shelling out to `pg_dump` would snapshot
  an EMPTY database (the committed view) regardless of what this test
  has written. A sandbox-internal snapshot (SELECT → in-memory map) is
  the semantically-equivalent operation for the sandbox test context.

  The REAL restore drill in `docs/operator/restore-drill.md` (SA2 T095)
  uses `pg_dump` + S3 replication because it runs against an
  uncommitted-sandbox-free production Postgres. This test's guarantee
  is "the code-path that ExportHandler + recurse-verify drive is
  resilient to a full table TRUNCATE + row re-insert" — which is the
  invariant a real `pg_restore` needs to preserve.

  ## `@moduletag :restore_drill`

  Excluded from default `mix test` via
  `apps/recurse_gateway/test/test_helper.exs`'s
  `ExUnit.start(exclude: [..., :restore_drill, ...])`. Nightly CI only.
  Local override:

      mix test --include restore_drill \\
        apps/recurse_gateway/test/integration/sc012_restore_drill_test.exs

  ## `async: false`

  Ecto Sandbox, ProviderRegistry, BundleLoader, `MockHttpUpstream`
  Bandit port, `System.cmd/3` — identical coupling profile to the other
  Phase-10 integration tests.

  ## Iron Law check (elixir:ecto-thinking)

  No new schemas, no new changesets. Raw SQL via
  `Ecto.Adapters.SQL.query!/4` for the TRUNCATE + INSERT cycles —
  which matches the `elixir:ecto-thinking` guidance for low-level DDL
  operations (creation / truncation / bulk restore) that don't fit the
  changeset-pipeline pattern.

  ## Cross-references

    * `specs/002-standalone-gateway-vertical-slice/spec.md` SC-012
    * `specs/002-standalone-gateway-vertical-slice/tasks.md` T103
    * `docs/operator/restore-drill.md` (SA2 T095) — the real runbook
    * `apps/recurse_gateway/test/integration/us3_export_verify_test.exs`
  """

  use ExUnit.Case, async: false

  setup_all do
    Recurse.Gateway.Test.KernelFixture.boot()
  end

  @moduletag :restore_drill
  @moduletag timeout: :timer.minutes(10)

  alias Ecto.Adapters.SQL
  alias Ecto.Adapters.SQL.Sandbox
  alias Recurse.Gateway.AuditPlane.ExportHandler
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
  @broker_audience "recurse-gateway-restore-drill"
  @broker_issuer "https://broker.recurse.test"
  @interactive_aud @broker_audience <> "-interactive"
  @archive_chain_anchor <<0::size(256)>>

  @router_opts Router.init([])
  @broker_endpoint_opts BrokerEndpoint.init([])

  # All F002-era ledger tables. Order matters for INSERT restore under
  # FK constraints: parents first (`tenants`, `sessions`), then children.
  # `TRUNCATE ... CASCADE` handles the clearance side without ordering
  # concerns; the insert side uses this exact list in order.
  @ledger_tables [
    "tenants",
    "sessions",
    "session_epochs",
    "attestations",
    "merkle_nodes",
    "global_ledger_entries",
    "payload_outbox",
    "jwt_jti_cache",
    "policy_bundles",
    "signing_keys",
    "audit_exports"
  ]

  @stub_storage_table :recurse_gateway_stub_storage_puts

  @mapping %{
    group_to_recurse_role: %{
      "cn=recurse-users,ou=groups,dc=corp,dc=example" => "caller",
      "cn=recurse-auditors,ou=groups,dc=corp,dc=example" => "tenant_auditor"
    },
    default_recurse_role: "caller",
    role_privilege_order: ["platform_operator", "tenant_auditor", "caller"]
  }

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
    :ok = Sandbox.checkout(Repo)
    Sandbox.mode(Repo, {:shared, self()})

    Repo.insert!(
      Tenant.changeset(%Tenant{}, %{
        tenant_id: @tenant_id,
        display_name: "SC-012 Restore Drill Tenant",
        tier: :standalone_gateway,
        created_at: DateTime.utc_now()
      }),
      on_conflict: :nothing,
      conflict_target: :tenant_id
    )

    {:ok, upstream} = MockHttpUpstream.start()

    # Real ES256 signing keypair — `recurse-verify` needs a trust anchor
    # whose public half matches the DSSE signing key the envelope builder
    # used. We inline the US3 mock-secrets pattern instead of promoting
    # it to a shared module (same rationale as the quickstart test:
    # divergent lifecycles across tests).
    {pub_raw, priv_raw} = :crypto.generate_key(:ecdh, :secp256r1)

    jwk =
      JOSE.JWK.from_key(
        {:ECPrivateKey, 1, priv_raw, {:namedCurve, :secp256r1}, pub_raw, :asn1_NOVALUE}
      )

    {_mod, pub_pem} = jwk |> JOSE.JWK.to_public() |> JOSE.JWK.to_pem()

    tmp_dir = Path.join(System.tmp_dir!(), "sc012_#{System.unique_integer([:positive])}")
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

    {:ok, llm_state} =
      OpenAiLlmProvider.init(%{
        base_url: MockHttpUpstream.url(upstream),
        finch_pool: :openai_pool,
        resolved_api_key: "sk-restore-drill-fake-key",
        timeout_ms: 10_000,
        pool_timeout_ms: 5_000
      })

    {:ok, ledger_state} = PostgresMerkleLedger.init(%{})
    {:ok, storage_state} = StubStorageProvider.init(%{bucket: "restore-drill-bucket"})
    {:ok, secrets_state} = __MODULE__.RestoreDrillSecrets.init(%{jwk: jwk})

    ProviderRegistry.install_raw!(%{
      llm: {OpenAiLlmProvider, llm_state},
      ledger: {PostgresMerkleLedger, ledger_state},
      storage: {StubStorageProvider, storage_state},
      secrets: {__MODULE__.RestoreDrillSecrets, secrets_state},
      tenant_id: @tenant_id,
      signer: "observed://gateway/restore-drill"
    })

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

    mock_issuer = MockOidcIssuer.new()
    jwks_plug = MockOidcIssuer.jwks_plug_fn(mock_issuer)

    SupervisorHelper.stop_auto_started(RecurseBroker.OIDC.DiscoveryCache)
    SupervisorHelper.stop_auto_started(RecurseBroker.JWT.KeyRing)

    start_supervised!({RecurseBroker.JWT.KeyRing, generate_ephemeral?: true})
    start_supervised!({RecurseBroker.OIDC.DiscoveryCache, req_opts: [plug: jwks_plug]})

    previous_broker_env = swap_broker_env(mock_issuer.issuer)
    on_exit(fn -> restore_broker_env(previous_broker_env) end)

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
      pub_pem: pub_pem,
      anchor_pem_path: anchor_pem_path,
      tmp_dir: tmp_dir,
      recurse_verify: recurse_verify_path()
    }
  end

  test "5 receipts → snapshot → truncate → restore → all 5 zips verify clean",
       %{
         upstream: upstream,
         mock_issuer: mock_issuer,
         pub_pem: pub_pem,
         anchor_pem_path: anchor_pem_path,
         tmp_dir: tmp_dir,
         recurse_verify: recurse_verify
       } do
    access_token = mint_access_token_for_auditor(mock_issuer)

    # -- Phase 1: Emit 5 receipts ----------------------------------------
    MockHttpUpstream.expect(upstream, fn conn ->
      {:ok, _raw, conn} = Plug.Conn.read_body(conn)

      conn
      |> Plug.Conn.put_resp_header("content-type", "application/json")
      |> Plug.Conn.send_resp(200, canned_completion_body())
    end)

    correlation_ids =
      for i <- 1..5 do
        emit_chat_and_return_correlation_id(access_token, i)
      end

    attestations = Enum.map(correlation_ids, &fetch_attestation!/1)
    run_ids = Enum.map(attestations, & &1.run_id)

    # Seed the signing_keys archive + policy_bundles once with the real
    # pub_pem so the very first export-evidence zip contains the PEM
    # that the trust anchor matches.
    {:ok, bundle_ref} = BundleLoader.current_bundle()
    Enum.each(attestations, fn att -> seed_signing_key(pub_pem, att) end)
    seed_policy_bundle(bundle_ref)

    # -- Phase 2: Snapshot ledger + stub storage -------------------------
    ledger_snapshot = snapshot_ledger(@ledger_tables)
    stub_snapshot = :ets.tab2list(@stub_storage_table)

    assert Enum.any?(ledger_snapshot["attestations"] || [], fn row ->
             Enum.any?(run_ids, fn id -> Enum.any?(row, fn v -> v == id end) end)
           end),
           "expected at least one attestation in snapshot matching the 5 run_ids"

    # -- Phase 3: Clear state (catastrophic loss simulation) --------------
    truncate_all_tables(@ledger_tables)
    :ok = StubStorageProvider.reset()

    # Sanity check: the table is empty now.
    %{rows: [[post_truncate_count]]} =
      SQL.query!(Repo, "SELECT count(*) FROM attestations", [])

    assert post_truncate_count == 0

    assert :ets.tab2list(@stub_storage_table) == [],
           "stub storage not cleared"

    # -- Phase 4: Restore from snapshot -----------------------------------
    restore_ledger(ledger_snapshot, @ledger_tables)
    Enum.each(stub_snapshot, fn row -> :ets.insert(@stub_storage_table, row) end)

    # Sanity check: rows are back.
    %{rows: [[post_restore_count]]} =
      SQL.query!(Repo, "SELECT count(*) FROM attestations", [])

    assert post_restore_count >= 5,
           "attestations table should have ≥ 5 rows post-restore; got #{post_restore_count}"

    # -- Phase 5: Export + verify each of the 5 run_ids ------------------
    for {run_id, idx} <- Enum.with_index(run_ids, 1) do
      export_conn =
        :post
        |> Plug.Test.conn("/v1/audit/export", JSON.encode!(%{"run_ids" => [run_id]}))
        |> Plug.Conn.put_req_header("content-type", "application/json")
        |> Plug.Conn.put_req_header("authorization", "Bearer " <> access_token)
        |> ExportHandler.handle()

      assert export_conn.status == 200,
             "ExportHandler returned #{export_conn.status} for run_id=#{run_id} (idx=#{idx}):\n" <>
               inspect(export_conn.resp_body, limit: 500)

      zip_path = Path.join(tmp_dir, "evidence-#{idx}.zip")
      File.write!(zip_path, export_conn.resp_body)

      {stdout, exit_code} =
        System.cmd(recurse_verify, [
          "--zip",
          zip_path,
          "--trust-anchor",
          anchor_pem_path
        ])

      assert exit_code == 0,
             "recurse-verify FAILED on restored zip idx=#{idx} run_id=#{run_id} " <>
               "(exit=#{exit_code}):\n#{stdout}"

      assert stdout =~ "VERIFY: PASS (strict, anchored)",
             "zip idx=#{idx} did not strict-pass; stdout:\n#{stdout}"
    end
  end

  # ---------------------------------------------------------------------------
  # Snapshot / restore helpers
  # ---------------------------------------------------------------------------

  # Map of `table_name => [row_tuple]` where each row_tuple is the
  # ordered list of column values as returned by `SELECT *`.
  defp snapshot_ledger(tables) do
    Map.new(tables, fn table ->
      %{columns: cols, rows: rows} = SQL.query!(Repo, "SELECT * FROM #{table}", [])
      {table, %{columns: cols, rows: rows}}
    end)
  end

  defp truncate_all_tables(tables) do
    # `TRUNCATE ... CASCADE` short-circuits FK ordering. `RESTART IDENTITY`
    # resets any serial sequences, which F002 doesn't use but is cheap
    # insurance for forward-compatibility if a migration adds one.
    list = Enum.join(tables, ", ")
    _ = SQL.query!(Repo, "TRUNCATE #{list} RESTART IDENTITY CASCADE", [])
    :ok
  end

  defp restore_ledger(snapshot, tables) do
    for table <- tables do
      case Map.fetch(snapshot, table) do
        {:ok, %{columns: [], rows: _}} ->
          :ok

        {:ok, %{columns: cols, rows: rows}} when rows != [] ->
          insert_rows(table, cols, rows)

        _ ->
          :ok
      end
    end

    :ok
  end

  defp insert_rows(table, cols, rows) do
    col_list = Enum.map_join(cols, ", ", fn c -> ~s("#{c}") end)

    Enum.each(rows, fn row ->
      placeholders =
        row
        |> Enum.with_index(1)
        |> Enum.map_join(", ", fn {_v, i} -> "$#{i}" end)

      _ =
        SQL.query!(
          Repo,
          "INSERT INTO #{table} (#{col_list}) VALUES (#{placeholders}) ON CONFLICT DO NOTHING",
          row
        )
    end)
  end

  # ---------------------------------------------------------------------------
  # Auth + chat helpers (shared pattern with quickstart + soak tests)
  # ---------------------------------------------------------------------------

  defp mint_access_token_for_auditor(mock_issuer) do
    id_token =
      MockOidcIssuer.mint_id_token(mock_issuer, %{
        "sub" => "auth0|restore-drill-auditor",
        "aud" => @interactive_aud,
        "groups" => ["cn=recurse-auditors,ou=groups,dc=corp,dc=example"]
      })

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

    %{"access_token" => access_token} = JSON.decode!(broker_conn.resp_body)
    access_token
  end

  defp emit_chat_and_return_correlation_id(access_token, i) do
    request_body = %{
      "model" => "gpt-4o-mini",
      "messages" => [%{"role" => "user", "content" => "restore drill turn #{i}"}]
    }

    conn =
      :post
      |> Plug.Test.conn("/v1/chat/completions", JSON.encode!(request_body))
      |> Plug.Conn.put_req_header("content-type", "application/json")
      |> Plug.Conn.put_req_header("authorization", "Bearer " <> access_token)
      |> Router.call(@router_opts)

    assert conn.status == 200,
           "chat #{i} failed: status=#{conn.status}, body=#{inspect(conn.resp_body)}"

    {_, cid} = List.keyfind(conn.resp_headers, "x-recurse-correlation-id", 0)
    cid
  end

  defp fetch_attestation!(correlation_id) do
    import Ecto.Query, only: [from: 2]

    from(a in Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Attestation,
      where: a.correlation_id == ^correlation_id,
      limit: 1
    )
    |> Repo.one!()
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
    now = DateTime.utc_now()

    sql = """
    INSERT INTO policy_bundles (id, tenant_id, policy_canonical_hash, bundle_bytes, cedar_version, loaded_at, source)
    VALUES ($1, $2, $3, $4, $5, $6, $7)
    ON CONFLICT DO NOTHING
    """

    {:ok, _} =
      SQL.query(Repo, sql, [
        Ecto.UUID.bingenerate(),
        @tenant_id,
        bundle_ref.canonical_hash,
        bundle_ref.bytes,
        "4.9.1",
        now,
        "filesystem"
      ])
  end

  defp canned_completion_body do
    JSON.encode!(%{
      "id" => "chatcmpl-restore-drill",
      "object" => "chat.completion",
      "created" => 1_700_000_000,
      "model" => "gpt-4o-mini",
      "choices" => [
        %{
          "index" => 0,
          "message" => %{"role" => "assistant", "content" => "restored"},
          "finish_reason" => "stop"
        }
      ],
      "usage" => %{"prompt_tokens" => 2, "completion_tokens" => 2, "total_tokens" => 4}
    })
  end

  # ---------------------------------------------------------------------------
  # Broker app-supervisor teardown lives in
  # `RecurseBroker.Test.SupervisorHelper` (see `stop_auto_started/1`).
  # ---------------------------------------------------------------------------

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

defmodule Recurse.Integration.SC012RestoreDrillTest.RestoreDrillSecrets do
  @moduledoc """
  Restore-drill-test-local `SecretsProvider` that signs DSSE PAE bytes
  with a real `JOSE.JWK`-wrapped EC P-256 key. Structurally identical
  to the US3 mock secrets provider (see
  `us3_export_verify_test.exs` bottom of file) and the quickstart
  test's `QuickstartSecretsProvider`. We inline per-test rather than
  promoting a shared helper because the key-lifecycle binding to the
  test's `setup/1` block differs subtly across tests (e.g. this test
  snapshots the `signing_keys` row mid-run, so the secrets provider
  MUST return the same PEM across the test's entire lifetime).
  """
  @behaviour Recurse.Providers.SecretsProvider

  @key_id "arn:aws:kms:us-east-1:000000000000:key/restore-drill-test-key"

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
