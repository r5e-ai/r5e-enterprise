defmodule Recurse.Gateway.Admin.ReceiptDetailHandlerContractTest do
  @moduledoc """
  Contract tests for the F004 T074 receipt-detail extension on
  `Recurse.Gateway.AuditPlane.ReceiptsHandler.handle_detail/1`.

  Asserts the `GET /v1/audit/receipts/{run_id}` shape per
  `audit_api_extensions.md` cross-references:

    * `tier_completeness_advisory: "partial"` at the top level (FR-017).
    * Full payload metadata (`payload_uri`, `payload_hash`,
      `payload_bytes_size`).
    * Full proof envelope (`session_chain_root`, `session_chain_epoch`,
      `local_inclusion_proof_b64`, `global_inclusion_proof_b64`,
      `dsse_signature_b64`, `signing_key_pem`, `verification_level`).
    * Matched-policy block with `policy_canonical_hash` + reserved
      `line_range` (`nil` until F005+).
    * F002 `signed_predicate` + `outer_container` blocks unchanged
      (additive-only — the F002 list shape stays byte-identical when
      no F004 fields are requested via the list path).

  Auth-gate variants reuse the F002 pattern: 401 missing Authorization,
  403 for the data-plane `caller` role, 200 for `tenant_auditor` /
  `platform_operator`. Tenant-mismatch returns 403 (cross-tenant
  defence-in-depth even though Phase-1 is single-tenant per BEAM).

  `async: false` because BundleLoader + ProviderRegistry are singletons.
  """

  use ExUnit.Case, async: false

  setup_all do
    Recurse.Gateway.Test.KernelFixture.boot()
  end

  alias Recurse.Gateway.AuditPlane.ReceiptsHandler
  alias Recurse.Gateway.Policy.BundleLoader
  alias Recurse.Gateway.ProviderRegistry
  alias Recurse.Gateway.Test.JwtTestHelper
  alias Recurse.Providers.Impls.PostgresMerkleLedger
  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.SigningKey
  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Tenant
  alias Recurse.Providers.Repo
  alias Recurse.Shared.Attestation.{Envelope, OuterContainer, SignedPredicate}
  alias Recurse.Shared.Ulid

  @tenant_id "01HQZN5K7J8M9N0P1Q2R3S4T5V"
  @other_tenant "01OTHER000000000000000000"
  @test_kms_key_id "arn:aws:kms:us-east-1:123:key/test"
  @test_signing_pem "-----BEGIN PUBLIC KEY-----\nTESTKEY\n-----END PUBLIC KEY-----\n"
  @archive_chain_anchor <<0::size(256)>>

  setup do
    :ok = Ecto.Adapters.SQL.Sandbox.checkout(Repo)

    bundle_path = write_bundle()

    entity_schema_path =
      Path.join([
        Application.app_dir(:recurse_gateway, "priv"),
        "cedar",
        "schema.cedarschema.json"
      ])

    _pid =
      start_supervised!(
        Supervisor.child_spec(
          {BundleLoader,
           bundle_path: bundle_path,
           entity_schema_path: entity_schema_path,
           trap_sighup: false,
           name: nil},
          id: make_ref()
        )
      )

    ProviderRegistry.install_raw!(%{
      llm: {Recurse.Gateway.Test.StubLLM, %{}},
      ledger: {PostgresMerkleLedger, %{repo: Repo, pubsub: Recurse.PubSub, config: %{}}},
      storage: {Recurse.Gateway.Test.StubStorage, %{}},
      secrets: {Recurse.Gateway.Test.StubSecretsProvider, %{}},
      tenant_id: @tenant_id,
      signer: "observed://gateway/test"
    })

    previous_validator_opts = Application.get_env(:recurse_gateway, :jwt_validator_opts)

    Application.put_env(:recurse_gateway, :jwt_validator_opts,
      audience: "recurse-gateway-test",
      issuer: "https://test-broker.example.invalid",
      known_kids: [
        {"test-key-rs256", JwtTestHelper.public_jwk(:rs256)}
      ]
    )

    on_exit(fn ->
      ProviderRegistry.uninstall()

      if previous_validator_opts do
        Application.put_env(:recurse_gateway, :jwt_validator_opts, previous_validator_opts)
      else
        Application.delete_env(:recurse_gateway, :jwt_validator_opts)
      end
    end)

    :ok
  end

  describe "GET /v1/audit/receipts/{run_id} — auth gate" do
    test "401 when Authorization is missing" do
      run_id = Ecto.UUID.generate()
      conn = build_conn(nil, run_id)
      conn = ReceiptsHandler.handle_detail(conn)

      assert conn.status == 401
      # Per-cause code (MR !31) — `:missing_authorization` from the
      # JWT validator surfaces as `ERR_UNAUTHORIZED_MISSING`.
      assert %{"error" => "ERR_UNAUTHORIZED_MISSING"} = JSON.decode!(conn.resp_body)
    end

    test "403 when caller has data-plane `caller` role (no ReadReceipts permit)" do
      run_id = Ecto.UUID.generate()
      jwt = mint_jwt("caller")
      conn = build_conn(jwt, run_id)
      conn = ReceiptsHandler.handle_detail(conn)

      assert conn.status == 403
      assert %{"error" => "ERR_FORBIDDEN"} = JSON.decode!(conn.resp_body)
    end
  end

  describe "GET /v1/audit/receipts/{run_id} — happy path detail shape" do
    test "tenant_auditor + committed receipt → 200 with full F004 detail extension shape" do
      env = build_envelope(@tenant_id)
      run_id = env.signed_predicate.run_id
      {:ok, _} = PostgresMerkleLedger.commit_attestation(env)
      seed_signing_key()

      jwt = mint_jwt("tenant_auditor")
      conn = build_conn(jwt, run_id)
      conn = ReceiptsHandler.handle_detail(conn)

      assert conn.status == 200
      body = JSON.decode!(conn.resp_body)

      # Top-level shape per the F004 contract.
      assert body["run_id"] == run_id

      # FR-017 — top-level tier_completeness_advisory is the load-bearing
      # field for the SPA's amber callout. Discovery-tier Standalone is
      # always "partial".
      assert body["tier_completeness_advisory"] == "partial"

      # F002 split-envelope blocks must stay byte-identical to the list
      # shape for the same receipt.
      assert %{"signed_predicate" => sp, "outer_container" => oc} = body
      assert sp["run_id"] == run_id
      assert oc["verification_level"] == "global_inclusion_verified"

      # F004 payload_metadata block.
      assert %{
               "payload_uri" => payload_uri,
               "payload_hash" => payload_hash_hex,
               "payload_bytes_size" => nil
             } = body["payload_metadata"]

      assert is_binary(payload_uri)
      assert byte_size(payload_hash_hex) == 64

      # F004 proof_envelope block.
      assert %{
               "session_chain_root" => session_root_hex,
               "session_chain_epoch" => 0,
               "local_inclusion_proof_b64" => local_b64,
               "global_inclusion_proof_b64" => global_b64,
               "dsse_signature_b64" => dsse_b64,
               "signing_key_pem" => pem,
               "verification_level" => "global_inclusion_verified"
             } = body["proof_envelope"]

      assert is_binary(session_root_hex) and byte_size(session_root_hex) == 64
      assert is_binary(local_b64)
      assert is_binary(global_b64) and byte_size(global_b64) > 0
      assert is_binary(dsse_b64)
      assert pem == @test_signing_pem

      # F004 matched_policy block — line_range reserved nil until F005+.
      assert %{
               "policy_canonical_hash" => policy_hex,
               "matched_policy_id" => nil,
               "line_range" => nil
             } = body["matched_policy"]

      assert byte_size(policy_hex) == 64
    end

    test "platform_operator can read same surface" do
      env = build_envelope(@tenant_id)
      run_id = env.signed_predicate.run_id
      {:ok, _} = PostgresMerkleLedger.commit_attestation(env)
      seed_signing_key()

      jwt = mint_jwt("platform_operator")
      conn = build_conn(jwt, run_id)
      conn = ReceiptsHandler.handle_detail(conn)

      assert conn.status == 200
    end

    test "signing_key_pem is nil when archive row is missing (graceful degradation)" do
      env = build_envelope(@tenant_id)
      run_id = env.signed_predicate.run_id
      {:ok, _} = PostgresMerkleLedger.commit_attestation(env)
      # Deliberately do NOT seed the signing-key archive row.

      jwt = mint_jwt("tenant_auditor")
      conn = build_conn(jwt, run_id)
      conn = ReceiptsHandler.handle_detail(conn)

      assert conn.status == 200
      body = JSON.decode!(conn.resp_body)
      assert body["proof_envelope"]["signing_key_pem"] == nil
    end
  end

  describe "GET /v1/audit/receipts/{run_id} — error envelopes" do
    test "404 when run_id does not exist" do
      missing = Ecto.UUID.generate()
      jwt = mint_jwt("tenant_auditor")

      conn = build_conn(jwt, missing)
      conn = ReceiptsHandler.handle_detail(conn)

      assert conn.status == 404
      assert %{"error" => "ERR_NOT_FOUND"} = JSON.decode!(conn.resp_body)
    end

    test "404 when run_id is not a valid UUID (cast failure)" do
      jwt = mint_jwt("tenant_auditor")

      conn = build_conn(jwt, "not-a-uuid")
      conn = ReceiptsHandler.handle_detail(conn)

      assert conn.status == 404
      assert %{"error" => "ERR_NOT_FOUND"} = JSON.decode!(conn.resp_body)
    end

    test "403 + tenant_mismatch when receipt belongs to a different tenant" do
      env = build_envelope(@other_tenant)
      run_id = env.signed_predicate.run_id
      {:ok, _} = PostgresMerkleLedger.commit_attestation(env)

      jwt = mint_jwt("tenant_auditor")
      conn = build_conn(jwt, run_id)
      conn = ReceiptsHandler.handle_detail(conn)

      assert conn.status == 403
      # Per-cause code (MR !31) — `:tenant_mismatch` from `TenantGuard`
      # surfaces as `ERR_FORBIDDEN_TENANT`, distinguishing the
      # cross-tenant denial from a generic Cedar-policy deny.
      assert %{"error" => "ERR_FORBIDDEN_TENANT"} = JSON.decode!(conn.resp_body)
    end
  end

  # ---------------------------------------------------------------------------
  # F002 list-shape regression — F004 detail extension MUST NOT change the
  # F002 list response when no detail param is in play.
  # ---------------------------------------------------------------------------

  describe "F002 list shape regression" do
    test "GET /v1/audit/receipts (list) is byte-identical to F002 baseline" do
      env = build_envelope(@tenant_id)
      run_id = env.signed_predicate.run_id
      {:ok, _} = PostgresMerkleLedger.commit_attestation(env)

      jwt = mint_jwt("tenant_auditor")

      # List endpoint — uses ReceiptsHandler.handle/1, not handle_detail.
      conn =
        :get
        |> Plug.Test.conn("/v1/audit/receipts")
        |> Plug.Conn.put_req_header("authorization", "Bearer " <> jwt)
        |> ReceiptsHandler.handle()

      assert conn.status == 200
      body = JSON.decode!(conn.resp_body)

      # F002 list-shape: top-level keys are exactly `receipts` + `cursor`,
      # nothing else. F004 detail-only fields MUST NOT leak into the list
      # response.
      assert Map.keys(body) |> Enum.sort() == ["cursor", "receipts"]
      assert is_list(body["receipts"])
      first = hd(body["receipts"])
      assert first["run_id"] == run_id
      # F004 detail-only fields are absent from list rows.
      refute Map.has_key?(first, "tier_completeness_advisory")
      refute Map.has_key?(first, "payload_metadata")
      refute Map.has_key?(first, "proof_envelope")
      refute Map.has_key?(first, "matched_policy")
    end
  end

  # ----- helpers -----

  defp build_conn(jwt, run_id) do
    conn = Plug.Test.conn(:get, "/v1/audit/receipts/#{run_id}")
    conn = %{conn | path_params: %{"run_id" => run_id}}

    case jwt do
      nil -> conn
      token -> Plug.Conn.put_req_header(conn, "authorization", "Bearer " <> token)
    end
  end

  defp mint_jwt(recurse_role) do
    JwtTestHelper.mint_test_jwt(
      recurse_role: recurse_role,
      audience: "recurse-gateway-test",
      issuer: "https://test-broker.example.invalid"
    )
  end

  defp write_bundle do
    source =
      Path.join([
        Application.app_dir(:recurse_gateway, "priv"),
        "reference_policies",
        "platform_roles.cedar"
      ])
      |> File.read!()

    path = Path.join(System.tmp_dir!(), "receipt_detail_bundle_#{System.unique_integer()}.cedar")
    File.write!(path, source)
    on_exit(fn -> File.rm(path) end)
    path
  end

  defp build_envelope(tenant_id) do
    session_id = Ecto.UUID.generate()
    run_id = Ecto.UUID.generate()

    Tenant.changeset(%Tenant{}, %{
      tenant_id: tenant_id,
      display_name: tenant_id,
      tier: :standalone_gateway,
      created_at: DateTime.utc_now()
    })
    |> Repo.insert(on_conflict: :nothing, conflict_target: :tenant_id)

    sp = %SignedPredicate{
      envelope_version: "1.0",
      run_id: run_id,
      step_id: run_id,
      turn_id: run_id,
      session_id: session_id,
      session_chain_position: 0,
      event_kind: :llm_call,
      timestamp: DateTime.utc_now() |> DateTime.to_iso8601(),
      tenant_id: tenant_id,
      machine_identity: %{
        observed_jwt_subject: "alice@example.com",
        observed_jwt_issuer: "https://issuer.example.com"
      },
      principal: %{"kind" => "obo_human", "subject" => "alice@example.com"},
      policy_canonical_hash: :crypto.hash(:sha256, "policy-" <> run_id),
      payload_hash: :crypto.hash(:sha256, "payload-" <> run_id),
      payload_uri: "s3://bucket/tenants/#{tenant_id}/runs/#{run_id}.json",
      correlation_id: Ulid.generate(),
      signer: @test_kms_key_id
    }

    oc = %OuterContainer{
      verification_level: :signed,
      tier_completeness_advisory: :partial,
      session_chain_epoch: 0,
      session_state: :active
    }

    Envelope.new(sp, oc, %{"signatures" => [%{"sig" => Base.encode64(<<0::size(8 * 72)>>)}]})
  end

  defp seed_signing_key do
    now = DateTime.utc_now()

    identity = %{
      tenant_id: @tenant_id,
      kms_key_id: @test_kms_key_id,
      key_version: "v1",
      public_key_pem: @test_signing_pem,
      algorithm: :ecdsa_p256,
      first_seen_at: now
    }

    chain_hash =
      :crypto.hash(:sha256, @archive_chain_anchor <> SigningKey.canonical_row_bytes(identity))

    attrs =
      identity
      |> Map.put(:last_seen_at, now)
      |> Map.put(:chain_hash, chain_hash)
      |> Map.put(:inserted_at, now)

    %SigningKey{}
    |> SigningKey.insert_changeset(attrs)
    |> Repo.insert(on_conflict: :nothing, conflict_target: [:kms_key_id, :key_version])
  end
end
