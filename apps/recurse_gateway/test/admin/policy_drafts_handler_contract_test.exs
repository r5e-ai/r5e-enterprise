defmodule Recurse.Gateway.Admin.PolicyDraftsHandlerContractTest do
  @moduledoc """
  Contract tests for the F004 Phase-5 (US3) policy-drafts surface (T084).

  Asserts each of the six draft endpoints + simulate against the contract
  in `specs/004-audit-console/contracts/audit_api_extensions.md`:

    * `GET /v1/policy/drafts`              — list (`DashboardQuery` / `:ui_query`)
    * `POST /v1/policy/drafts`             — create (`PolicyDraftCreate` / `:ui_policy_draft_created`)
    * `GET /v1/policy/drafts/{id}`         — fetch single (`DashboardQuery` / `:ui_query`)
    * `PATCH /v1/policy/drafts/{id}`       — edit (`PolicyDraftEdit` / `:ui_policy_draft_edited`)
    * `DELETE /v1/policy/drafts/{id}`      — archive (`PolicyDraftArchive` / `:ui_policy_draft_archived`)
    * `POST /v1/policy/drafts/from-receipt` — skeleton (`PolicyDraftCreate` / `:ui_policy_draft_created`)
    * `POST /v1/policy/drafts/{id}/dry-run` — Blast Radius
      (`PolicyDraftDryRun` / `:ui_policy_draft_dry_run`); MUST surface
      `would_have_allowed` as a top-level integer per algorithm §5a.
    * `POST /v1/policy/simulate`           — synthetic eval (`PolicySimulate` / `:ui_policy_simulate`)

  Each test asserts the `event_kind` emitted matches the canonical matrix
  at `data-model.md` §0 verbatim. Drift fails CI.

  `async: false` because BundleLoader + ProviderRegistry are singletons
  per F002 convention.
  """

  use ExUnit.Case, async: false

  setup_all do
    Recurse.Gateway.Test.KernelFixture.boot()
  end

  alias Recurse.Gateway.Admin.BlastRadius
  alias Recurse.Gateway.Admin.BrowserAuth.UiReceipts
  alias Recurse.Gateway.Admin.PolicyDrafts
  alias Recurse.Gateway.Admin.PolicyDraftsDryRunHandler
  alias Recurse.Gateway.Admin.PolicyDraftsFromReceiptHandler
  alias Recurse.Gateway.Admin.PolicyDraftsHandler
  alias Recurse.Gateway.Admin.PolicySimulateHandler
  alias Recurse.Gateway.Policy.BundleLoader
  alias Recurse.Gateway.ProviderRegistry
  alias Recurse.Gateway.Test.JwtTestHelper
  alias Recurse.Providers.Impls.PostgresMerkleLedger
  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Tenant
  alias Recurse.Providers.Repo

  @tenant_id "01HQZN5K7J8M9N0P1Q2R3S4T5V"
  # GAN-review fix (PR-readiness #1, 2026-04-25): used by the cross-tenant
  # rejection tests below. Belongs to a different tenant than the JWT we
  # mint; mutation paths MUST return 404 (not 200, not 403) per
  # FR-006 + Constitution Principle V.
  @other_tenant_id "01HQZN5K7J8M9N0P1Q2R3S4T0X"

  @cedar_skeleton """
  permit (
    principal,
    action == Recurse::Action::"DashboardQuery",
    resource
  )
  when {
    principal.recurse_role == "platform_operator" && principal.tenant_id == context.tenant_id
  };
  """

  setup do
    :ok = Ecto.Adapters.SQL.Sandbox.checkout(Repo)
    Ecto.Adapters.SQL.Sandbox.mode(Repo, {:shared, self()})

    Repo.insert!(
      Tenant.changeset(%Tenant{}, %{
        tenant_id: @tenant_id,
        display_name: "Phase-5 Test Tenant",
        tier: :standalone_gateway,
        created_at: DateTime.utc_now()
      }),
      on_conflict: :nothing,
      conflict_target: :tenant_id
    )

    # GAN-review fix (PR-readiness #1): seed a second tenant so cross-tenant
    # rejection tests can insert a draft owned by it.
    Repo.insert!(
      Tenant.changeset(%Tenant{}, %{
        tenant_id: @other_tenant_id,
        display_name: "Phase-5 Other Tenant",
        tier: :standalone_gateway,
        created_at: DateTime.utc_now()
      }),
      on_conflict: :nothing,
      conflict_target: :tenant_id
    )

    bundle_path = write_bundle()

    entity_schema_path =
      Path.join([
        Application.app_dir(:recurse_gateway, "priv"),
        "cedar",
        "schema.cedarschema.json"
      ])

    _ =
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
      signer: "observed://gateway/policy-drafts-contract-test"
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

  describe "POST /v1/policy/drafts (create)" do
    test "201 + emits :ui_policy_draft_created" do
      attach_ui_receipts_telemetry()
      jwt = mint_jwt("platform_operator")

      conn =
        :post
        |> Plug.Test.conn("/v1/policy/drafts", create_body())
        |> with_json(jwt)
        |> PolicyDraftsHandler.create()

      assert conn.status == 201
      body = JSON.decode!(conn.resp_body)
      assert is_binary(body["id"])
      assert body["status"] == "draft"
      assert body["tenant_id"] == @tenant_id

      assert_receive {:ui_receipt_emitted, %{event_kind: :ui_policy_draft_created}}, 2_000
    end

    test "403 for tenant_auditor (write actions blocked)" do
      jwt = mint_jwt("tenant_auditor")

      conn =
        :post
        |> Plug.Test.conn("/v1/policy/drafts", create_body())
        |> with_json(jwt)
        |> PolicyDraftsHandler.create()

      assert conn.status == 403
      assert %{"error" => "ERR_FORBIDDEN"} = JSON.decode!(conn.resp_body)
    end
  end

  describe "GET /v1/policy/drafts (list)" do
    test "200 + emits :ui_query (query_kind=policy_drafts)" do
      attach_ui_receipts_telemetry()
      {:ok, _draft} = seed_draft()

      jwt = mint_jwt("platform_operator")

      conn =
        :get
        |> Plug.Test.conn("/v1/policy/drafts?status=draft")
        |> with_jwt(jwt)
        |> PolicyDraftsHandler.list()

      assert conn.status == 200
      body = JSON.decode!(conn.resp_body)
      assert is_list(body["drafts"])
      assert body["drafts"] != []

      assert_receive {:ui_receipt_emitted, %{event_kind: :ui_query, query_kind: "policy_drafts"}},
                     2_000
    end
  end

  describe "GET /v1/policy/drafts/{id} (fetch)" do
    test "200 with full body + emits :ui_query" do
      attach_ui_receipts_telemetry()
      {:ok, draft} = seed_draft()

      jwt = mint_jwt("platform_operator")

      conn =
        :get
        |> Plug.Test.conn("/v1/policy/drafts/#{draft.id}")
        |> with_path_params(%{"id" => draft.id})
        |> with_jwt(jwt)
        |> PolicyDraftsHandler.get()

      assert conn.status == 200
      body = JSON.decode!(conn.resp_body)
      assert body["id"] == draft.id
      assert body["cedar_source"] == draft.cedar_source

      assert_receive {:ui_receipt_emitted, %{event_kind: :ui_query, query_kind: "policy_drafts"}},
                     2_000
    end

    test "404 for missing draft" do
      jwt = mint_jwt("platform_operator")

      conn =
        :get
        |> Plug.Test.conn("/v1/policy/drafts/#{Ecto.UUID.generate()}")
        |> with_path_params(%{"id" => Ecto.UUID.generate()})
        |> with_jwt(jwt)
        |> PolicyDraftsHandler.get()

      assert conn.status == 404
    end
  end

  describe "PATCH /v1/policy/drafts/{id} (edit)" do
    test "200 + emits :ui_policy_draft_edited + invalidates cache" do
      attach_ui_receipts_telemetry()
      {:ok, draft} = seed_draft_with_cache()

      jwt = mint_jwt("platform_operator")
      new_source = @cedar_skeleton <> "\n// edit"

      body = JSON.encode!(%{"cedar_source" => new_source})

      conn =
        :patch
        |> Plug.Test.conn("/v1/policy/drafts/#{draft.id}", body)
        |> with_path_params(%{"id" => draft.id})
        |> with_json(jwt)
        |> PolicyDraftsHandler.update()

      assert conn.status == 200
      result = JSON.decode!(conn.resp_body)
      assert result["cedar_source"] == new_source
      # Cache invalidation per blast_radius_algorithm.md §7
      assert is_nil(result["last_blast_radius_summary"])

      assert_receive {:ui_receipt_emitted, %{event_kind: :ui_policy_draft_edited}}, 2_000
    end
  end

  describe "DELETE /v1/policy/drafts/{id} (archive)" do
    test "204 + emits :ui_policy_draft_archived" do
      attach_ui_receipts_telemetry()
      {:ok, draft} = seed_draft()

      jwt = mint_jwt("platform_operator")

      conn =
        :delete
        |> Plug.Test.conn("/v1/policy/drafts/#{draft.id}")
        |> with_path_params(%{"id" => draft.id})
        |> with_jwt(jwt)
        |> PolicyDraftsHandler.archive()

      assert conn.status == 204

      assert_receive {:ui_receipt_emitted, %{event_kind: :ui_policy_draft_archived}}, 2_000
    end
  end

  # ---------------------------------------------------------------------------
  # GAN-review fix (PR-readiness #1, 2026-04-25): cross-tenant rejection on
  # mutation paths. Symmetrical to the `:tenant_scope` guard already on
  # `do_get_one`. Cross-tenant access MUST return 404 (not 403) so the
  # response leaks nothing about whether the resource exists. Defends FR-006
  # + Constitution Principle V even though Phase-1 deployments are
  # single-tenant per BEAM (operationally unreachable today, but the
  # multi-tenant SaaS roadmap depends on this guard being in place from day 1).
  # ---------------------------------------------------------------------------

  describe "PATCH /v1/policy/drafts/{id} — cross-tenant" do
    test "404 (not 200) when draft belongs to a different tenant" do
      attach_ui_receipts_telemetry()
      # Seed a draft owned by @other_tenant_id (NOT @tenant_id, the JWT's tenant).
      {:ok, foreign_draft} =
        PolicyDrafts.create(@other_tenant_id, %{
          "cedar_source" => @cedar_skeleton,
          "scope_metadata" => %{"scope_kind" => "tenant", "scope_value" => @other_tenant_id},
          "condition_metadata" => [],
          "author_principal_subject" => "other-tenant-author@corp",
          "status" => :draft
        })

      jwt = mint_jwt("platform_operator")
      body = JSON.encode!(%{"cedar_source" => @cedar_skeleton <> "\n// cross-tenant"})

      conn =
        :patch
        |> Plug.Test.conn("/v1/policy/drafts/#{foreign_draft.id}", body)
        |> with_path_params(%{"id" => foreign_draft.id})
        |> with_json(jwt)
        |> PolicyDraftsHandler.update()

      # MUST be 404, NOT 200 (would have edited cross-tenant) and NOT 403
      # (would leak existence). Mirrors `do_get_one`'s response.
      assert conn.status == 404

      # Negative assertion: no edit receipt should be emitted on rejection.
      refute_receive {:ui_receipt_emitted, %{event_kind: :ui_policy_draft_edited}}, 500

      # Verify the foreign draft is unchanged in the DB.
      {:ok, reloaded} =
        PolicyDrafts.get(foreign_draft.id,
          include_archived: true,
          tenant_scope: @other_tenant_id
        )

      assert reloaded.cedar_source == foreign_draft.cedar_source
    end
  end

  describe "DELETE /v1/policy/drafts/{id} — cross-tenant" do
    test "404 (not 204) when draft belongs to a different tenant" do
      attach_ui_receipts_telemetry()

      {:ok, foreign_draft} =
        PolicyDrafts.create(@other_tenant_id, %{
          "cedar_source" => @cedar_skeleton,
          "scope_metadata" => %{"scope_kind" => "tenant", "scope_value" => @other_tenant_id},
          "condition_metadata" => [],
          "author_principal_subject" => "other-tenant-author@corp",
          "status" => :draft
        })

      jwt = mint_jwt("platform_operator")

      conn =
        :delete
        |> Plug.Test.conn("/v1/policy/drafts/#{foreign_draft.id}")
        |> with_path_params(%{"id" => foreign_draft.id})
        |> with_jwt(jwt)
        |> PolicyDraftsHandler.archive()

      assert conn.status == 404

      refute_receive {:ui_receipt_emitted, %{event_kind: :ui_policy_draft_archived}}, 500

      # Verify the foreign draft is still :draft (not archived).
      {:ok, reloaded} =
        PolicyDrafts.get(foreign_draft.id,
          include_archived: true,
          tenant_scope: @other_tenant_id
        )

      assert reloaded.status == :draft
      assert is_nil(reloaded.archived_at)
    end
  end

  describe "POST /v1/policy/drafts/from-receipt" do
    test "201 with skeleton + emits :ui_policy_draft_created (seeded_from_receipt)" do
      attach_ui_receipts_telemetry()
      run_id = seed_attestation()

      jwt = mint_jwt("platform_operator")
      body = JSON.encode!(%{"source_receipt_run_id" => run_id})

      conn =
        :post
        |> Plug.Test.conn("/v1/policy/drafts/from-receipt", body)
        |> with_json(jwt)
        |> PolicyDraftsFromReceiptHandler.handle()

      assert conn.status == 201
      result = JSON.decode!(conn.resp_body)
      assert result["source_receipt_run_id"] == run_id
      assert String.contains?(result["cedar_source"], "forbid")

      assert_receive {:ui_receipt_emitted, %{event_kind: :ui_policy_draft_created}}, 2_000
    end

    test "404 when source receipt missing" do
      jwt = mint_jwt("platform_operator")
      body = JSON.encode!(%{"source_receipt_run_id" => Ecto.UUID.generate()})

      conn =
        :post
        |> Plug.Test.conn("/v1/policy/drafts/from-receipt", body)
        |> with_json(jwt)
        |> PolicyDraftsFromReceiptHandler.handle()

      assert conn.status == 404
    end

    test "400 when source_receipt_run_id missing" do
      jwt = mint_jwt("platform_operator")
      body = JSON.encode!(%{})

      conn =
        :post
        |> Plug.Test.conn("/v1/policy/drafts/from-receipt", body)
        |> with_json(jwt)
        |> PolicyDraftsFromReceiptHandler.handle()

      assert conn.status == 400
    end
  end

  describe "POST /v1/policy/drafts/{id}/dry-run" do
    test "200 sync with 4-cell counts including would_have_allowed top-level integer" do
      attach_ui_receipts_telemetry()
      {:ok, draft} = seed_draft()

      jwt = mint_jwt("platform_operator")
      body = JSON.encode!(%{"window_days" => 30})

      conn =
        :post
        |> Plug.Test.conn("/v1/policy/drafts/#{draft.id}/dry-run", body)
        |> with_path_params(%{"id" => draft.id})
        |> with_json(jwt)
        |> PolicyDraftsDryRunHandler.handle()

      assert conn.status == 200
      result = JSON.decode!(conn.resp_body)

      # **Load-bearing 4-cell field per blast_radius_algorithm.md §5a**
      assert is_integer(result["would_have_allowed"])
      assert is_integer(result["matches_intent"])
      assert is_integer(result["unintended"])
      assert is_integer(result["no_change"])
      assert is_integer(result["total_affected"])
      assert is_integer(result["total_receipts_in_window"])
      assert result["mode"] == "sync"

      assert_receive {:ui_receipt_emitted, %{event_kind: :ui_policy_draft_dry_run}}, 2_000
    end

    test "400 when Cedar source has parse error" do
      jwt = mint_jwt("platform_operator")

      attrs = %{
        "cedar_source" => "this is not cedar source !!!",
        "scope_metadata" => %{"scope_kind" => "tenant", "scope_value" => @tenant_id},
        "condition_metadata" => [],
        "author_principal_subject" => "test-author@corp",
        "status" => :draft
      }

      {:ok, bad_draft} = PolicyDrafts.create(@tenant_id, attrs)

      conn =
        :post
        |> Plug.Test.conn("/v1/policy/drafts/#{bad_draft.id}/dry-run", JSON.encode!(%{}))
        |> with_path_params(%{"id" => bad_draft.id})
        |> with_json(jwt)
        |> PolicyDraftsDryRunHandler.handle()

      assert conn.status == 400
    end

    test "404 when draft missing" do
      jwt = mint_jwt("platform_operator")
      missing = Ecto.UUID.generate()

      conn =
        :post
        |> Plug.Test.conn("/v1/policy/drafts/#{missing}/dry-run", JSON.encode!(%{}))
        |> with_path_params(%{"id" => missing})
        |> with_json(jwt)
        |> PolicyDraftsDryRunHandler.handle()

      assert conn.status == 404
    end
  end

  describe "POST /v1/policy/simulate" do
    test "200 + emits :ui_policy_simulate" do
      attach_ui_receipts_telemetry()
      jwt = mint_jwt("platform_operator")

      body =
        JSON.encode!(%{
          "cedar_source" => @cedar_skeleton,
          "principal" => %{
            "kind" => "obo_human",
            "id" => "alice@corp",
            "attrs" => %{
              "subject" => "alice@corp",
              "issuer" => "https://test/",
              "groups" => [],
              "recurse_role" => "platform_operator",
              "tenant_id" => @tenant_id
            }
          },
          "action" => ~s(Recurse::Action::"DashboardQuery"),
          "resource" => %{
            "kind" => "Recurse::Resource::ConsoleSurface",
            "id" => "policy_simulate",
            "attrs" => %{}
          },
          "context" => %{"tenant_id" => @tenant_id}
        })

      conn =
        :post
        |> Plug.Test.conn("/v1/policy/simulate", body)
        |> with_json(jwt)
        |> PolicySimulateHandler.handle()

      assert conn.status == 200
      result = JSON.decode!(conn.resp_body)
      assert result["decision"] in ["allow", "deny"]
      assert is_list(result["matched_policies"])
      assert is_binary(result["attested_run_id"])

      assert_receive {:ui_receipt_emitted, %{event_kind: :ui_policy_simulate}}, 2_000
    end

    test "400 on cedar parse error returns line/col-bearing message" do
      jwt = mint_jwt("platform_operator")

      body =
        JSON.encode!(%{
          "cedar_source" => "this is garbage cedar !!!",
          "principal" => %{"kind" => "obo_human", "id" => "alice"},
          "action" => ~s(Recurse::Action::"DashboardQuery"),
          "resource" => %{"kind" => "Recurse::Resource::ConsoleSurface", "id" => "x"},
          "context" => %{}
        })

      conn =
        :post
        |> Plug.Test.conn("/v1/policy/simulate", body)
        |> with_json(jwt)
        |> PolicySimulateHandler.handle()

      assert conn.status == 400
    end
  end

  describe "BlastRadius engine — basic guarantees" do
    test "compute/1 returns :async_required for windows > 10K (sentinel only)" do
      # We don't seed 10K rows; just assert the threshold helper is exposed
      # for handler logic + consistency tests.
      assert BlastRadius.async_threshold() == 10_000
    end

    test "classify_pair/2 honors the 4-cell matrix verbatim" do
      assert BlastRadius.classify_pair(:deny, :deny) == :matches_intent
      assert BlastRadius.classify_pair(:deny, :allow) == :would_have_allowed
      assert BlastRadius.classify_pair(:allow, :deny) == :unintended
      assert BlastRadius.classify_pair(:allow, :allow) == :no_change
    end
  end

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  defp create_body do
    JSON.encode!(%{
      "cedar_source" => @cedar_skeleton,
      "scope_metadata" => %{"scope_kind" => "tenant", "scope_value" => @tenant_id},
      "condition_metadata" => []
    })
  end

  defp seed_draft do
    PolicyDrafts.create(@tenant_id, %{
      "cedar_source" => @cedar_skeleton,
      "scope_metadata" => %{"scope_kind" => "tenant", "scope_value" => @tenant_id},
      "condition_metadata" => [],
      "author_principal_subject" => "test-author@corp",
      "status" => :draft
    })
  end

  defp seed_draft_with_cache do
    {:ok, draft} = seed_draft()

    PolicyDrafts.persist_blast_radius_summary(draft.id, %{
      "total_scanned" => 100,
      "matches_intent" => 50,
      "unintended" => 0,
      "would_have_allowed" => 0,
      "no_change" => 50,
      "total_affected" => 50
    })
  end

  # Insert a real-ish receipt so from-receipt has something to seed against.
  defp seed_attestation do
    alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Attestation
    alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Session

    now = DateTime.utc_now()

    {:ok, session} =
      %Session{}
      |> Session.changeset(%{
        tenant_id: @tenant_id,
        session_scope: :discovery_session,
        state: :active,
        session_start: now,
        principal_kind: :obo_human,
        principal_canonical: "alice@corp"
      })
      |> Repo.insert()

    session_id = session.session_id

    attestation =
      %Attestation{}
      |> Attestation.changeset(%{
        session_id: session_id,
        turn_id: Ecto.UUID.generate(),
        event_kind: :llm_call,
        machine_identity: %{"observed_jwt_subject" => "agent", "observed_jwt_issuer" => "test"},
        principal: %{
          "kind" => "obo_human",
          "subject" => "alice@corp",
          "issuer" => "https://test/",
          "recurse_role" => "caller"
        },
        tenant_id: @tenant_id,
        policy_canonical_hash: :crypto.hash(:sha256, "policy"),
        payload_hash: :crypto.hash(:sha256, "payload"),
        payload_uri: "s3://bucket/p.json",
        correlation_id: "corr-test",
        signer_kms_key_id: "test-key",
        signer_key_version: "v1",
        timestamp: now,
        signed_predicate_bytes: <<0::64>>,
        dsse_signature: <<0::64>>,
        verification_level: :signed,
        tier_completeness_advisory: :partial,
        policy_decision: :allow,
        outcome: :success
      })
      |> Repo.insert!()

    attestation.run_id
  end

  defp mint_jwt(recurse_role) do
    JwtTestHelper.mint_test_jwt(
      recurse_role: recurse_role,
      audience: "recurse-gateway-test",
      issuer: "https://test-broker.example.invalid"
    )
  end

  defp with_jwt(conn, jwt) do
    Plug.Conn.put_req_header(conn, "authorization", "Bearer " <> jwt)
  end

  # Set the auth header + content-type AND run the JSON parser. The
  # production router has `Plug.Parsers` upstream of every handler so
  # `conn.body_params` is populated; tests that call handlers directly
  # need to apply the parser inline.
  defp with_json(conn, jwt) do
    conn
    |> Plug.Conn.put_req_header("authorization", "Bearer " <> jwt)
    |> Plug.Conn.put_req_header("content-type", "application/json")
    |> Plug.Parsers.call(Plug.Parsers.init(parsers: [:json], pass: ["*/*"], json_decoder: JSON))
  end

  defp with_path_params(conn, params) do
    %{conn | path_params: Map.merge(conn.path_params || %{}, params)}
  end

  defp attach_ui_receipts_telemetry do
    test_pid = self()
    handler_id = "ui-receipt-test-#{System.unique_integer()}"

    :telemetry.attach(
      handler_id,
      UiReceipts.telemetry_event(),
      fn _event, _measurements, meta, _config ->
        send(test_pid, {:ui_receipt_emitted, meta})
      end,
      nil
    )

    on_exit(fn -> :telemetry.detach(handler_id) end)
  end

  defp write_bundle do
    source =
      Path.join([
        Application.app_dir(:recurse_gateway, "priv"),
        "reference_policies",
        "platform_roles.cedar"
      ])
      |> File.read!()

    path = Path.join(System.tmp_dir!(), "policy_drafts_bundle_#{System.unique_integer()}.cedar")
    File.write!(path, source)
    on_exit(fn -> File.rm(path) end)
    path
  end
end
