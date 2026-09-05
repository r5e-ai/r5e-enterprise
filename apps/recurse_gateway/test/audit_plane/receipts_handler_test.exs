defmodule Recurse.Gateway.AuditPlane.ReceiptsHandlerTest do
  @moduledoc """
  Contract tests for `Recurse.Gateway.AuditPlane.ReceiptsHandler` (F002
  T059 / FR-021).

  Covers:

    * Missing Authorization → 401 F001 error envelope.
    * `caller` role principal → 403 F001 error envelope (Cedar deny).
    * `tenant_auditor` role principal → 200 with receipts list.
    * Cursor pagination round-trip.

  `async: false` because the BundleLoader + ProviderRegistry are singletons.
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
  alias Recurse.Providers.Repo
  alias Recurse.Shared.Attestation.{Envelope, OuterContainer, SignedPredicate}
  alias Recurse.Shared.Ulid

  @tenant_id "01HQZN5K7J8M9N0P1Q2R3S4T5V"

  setup do
    :ok = Ecto.Adapters.SQL.Sandbox.checkout(Repo)

    bundle_path = write_bundle("platform_roles.cedar")

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

  describe "GET /v1/audit/receipts — auth" do
    test "returns 401 in F001 envelope when Authorization is missing" do
      conn = build_conn(nil)
      conn = ReceiptsHandler.handle(conn)

      assert conn.status == 401
      # Per-cause code preserves the SIEM-discriminator the F001-nested
      # `details.auth_reason` field used to provide pre-MR-31.
      assert %{"error" => "ERR_UNAUTHORIZED_MISSING"} = JSON.decode!(conn.resp_body)
    end

    test "returns 403 in F001 envelope when caller has `caller` role (no Audit-Plane access)" do
      jwt = mint_jwt(recurse_role: "caller")
      conn = build_conn(jwt)
      conn = ReceiptsHandler.handle(conn)

      assert conn.status == 403
      assert %{"error" => "ERR_FORBIDDEN"} = JSON.decode!(conn.resp_body)
    end
  end

  describe "GET /v1/audit/receipts — happy path" do
    test "tenant_auditor + no receipts → 200 empty page" do
      jwt = mint_jwt(recurse_role: "tenant_auditor")
      conn = build_conn(jwt)
      conn = ReceiptsHandler.handle(conn)

      assert conn.status == 200
      assert %{"receipts" => [], "cursor" => nil} = JSON.decode!(conn.resp_body)
    end

    test "platform_operator + 2 committed receipts → 200 with both rendered" do
      envelope_1 = build_envelope()
      envelope_2 = build_envelope()
      run_id_1 = envelope_1.signed_predicate.run_id
      run_id_2 = envelope_2.signed_predicate.run_id

      {:ok, _} = PostgresMerkleLedger.commit_attestation(envelope_1)
      {:ok, _} = PostgresMerkleLedger.commit_attestation(envelope_2)

      jwt = mint_jwt(recurse_role: "platform_operator")
      conn = build_conn(jwt)
      conn = ReceiptsHandler.handle(conn)

      assert conn.status == 200
      assert %{"receipts" => receipts, "cursor" => nil} = JSON.decode!(conn.resp_body)
      assert length(receipts) == 2

      ids = Enum.map(receipts, & &1["run_id"])
      assert run_id_1 in ids
      assert run_id_2 in ids

      # Each receipt carries the F001 split-envelope shape.
      first = hd(receipts)
      assert %{"signed_predicate" => sp, "outer_container" => oc} = first
      assert is_map(sp) and is_map(oc)
      assert sp["run_id"] == first["run_id"]
      assert oc["verification_level"] == "global_inclusion_verified"
    end

    test "cursor pagination produces non-overlapping pages" do
      envelopes = for _ <- 1..3, do: build_envelope()
      for e <- envelopes, do: {:ok, _} = PostgresMerkleLedger.commit_attestation(e)

      jwt = mint_jwt(recurse_role: "tenant_auditor")

      # Page 1: limit=2.
      page_1_conn =
        jwt
        |> build_conn()
        |> with_query("limit=2")

      page_1_conn = ReceiptsHandler.handle(page_1_conn)
      assert page_1_conn.status == 200
      page_1 = JSON.decode!(page_1_conn.resp_body)
      assert length(page_1["receipts"]) == 2
      assert is_binary(page_1["cursor"])

      # Page 2: same limit, cursor from page 1.
      cursor = page_1["cursor"]

      page_2_conn =
        jwt
        |> build_conn()
        |> with_query("limit=2&cursor=#{cursor}")

      page_2_conn = ReceiptsHandler.handle(page_2_conn)
      assert page_2_conn.status == 200
      page_2 = JSON.decode!(page_2_conn.resp_body)
      assert length(page_2["receipts"]) == 1
      assert page_2["cursor"] == nil

      page_1_ids = MapSet.new(page_1["receipts"], & &1["run_id"])
      page_2_ids = MapSet.new(page_2["receipts"], & &1["run_id"])
      assert MapSet.intersection(page_1_ids, page_2_ids) |> MapSet.size() == 0
    end
  end

  describe "GET /v1/audit/receipts — query-param validation" do
    test "returns 400 on a malformed cursor" do
      jwt = mint_jwt(recurse_role: "tenant_auditor")

      conn =
        jwt
        |> build_conn()
        |> with_query("cursor=not-valid-base64")

      conn = ReceiptsHandler.handle(conn)

      assert conn.status == 400
      assert %{"error" => "ERR_BAD_REQUEST"} = JSON.decode!(conn.resp_body)
    end

    test "returns 400 on an unknown verification_level" do
      jwt = mint_jwt(recurse_role: "tenant_auditor")

      conn =
        jwt
        |> build_conn()
        |> with_query("verification_level=unknown")

      conn = ReceiptsHandler.handle(conn)
      assert conn.status == 400
    end
  end

  describe "GET /v1/audit/receipts — event_kind filter (F16 regression)" do
    # Demo-blocker fix (2026-04-30): a tool_call receipt MUST surface
    # in the dashboard list when the operator clicks the `tool_call`
    # filter pill, even when the tenant has many higher-volume `:ui_query`
    # self-emission receipts that would otherwise saturate the LIMIT-50
    # most-recent page. Adversarial check: revert
    # `apply_in_filter(:event_kind, ...)` in
    # `PostgresMerkleLedger.query_paginated/1` and this test should
    # fail (the `:tool_call` row is pushed off the LIMIT page by the
    # 60 newer `:ui_query` rows).
    test "tool_call receipt surfaces past LIMIT-50 ui_query saturation" do
      tool_envelope = build_envelope(event_kind: :tool_call)
      tool_run_id = tool_envelope.signed_predicate.run_id
      {:ok, _} = PostgresMerkleLedger.commit_attestation(tool_envelope)

      # Saturate the most-recent page with `:ui_query` rows committed
      # AFTER the tool_call row. Without SQL push-down on event_kind
      # the LIMIT-50 page returns these and zero tool_call rows.
      for _ <- 1..60 do
        env = build_envelope(event_kind: :ui_query)
        {:ok, _} = PostgresMerkleLedger.commit_attestation(env)
      end

      jwt = mint_jwt(recurse_role: "platform_operator")

      conn =
        jwt
        |> build_conn()
        |> with_query("event_kind=tool_call&limit=50")

      conn = ReceiptsHandler.handle(conn)

      assert conn.status == 200
      assert %{"receipts" => receipts} = JSON.decode!(conn.resp_body)

      ids = Enum.map(receipts, & &1["run_id"])

      assert tool_run_id in ids,
             "tool_call receipt must appear in dashboard list filtered by event_kind=tool_call"

      assert Enum.all?(receipts, fn r -> r["signed_predicate"]["event_kind"] == "tool_call" end),
             "every returned row must match the event_kind filter"
    end

    test "comma-separated event_kind=llm_call,tool_call returns the union" do
      llm_envelope = build_envelope(event_kind: :llm_call)
      tool_envelope = build_envelope(event_kind: :tool_call)
      ui_envelope = build_envelope(event_kind: :ui_query)

      llm_run_id = llm_envelope.signed_predicate.run_id
      tool_run_id = tool_envelope.signed_predicate.run_id
      ui_run_id = ui_envelope.signed_predicate.run_id

      {:ok, _} = PostgresMerkleLedger.commit_attestation(llm_envelope)
      {:ok, _} = PostgresMerkleLedger.commit_attestation(tool_envelope)
      {:ok, _} = PostgresMerkleLedger.commit_attestation(ui_envelope)

      jwt = mint_jwt(recurse_role: "platform_operator")

      conn =
        jwt
        |> build_conn()
        |> with_query("event_kind=llm_call,tool_call")

      conn = ReceiptsHandler.handle(conn)

      assert conn.status == 200
      assert %{"receipts" => receipts} = JSON.decode!(conn.resp_body)

      ids = MapSet.new(receipts, & &1["run_id"])
      assert llm_run_id in ids
      assert tool_run_id in ids
      refute ui_run_id in ids
    end
  end

  describe "GET /v1/audit/receipts?facets=true — facet counts (issue #44 regression)" do
    # Issue #44 (2026-04-30): the dashboard's left-sidebar Event Kind picker
    # rendered counts derived from the paginated page. When >LIMIT receipts
    # of one kind committed AFTER a single tool_call row, that tool_call was
    # pushed off the LIMIT page and the picker said "tool_call: 0" — the
    # operator could not see / could not click that filter chip.
    #
    # Adversarial check: revert `compute_facets/1` in `receipts_handler.ex`
    # back to the in-memory `Enum.frequencies_by/2` over `rows` and this
    # test fails (the tool_call count drops to 0 when the paginated page
    # is saturated by ui_query rows committed after).
    test "facet counts come from full filtered set, NOT just the paginated page" do
      tool_envelope = build_envelope(event_kind: :tool_call)
      {:ok, _} = PostgresMerkleLedger.commit_attestation(tool_envelope)

      # Saturate the most-recent LIMIT page with `:ui_query` rows committed
      # AFTER the tool_call row. Page-scoped facets miss the tool_call.
      for _ <- 1..60 do
        env = build_envelope(event_kind: :ui_query)
        {:ok, _} = PostgresMerkleLedger.commit_attestation(env)
      end

      jwt = mint_jwt(recurse_role: "platform_operator")

      conn =
        jwt
        |> build_conn()
        |> with_query("facets=true&limit=50")

      conn = ReceiptsHandler.handle(conn)
      assert conn.status == 200

      body = JSON.decode!(conn.resp_body)
      assert is_map(body["facets"])

      ek_facets = body["facets"]["event_kind"]
      assert is_map(ek_facets)
      # tool_call is OFF the paginated page (LIMIT 50, 60 newer ui_query
      # rows after) but MUST appear in the facets so the picker chip is
      # clickable.
      assert ek_facets["tool_call"] == 1,
             "tool_call must show count=1 in facets even when off the paginated page"

      # Sanity: the saturating ui_query rows are also in the facet map.
      assert ek_facets["ui_query"] >= 60
    end

    test "facet counts respect the same WHERE filters as the paginated query" do
      # Two tool_call rows + one llm_call row.
      tool1 = build_envelope(event_kind: :tool_call)
      tool2 = build_envelope(event_kind: :tool_call)
      llm = build_envelope(event_kind: :llm_call)

      {:ok, _} = PostgresMerkleLedger.commit_attestation(tool1)
      {:ok, _} = PostgresMerkleLedger.commit_attestation(tool2)
      {:ok, _} = PostgresMerkleLedger.commit_attestation(llm)

      jwt = mint_jwt(recurse_role: "platform_operator")

      # When the user has filtered to event_kind=tool_call, the facet
      # counts should ONLY count the tool_call rows (not the llm_call
      # row that's been excluded by the SQL filter).
      conn =
        jwt
        |> build_conn()
        |> with_query("facets=true&event_kind=tool_call")

      conn = ReceiptsHandler.handle(conn)
      assert conn.status == 200

      body = JSON.decode!(conn.resp_body)
      ek_facets = body["facets"]["event_kind"]
      assert ek_facets["tool_call"] == 2
      # llm_call has been filtered out entirely; it should be ABSENT
      # (not zero) from the facet map. The SPA's picker is responsible
      # for rendering the canonical 29-kind list with absent kinds at
      # count 0 so the user can flip the filter.
      refute Map.has_key?(ek_facets, "llm_call")
    end

    test "facet counts include kinds with zero rows as absent (SPA fills the canonical enum)" do
      # No rows committed; facet map should be empty for every axis.
      jwt = mint_jwt(recurse_role: "platform_operator")

      conn =
        jwt
        |> build_conn()
        |> with_query("facets=true")

      conn = ReceiptsHandler.handle(conn)
      assert conn.status == 200

      body = JSON.decode!(conn.resp_body)

      assert body["facets"]["event_kind"] == %{}
      assert body["facets"]["policy_decision"] == %{}
      assert body["facets"]["verification_level"] == %{}
    end
  end

  # -- Helpers --------------------------------------------------------------

  defp build_conn(jwt) do
    conn = Plug.Test.conn(:get, "/v1/audit/receipts")

    case jwt do
      nil -> conn
      token -> Plug.Conn.put_req_header(conn, "authorization", "Bearer " <> token)
    end
  end

  defp with_query(conn, query_string) do
    %{conn | query_string: query_string}
  end

  defp mint_jwt(opts) do
    JwtTestHelper.mint_test_jwt(
      recurse_role: Keyword.fetch!(opts, :recurse_role),
      audience: "recurse-gateway-test",
      issuer: "https://test-broker.example.invalid"
    )
  end

  defp write_bundle(_name) do
    source =
      Path.join([
        Application.app_dir(:recurse_gateway, "priv"),
        "reference_policies",
        "platform_roles.cedar"
      ])
      |> File.read!()

    path = Path.join(System.tmp_dir!(), "receipts_bundle_#{System.unique_integer()}.cedar")
    File.write!(path, source)
    on_exit(fn -> File.rm(path) end)
    path
  end

  defp build_envelope(opts \\ []) do
    event_kind = Keyword.get(opts, :event_kind, :llm_call)
    tenant_id = @tenant_id
    session_id = Ecto.UUID.generate()
    run_id = Ecto.UUID.generate()

    Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Tenant.changeset(
      %Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Tenant{},
      %{
        tenant_id: tenant_id,
        display_name: "test",
        tier: :standalone_gateway,
        created_at: DateTime.utc_now()
      }
    )
    |> Repo.insert(on_conflict: :nothing, conflict_target: :tenant_id)

    sp = %SignedPredicate{
      envelope_version: "1.0",
      run_id: run_id,
      step_id: run_id,
      turn_id: run_id,
      session_id: session_id,
      session_chain_position: 0,
      event_kind: event_kind,
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
      signer: "arn:aws:kms:us-east-1:123:key/test"
    }

    oc = %OuterContainer{
      verification_level: :signed,
      tier_completeness_advisory: :partial,
      session_chain_epoch: 0,
      session_state: :active
    }

    Envelope.new(sp, oc, %{"signatures" => [%{"sig" => Base.encode64(<<0::size(8 * 72)>>)}]})
  end
end
