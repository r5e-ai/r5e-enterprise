defmodule Recurse.Gateway.Admin.SessionTimelineHandlerContractTest do
  @moduledoc """
  Contract tests for `Recurse.Gateway.Admin.SessionTimelineHandler`
  (F004 T058) per `contracts/audit_api_extensions.md` §"Session timeline".

  Covers:

    * `GET /v1/audit/sessions/{session_id}` happy path with the
      `tenant_auditor` role.
    * Cursor pagination per D8 — server-signed opaque cursor; tampered
      cursors return 400 with the F001 envelope.
    * 401 when no Authorization is present.
    * 403 cross-tenant + attested `:policy_denied` receipt per
      `audit_api_extensions.md` §"Cross-cutting rules".
    * 404 session-not-found.

  `async: false` because the BundleLoader + ProviderRegistry are
  process-global singletons.
  """

  use ExUnit.Case, async: false

  setup_all do
    Recurse.Gateway.Test.KernelFixture.boot()
  end

  alias Recurse.Gateway.Admin.BrowserAuth.UiReceipts
  alias Recurse.Gateway.Admin.Cursor
  alias Recurse.Gateway.Admin.SessionTimelineHandler
  alias Recurse.Gateway.Policy.BundleLoader
  alias Recurse.Gateway.ProviderRegistry
  alias Recurse.Gateway.Test.JwtTestHelper
  alias Recurse.Providers.Impls.PostgresMerkleLedger
  alias Recurse.Providers.Repo
  alias Recurse.Shared.Attestation.{Envelope, OuterContainer, SignedPredicate}
  alias Recurse.Shared.Ulid

  @tenant_id "01HQZN5K7J8M9N0P1Q2R3S4T5V"
  @other_tenant "01OTHER000000000000000000"
  @cursor_key :crypto.strong_rand_bytes(64)

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

    previous_browser_session = Application.get_env(:recurse_gateway, :browser_session)

    Application.put_env(:recurse_gateway, :browser_session,
      cookie_name: "r5e_session",
      secret_key_base: @cursor_key,
      secure_cookie?: false,
      absent_cookie_redirect: :always_401
    )

    on_exit(fn ->
      ProviderRegistry.uninstall()

      if previous_validator_opts do
        Application.put_env(:recurse_gateway, :jwt_validator_opts, previous_validator_opts)
      else
        Application.delete_env(:recurse_gateway, :jwt_validator_opts)
      end

      if previous_browser_session do
        Application.put_env(:recurse_gateway, :browser_session, previous_browser_session)
      else
        Application.delete_env(:recurse_gateway, :browser_session)
      end
    end)

    :ok
  end

  describe "GET /v1/audit/sessions/{session_id} — auth gate" do
    test "401 when Authorization is missing" do
      session_id = Ecto.UUID.generate()
      conn = build_conn(nil, session_id)
      conn = SessionTimelineHandler.handle(conn)

      assert conn.status == 401
      # Per-cause code (MR !31) — `:missing_authorization` from the
      # JWT validator surfaces as `ERR_UNAUTHORIZED_MISSING`.
      assert %{"error" => "ERR_UNAUTHORIZED_MISSING"} = JSON.decode!(conn.resp_body)
    end

    test "403 when caller has the data-plane `caller` role (no DashboardQuery permit)" do
      session_id = Ecto.UUID.generate()
      jwt = mint_jwt(recurse_role: "caller")
      conn = build_conn(jwt, session_id)
      conn = SessionTimelineHandler.handle(conn)

      assert conn.status == 403
      assert %{"error" => "ERR_FORBIDDEN"} = JSON.decode!(conn.resp_body)
    end
  end

  describe "GET /v1/audit/sessions/{session_id} — happy path" do
    test "tenant_auditor + matching tenant returns 200 with chronological receipts" do
      session_id = Ecto.UUID.generate()

      _ = build_envelope(session_id, @tenant_id) |> commit!()
      _ = build_envelope(session_id, @tenant_id) |> commit!()
      _ = build_envelope(session_id, @tenant_id) |> commit!()

      jwt = mint_jwt(recurse_role: "tenant_auditor")
      conn = build_conn(jwt, session_id)
      conn = SessionTimelineHandler.handle(conn)

      assert conn.status == 200
      body = JSON.decode!(conn.resp_body)
      assert body["session_id"] == session_id
      assert body["tenant_id"] == @tenant_id
      assert is_list(body["receipts"])
      assert length(body["receipts"]) == 3
      assert body["epoch_count"] == 1
      assert is_binary(body["started_at"])
      assert is_binary(body["last_seen_at"])
    end

    test "platform_operator can read same surface" do
      session_id = Ecto.UUID.generate()
      _ = build_envelope(session_id, @tenant_id) |> commit!()

      jwt = mint_jwt(recurse_role: "platform_operator")
      conn = build_conn(jwt, session_id)
      conn = SessionTimelineHandler.handle(conn)

      assert conn.status == 200
    end
  end

  describe "GET /v1/audit/sessions/{session_id} — pagination" do
    test "valid signed cursor is decoded; tampered cursor returns 400" do
      session_id = Ecto.UUID.generate()
      for _ <- 1..3, do: build_envelope(session_id, @tenant_id) |> commit!()

      # Mint a valid cursor via the same key as the handler.
      cursor =
        Cursor.encode({System.system_time(:microsecond), Ecto.UUID.generate()},
          key: @cursor_key
        )

      jwt = mint_jwt(recurse_role: "tenant_auditor")

      conn =
        jwt
        |> build_conn(session_id)
        |> with_query("cursor=#{URI.encode_www_form(cursor)}")

      conn = SessionTimelineHandler.handle(conn)
      assert conn.status == 200

      # Tampered cursor → 400 ERR_BAD_REQUEST.
      tampered = String.replace(cursor, ".", ".0")

      conn =
        jwt
        |> build_conn(session_id)
        |> with_query("cursor=#{URI.encode_www_form(tampered)}")

      conn = SessionTimelineHandler.handle(conn)
      assert conn.status == 400
      assert %{"error" => "ERR_BAD_REQUEST"} = JSON.decode!(conn.resp_body)
    end
  end

  describe "GET /v1/audit/sessions/{session_id} — cross-tenant + 404" do
    test "session belongs to different tenant → 403 + attested :policy_denied" do
      foreign_session_id = Ecto.UUID.generate()
      _ = build_envelope(foreign_session_id, @other_tenant) |> commit!()

      jwt = mint_jwt(recurse_role: "tenant_auditor")
      conn = build_conn(jwt, foreign_session_id)

      attach_ui_receipts_telemetry()
      conn = SessionTimelineHandler.handle(conn)

      assert conn.status == 403
      # The :ui_session policy_denied event was attested (telemetry emitted).
      assert_receive {:ui_receipt_emitted, %{event_kind: :ui_session, event: "policy_denied"}},
                     1_000
    end

    test "session not found → 404" do
      missing = Ecto.UUID.generate()
      jwt = mint_jwt(recurse_role: "tenant_auditor")
      conn = build_conn(jwt, missing)
      conn = SessionTimelineHandler.handle(conn)

      assert conn.status == 404
      assert %{"error" => "ERR_NOT_FOUND"} = JSON.decode!(conn.resp_body)
    end
  end

  # ----- helpers -----

  defp build_conn(jwt, session_id) do
    conn = Plug.Test.conn(:get, "/v1/audit/sessions/#{session_id}")
    conn = %{conn | path_params: %{"session_id" => session_id}}

    case jwt do
      nil -> conn
      token -> Plug.Conn.put_req_header(conn, "authorization", "Bearer " <> token)
    end
  end

  defp with_query(conn, query_string), do: %{conn | query_string: query_string}

  defp mint_jwt(opts) do
    JwtTestHelper.mint_test_jwt(
      recurse_role: Keyword.fetch!(opts, :recurse_role),
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

    path =
      Path.join(System.tmp_dir!(), "session_timeline_bundle_#{System.unique_integer()}.cedar")

    File.write!(path, source)
    on_exit(fn -> File.rm(path) end)
    path
  end

  defp build_envelope(session_id, tenant_id) do
    run_id = Ecto.UUID.generate()

    Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Tenant.changeset(
      %Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Tenant{},
      %{
        tenant_id: tenant_id,
        display_name: tenant_id,
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
      event_kind: :llm_call,
      timestamp: DateTime.utc_now() |> DateTime.to_iso8601(),
      tenant_id: tenant_id,
      machine_identity: %{
        observed_jwt_subject: "alice@corp",
        observed_jwt_issuer: "https://issuer.example.com"
      },
      principal: %{"kind" => "obo_human", "subject" => "alice@corp"},
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

  # F002's `commit_attestation/2` enforces 1-run-1-session (it always
  # inserts a new session row). For F004 session-timeline tests we need
  # multiple receipts sharing one session_id. This helper bypasses the
  # F002 commit pipeline by inserting the session once + each
  # attestation row directly via Ecto. Identical schema, just skips the
  # serializable Multi (which we don't need for fixture purposes) and
  # the global-tree append (irrelevant to the timeline read-path).
  defp commit!(%Envelope{signed_predicate: sp}) do
    now = DateTime.utc_now()

    # Idempotent session insert.
    Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Session.changeset(
      %Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Session{
        session_id: sp.session_id
      },
      %{
        tenant_id: sp.tenant_id,
        session_scope: :discovery_session,
        state: :active,
        session_start: now,
        principal_kind: :obo_human,
        principal_canonical: Jason.encode!(sp.principal)
      }
    )
    |> Repo.insert(on_conflict: :nothing, conflict_target: :session_id)

    # Insert the attestation row directly.
    Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Attestation.changeset(
      %Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Attestation{
        run_id: sp.run_id
      },
      %{
        session_id: sp.session_id,
        turn_id: sp.turn_id || sp.run_id,
        event_kind: sp.event_kind,
        machine_identity: stringify(sp.machine_identity),
        principal: sp.principal,
        tenant_id: sp.tenant_id,
        policy_canonical_hash: sp.policy_canonical_hash,
        payload_hash: sp.payload_hash,
        payload_uri: sp.payload_uri,
        correlation_id: sp.correlation_id,
        signer_kms_key_id: sp.signer,
        signer_key_version: "v1",
        timestamp: parse_ts(sp.timestamp) || now,
        signed_predicate_bytes: <<0>>,
        dsse_signature: <<0::size(8 * 72)>>,
        verification_level: :global_inclusion_verified,
        tier_completeness_advisory: :partial,
        session_chain_epoch: 0,
        policy_decision: :allow,
        outcome: :success
      }
    )
    |> Repo.insert!()
  end

  defp stringify(%{} = map) do
    Map.new(map, fn
      {k, v} when is_atom(k) -> {Atom.to_string(k), v}
      other -> other
    end)
  end

  defp parse_ts(nil), do: nil
  defp parse_ts(%DateTime{} = dt), do: dt

  defp parse_ts(bin) when is_binary(bin) do
    case DateTime.from_iso8601(bin) do
      {:ok, dt, _} -> dt
      _ -> nil
    end
  end

  # Telemetry helper: forward UiReceipts emissions to the test process so
  # we can assert receipt-emission discriminators (event_kind + event).
  defp attach_ui_receipts_telemetry do
    parent = self()
    handler_id = "ui-receipts-#{System.unique_integer()}"

    :telemetry.attach(
      handler_id,
      UiReceipts.telemetry_event(),
      fn _event, _measurements, metadata, _config ->
        send(parent, {:ui_receipt_emitted, metadata})
      end,
      nil
    )

    on_exit(fn -> :telemetry.detach(handler_id) end)
    :ok
  end
end
