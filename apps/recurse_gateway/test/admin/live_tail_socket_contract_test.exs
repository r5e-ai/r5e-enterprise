defmodule Recurse.Gateway.Admin.LiveTailSocketContractTest do
  @moduledoc """
  Contract tests for `Recurse.Gateway.Admin.LiveTailSocket` (F004 T059)
  per `contracts/live_tail_transport.md`.

  We exercise the WebSock callbacks DIRECTLY (init/1, handle_in/2,
  handle_info/2, terminate/2) rather than spinning up a real TCP socket
  + Bandit upgrade. This keeps the contract tests fast + deterministic
  while still asserting the wire-protocol invariants:

    * `attestation` frame shape on PubSub delivery
    * `set_filter` control frame round-trip → `filter_acknowledged` reply
    * `backfill_summary` truncation at 1,000-receipt bound
    * Heartbeat timeout (90s client-idle) → close 4408
    * Backpressure: 100-pending-frame threshold, 30s warning, 60s close

  The upgrade-time gate (cookie + Cedar deny → 403 + :policy_denied) is
  exercised via `LiveTailSocket.upgrade/1` against a Plug.Test conn, which
  hits the F002 `Authz.gate/4` path identically to the production flow
  (BrowserSessionPlug is not in scope here — the upgrade function takes
  a Plug.Conn with the Authorization header already lifted).

  `async: false` because BundleLoader + ProviderRegistry are singletons.
  """

  use ExUnit.Case, async: false

  setup_all do
    Recurse.Gateway.Test.KernelFixture.boot()
  end

  alias Recurse.Gateway.Admin.BrowserAuth.UiReceipts
  alias Recurse.Gateway.Admin.LiveTailSocket
  alias Recurse.Gateway.Policy.BundleLoader
  alias Recurse.Gateway.ProviderRegistry
  alias Recurse.Gateway.Test.JwtTestHelper
  alias Recurse.Providers.Impls.PostgresMerkleLedger
  alias Recurse.Providers.Repo
  alias Recurse.Shared.Ulid

  @tenant_id "01HQZN5K7J8M9N0P1Q2R3S4T5V"
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

  describe "upgrade gate" do
    test "caller role → 403 + emitted :policy_denied receipt" do
      jwt = mint_jwt(recurse_role: "caller")

      conn =
        Plug.Test.conn(:get, "/admin/live-tail")
        |> Plug.Conn.put_req_header("authorization", "Bearer " <> jwt)

      attach_ui_receipts_telemetry()
      conn = LiveTailSocket.upgrade(conn)

      assert conn.status == 403

      assert_receive {:ui_receipt_emitted, %{event_kind: :ui_session, event: "policy_denied"}},
                     1_000
    end
  end

  describe "WebSock callbacks — connection lifecycle" do
    test "init/1 subscribes to PubSub + emits :ui_session live_tail_open" do
      attach_ui_receipts_telemetry()

      state = build_state(filter: %{})
      assert {:ok, ^state} = LiveTailSocket.init(state)

      assert_receive {:ui_receipt_emitted, %{event_kind: :ui_session, event: "live_tail_open"}},
                     1_000
    end

    test "terminate/2 emits :ui_session live_tail_close" do
      attach_ui_receipts_telemetry()
      state = build_state(filter: %{})
      LiveTailSocket.terminate(:remote, state)

      assert_receive {:ui_receipt_emitted, %{event_kind: :ui_session, event: "live_tail_close"}},
                     1_000
    end
  end

  describe "WebSock callbacks — set_filter round-trip" do
    test "valid set_filter returns filter_acknowledged" do
      state = build_state(filter: %{})

      payload =
        JSON.encode!(%{"type" => "set_filter", "filter" => %{"policy_decision" => "deny"}})

      assert {:push, [{:text, ack}], new_state} =
               LiveTailSocket.handle_in({payload, opcode: :text}, state)

      decoded = JSON.decode!(ack)
      assert decoded["type"] == "filter_acknowledged"
      assert decoded["filter"] == %{"policy_decision" => "deny"}
      assert new_state.filter == %{"policy_decision" => "deny"}
    end

    test "unknown filter key → error frame, previous filter retained" do
      state = build_state(filter: %{"event_kind" => ["ui_query"]})
      payload = JSON.encode!(%{"type" => "set_filter", "filter" => %{"banana" => true}})

      assert {:push, [{:text, frame}], new_state} =
               LiveTailSocket.handle_in({payload, opcode: :text}, state)

      decoded = JSON.decode!(frame)
      assert decoded["type"] == "error"
      assert decoded["code"] == "unknown_filter_key"
      # previous filter retained.
      assert new_state.filter == %{"event_kind" => ["ui_query"]}
    end

    test "malformed filter value (event_kind not list) → error frame" do
      state = build_state(filter: %{})
      payload = JSON.encode!(%{"type" => "set_filter", "filter" => %{"event_kind" => "ui_query"}})

      assert {:push, [{:text, frame}], _state} =
               LiveTailSocket.handle_in({payload, opcode: :text}, state)

      decoded = JSON.decode!(frame)
      assert decoded["type"] == "error"
      assert decoded["code"] == "invalid_filter"
    end
  end

  describe "WebSock callbacks — attestation frame" do
    test "PubSub delivery in same tenant + matching filter → attestation frame" do
      state = build_state(filter: %{"policy_decision" => "any"})

      attestation = %{
        run_id: Ecto.UUID.generate(),
        tenant_id: @tenant_id,
        session_id: Ecto.UUID.generate(),
        event_kind: :ui_query,
        policy_decision: :allow,
        principal: %{"subject" => "alice@corp"},
        timestamp: DateTime.utc_now(),
        outcome: :success,
        verification_level: :global_inclusion_verified
      }

      assert {:push, [{:text, frame}], _new_state} =
               LiveTailSocket.handle_info(
                 {:first_committed, attestation.run_id, %{attestation: attestation}},
                 state
               )

      decoded = JSON.decode!(frame)
      assert decoded["type"] == "attestation"
      assert decoded["run_id"] == attestation.run_id
      assert decoded["event_kind"] == "ui_query"
      assert decoded["policy_decision"] == "allow"
      assert decoded["tenant_id"] == @tenant_id
    end

    test "cross-tenant attestation is silently dropped" do
      state = build_state(filter: %{})

      attestation = %{
        run_id: Ecto.UUID.generate(),
        tenant_id: "01OTHER000000000000000000",
        session_id: Ecto.UUID.generate(),
        event_kind: :ui_query,
        policy_decision: :allow,
        principal: %{"subject" => "mallory@evil"},
        timestamp: DateTime.utc_now()
      }

      assert {:ok, _state} =
               LiveTailSocket.handle_info(
                 {:first_committed, attestation.run_id, %{attestation: attestation}},
                 state
               )
    end

    test "filter mismatch silently drops" do
      state = build_state(filter: %{"policy_decision" => "deny"})

      attestation = %{
        run_id: Ecto.UUID.generate(),
        tenant_id: @tenant_id,
        session_id: Ecto.UUID.generate(),
        event_kind: :ui_query,
        policy_decision: :allow,
        principal: %{"subject" => "alice@corp"}
      }

      assert {:ok, _state} =
               LiveTailSocket.handle_info(
                 {:first_committed, attestation.run_id, %{attestation: attestation}},
                 state
               )
    end
  end

  describe "WebSock callbacks — backfill (T063 §Reconnection + bounded backfill)" do
    @tag :slow
    test "backfill capped at 1,000 receipts → backfill_summary{truncated: true}" do
      cursor_run_id = Ecto.UUID.generate()
      now = DateTime.utc_now()

      # Insert 1,001 receipts AFTER the cursor's committed_at. Each one
      # gets its own session_id (the F002 1-run-1-session invariant);
      # the LiveTailSocket backfill query orders by `(timestamp ASC,
      # run_id ASC)` for the tenant globally — session_id isn't a
      # filter at the backfill stage.
      _ = direct_insert_receipt(cursor_run_id, @tenant_id, now)

      for i <- 1..1_001 do
        direct_insert_receipt(
          Ecto.UUID.generate(),
          @tenant_id,
          DateTime.add(now, i, :microsecond)
        )
      end

      state = build_state(filter: %{}, last_seen_run_id: cursor_run_id)
      assert {:push, frames, _new_state} = LiveTailSocket.init(state)

      # Last frame is the summary; everything before it is `attestation`.
      summary_text = frames |> List.last() |> elem(1)
      summary = JSON.decode!(summary_text)
      assert summary["type"] == "backfill_summary"
      assert summary["truncated"] == true
      assert summary["delivered_count"] == 1_000

      attestation_count =
        frames
        |> Enum.count(fn {:text, raw} -> JSON.decode!(raw)["type"] == "attestation" end)

      assert attestation_count == 1_000
    end
  end

  describe "WebSock callbacks — heartbeat (T063 §Heartbeat)" do
    test "missed heartbeats (client idle 91s) → close 4408" do
      # Build a state whose last_client_frame_at is 91s in the past
      # (monotonic milliseconds). The heartbeat tick must close 4408.
      stale_state =
        build_state(filter: %{})
        |> Map.put(:last_client_frame_at, System.monotonic_time(:millisecond) - 91_000)

      assert {:stop, :normal, {4408, _msg}, _state} =
               LiveTailSocket.handle_info(:heartbeat_tick, stale_state)
    end

    test "active client (recent ping) → no close" do
      fresh_state = build_state(filter: %{})
      assert {:ok, _} = LiveTailSocket.handle_info(:heartbeat_tick, fresh_state)
    end
  end

  describe "WebSock callbacks — backpressure (T069 §Backpressure)" do
    test "pending_frames at threshold AND stalled 30s+ → backpressure_warning" do
      state =
        build_state(filter: %{})
        |> Map.put(:pending_frames, 100)
        |> Map.put(:stalled_at, System.monotonic_time(:millisecond) - 31_000)

      assert {:push, frames, _new_state} = LiveTailSocket.handle_info(:heartbeat_tick, state)

      assert Enum.any?(frames, fn {:text, raw} ->
               JSON.decode!(raw)["code"] == "backpressure"
             end)
    end

    test "stalled 60s+ → close 4408" do
      state =
        build_state(filter: %{})
        |> Map.put(:pending_frames, 100)
        |> Map.put(:stalled_at, System.monotonic_time(:millisecond) - 61_000)

      assert {:stop, :normal, {4408, _msg}, _} =
               LiveTailSocket.handle_info(:heartbeat_tick, state)
    end

    test "pending_frames at threshold drops new attestation, marks stall" do
      state =
        build_state(filter: %{})
        |> Map.put(:pending_frames, 100)

      attestation = %{
        run_id: Ecto.UUID.generate(),
        tenant_id: @tenant_id,
        session_id: Ecto.UUID.generate(),
        event_kind: :ui_query,
        policy_decision: :allow,
        principal: %{"subject" => "alice@corp"}
      }

      assert {:ok, new_state} =
               LiveTailSocket.handle_info(
                 {:first_committed, attestation.run_id, %{attestation: attestation}},
                 state
               )

      assert is_integer(new_state.stalled_at)
    end
  end

  # ----- helpers -----

  defp build_state(opts) do
    filter = Keyword.get(opts, :filter, %{})

    %{
      principal_subject: "alice@corp",
      tenant_id: @tenant_id,
      browser_session_id: nil,
      correlation_id: Ulid.generate(),
      filter: filter,
      filter_compiled: compile_local(filter),
      last_seen_run_id: Keyword.get(opts, :last_seen_run_id, nil),
      last_seen_committed_at: nil,
      last_client_frame_at: System.monotonic_time(:millisecond),
      pending_frames: 0,
      stalled_at: nil
    }
  end

  # Tiny in-test filter compiler mirroring the production one — keeps the
  # contract test independent of the production module's private helpers.
  defp compile_local(filter) do
    fn att ->
      pass_decision?(att, Map.get(filter, "policy_decision"))
    end
  end

  defp pass_decision?(_att, nil), do: true
  defp pass_decision?(_att, "any"), do: true

  defp pass_decision?(att, val) when val in ["allow", "deny"] do
    case Map.get(att, :policy_decision) do
      atom when is_atom(atom) -> Atom.to_string(atom) == val
      _ -> false
    end
  end

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

    path = Path.join(System.tmp_dir!(), "live_tail_bundle_#{System.unique_integer()}.cedar")
    File.write!(path, source)
    on_exit(fn -> File.rm(path) end)
    path
  end

  # Direct fixture insert — bypasses F002's commit_attestation pipeline
  # (which enforces 1-run-1-session via insert-not-upsert) so we can
  # bulk-seed the backfill window.
  defp direct_insert_receipt(run_id, tenant_id, ts) do
    Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Tenant.changeset(
      %Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Tenant{},
      %{
        tenant_id: tenant_id,
        display_name: tenant_id,
        tier: :standalone_gateway,
        created_at: ts
      }
    )
    |> Repo.insert(on_conflict: :nothing, conflict_target: :tenant_id)

    session_id = Ecto.UUID.generate()

    Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Session.changeset(
      %Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Session{
        session_id: session_id
      },
      %{
        tenant_id: tenant_id,
        session_scope: :discovery_session,
        state: :active,
        session_start: ts,
        principal_kind: :obo_human,
        principal_canonical: Jason.encode!(%{"kind" => "obo_human", "subject" => "alice@corp"})
      }
    )
    |> Repo.insert!()

    Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Attestation.changeset(
      %Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Attestation{run_id: run_id},
      %{
        session_id: session_id,
        turn_id: run_id,
        event_kind: :llm_call,
        machine_identity: %{
          "observed_jwt_subject" => "alice@corp",
          "observed_jwt_issuer" => "https://issuer.example.com"
        },
        principal: %{"kind" => "obo_human", "subject" => "alice@corp"},
        tenant_id: tenant_id,
        policy_canonical_hash: :crypto.hash(:sha256, "policy-" <> run_id),
        payload_hash: :crypto.hash(:sha256, "payload-" <> run_id),
        payload_uri: "s3://bucket/tenants/#{tenant_id}/runs/#{run_id}.json",
        correlation_id: Ulid.generate(),
        signer_kms_key_id: "arn:aws:kms:us-east-1:123:key/test",
        signer_key_version: "v1",
        timestamp: ts,
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
