defmodule Recurse.Gateway.Admin.CedarBundleActivateHandlerTest do
  @moduledoc """
  Contract tests for `POST /v1/admin/cedar-bundle/activate` (MR !119,
  Spec A).

  Asserts:

    * 200 happy path: ref + digest → activate → JSON envelope.
    * 401/403 path: non-platform_operator (`tenant_auditor`) is denied
      by the Cedar bundle.
    * 400 on missing ref / wrong type.
    * 502 on registry / cosign / canonical-hash failure (mocked through
      a fake OciBundleManager — we run a separate GenServer name and
      drive its FakeProvider through the same ETS stash the
      OciBundleManager test uses).

  The OciBundleManager has its own dedicated module test for atomic-swap
  + persistent_term semantics; this test focuses on the HTTP surface.

  `async: false` because the handler reads `OciBundleManager` by its
  registered name, ProviderRegistry is a global singleton, and the
  Cedar BundleLoader populates a process-global `:persistent_term` slot.
  """

  use ExUnit.Case, async: false

  setup_all do
    Recurse.Gateway.Test.KernelFixture.boot()
  end

  alias Recurse.Gateway.Admin.BrowserAuth.UiReceipts
  alias Recurse.Gateway.Admin.CedarBundleActivateHandler
  alias Recurse.Gateway.Policy.BundleLoader
  alias Recurse.Gateway.Policy.OciBundleManager
  alias Recurse.Gateway.ProviderRegistry
  alias Recurse.Gateway.Test.JwtTestHelper
  alias Recurse.Providers.Impls.PostgresMerkleLedger
  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Tenant
  alias Recurse.Providers.Repo

  @tenant_id "01HQZN5K7J8M9N0P1Q2R3S4T5V"

  # Permissive Cedar policy that matches the F004 role-allowlist shape:
  # platform_operator can do CedarBundleActivate; tenant_auditor cannot.
  @cedar_skeleton """
  permit (
    principal,
    action == Recurse::Action::"CedarBundleActivate",
    resource
  )
  when {
    principal.recurse_role == "platform_operator"
  };
  """

  defmodule FakeOciProvider do
    @behaviour Recurse.Providers.PolicyProvider

    @impl true
    def init(config) do
      case :ets.lookup(:cedar_activate_test_stash, :init_response) do
        [{:init_response, {:ok, state}}] -> {:ok, state}
        [{:init_response, {:error, reason}}] -> {:error, reason}
        [] -> {:ok, %{ref: Map.get(config, :ref), bundle: default_bundle(config)}}
      end
    end

    @impl true
    def fetch_active_bundle(%{bundle: bundle}), do: {:ok, bundle}
    def fetch_active_bundle(_), do: {:error, :no_active_bundle}

    @impl true
    def fetch_bundle(_state, _digest), do: {:error, :not_found}

    @impl true
    def subscribe_supersede_notifications(_state, _callback),
      do: {:ok, "policy_provider:supersede"}

    @impl true
    def simulate(_state, _candidate, _mock), do: {:error, :not_applicable}

    @impl true
    def blast_radius(_state, _candidate, _w, _ctx), do: {:error, :not_applicable}

    @impl true
    def propose_from_event(_state, _e), do: {:error, :not_applicable}

    @impl true
    def capabilities(_state), do: [:test]

    @impl true
    def healthcheck(_state), do: :ok

    @impl true
    def terminate(_state, _reason), do: :ok

    defp default_bundle(config) do
      ref = Map.get(config, :ref, "test-ref")

      %{
        digest: :crypto.hash(:sha256, "bytes-#{ref}"),
        bytes: "permit(principal, action, resource);\n",
        canonical_hash: :crypto.hash(:sha256, "canon-#{ref}"),
        cedar_version: "4.9.1",
        loaded_at: DateTime.utc_now(),
        source: :oci,
        source_ref: "test/cedar:#{ref}",
        manifest: %{"version" => ref}
      }
    end
  end

  setup do
    if :ets.info(:cedar_activate_test_stash) == :undefined do
      :ets.new(:cedar_activate_test_stash, [:set, :public, :named_table])
    end

    :ets.delete_all_objects(:cedar_activate_test_stash)

    :ok = Ecto.Adapters.SQL.Sandbox.checkout(Repo)
    Ecto.Adapters.SQL.Sandbox.mode(Repo, {:shared, self()})

    Repo.insert!(
      Tenant.changeset(%Tenant{}, %{
        tenant_id: @tenant_id,
        display_name: "Cedar Activate Test Tenant",
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
      signer: "observed://gateway/cedar-activate-test"
    })

    previous_validator_opts = Application.get_env(:recurse_gateway, :jwt_validator_opts)

    Application.put_env(:recurse_gateway, :jwt_validator_opts,
      audience: "recurse-gateway-test",
      issuer: "https://test-broker.example.invalid",
      known_kids: [
        {"test-key-rs256", JwtTestHelper.public_jwk(:rs256)}
      ]
    )

    # Start a test-scoped OciBundleManager registered under the canonical
    # name so the handler resolves it. Use a test-scoped persistent_term
    # key to avoid contaminating the shared canonical key across the
    # suite.
    pt_key = {:cedar_activate_test, make_ref()}
    on_exit(fn -> :persistent_term.erase(pt_key) end)

    :ets.insert(
      :cedar_activate_test_stash,
      {:init_response,
       {:ok,
        %{
          ref: "1.0.0-orig",
          bundle: build_bundle("1.0.0-orig")
        }}}
    )

    # `write_to_active?: false` so this test-scoped OciBundleManager
    # doesn't overwrite the sibling BundleLoader's strict role-allowlist
    # bundle in the canonical `Recurse.Gateway.Policy.Active` store.
    # This test exercises the activate-API surface in isolation; the
    # role-allowlist bundle (loaded by BundleLoader above) is what
    # Authz reads to decide whether tenant_auditor can hit this endpoint.
    start_supervised!(
      {OciBundleManager,
       config: %{ref: "1.0.0-orig"},
       provider_module: FakeOciProvider,
       persistent_term_key: pt_key,
       pubsub: Recurse.PubSub,
       write_to_active?: false}
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

  describe "POST /v1/admin/cedar-bundle/activate" do
    test "200 + JSON envelope on platform_operator happy path" do
      attach_ui_receipts_telemetry()
      jwt = mint_jwt("platform_operator")

      :ets.insert(
        :cedar_activate_test_stash,
        {:init_response, {:ok, %{ref: "1.0.1-new", bundle: build_bundle("1.0.1-new")}}}
      )

      conn =
        :post
        |> Plug.Test.conn(
          "/v1/admin/cedar-bundle/activate",
          JSON.encode!(%{"ref" => "1.0.1-new"})
        )
        |> with_json(jwt)
        |> CedarBundleActivateHandler.handle()

      assert conn.status == 200
      body = JSON.decode!(conn.resp_body)
      assert body["ok"] == true
      assert body["ref"] == "1.0.1-new"
      assert is_binary(body["new_digest"])
      assert is_binary(body["activated_at"])
    end

    test "403 for tenant_auditor (write actions blocked)" do
      jwt = mint_jwt("tenant_auditor")

      conn =
        :post
        |> Plug.Test.conn(
          "/v1/admin/cedar-bundle/activate",
          JSON.encode!(%{"ref" => "1.0.1-new"})
        )
        |> with_json(jwt)
        |> CedarBundleActivateHandler.handle()

      assert conn.status == 403
      assert %{"error" => "ERR_FORBIDDEN"} = JSON.decode!(conn.resp_body)
    end

    test "400 when ref is missing" do
      jwt = mint_jwt("platform_operator")

      conn =
        :post
        |> Plug.Test.conn(
          "/v1/admin/cedar-bundle/activate",
          JSON.encode!(%{})
        )
        |> with_json(jwt)
        |> CedarBundleActivateHandler.handle()

      assert conn.status == 400
      body = JSON.decode!(conn.resp_body)
      assert body["error"] == "ERR_BAD_REQUEST"
      assert body["error_description"] =~ "ref is required"
    end

    test "400 when ref is empty string" do
      jwt = mint_jwt("platform_operator")

      conn =
        :post
        |> Plug.Test.conn(
          "/v1/admin/cedar-bundle/activate",
          JSON.encode!(%{"ref" => ""})
        )
        |> with_json(jwt)
        |> CedarBundleActivateHandler.handle()

      assert conn.status == 400
    end

    test "400 when ref is not a string" do
      jwt = mint_jwt("platform_operator")

      conn =
        :post
        |> Plug.Test.conn(
          "/v1/admin/cedar-bundle/activate",
          JSON.encode!(%{"ref" => 42})
        )
        |> with_json(jwt)
        |> CedarBundleActivateHandler.handle()

      assert conn.status == 400
    end

    test "502 when registry / verify fails (provider returns error)" do
      jwt = mint_jwt("platform_operator")

      :ets.insert(
        :cedar_activate_test_stash,
        {:init_response, {:error, :cosign_signature_mismatch}}
      )

      conn =
        :post
        |> Plug.Test.conn(
          "/v1/admin/cedar-bundle/activate",
          JSON.encode!(%{"ref" => "1.0.1-bad"})
        )
        |> with_json(jwt)
        |> CedarBundleActivateHandler.handle()

      assert conn.status == 502
      body = JSON.decode!(conn.resp_body)
      assert body["error"] == "ERR_BUNDLE_ACTIVATE_UPSTREAM"
      assert body["error_description"] =~ "cosign_signature_mismatch"
    end
  end

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  defp build_bundle(ref) do
    %{
      digest: :crypto.hash(:sha256, "bytes-#{ref}"),
      bytes: "permit(principal, action, resource);\n",
      canonical_hash: :crypto.hash(:sha256, "canon-#{ref}"),
      cedar_version: "4.9.1",
      loaded_at: DateTime.utc_now(),
      source: :oci,
      source_ref: "test/cedar:#{ref}",
      manifest: %{"version" => ref}
    }
  end

  defp mint_jwt(recurse_role) do
    JwtTestHelper.mint_test_jwt(
      recurse_role: recurse_role,
      audience: "recurse-gateway-test",
      issuer: "https://test-broker.example.invalid"
    )
  end

  defp with_json(conn, jwt) do
    conn
    |> Plug.Conn.put_req_header("authorization", "Bearer " <> jwt)
    |> Plug.Conn.put_req_header("content-type", "application/json")
    |> Plug.Parsers.call(Plug.Parsers.init(parsers: [:json], pass: ["*/*"], json_decoder: JSON))
  end

  defp attach_ui_receipts_telemetry do
    test_pid = self()
    handler_id = "ui-receipt-cedar-activate-test-#{System.unique_integer()}"

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
    File.write!(bundle_path(), @cedar_skeleton)
    on_exit(fn -> File.rm(bundle_path()) end)
    bundle_path()
  end

  defp bundle_path do
    Path.join(System.tmp_dir!(), "cedar_bundle_activate_test.cedar")
  end
end
