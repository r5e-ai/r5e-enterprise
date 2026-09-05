defmodule Recurse.Gateway.Admin.ParserDriftHandlerContractTest do
  @moduledoc """
  Contract tests for `Recurse.Gateway.Admin.ParserDriftHandler`
  (spec 012 S4, `GET /v1/audit/parser-drift`).

    * 401 without Authorization; 403 for the data-plane `caller` role.
    * `tenant_auditor` and `platform_operator` (both hold `DashboardQuery`)
      get the tenant's drift rows, most recent first, plus
      `new_since_boot`; other tenants' rows are not visible.
    * The response validates against `priv/schemas/parser_drift_list_response.json`.
    * A `:ui_query` receipt (`query_kind: "parser_drift"`) is emitted.

  `async: false` — BundleLoader + ProviderRegistry + the drift boot
  counter are process-global.
  """

  use ExUnit.Case, async: false

  setup_all do
    Recurse.Gateway.Test.KernelFixture.boot()
  end

  import Ecto.Query, only: [from: 2]

  alias Recurse.Gateway.Admin.ParserDriftHandler
  alias Recurse.Gateway.LlmProxy.ParserDrift
  alias Recurse.Gateway.Policy.BundleLoader
  alias Recurse.Gateway.ProviderRegistry
  alias Recurse.Gateway.Test.JwtTestHelper
  alias Recurse.Providers.Impls.PostgresMerkleLedger
  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Attestation
  alias Recurse.Providers.ParserDrift, as: Store
  alias Recurse.Providers.Repo

  @tenant_id "01HQZN5K7J8M9N0P1Q2R3S4T5V"
  @other_tenant "01OTHER000000000000000000"
  @cursor_key :crypto.strong_rand_bytes(64)

  setup do
    :ok = Ecto.Adapters.SQL.Sandbox.checkout(Repo)
    Ecto.Adapters.SQL.Sandbox.mode(Repo, {:shared, self()})

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
      known_kids: [{"test-key-rs256", JwtTestHelper.public_jwk(:rs256)}]
    )

    previous_browser_session = Application.get_env(:recurse_gateway, :browser_session)

    Application.put_env(:recurse_gateway, :browser_session,
      cookie_name: "r5e_session",
      secret_key_base: @cursor_key,
      secure_cookie?: false,
      absent_cookie_redirect: :always_401
    )

    ParserDrift.reset_counter()

    on_exit(fn ->
      ProviderRegistry.uninstall()

      if previous_validator_opts,
        do: Application.put_env(:recurse_gateway, :jwt_validator_opts, previous_validator_opts),
        else: Application.delete_env(:recurse_gateway, :jwt_validator_opts)

      if previous_browser_session,
        do: Application.put_env(:recurse_gateway, :browser_session, previous_browser_session),
        else: Application.delete_env(:recurse_gateway, :browser_session)
    end)

    :ok
  end

  test "401 when Authorization is missing" do
    conn = ParserDriftHandler.handle(build_conn(nil))
    assert conn.status == 401
  end

  test "403 for the data-plane caller role" do
    conn = ParserDriftHandler.handle(build_conn(mint_jwt(recurse_role: "caller")))
    assert conn.status == 403
    assert %{"error" => "ERR_FORBIDDEN"} = JSON.decode!(conn.resp_body)
  end

  test "empty tenant → 200 with an empty list and the boot counter" do
    conn = ParserDriftHandler.handle(build_conn(mint_jwt(recurse_role: "tenant_auditor")))
    assert conn.status == 200
    assert %{"events" => [], "new_since_boot" => 0} = JSON.decode!(conn.resp_body)
  end

  test "lists the tenant's rows most-recent first, validates against the schema, emits :ui_query" do
    summary = %{
      unhandled_types: ["block:widget", "event:telemetry"],
      unhandled_samples: %{
        "block:widget" => "keys=payload,type",
        "event:telemetry" => "keys=k,type"
      }
    }

    assert 2 == ParserDrift.record_summary(@tenant_id, :anthropic_messages, summary)

    assert {:ok, :seen, _} =
             Store.record(%{
               tenant_id: @tenant_id,
               api_format: "anthropic_messages",
               event_type: "block:widget",
               seen_at: DateTime.add(DateTime.utc_now(), 60, :second)
             })

    assert {:ok, :new, _} =
             Store.record(%{
               tenant_id: @other_tenant,
               api_format: "openai_responses",
               event_type: "event:x"
             })

    conn = ParserDriftHandler.handle(build_conn(mint_jwt(recurse_role: "platform_operator")))
    assert conn.status == 200
    assert {"content-type", "application/json; charset=utf-8"} in conn.resp_headers

    body = JSON.decode!(conn.resp_body)

    schema =
      [
        Application.app_dir(:recurse_gateway, "priv"),
        "schemas",
        "parser_drift_list_response.json"
      ]
      |> Path.join()
      |> File.read!()
      |> JSON.decode!()

    assert :ok = Recurse.Gateway.Test.JsonSchemaValidator.validate!(body, schema)

    assert body["new_since_boot"] == 2
    assert [first, second] = body["events"]
    assert first["event_type"] == "block:widget"
    assert first["count"] == 2
    assert first["api_format"] == "anthropic_messages"
    assert first["sample_redacted"] == "keys=payload,type"
    assert second["event_type"] == "event:telemetry"
    refute Enum.any?(body["events"], &(&1["event_type"] == "event:x"))

    assert Repo.exists?(
             from(a in Attestation,
               where: a.event_kind == :ui_query and a.tenant_id == ^@tenant_id
             )
           )
  end

  test "api_format and limit query params filter the list" do
    assert {:ok, :new, _} =
             Store.record(%{
               tenant_id: @tenant_id,
               api_format: "anthropic_messages",
               event_type: "event:a"
             })

    assert {:ok, :new, _} =
             Store.record(%{
               tenant_id: @tenant_id,
               api_format: "openai_responses",
               event_type: "event:b"
             })

    conn =
      build_conn(mint_jwt(recurse_role: "tenant_auditor"))
      |> Map.put(:query_string, "api_format=openai_responses&limit=1")
      |> ParserDriftHandler.handle()

    assert %{"events" => [%{"api_format" => "openai_responses", "event_type" => "event:b"}]} =
             JSON.decode!(conn.resp_body)
  end

  defp build_conn(jwt) do
    conn = Plug.Test.conn(:get, "/v1/audit/parser-drift")

    case jwt do
      nil -> conn
      token -> Plug.Conn.put_req_header(conn, "authorization", "Bearer " <> token)
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

    path = Path.join(System.tmp_dir!(), "parser_drift_bundle_#{System.unique_integer()}.cedar")
    File.write!(path, source)
    on_exit(fn -> File.rm(path) end)
    path
  end
end
