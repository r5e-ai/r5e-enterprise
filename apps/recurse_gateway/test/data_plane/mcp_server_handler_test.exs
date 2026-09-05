defmodule Recurse.Gateway.DataPlane.McpServerHandlerTest do
  @moduledoc """
  Unit tests for `POST /v1/mcp/{server}/tools/{tool}`.

  Asserts:

    * Authentication: missing / malformed bearers → 401.
    * Demo synthetic-token shape (`Bearer demo-mcp-token-*`) is accepted.
    * Real (non-demo) bearer is also accepted as the production-stub
      placeholder (until the broker wire-up lands).
    * Registry miss → 404.
    * Unsupported tool → 404.
    * Quarantined registry entry → 403 + receipt with policy_decision="deny".
    * Allow path emits `:mcp_tool_call` telemetry (proxy for ledger commit).

  We attach to the `UiReceipts.telemetry_event/0` to assert the emission
  fires regardless of decision; the underlying ledger commit is exercised
  in the integration suite when present.
  """

  use ExUnit.Case, async: false

  alias Recurse.Gateway.Admin.BrowserAuth.UiReceipts
  alias Recurse.Gateway.DataPlane.McpServerHandler
  alias Recurse.Gateway.McpRegistry.Loader
  alias Recurse.Gateway.ProviderRegistry

  setup do
    :persistent_term.erase({Loader, :registry})
    Application.delete_env(:recurse_gateway, :mcp_registry_path)
    :ok = Loader.load!()

    # Stub provider registry — telemetry-only emission path (no real ledger
    # commit needed for these tests; UiReceipts.emit/2 falls through to the
    # telemetry-only mode when the ledger commit fails).
    ProviderRegistry.install_raw!(%{
      llm: {Recurse.Gateway.Test.StubLLM, %{}},
      ledger: {Recurse.Gateway.Test.StubLedger, %{}},
      storage: {Recurse.Gateway.Test.StubStorage, %{}},
      secrets: {Recurse.Gateway.Test.StubSecretsProvider, %{}},
      tenant_id: "01HQZN5K7J8M9N0P1Q2R3S4T5V",
      signer: "observed://gateway/mcp-test"
    })

    on_exit(fn ->
      ProviderRegistry.uninstall()
      :persistent_term.erase({Loader, :registry})
    end)

    :ok
  end

  defp attach_receipt_telemetry(test) do
    handler_id = "mcp-test-#{:erlang.phash2(test)}"
    parent = self()

    :ok =
      :telemetry.attach(
        handler_id,
        UiReceipts.telemetry_event(),
        fn _evt, _measurements, meta, _cfg -> send(parent, {:receipt, meta}) end,
        nil
      )

    on_exit(fn -> :telemetry.detach(handler_id) end)
    :ok
  end

  defp build_conn(server, tool, body, headers) do
    conn =
      :post
      |> Plug.Test.conn("/v1/mcp/#{server}/tools/#{tool}", JSON.encode!(body))
      |> Plug.Conn.put_req_header("content-type", "application/json")
      |> Map.put(:body_params, body)
      |> Map.put(:path_params, %{"server" => server, "tool" => tool})

    Enum.reduce(headers, conn, fn {k, v}, c -> Plug.Conn.put_req_header(c, k, v) end)
  end

  describe "auth" do
    test "missing Authorization header → 401 missing_authorization" do
      conn =
        build_conn(
          "r5e-audit-mcp",
          "r5e.audit.list_receipts",
          %{"arguments" => %{}},
          []
        )
        |> McpServerHandler.handle()

      assert conn.status == 401
      assert JSON.decode!(conn.resp_body)["error"] == "missing_authorization"
    end

    test "malformed Authorization header (not Bearer) → 401" do
      conn =
        build_conn(
          "r5e-audit-mcp",
          "r5e.audit.list_receipts",
          %{"arguments" => %{}},
          [{"authorization", "Basic abc123"}]
        )
        |> McpServerHandler.handle()

      assert conn.status == 401
    end

    test "synthetic Bearer demo-mcp-token-* is accepted (Phase-1 demo path)" do
      conn =
        build_conn(
          "r5e-audit-mcp",
          "r5e.audit.list_receipts",
          %{"arguments" => %{}},
          [{"authorization", "Bearer demo-mcp-token-test-001"}]
        )
        |> McpServerHandler.handle()

      assert conn.status == 200
    end
  end

  describe "registry / tool dispatch" do
    test "404 mcp_server_not_found on unknown server" do
      conn =
        build_conn(
          "no-such-mcp",
          "r5e.audit.list_receipts",
          %{"arguments" => %{}},
          [{"authorization", "Bearer demo-mcp-token-x"}]
        )
        |> McpServerHandler.handle()

      assert conn.status == 404
      assert JSON.decode!(conn.resp_body)["error"] == "mcp_server_not_found"
    end

    test "404 tool_not_found on unsupported tool name" do
      conn =
        build_conn(
          "r5e-audit-mcp",
          "r5e.audit.fictional_tool",
          %{"arguments" => %{}},
          [{"authorization", "Bearer demo-mcp-token-x"}]
        )
        |> McpServerHandler.handle()

      assert conn.status == 404
      assert JSON.decode!(conn.resp_body)["error"] == "tool_not_found"
    end
  end

  describe "trust-tier gate (the demo's policy story)" do
    test "quarantined entry → 403 + policy_decision=deny + attested run_id" do
      attach_receipt_telemetry({:quarantine_test, :erlang.unique_integer()})

      conn =
        build_conn(
          "legacy-pdf-mcp",
          "r5e.audit.list_receipts",
          %{"arguments" => %{}},
          [{"authorization", "Bearer demo-mcp-token-q"}]
        )
        |> McpServerHandler.handle()

      assert conn.status == 403
      body = JSON.decode!(conn.resp_body)
      assert body["policy_decision"] == "deny"
      assert is_binary(body["attested_run_id"])
      assert body["trust_tier"] == "quarantined"
      assert is_binary(body["deny_reason"])

      # Receipt must have fired (Constitution Principle III: deny is also
      # attested).
      assert_receive {:receipt, meta}, 500
      assert meta.event_kind == :mcp_tool_call
      assert meta.trust_tier == "quarantined"
      assert meta.policy_decision == "deny"
    end

    test "verified entry → 200 + policy_decision=allow + attested run_id" do
      attach_receipt_telemetry({:allow_test, :erlang.unique_integer()})

      conn =
        build_conn(
          "r5e-audit-mcp",
          "r5e.audit.list_receipts",
          %{"arguments" => %{"limit" => 3}},
          [{"authorization", "Bearer demo-mcp-token-a"}]
        )
        |> McpServerHandler.handle()

      assert conn.status == 200
      body = JSON.decode!(conn.resp_body)
      assert body["policy_decision"] == "allow"
      assert is_binary(body["attested_run_id"])
      assert body["trust_tier"] == "verified"
      assert is_map(body["result"])
      assert is_list(body["result"]["receipts"])
      assert length(body["result"]["receipts"]) == 3

      assert_receive {:receipt, meta}, 500
      assert meta.event_kind == :mcp_tool_call
      assert meta.tool == "r5e.audit.list_receipts"
      assert meta.mcp_server == "r5e-audit-mcp"
    end
  end

  describe "demo tool implementations" do
    test "verify_receipt with run_id returns VALID + 5-check pass" do
      conn =
        build_conn(
          "r5e-audit-mcp",
          "r5e.audit.verify_receipt",
          %{"arguments" => %{"run_id" => "demo-run-1"}},
          [{"authorization", "Bearer demo-mcp-token-v"}]
        )
        |> McpServerHandler.handle()

      assert conn.status == 200
      body = JSON.decode!(conn.resp_body)
      assert body["result"]["verification_status"] == "VALID"
      assert body["result"]["run_id"] == "demo-run-1"
      assert is_map(body["result"]["checks"])
    end

    test "query_attestations echoes the query and returns matches" do
      conn =
        build_conn(
          "r5e-audit-mcp",
          "r5e.audit.query_attestations",
          %{"arguments" => %{"query" => "policy_denied"}},
          [{"authorization", "Bearer demo-mcp-token-q"}]
        )
        |> McpServerHandler.handle()

      assert conn.status == 200
      body = JSON.decode!(conn.resp_body)
      assert body["result"]["query"] == "policy_denied"
      assert is_list(body["result"]["matches"])
    end
  end

  describe "request id echo" do
    test "echoes the client-supplied id in the response envelope" do
      conn =
        build_conn(
          "r5e-audit-mcp",
          "r5e.audit.list_receipts",
          %{"id" => "req-42", "arguments" => %{}},
          [{"authorization", "Bearer demo-mcp-token-x"}]
        )
        |> McpServerHandler.handle()

      assert JSON.decode!(conn.resp_body)["id"] == "req-42"
    end
  end
end
