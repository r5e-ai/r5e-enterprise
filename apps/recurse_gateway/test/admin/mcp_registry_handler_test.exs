defmodule Recurse.Gateway.Admin.McpRegistryHandlerTest do
  @moduledoc """
  Unit tests for `GET /v1/mcp/registry` and `GET /v1/mcp/registry/:id`.

  Drives the handler directly via `Plug.Test.conn/3` — no auth pipe in
  scope here (those are exercised in `RouterAuthPropertyTest`). The
  registry catalog is loaded via `Loader.load!/0` against the production
  priv file (no fixture path needed for the read-only paths).
  """

  use ExUnit.Case, async: false

  alias Recurse.Gateway.Admin.McpRegistryHandler
  alias Recurse.Gateway.McpRegistry.Loader

  setup do
    :persistent_term.erase({Loader, :registry})
    Application.delete_env(:recurse_gateway, :mcp_registry_path)
    :ok = Loader.load!()
    on_exit(fn -> :persistent_term.erase({Loader, :registry}) end)
    :ok
  end

  describe "list/1" do
    test "returns the catalog payload with entries + version + generated_at" do
      conn =
        :get
        |> Plug.Test.conn("/v1/mcp/registry")
        |> McpRegistryHandler.list()

      assert conn.status == 200
      assert {"content-type", "application/json; charset=utf-8"} in conn.resp_headers

      body = JSON.decode!(conn.resp_body)
      assert is_binary(body["version"])
      assert is_binary(body["generated_at"])
      assert is_list(body["entries"])
      assert length(body["entries"]) >= 4

      first = List.first(body["entries"])
      # All required wire fields present.
      for k <-
            ~w(id name description source version transport trust_tier publisher capabilities policy_constraints sbom) do
        assert Map.has_key?(first, k), "missing key #{inspect(k)} in entry"
      end

      # trust_tier is the wire-encoded string.
      assert first["trust_tier"] in ~w(verified community quarantined)
    end

    test "demo CVE story is visible — at least one entry has a vulnerability" do
      conn =
        :get
        |> Plug.Test.conn("/v1/mcp/registry")
        |> McpRegistryHandler.list()

      body = JSON.decode!(conn.resp_body)

      vuln_count =
        body["entries"]
        |> Enum.flat_map(&Map.get(&1["sbom"], "components", []))
        |> Enum.flat_map(&Map.get(&1, "vulnerabilities", []))
        |> length()

      assert vuln_count >= 1
    end
  end

  describe "get_one/1" do
    test "200 + entry body on hit" do
      conn =
        :get
        |> Plug.Test.conn("/v1/mcp/registry/r5e-audit-mcp")
        |> Map.put(:path_params, %{"id" => "r5e-audit-mcp"})
        |> McpRegistryHandler.get_one()

      assert conn.status == 200
      body = JSON.decode!(conn.resp_body)
      assert body["id"] == "r5e-audit-mcp"
      assert body["trust_tier"] == "verified"
    end

    test "404 F001 envelope on miss" do
      conn =
        :get
        |> Plug.Test.conn("/v1/mcp/registry/does-not-exist")
        |> Map.put(:path_params, %{"id" => "does-not-exist"})
        |> McpRegistryHandler.get_one()

      assert conn.status == 404
      body = JSON.decode!(conn.resp_body)
      assert body["error"] == "not_found"
      assert is_binary(body["error_description"])
      assert body["attested_run_id"] == nil
    end
  end
end
