defmodule Recurse.Gateway.McpRegistry.LoaderTest do
  @moduledoc """
  Unit tests for the static MCP Trusted Registry loader.

  Cover:
    * load!/0 reads + parses the priv catalog and primes persistent_term.
    * list/0 returns all entries in declaration order.
    * get/1 hits / misses by id.
    * Trust-tier vocabulary parses as atoms.
    * The `:mcp_tool_call` event_kind is registered (drift guard).
    * Override path via `Application.put_env/3` works for fixture testing.
  """

  use ExUnit.Case, async: false

  alias Recurse.Gateway.McpRegistry.Loader
  alias Recurse.Shared.Attestation.SignedPredicate

  setup do
    # Reset persistent_term + app config between tests so order doesn't matter.
    :persistent_term.erase({Loader, :registry})
    Application.delete_env(:recurse_gateway, :mcp_registry_path)
    on_exit(fn -> :persistent_term.erase({Loader, :registry}) end)
    :ok
  end

  describe "load!/0 — production catalog" do
    test "loads + parses the priv-shipped registry.json without raising" do
      assert :ok = Loader.load!()
      catalog = Loader.catalog()

      assert is_binary(catalog.version)
      assert is_binary(catalog.generated_at)
      assert is_list(catalog.entries)
      assert length(catalog.entries) >= 4
    end

    test "every entry has the required typed fields" do
      :ok = Loader.load!()

      for entry <- Loader.list() do
        assert is_binary(entry.id)
        assert is_binary(entry.name)
        assert is_binary(entry.description)
        assert is_binary(entry.source)
        assert is_binary(entry.version)
        assert is_binary(entry.transport)
        assert entry.trust_tier in [:verified, :community, :quarantined]
        assert is_map(entry.capabilities)
        assert is_map(entry.policy_constraints)
        assert is_map(entry.sbom)
      end
    end

    test "at least one entry is quarantined (the demo CVE story)" do
      :ok = Loader.load!()
      tiers = Enum.map(Loader.list(), & &1.trust_tier)
      assert :quarantined in tiers
    end

    test "at least one component carries a CVE entry (the demo SBOM story)" do
      :ok = Loader.load!()

      vuln_count =
        Loader.list()
        |> Enum.flat_map(&Map.get(&1.sbom, "components", []))
        |> Enum.flat_map(&Map.get(&1, "vulnerabilities", []))
        |> length()

      assert vuln_count >= 1
    end
  end

  describe "get/1" do
    setup do
      :ok = Loader.load!()
      :ok
    end

    test "hits by canonical id" do
      assert {:ok, entry} = Loader.get("r5e-audit-mcp")
      assert entry.id == "r5e-audit-mcp"
      assert entry.trust_tier == :verified
    end

    test "misses on unknown id" do
      assert :error = Loader.get("does-not-exist")
    end
  end

  describe "entry_to_json/1" do
    test "stringifies trust_tier atom and round-trips JSON-encodable" do
      :ok = Loader.load!()
      [entry | _] = Loader.list()

      json = Loader.entry_to_json(entry)
      assert is_binary(json["trust_tier"])
      assert json["trust_tier"] in ["verified", "community", "quarantined"]

      # Round-trip via JSON encode/decode — guarantees no Elixir-only terms
      # leak into the wire shape (atoms beyond the trust_tier discriminator,
      # tuples, etc.).
      encoded = JSON.encode!(json)
      decoded = JSON.decode!(encoded)
      assert decoded["id"] == entry.id
    end
  end

  describe "config override — :mcp_registry_path" do
    test "reads the override path when set" do
      tmp = Path.join(System.tmp_dir!(), "mcp_test_registry_#{System.unique_integer([:positive])}.json")

      File.write!(
        tmp,
        JSON.encode!(%{
          "version" => "test-9.9.9",
          "generated_at" => "2026-04-30T00:00:00Z",
          "description" => "test fixture",
          "entries" => [
            %{
              "id" => "test-mcp",
              "name" => "Test MCP",
              "description" => "fixture",
              "source" => "github.com/test/mcp",
              "version" => "0.0.1",
              "transport" => "http",
              "trust_tier" => "community",
              "publisher" => "test",
              "capabilities" => %{"tools" => []},
              "policy_constraints" => %{},
              "sbom" => %{"format" => "test", "digest" => "sha256:test", "components" => []}
            }
          ]
        })
      )

      Application.put_env(:recurse_gateway, :mcp_registry_path, tmp)
      :persistent_term.erase({Loader, :registry})

      :ok = Loader.load!()
      assert {:ok, entry} = Loader.get("test-mcp")
      assert entry.trust_tier == :community
      assert Loader.catalog().version == "test-9.9.9"
    after
      Application.delete_env(:recurse_gateway, :mcp_registry_path)
    end
  end

  describe "assert_event_kind_registered!/0 — drift guard" do
    test "passes when :mcp_tool_call is in SignedPredicate.event_kinds/0" do
      assert :mcp_tool_call in SignedPredicate.event_kinds()
      assert :ok = Loader.assert_event_kind_registered!()
    end
  end
end
