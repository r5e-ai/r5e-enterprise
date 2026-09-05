defmodule Recurse.Gateway.LlmProxy.UpstreamSeedTest do
  @moduledoc """
  Spec 012 S2 — boot-time upstream seeding. Live SQL Sandbox per the
  `upstream_resolver_test.exs` pattern.
  """

  use ExUnit.Case, async: false

  import Ecto.Query, only: [from: 2]
  import ExUnit.CaptureLog, only: [with_log: 2]

  alias Ecto.Adapters.SQL.Sandbox
  alias Recurse.Gateway.LlmProxy.UpstreamResolver
  alias Recurse.Gateway.LlmProxy.UpstreamSeed
  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Tenant
  alias Recurse.Providers.Repo
  alias Recurse.Providers.Schemas.LlmProviderConfig
  alias Recurse.Shared.Ulid

  require Logger

  doctest UpstreamSeed

  setup do
    :ok = Sandbox.checkout(Repo)
    Sandbox.mode(Repo, {:shared, self()})
    {:ok, tenant_id: "01TEN_SEED_" <> Ulid.generate()}
  end

  # config/test.exs silences `:logger` below :warning; the skip paths log at
  # :info, so opt this module back in for the tests that assert on them.
  defp capture_info_log(fun) do
    Logger.put_module_level(UpstreamSeed, :info)
    on_exit(fn -> Logger.delete_module_level(UpstreamSeed) end)
    with_log([level: :info], fun)
  end

  test "parse_upstreams/1 trims, drops empties, dedupes" do
    assert UpstreamSeed.parse_upstreams("anthropic") == ["anthropic"]
    assert UpstreamSeed.parse_upstreams("anthropic,openai_api") == ["anthropic", "openai_api"]
    assert UpstreamSeed.parse_upstreams(" , ") == []
    assert UpstreamSeed.parse_upstreams("") == []
  end

  test "anthropic preset is the S2 row: api.anthropic.com, https-sse, anthropic_messages, passthrough" do
    assert %{
             provider: "anthropic",
             upstream_host: "api.anthropic.com",
             upstream_port: 443,
             transport_modes: ["https-sse"],
             auth_mode: :passthrough,
             api_format: :anthropic_messages,
             metadata: %{"scheme" => "https"}
           } = UpstreamSeed.presets()["anthropic"]
  end

  test "run/2 creates the tenant and the row on an empty database", %{tenant_id: tenant_id} do
    assert Repo.get(Tenant, tenant_id) == nil

    assert {:ok, [%LlmProviderConfig{} = row]} = UpstreamSeed.run(tenant_id, ["anthropic"])
    assert row.tenant_id == tenant_id
    assert row.upstream_host == "api.anthropic.com"
    assert row.api_format == :anthropic_messages
    assert row.auth_mode == :passthrough
    assert row.enabled

    assert %Tenant{} = Repo.get(Tenant, tenant_id)

    # The resolver — what ProxyRouter uses — finds it.
    assert {:ok, %LlmProviderConfig{provider: "anthropic"}} =
             UpstreamResolver.resolve(tenant_id, "api.anthropic.com")
  end

  test "run/2 is idempotent: a seed-marked row is refreshed in place, operator extras kept",
       %{tenant_id: tenant_id} do
    assert {:ok, [first]} = UpstreamSeed.run(tenant_id, ["anthropic"])
    assert first.metadata["seed"] == "upstream_seed"

    # Operator disables the row and adds a denial template (kept), and the
    # preset fields drift (refreshed, each drift logged at warning).
    first
    |> LlmProviderConfig.changeset(%{
      enabled: false,
      metadata: Map.merge(first.metadata, %{"denial_template" => "custom", "scheme" => "http"}),
      transport_modes: ["wss"],
      upstream_port: 8443
    })
    |> Repo.update!()

    {result, log} =
      with_log([level: :warning], fn -> UpstreamSeed.run(tenant_id, ["anthropic"]) end)

    assert {:ok, [second]} = result

    assert second.id == first.id
    refute second.enabled, "reboot must not undo an operator disable"
    assert second.metadata["denial_template"] == "custom"
    assert second.metadata["scheme"] == "https"
    assert second.transport_modes == ["https-sse"], "preset fields are refreshed"
    assert second.upstream_port == 443

    assert log =~ ~s(transport_modes: ["wss"] -> ["https-sse"])
    assert log =~ "upstream_port: 8443 -> 443"
    assert log =~ ~s(metadata.scheme: "http" -> "https")
    refute log =~ "api_format:", "unchanged fields are not logged"

    # A third run with nothing drifted is silent at warning.
    {{:ok, [third]}, quiet} =
      with_log([level: :warning], fn -> UpstreamSeed.run(tenant_id, ["anthropic"]) end)

    assert third.updated_at == second.updated_at
    refute quiet =~ "upstream_seed: refreshed"

    count =
      Repo.aggregate(
        from(c in LlmProviderConfig, where: c.tenant_id == ^tenant_id),
        :count
      )

    assert count == 1
  end

  test "run/2 leaves a row alone when the operator removed the seed marker",
       %{tenant_id: tenant_id} do
    assert {:ok, [first]} = UpstreamSeed.run(tenant_id, ["anthropic"])

    first
    |> LlmProviderConfig.changeset(%{
      metadata: Map.delete(first.metadata, "seed"),
      transport_modes: ["wss"],
      upstream_port: 8443
    })
    |> Repo.update!()

    {result, log} = capture_info_log(fn -> UpstreamSeed.run(tenant_id, ["anthropic"]) end)
    assert {:ok, [second]} = result

    assert second.id == first.id
    assert second.transport_modes == ["wss"], "operator-owned row is not refreshed"
    assert second.upstream_port == 8443
    refute Map.has_key?(second.metadata, "seed"), "the marker is not re-added"
    assert log =~ "upstream_seed: skipped"
    assert log =~ "metadata.seed is nil"
    refute log =~ "upstream_seed: refreshed"
  end

  test "run/2 leaves a row alone when the operator changed auth_mode",
       %{tenant_id: tenant_id} do
    assert {:ok, [first]} = UpstreamSeed.run(tenant_id, ["anthropic"])

    first
    |> LlmProviderConfig.changeset(%{auth_mode: :bearer, transport_modes: ["wss"]})
    |> Repo.update!()

    {result, log} = capture_info_log(fn -> UpstreamSeed.run(tenant_id, ["anthropic"]) end)
    assert {:ok, [second]} = result

    assert second.id == first.id
    assert second.auth_mode == :bearer, "reboot must not undo an operator auth_mode change"
    assert second.transport_modes == ["wss"]
    assert log =~ "upstream_seed: skipped"
    assert log =~ "auth_mode is :bearer, preset is :passthrough"
    refute log =~ "upstream_seed: refreshed"
  end

  test "with_db_retry/2 retries connection errors per the schedule, then re-raises" do
    counter = :counters.new(1, [])

    flaky = fn ->
      :counters.add(counter, 1, 1)

      if :counters.get(counter, 1) < 3 do
        raise DBConnection.ConnectionError, "connection refused"
      else
        :seeded
      end
    end

    {result, log} =
      with_log([level: :warning], fn -> UpstreamSeed.with_db_retry([0, 0, 0], flaky) end)

    assert result == :seeded
    assert :counters.get(counter, 1) == 3
    assert log =~ "database unavailable"
    assert log =~ "retrying in 0ms"

    # Exhausted schedule: the connection error propagates.
    {_, exhausted_log} =
      with_log([level: :warning], fn ->
        assert_raise DBConnection.ConnectionError, fn ->
          UpstreamSeed.with_db_retry([0, 0, 0], fn ->
            raise DBConnection.ConnectionError, "still down"
          end)
        end
      end)

    assert exhausted_log =~ "0 retries left"

    # Non-connection errors are not retried at all.
    :counters.put(counter, 1, 0)

    assert_raise ArgumentError, fn ->
      UpstreamSeed.with_db_retry([0, 0, 0], fn ->
        :counters.add(counter, 1, 1)
        raise ArgumentError, "bad preset"
      end)
    end

    assert :counters.get(counter, 1) == 1
  end

  test "run/2 seeds several presets in order", %{tenant_id: tenant_id} do
    assert {:ok, [a, o]} = UpstreamSeed.run(tenant_id, ["anthropic", "openai_api"])
    assert a.upstream_host == "api.anthropic.com"
    assert o.upstream_host == "api.openai.com"
    assert o.api_format == :openai_responses
  end

  test "run/2 rejects an unknown preset before touching the database",
       %{tenant_id: tenant_id} do
    assert {:error, {:unknown_preset, "anthropc"}} =
             UpstreamSeed.run(tenant_id, ["anthropic", "anthropc"])

    assert Repo.get(Tenant, tenant_id) == nil
  end

  test "start_link/1 seeds synchronously and returns :ignore; unknown preset raises",
       %{tenant_id: tenant_id} do
    assert :ignore = UpstreamSeed.start_link(tenant_id: tenant_id, upstreams: ["anthropic"])
    assert {:ok, _} = UpstreamResolver.resolve(tenant_id, "api.anthropic.com")

    assert_raise ArgumentError, ~r/unknown preset "bogus"/, fn ->
      UpstreamSeed.start_link(tenant_id: tenant_id, upstreams: ["bogus"])
    end

    spec = UpstreamSeed.child_spec([])
    assert spec.id == UpstreamSeed
    assert spec.restart == :transient
  end
end
