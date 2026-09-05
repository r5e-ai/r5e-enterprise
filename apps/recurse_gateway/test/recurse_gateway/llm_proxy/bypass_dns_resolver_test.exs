defmodule Recurse.Gateway.LlmProxy.BypassDnsResolverTest do
  @moduledoc """
  Unit tests for `Recurse.Gateway.LlmProxy.BypassDnsResolver`.

  Spec source of truth:
  `specs/009-llm-api-proxy/contracts/streaming_proxy.md` §"Upstream
  connection (bypass DNS)" + research.md R-011.

  Test surface:
    * happy-path lookup against a stub DNS module
    * cache hit on second lookup of the same host
    * NXDOMAIN, SERVFAIL, timeout error mapping
    * defensive: unexpected raise from stub does not crash caller
    * configured upstream resolver IPs are passed through to the DNS
      module
    * `invalidate/1` and `clear/0` drop cached entries
    * cache miss after TTL expires (controllable via stubbing
      monotonic_time is impractical, so we test by clearing).

  We do NOT make real DNS queries in CI — the test injects a stub via
  `:bypass_dns_module` app env. See the resolver's @moduledoc for the
  test-seam contract.
  """

  use ExUnit.Case, async: false

  alias Recurse.Gateway.LlmProxy.BypassDnsResolver

  @stub_module __MODULE__.StubDns

  defmodule StubDns do
    @moduledoc false
    # Records every lookup call so tests can assert on dispatch.
    # Returns whatever value the test pre-loaded via `expect/2`.

    def start_link do
      Agent.start_link(fn -> %{calls: [], queue: []} end, name: __MODULE__)
    end

    def expect(value) do
      Agent.update(__MODULE__, fn s -> %{s | queue: s.queue ++ [value]} end)
    end

    def calls do
      Agent.get(__MODULE__, & &1.calls)
    end

    def reset do
      Agent.update(__MODULE__, fn _ -> %{calls: [], queue: []} end)
    end

    def lookup(name, class, type, opts) do
      Agent.get_and_update(__MODULE__, fn s ->
        new_calls = s.calls ++ [{name, class, type, opts}]

        case s.queue do
          [next | rest] ->
            {next, %{s | calls: new_calls, queue: rest}}

          [] ->
            # No expectation set — return empty list so resolver maps
            # to :nxdomain. Loud failure rather than silent default.
            {[], %{s | calls: new_calls}}
        end
      end)
    end
  end

  setup do
    # The stub is a named Agent. Started with a bare `start_link` it is linked
    # to the test process, so the next test's setup could adopt a pid that is
    # mid-exit and then call it (seen once on a shared CI runner, 2026-09-05).
    # Kill any stale instance and start this test's own under ExUnit's
    # supervisor, which stops it deterministically at test exit.
    if pid = Process.whereis(StubDns) do
      Process.exit(pid, :kill)
      ref = Process.monitor(pid)

      receive do
        {:DOWN, ^ref, :process, ^pid, _} -> :ok
      after
        1_000 -> :ok
      end
    end

    start_supervised!(%{id: StubDns, start: {StubDns, :start_link, []}, restart: :temporary})

    StubDns.reset()
    BypassDnsResolver.clear()

    prev_module = Application.get_env(:recurse_gateway, :bypass_dns_module)
    Application.put_env(:recurse_gateway, :bypass_dns_module, @stub_module)

    on_exit(fn ->
      if prev_module do
        Application.put_env(:recurse_gateway, :bypass_dns_module, prev_module)
      else
        Application.delete_env(:recurse_gateway, :bypass_dns_module)
      end
    end)

    :ok
  end

  describe "resolve/1 — happy path" do
    test "returns IPs from the underlying DNS module" do
      StubDns.expect([{93, 184, 216, 34}])

      assert {:ok, [{93, 184, 216, 34}]} = BypassDnsResolver.resolve("example.com")
    end

    test "passes the configured upstream resolver IPs to :inet_res-style call" do
      StubDns.expect([{1, 2, 3, 4}])

      Application.put_env(:recurse_gateway, :llm_proxy_bypass_dns_resolvers, [
        {198, 51, 100, 10}
      ])

      on_exit(fn ->
        Application.delete_env(:recurse_gateway, :llm_proxy_bypass_dns_resolvers)
      end)

      {:ok, _} = BypassDnsResolver.resolve("internal.corp")

      [{name, class, type, opts}] = StubDns.calls()
      assert name == ~c"internal.corp"
      assert class == :in
      assert type == :a
      # `:inet_res.lookup/4` requires `{ip, port}` pairs. Operator config
      # is written as bare IP tuples, so the resolver normalises them by
      # appending port 53. Asserting the bare tuple here is what let the
      # original bug ship: `:inet_res` raises ArgumentError on bare IPs,
      # the rescue turned that into {:error, {:resolver_error, _}}, and
      # every caller silently fell back to system DNS — the exact
      # resolver this module exists to bypass.
      assert Keyword.get(opts, :nameservers) == [{{198, 51, 100, 10}, 53}]
      assert is_integer(Keyword.get(opts, :timeout))
    end

    test "normalises bare-IP resolver config into {ip, port} pairs" do
      StubDns.expect([{1, 2, 3, 4}])

      Application.put_env(:recurse_gateway, :llm_proxy_bypass_dns_resolvers, [
        {8, 8, 8, 8},
        {{1, 1, 1, 1}, 5353}
      ])

      on_exit(fn ->
        Application.delete_env(:recurse_gateway, :llm_proxy_bypass_dns_resolvers)
      end)

      {:ok, _} = BypassDnsResolver.resolve("mixed-shapes.example")

      [{_name, _class, _type, opts}] = StubDns.calls()

      # Bare IPv4 gains the default port; an explicit {ip, port} is left
      # exactly as the operator wrote it.
      assert Keyword.get(opts, :nameservers) == [{{8, 8, 8, 8}, 53}, {{1, 1, 1, 1}, 5353}]
    end
  end

  describe "resolve/1 — cache" do
    test "second resolve of same host hits cache (no second DNS call)" do
      StubDns.expect([{10, 0, 0, 1}])

      assert {:ok, [{10, 0, 0, 1}]} = BypassDnsResolver.resolve("cached.example")
      assert {:ok, [{10, 0, 0, 1}]} = BypassDnsResolver.resolve("cached.example")

      # Only one underlying DNS call.
      assert length(StubDns.calls()) == 1
    end

    test "invalidate/1 forces a re-resolve" do
      StubDns.expect([{10, 0, 0, 1}])
      StubDns.expect([{10, 0, 0, 99}])

      {:ok, _} = BypassDnsResolver.resolve("rotating.example")
      :ok = BypassDnsResolver.invalidate("rotating.example")
      {:ok, ips} = BypassDnsResolver.resolve("rotating.example")

      assert ips == [{10, 0, 0, 99}]
      assert length(StubDns.calls()) == 2
    end

    test "clear/0 wipes the entire cache" do
      StubDns.expect([{1, 1, 1, 1}])
      StubDns.expect([{1, 1, 1, 1}])

      {:ok, _} = BypassDnsResolver.resolve("a.example")
      :ok = BypassDnsResolver.clear()
      {:ok, _} = BypassDnsResolver.resolve("a.example")

      assert length(StubDns.calls()) == 2
    end

    test "different hostnames cache independently" do
      StubDns.expect([{10, 0, 0, 1}])
      StubDns.expect([{10, 0, 0, 2}])

      {:ok, [a]} = BypassDnsResolver.resolve("alpha.example")
      {:ok, [b]} = BypassDnsResolver.resolve("beta.example")

      assert a == {10, 0, 0, 1}
      assert b == {10, 0, 0, 2}
      # Re-resolve both — both cached.
      {:ok, _} = BypassDnsResolver.resolve("alpha.example")
      {:ok, _} = BypassDnsResolver.resolve("beta.example")

      # Two underlying calls total (one per host).
      assert length(StubDns.calls()) == 2
    end
  end

  describe "resolve/1 — error mapping" do
    test "empty result list maps to {:error, :nxdomain}" do
      StubDns.expect([])
      assert {:error, :nxdomain} = BypassDnsResolver.resolve("nope.example")
    end

    test "{:error, :timeout} from stub maps to {:error, :timeout}" do
      StubDns.expect({:error, :timeout})
      assert {:error, :timeout} = BypassDnsResolver.resolve("slow.example")
    end

    test "{:error, :nxdomain} from stub propagates" do
      StubDns.expect({:error, :nxdomain})
      assert {:error, :nxdomain} = BypassDnsResolver.resolve("ghost.example")
    end

    test "{:error, {:servfail, _}} maps to {:error, :servfail}" do
      StubDns.expect({:error, {:servfail, ~c"server fail"}})
      assert {:error, :servfail} = BypassDnsResolver.resolve("broken.example")
    end

    test "any other error reason wraps as {:resolver_error, reason}" do
      StubDns.expect({:error, :weird_undocumented_reason})

      assert {:error, {:resolver_error, :weird_undocumented_reason}} =
               BypassDnsResolver.resolve("weird.example")
    end

    test "errors are NOT cached (next call retries the resolver)" do
      StubDns.expect({:error, :timeout})
      StubDns.expect([{8, 8, 8, 8}])

      {:error, :timeout} = BypassDnsResolver.resolve("flaky.example")
      {:ok, [{8, 8, 8, 8}]} = BypassDnsResolver.resolve("flaky.example")

      assert length(StubDns.calls()) == 2
    end
  end

  describe "resolve/1 — totality" do
    test "stub raising an exception degrades to {:resolver_error, _} not a crash" do
      defmodule CrashingDns do
        def lookup(_, _, _, _), do: raise("network on fire")
      end

      Application.put_env(:recurse_gateway, :bypass_dns_module, CrashingDns)
      on_exit(fn -> Application.put_env(:recurse_gateway, :bypass_dns_module, @stub_module) end)

      assert {:error, {:resolver_error, _}} = BypassDnsResolver.resolve("crash.example")
    end
  end
end
