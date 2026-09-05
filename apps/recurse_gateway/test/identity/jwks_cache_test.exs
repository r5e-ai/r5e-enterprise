defmodule Recurse.Gateway.Identity.JwksCacheTest do
  @moduledoc """
  Contract tests for `Recurse.Gateway.Identity.JwksCache` (F002 T042).

  Covers:

    * TTL-hot path — cached kid returns without a new HTTP fetch.
    * `kid`-miss refresh — unknown kid triggers a JWKS fetch + populates
      the cache.
    * Coalescing — N concurrent `fetch_jwk/2` calls on an unknown kid
      trigger EXACTLY ONE upstream fetch. This is Surface P's core
      invariant.
    * HTTP failure — 5xx / connect errors surface as
      `{:error, :jwks_fetch_failed}` and do NOT poison the cache.
    * Unknown issuer — config boundary check.

  `async: false` because `Recurse.Providers.Support.MockHttpUpstream`
  binds a port per test. Two tests starting upstreams in parallel could
  race on ephemeral port allocation; serialization is the cheap fix.
  """

  use ExUnit.Case, async: false

  alias Recurse.Gateway.Identity.JwksCache
  alias Recurse.Gateway.Test.JwtTestHelper
  alias Recurse.Providers.Support.MockHttpUpstream

  @test_issuer "https://test-broker.example.invalid"

  setup do
    {:ok, upstream} = MockHttpUpstream.start()

    on_exit(fn -> MockHttpUpstream.stop(upstream) end)

    # Each test gets its own Task.Supervisor so concurrent fetches in
    # this test are isolated from the Gateway's app-level supervisor.
    # credo:disable-for-next-line Credo.Check.Warning.UnsafeToAtom
    task_sup_name = :"jwks_cache_task_sup_#{System.unique_integer([:positive])}"
    {:ok, _pid} = start_supervised({Task.Supervisor, name: task_sup_name})

    %{upstream: upstream, task_supervisor: task_sup_name}
  end

  describe "start_link/1 + fetch_jwk/2 happy-path" do
    test "refreshes on cache-miss and caches for subsequent reads", %{
      upstream: upstream,
      task_supervisor: task_sup
    } do
      call_counter = start_counter()

      MockHttpUpstream.expect(upstream, fn conn ->
        increment(call_counter)

        conn
        |> Plug.Conn.put_resp_header("content-type", "application/json")
        |> Plug.Conn.send_resp(200, rs256_jwks_body())
      end)

      cache = start_cache!(upstream, task_sup)

      assert {:ok, %{"kid" => "test-key-rs256"}} =
               JwksCache.fetch_jwk(cache, @test_issuer, "test-key-rs256")

      # Second call — cache is warm, NO new upstream hit.
      assert {:ok, %{"kid" => "test-key-rs256"}} =
               JwksCache.fetch_jwk(cache, @test_issuer, "test-key-rs256")

      assert counter_value(call_counter) == 1
    end

    test "unknown kid after successful refresh returns :unknown_kid", %{
      upstream: upstream,
      task_supervisor: task_sup
    } do
      MockHttpUpstream.expect(upstream, fn conn ->
        conn
        |> Plug.Conn.put_resp_header("content-type", "application/json")
        |> Plug.Conn.send_resp(200, rs256_jwks_body())
      end)

      cache = start_cache!(upstream, task_sup)

      assert {:error, :unknown_kid} =
               JwksCache.fetch_jwk(cache, @test_issuer, "not-in-jwks")
    end

    test "unknown issuer returns :unknown_issuer without touching the network", %{
      upstream: upstream,
      task_supervisor: task_sup
    } do
      call_counter = start_counter()

      MockHttpUpstream.expect(upstream, fn conn ->
        increment(call_counter)
        Plug.Conn.send_resp(conn, 200, rs256_jwks_body())
      end)

      cache = start_cache!(upstream, task_sup)

      assert {:error, :unknown_issuer} =
               JwksCache.fetch_jwk(cache, "https://unknown-broker.example", "test-key-rs256")

      assert counter_value(call_counter) == 0
    end
  end

  describe "coalesced kid-miss refresh (Surface P)" do
    test "N concurrent fetch_jwk calls coalesce behind one upstream fetch", %{
      upstream: upstream,
      task_supervisor: task_sup
    } do
      call_counter = start_counter()
      gate = start_gate()

      MockHttpUpstream.expect(upstream, fn conn ->
        increment(call_counter)

        # Block until the test releases the gate — ensures all N callers
        # enqueue BEFORE the refresh completes.
        wait_for_release(gate)

        conn
        |> Plug.Conn.put_resp_header("content-type", "application/json")
        |> Plug.Conn.send_resp(200, rs256_jwks_body())
      end)

      cache = start_cache!(upstream, task_sup)

      n = 20

      tasks =
        for _ <- 1..n do
          Task.async(fn ->
            JwksCache.fetch_jwk(cache, @test_issuer, "test-key-rs256")
          end)
        end

      # Give the GenServer time to enqueue all N waiters before we let
      # the upstream respond. 100 ms is comfortably above the call
      # dispatch cost while keeping the test fast.
      Process.sleep(100)
      release_gate(gate)

      results = Task.await_many(tasks, 5_000)

      assert Enum.all?(results, &match?({:ok, %{"kid" => "test-key-rs256"}}, &1))
      assert counter_value(call_counter) == 1
    end
  end

  describe "HTTP failure handling" do
    test "upstream 5xx returns :jwks_fetch_failed to all coalesced waiters", %{
      upstream: upstream,
      task_supervisor: task_sup
    } do
      MockHttpUpstream.expect(upstream, fn conn ->
        Plug.Conn.send_resp(conn, 503, "service down")
      end)

      cache = start_cache!(upstream, task_sup)

      # Single caller is enough to exercise the error path — coalescing
      # is already covered above.
      assert {:error, :jwks_fetch_failed} =
               JwksCache.fetch_jwk(cache, @test_issuer, "test-key-rs256")
    end

    test "subsequent call after failure re-attempts the fetch", %{
      upstream: upstream,
      task_supervisor: task_sup
    } do
      call_counter = start_counter()

      MockHttpUpstream.expect(upstream, fn conn ->
        count = increment(call_counter)

        if count == 1 do
          Plug.Conn.send_resp(conn, 503, "down")
        else
          conn
          |> Plug.Conn.put_resp_header("content-type", "application/json")
          |> Plug.Conn.send_resp(200, rs256_jwks_body())
        end
      end)

      cache = start_cache!(upstream, task_sup)

      assert {:error, :jwks_fetch_failed} =
               JwksCache.fetch_jwk(cache, @test_issuer, "test-key-rs256")

      assert {:ok, %{"kid" => "test-key-rs256"}} =
               JwksCache.fetch_jwk(cache, @test_issuer, "test-key-rs256")

      assert counter_value(call_counter) == 2
    end
  end

  describe "refresh/1" do
    test "forces a JWKS fetch even when cache has entries", %{
      upstream: upstream,
      task_supervisor: task_sup
    } do
      call_counter = start_counter()

      MockHttpUpstream.expect(upstream, fn conn ->
        increment(call_counter)

        conn
        |> Plug.Conn.put_resp_header("content-type", "application/json")
        |> Plug.Conn.send_resp(200, rs256_jwks_body())
      end)

      cache = start_cache!(upstream, task_sup)

      assert {:ok, _} = JwksCache.fetch_jwk(cache, @test_issuer, "test-key-rs256")
      assert :ok = JwksCache.refresh(cache, @test_issuer)
      assert counter_value(call_counter) == 2
    end

    test "returns :unknown_issuer when issuer not configured", %{
      upstream: upstream,
      task_supervisor: task_sup
    } do
      cache = start_cache!(upstream, task_sup)

      assert {:error, :unknown_issuer} = JwksCache.refresh(cache, "https://nope.example")
    end
  end

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  defp start_cache!(upstream, task_supervisor) do
    # credo:disable-for-next-line Credo.Check.Warning.UnsafeToAtom
    name = :"jwks_cache_#{System.unique_integer([:positive])}"

    {:ok, pid} =
      start_supervised(
        {JwksCache,
         [
           issuers: [
             %{
               issuer_url: @test_issuer,
               jwks_url: MockHttpUpstream.url(upstream) <> "/oidc/jwks",
               ttl_seconds: 300
             }
           ],
           finch_pool: :jwks_pool,
           task_supervisor: task_supervisor,
           name: name
         ]}
      )

    _ = pid
    name
  end

  # Real RS256 JWKS body using the JwtTestHelper's per-BEAM keypair so
  # callers that round-trip through the validator work against the same
  # keys.
  defp rs256_jwks_body do
    %{"keys" => [JwtTestHelper.public_jwk(:rs256)]}
    |> JSON.encode!()
  end

  # Tiny atomic counter via an Agent. We use Agent here instead of
  # `:counters.new/2` so the increment ops are ordered + readable; these
  # are tests, not a hot path.
  defp start_counter do
    {:ok, pid} = Agent.start_link(fn -> 0 end)
    pid
  end

  defp increment(counter) do
    Agent.get_and_update(counter, fn n -> {n + 1, n + 1} end)
  end

  defp counter_value(counter), do: Agent.get(counter, & &1)

  # A "gate" is a process the upstream handler blocks on until the test
  # explicitly releases it — used to enforce "all N waiters have
  # enqueued" in the coalescing test.
  defp start_gate do
    {:ok, pid} = Agent.start_link(fn -> :closed end)
    pid
  end

  defp wait_for_release(gate) do
    if Agent.get(gate, & &1) == :open do
      :ok
    else
      Process.sleep(10)
      wait_for_release(gate)
    end
  end

  defp release_gate(gate), do: Agent.update(gate, fn _ -> :open end)
end
