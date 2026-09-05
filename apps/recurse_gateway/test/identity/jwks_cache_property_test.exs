defmodule Recurse.Gateway.Identity.JwksCachePropertyTest do
  @moduledoc """
  Surface P — Gateway JWKS kid-miss refresh coalescing (F002 T096).

  ## Invariant under test

  Parallel to broker-side T080 (`apps/recurse_broker/test/jwks_kid_refresh_property_test.exs`)
  but driven against the Gateway's `Recurse.Gateway.Identity.JwksCache`
  GenServer rather than the broker's `DiscoveryCache`.

  N (random 2–50) concurrent `JwksCache.fetch_jwk/3` callers on an
  unknown-to-cache `kid` MUST coalesce behind exactly ONE upstream JWKS
  fetch. After the refresh resolves, either:

    * all N callers receive `{:ok, jwk}` with the kid from the refreshed
      JWKS (success scenario), or
    * all N callers receive `{:error, :jwks_fetch_failed}` (upstream
      error scenario) — and crucially, the error atom must be identical
      across all callers.

  No deadlock: every iteration's N tasks return within the aggregated
  timeout.

  ## Why this property matters

  Without coalescing, N concurrent "unknown kid" requests would produce
  N upstream JWKS fetches — a thundering-herd bug that (a) wastes
  bandwidth on the identity broker + (b) triggers IdP rate limits that
  deny the burst and cause correctness failures mid-request. The
  `JwksCache` GenServer centralizes a "is a refresh in flight?" check
  so the first miss starts a single Task.Supervisor-managed fetch and
  every subsequent N-1 miss parks behind the same task.

  This is the Iron-Law-validated GenServer:

    1. Mutable state across calls? YES — fetched JWKS keys +
       `refresh_coalescing` waiter list.
    2. Fault isolation? YES — a crashed refresh must not tear down
       callers; supervisor restarts a clean cache.
    3. Serialized access? YES — coalescing requires a single
       authoritative "who's refreshing now" state.

  ## How the property is driven

  Per iteration:

    * Start a fresh `Recurse.Providers.Support.MockHttpUpstream`
      (ephemeral port, per-test) + its companion Agent.
    * Install an `expect/2` callback that:
        - atomically increments a counter via `:atomics`,
        - sleeps 0–100ms to widen the coalescing window,
        - responds with a small RS256 JWKS containing the configured
          kid (success scenario) OR a 503 body (failure scenario).
    * Start a fresh `JwksCache` GenServer bound to the mock's URL, under
      a unique `:name` so iterations don't collide.
    * Spawn N `Task.async` tasks that all call `fetch_jwk(cache, issuer,
      kid)` simultaneously.
    * Await all; assert.

  ## Why not extend JwksCache with an `:upstream_fetcher` DI opt?

  The task prompt suggested a `:upstream_fetcher` opt as the injection
  seat. Re-reading the existing cache shows the `:finch_pool` opt +
  `MockHttpUpstream` already provides an equivalent seam: the cache
  issues real HTTP through the configured pool to the mock's URL, so
  the coalescing semantics are exercised through the true code path
  — including the Task.Supervisor hand-off and `handle_info/2`
  completion. Adding a `:upstream_fetcher` would bypass that code
  path and weaken the test. Prefer the real-HTTP approach the
  existing `JwksCacheTest` already uses.

  ## Cache isolation between iterations

  Each iteration starts a fresh GenServer under a unique registered
  name via `start_supervised/2`. The GenServer state is process-local
  (no ETS, no `:persistent_term`), so iteration N cannot leak into
  iteration N+1. The `MockHttpUpstream` agent is likewise per-iteration.

  ## Cross-references

    * `specs/002-standalone-gateway-vertical-slice/contracts/property_test_surface_catalog_f002.md`
      §Surface P
    * `specs/002-standalone-gateway-vertical-slice/tasks.md` T096
    * `apps/recurse_broker/test/jwks_kid_refresh_property_test.exs` (sibling T080)
    * `apps/recurse_gateway/lib/recurse_gateway/identity/jwks_cache.ex`
  """

  use ExUnit.Case, async: false
  use ExUnitProperties

  @moduletag timeout: :timer.minutes(3)

  alias Recurse.Gateway.Identity.JwksCache
  alias Recurse.Gateway.Test.JwtTestHelper
  alias Recurse.Providers.Support.MockHttpUpstream

  property "N concurrent unknown-kid fetches coalesce behind one upstream hit" do
    check all(scenario <- scenario_gen(), max_runs: 100) do
      %{
        n_callers: n_callers,
        delay_ms: delay_ms,
        response_mode: response_mode,
        issuer_suffix: issuer_suffix
      } = scenario

      issuer_url = "https://mock-issuer-" <> issuer_suffix <> ".invalid"

      {:ok, upstream} = MockHttpUpstream.start()

      try do
        counter = :atomics.new(1, signed: false)

        MockHttpUpstream.expect(upstream, fn conn ->
          :atomics.add(counter, 1, 1)

          if delay_ms > 0, do: Process.sleep(delay_ms)

          case response_mode do
            :ok ->
              conn
              |> Plug.Conn.put_resp_header("content-type", "application/json")
              |> Plug.Conn.send_resp(200, jwks_body())

            :http_503 ->
              Plug.Conn.send_resp(conn, 503, ~s|{"error":"unavailable"}|)
          end
        end)

        cache = start_cache_for_iteration(upstream, issuer_url)

        tasks =
          for _ <- 1..n_callers do
            Task.async(fn ->
              JwksCache.fetch_jwk(cache, issuer_url, "test-key-rs256")
            end)
          end

        results = Enum.map(tasks, &Task.await(&1, delay_ms + 5_000))

        # --- Invariant 1: upstream hit count is ≤ 1 regardless of N ------
        hits = :atomics.get(counter, 1)

        assert hits <= 1,
               "coalescing violated: expected ≤ 1 upstream hit, got #{hits} for n=#{n_callers}"

        # Success path fires exactly once; 503-path ALSO fires once
        # (JwksCache does a single fetch; the error is surfaced to all
        # coalesced waiters).
        assert hits == 1, "expected exactly 1 upstream hit under coalescing, got #{hits}"

        # --- Invariant 2: all N results identical ------------------------
        [first | _rest] = results

        Enum.each(results, fn r ->
          assert same_result?(first, r),
                 "mismatched results under coalescing: first=#{inspect(first)}, other=#{inspect(r)}"
        end)

        # --- Invariant 3: result shape matches the scenario branch -------
        case response_mode do
          :ok ->
            assert {:ok, jwk} = first
            assert is_map(jwk)
            assert jwk["kid"] == "test-key-rs256"

          :http_503 ->
            assert {:error, :jwks_fetch_failed} = first
        end
      after
        MockHttpUpstream.stop(upstream)
      end
    end
  end

  # ---------------------------------------------------------------------------
  # Generators
  # ---------------------------------------------------------------------------

  defp scenario_gen do
    gen all(
          n_callers <- StreamData.integer(2..50),
          delay_ms <- StreamData.integer(0..100),
          response_mode <- StreamData.one_of([constant(:ok), constant(:http_503)]),
          issuer_suffix <-
            StreamData.string(:alphanumeric, min_length: 6, max_length: 16)
        ) do
      %{
        n_callers: n_callers,
        delay_ms: delay_ms,
        response_mode: response_mode,
        issuer_suffix: issuer_suffix
      }
    end
  end

  # ---------------------------------------------------------------------------
  # Per-iteration cache start
  # ---------------------------------------------------------------------------

  defp start_cache_for_iteration(upstream, issuer_url) do
    # credo:disable-for-next-line Credo.Check.Warning.UnsafeToAtom
    cache_name = :"jwks_cache_prop_#{System.unique_integer([:positive])}"

    # credo:disable-for-next-line Credo.Check.Warning.UnsafeToAtom
    task_sup = :"jwks_prop_task_sup_#{System.unique_integer([:positive])}"

    {:ok, _sup_pid} = start_supervised({Task.Supervisor, name: task_sup})

    {:ok, _cache_pid} =
      start_supervised(
        {JwksCache,
         [
           issuers: [
             %{
               issuer_url: issuer_url,
               jwks_url: MockHttpUpstream.url(upstream) <> "/oidc/jwks",
               ttl_seconds: 300
             }
           ],
           finch_pool: :jwks_pool,
           task_supervisor: task_sup,
           name: cache_name
         ]},
        id: cache_name
      )

    cache_name
  end

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  defp jwks_body do
    %{"keys" => [JwtTestHelper.public_jwk(:rs256)]}
    |> JSON.encode!()
  end

  # Define "same result" under coalescing:
  #
  #   * Both `{:ok, jwk}` with matching kid — we compare the kid field
  #     because the RS256 public JWK contains large base64 strings for
  #     `n` + `e` that can technically carry tiny encoding variations in
  #     unrelated test helpers, but the kid is our cache-lookup invariant.
  #   * Both `{:error, atom}` with identical atoms.
  defp same_result?({:ok, %{"kid" => kid}}, {:ok, %{"kid" => kid}}), do: true
  defp same_result?({:error, a}, {:error, a}), do: true
  defp same_result?(_, _), do: false
end
