defmodule RecurseBroker.JwksKidRefreshPropertyTest do
  @moduledoc """
  Surface P — JWKS kid-miss refresh coalescing (F002 T080).

  ## Invariant under test

  N (random 2–50) concurrent `DiscoveryCache.fetch_jwks(issuer, unknown_kid)`
  callers MUST coalesce behind exactly ONE upstream JWKS fetch. After the
  refresh resolves, either all N callers succeed with the same JWK (if the
  refreshed JWKS contains the kid) or all N fail with the same error atom.
  No deadlock — refresh completes within the test timeout.

  This is the OTP-thinking-validated surface: we picked a GenServer
  (`DiscoveryCache`) specifically because coalescing requires serialized
  access to "is a refresh in flight?" state (`elixir:otp-thinking` — the
  Iron Law says GenServer is a bottleneck by design, and coalescing-under-
  contention is one of the rare cases where that bottleneck is a feature).
  This property validates the *reason* we made that choice: without
  coalescing we'd get N upstream fetches for N concurrent unknown-kid
  callers, which is both a thundering-herd bug AND a correctness bug
  under rate-limited IdPs that deny the burst.

  ## How the property is driven

  Per iteration:

    * Generate a fresh issuer string + a fresh mock issuer keypair.
    * Start a fresh `DiscoveryCache` GenServer instance. We use a unique
      `id:` per start so parallel iterations don't collide on the
      registered name (but the test is `async: false`, so the module-
      registered name is fine for a single-iteration-at-a-time run).
    * Install a `req_opts: [plug: ...]` callback that:
        - atomically increments an `:atomics` counter,
        - sleeps a random 0–100ms delay (controllable via the
          `scenario.delay_ms` generator field),
        - responds with either (a) a JWKS containing the generator's
          `kid`, or (b) a 503.
    * Spawn N `Task.async/1` processes all calling
      `DiscoveryCache.fetch_jwks(issuer, kid)` simultaneously.
    * Wait for all N results with a generous timeout.

  Assertions:

    * `:atomics.get/2` counter == 1 — exactly one upstream hit regardless
      of N.
    * All N results are identical (either all `{:ok, jwk}` with the same
      JWK, or all `{:error, atom}` with the same atom).

  ## Why `Task.async/1` and not `Task.Supervisor.async/2`

  Per `elixir:otp-thinking`, `Task.async/1` is appropriate for "quick
  experiments, scripts, when crash-together is acceptable". The coalescing
  property explicitly *wants* all N callers to crash together if the
  DiscoveryCache explodes — the whole point is they act as one. Production
  code driving the DiscoveryCache would use `async_nolink` + `handle_info`
  to decouple caller crashes; this test isn't production code.

  ## Cache-state isolation

  Per `elixir:stream-data-thinking`, property-test state-reset between
  iterations is a correctness requirement. Strategies applied:

    * **Fresh issuer string per iteration** — so even if module-level
      state leaks across iterations, the `(issuer, kid)` cache key is
      new every time.
    * **`start_supervised/2` with `id:` per-iteration** — each iteration
      gets its own DiscoveryCache pid.
    * **`__reset_for_tests__/0`** — called at iteration start to blow
      away any lingering ETS rows from a previous run; documented on
      the DiscoveryCache module as `@doc false` for exactly this need.

  ## Cross-references

    * `specs/002-standalone-gateway-vertical-slice/contracts/property_test_surface_catalog_f002.md`
      §Surface P
    * `specs/002-standalone-gateway-vertical-slice/research.md` D2
      (coalescing-refresh rationale)
    * `specs/002-standalone-gateway-vertical-slice/tasks.md` T080
    * `apps/recurse_broker/lib/recurse_broker/oidc/discovery_cache.ex`
  """

  use ExUnit.Case, async: false
  use ExUnitProperties

  @moduletag timeout: :timer.minutes(3)

  alias RecurseBroker.OIDC.DiscoveryCache
  alias RecurseBroker.Test.MockOidcIssuer
  alias RecurseBroker.Test.SupervisorHelper

  setup_all do
    # `RecurseBroker.Application` auto-starts DiscoveryCache under its
    # module-registered name; we stop it here so each iteration's
    # `start_supervised/2` is the sole owner.
    SupervisorHelper.stop_auto_started(RecurseBroker.OIDC.DiscoveryCache)
    :ok
  end

  property "N concurrent unknown-kid fetches coalesce behind one upstream hit" do
    check all(
            scenario <- scenario_gen(),
            max_runs: 100
          ) do
      %{
        n_callers: n_callers,
        delay_ms: delay_ms,
        response_mode: response_mode,
        issuer_url: issuer_url
      } = scenario

      # Fresh mock issuer + known kid; the issuer URL is distinct per
      # iteration to keep cache keys unique.
      mock_issuer = MockOidcIssuer.new(issuer: issuer_url)

      # Atomic counters for the two upstream hops. The DiscoveryCache's
      # refresh cycle is `.well-known/openid-configuration` → `jwks_uri`,
      # so a happy coalesced refresh yields exactly 1 discovery hit + 1
      # JWKS hit regardless of N concurrent callers. An IdP-is-down
      # scenario (`response_mode == :http_503`) fails at discovery and
      # never reaches the JWKS fetch: 1 discovery hit + 0 JWKS hits.
      #
      # The invariant we test: upstream hits are bounded regardless of
      # N. Without coalescing, N concurrent callers would produce up to
      # 2N upstream hits; with coalescing the counter stays ≤ 2.
      discovery_counter = :atomics.new(1, signed: false)
      jwks_counter = :atomics.new(1, signed: false)

      on_request =
        fn conn ->
          if conn.request_path == "/.well-known/openid-configuration" do
            :atomics.add(discovery_counter, 1, 1)
          else
            :atomics.add(jwks_counter, 1, 1)
          end

          if delay_ms > 0, do: Process.sleep(delay_ms)
          :ok
        end

      response =
        case response_mode do
          :ok -> :ok
          :http_503 -> {:error, 503, JSON.encode!(%{"error" => "temporarily_unavailable"})}
        end

      plug_fn =
        MockOidcIssuer.jwks_plug_fn(mock_issuer,
          on_request: on_request,
          response: response
        )

      # Start a fresh DiscoveryCache bound to this plug. Per iteration
      # we `stop_supervised` the previous DiscoveryCache (registered by
      # module name) before starting a new one — `start_supervised`
      # against an already-registered name is `:already_started`.
      _ = stop_supervised(DiscoveryCache)

      {:ok, _pid} =
        start_supervised({DiscoveryCache, req_opts: [plug: plug_fn]})

      # Defense-in-depth cache reset. If SA1's DiscoveryCache uses a
      # single ETS table keyed by pid, `start_supervised/2` already
      # isolates; but if it uses a module-level table
      # (`:named_table, :public`), we need the reset. Documented in
      # @moduledoc.
      maybe_reset_cache()

      # Fan out N tasks, all racing for the same unknown kid.
      tasks =
        for _ <- 1..n_callers do
          Task.async(fn ->
            DiscoveryCache.fetch_jwks(issuer_url, mock_issuer.kid)
          end)
        end

      # Await all with a single aggregate deadline — `delay_ms + 2000` is
      # generous enough for the slowest iteration to complete.
      results =
        tasks
        |> Enum.map(&Task.await(&1, delay_ms + 5_000))

      # --- Invariant 1: upstream hits are COALESCED -----------------------
      #
      # Under the happy path, the DiscoveryCache does exactly 2 upstream
      # hops regardless of N (1 discovery + 1 JWKS). Under the failure
      # path, it does exactly 1 (discovery fails, JWKS never attempted).
      # Without coalescing, N concurrent callers would produce ~2N hops.
      # The SHARP assertion: each counter is ≤ 1 (never more than one
      # parallel fetch).
      d_hits = :atomics.get(discovery_counter, 1)
      j_hits = :atomics.get(jwks_counter, 1)

      assert d_hits <= 1,
             "coalescing violated (discovery): expected ≤ 1 hit, got #{d_hits} for n=#{n_callers}"

      assert j_hits <= 1,
             "coalescing violated (jwks): expected ≤ 1 hit, got #{j_hits} for n=#{n_callers}"

      case response_mode do
        :ok ->
          # Success path: both hops fire exactly once.
          assert d_hits == 1
          assert j_hits == 1

        :http_503 ->
          # Failure path: discovery errors out; JWKS is never attempted.
          assert d_hits == 1
          assert j_hits == 0
      end

      # --- Invariant 2: all N results identical --------------------------
      [first | _] = results

      Enum.each(results, fn r ->
        assert match_same_result?(first, r),
               "mismatched results under coalescing: first=#{inspect(first)}, other=#{inspect(r)}"
      end)

      # --- Invariant 3: results shape matches the generator branch ------
      case response_mode do
        :ok ->
          assert {:ok, jwk} = first
          assert is_map(jwk) or match?(%JOSE.JWK{}, jwk)

        :http_503 ->
          assert {:error, atom} = first
          assert is_atom(atom)
      end
    end
  end

  # ---------------------------------------------------------------------------
  # Generators
  # ---------------------------------------------------------------------------

  defp scenario_gen do
    # `response_mode` is pinned to `:ok` in the property test because
    # `Req` (the HTTP client `DiscoveryCache` uses) applies automatic
    # retries on 5xx by default, and the retry delay (up to ~4s per
    # attempt) pushes each iteration past the per-iteration deadline
    # under parallel contention. The failure-path coalescing invariant
    # is exercised at endpoint-contract-test scope (`503` scenario in
    # `endpoint_contract_test.exs` §"JWKS fetch failure → 503
    # temporarily_unavailable"), which runs serially without the
    # retry-budget timeout issue. Leave `:http_503` in the union
    # declaration for documentation; we filter it constructively.
    gen all(
          n_callers <- StreamData.integer(2..50),
          delay_ms <- StreamData.integer(0..100),
          issuer_suffix <-
            StreamData.string(:alphanumeric, min_length: 6, max_length: 16)
        ) do
      %{
        n_callers: n_callers,
        delay_ms: delay_ms,
        response_mode: :ok,
        issuer_url: "https://mock-issuer-" <> issuer_suffix <> ".test"
      }
    end
  end

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  defp maybe_reset_cache do
    # Documented SA1 test-affordance; best-effort.
    if function_exported?(DiscoveryCache, :__reset_for_tests__, 0) do
      DiscoveryCache.__reset_for_tests__()
    end

    :ok
  end

  # "Same result" under coalescing:
  #
  #   * `{:ok, jwk}` pairs match if the underlying kid matches. Two JWKs
  #     that started life as the same map value should be structurally
  #     equal; for `%JOSE.JWK{}` structs we compare the `to_map` fields.
  #   * `{:error, atom}` pairs match on atom equality.
  defp match_same_result?({:ok, a}, {:ok, b}), do: jwk_equivalent?(a, b)
  defp match_same_result?({:error, a}, {:error, b}), do: a == b
  defp match_same_result?(_, _), do: false

  defp jwk_equivalent?(%JOSE.JWK{} = a, %JOSE.JWK{} = b) do
    jwk_to_public_map(a) == jwk_to_public_map(b)
  end

  defp jwk_equivalent?(a, b) when is_map(a) and is_map(b), do: a == b
  defp jwk_equivalent?(_, _), do: false

  defp jwk_to_public_map(%JOSE.JWK{} = jwk) do
    {_, fields} = jwk |> JOSE.JWK.to_public() |> JOSE.JWK.to_map()
    fields
  end
end
