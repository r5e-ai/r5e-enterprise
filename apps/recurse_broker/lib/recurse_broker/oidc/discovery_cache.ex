defmodule RecurseBroker.OIDC.DiscoveryCache do
  @moduledoc """
  OIDC discovery + JWKS cache for the Recurse Standalone Identity Broker
  (F002 T082).

  ## Iron Law decision (otp-thinking)

  This is one of the two **legitimate** GenServers in the broker (the
  other is `RecurseBroker.JWT.KeyRing`). Each of the three Iron Law
  checks answers YES:

    1. Mutable state persisting across calls? YES — we hold customer-IdP
       JWKS keyed `{issuer, kid}` with a TTL, across many incoming
       `fetch_jwks/2` calls.
    2. Concurrent execution / serialization? YES — when N concurrent
       callers miss the cache on the same `{issuer, kid}` we MUST
       coalesce them behind a single outbound HTTP fetch. Without the
       GenServer's serial `handle_call` we'd get a thundering herd
       against the customer's IdP (the exact failure mode described in
       `contracts/property_test_surface_catalog_f002.md` §Surface P).
    3. Fault isolation? YES — the DiscoveryCache is supervised by
       `RecurseBroker.Application` with `:one_for_one` so a crash on a
       malformed JWKS response can't take the HTTP endpoint down.

  **Read-path bypass**: the `fetch_jwks/2` fast-path reads ETS directly
  (no `GenServer.call`) so an already-cached lookup doesn't serialize
  against the single GenServer process. Only misses hit the GenServer
  for coalesced refresh.

  ## ETS layout

    * Table name: `:recurse_broker_oidc_cache` (`:named_table, :public,
      :set, read_concurrency: true`).
    * Key: `{issuer_binary, kid_binary}`.
    * Value: `{jwk_map, inserted_at_monotonic_seconds}`.

  TTL is LAZY: entries can linger in ETS past TTL. A kid-miss triggers
  a refresh. This matches FR-007 "refresh on kid-miss" behavior; we
  don't run a periodic sweep because stale entries have bounded blast
  radius (signature verify via `Validator` will still fail against an
  unused key).

  ## Coalescing

  The GenServer state holds `%{pending: %{issuer => [from_list]}}`. If
  `{:fetch, issuer, kid}` arrives while an identical `issuer` fetch is
  in flight, the caller's `from` is appended; no second HTTP fetch is
  launched. When the fetch Task finishes, we reply to every `from` in
  the list with the same result. Kid-miss within the same issuer fetch
  is implicit — fetching the discovery doc + JWKS for an issuer
  refreshes ALL kids for that issuer.

  Fetches are launched via `Task.Supervisor.start_child/2` against
  `RecurseBroker.OIDC.TaskSupervisor` (fire-and-forget + send-back via
  a tagged message). The dedicated supervisor — rather than `spawn/1`
  or a linked `Task` — is what we want here: tasks are observable, get
  proper graceful shutdown, and CANNOT propagate failures into the
  GenServer (the supervisor isn't linked to the cache process). A
  fetcher crash surfaces as a missing `{:__fetch_complete__, ...}`
  message; the GenServer's coalesced waiters reach their call
  timeout, which is the documented failure mode.

  ## HTTP layer

  `Req` is the client. By default Req builds its own Finch pool; we
  name one (`:broker_jwks_pool`) when started so telemetry + pool
  sizing are under our control. Pool startup is OPT-IN via
  `Application.get_env(:recurse_broker, :jwks_finch_pool, nil)` — if
  absent, Req's default pool is used (fine for tests + first-run
  demos). The pool itself is started by `RecurseBroker.Application`
  only when configured; this module does NOT start it from `init/1`.

  Tests DI via `:req_opts` on `start_link` — e.g.
  `[req_opts: [plug: fn conn -> ... end]]` for a full Plug-stub fake
  that doesn't open a socket. See `test/oidc/discovery_cache_test.exs`
  (SA3's T081) for the fixture shape.

  ## Time source DI

  `:now_monotonic` is an arity-0 fn, defaulting to
  `System.monotonic_time/1 :: seconds`. Tests override to fast-forward
  past TTL without sleeping.

  ## Public API

    * `start_link/1` — standard supervisor-invoked GenServer boot.
      Opts: `:req_opts`, `:now_monotonic`, `:ttl_seconds` (default 3600).
    * `fetch_jwks/2` — `(issuer, kid)` → `{:ok, jwk_map} | {:error, atom}`.
      Fast-path ETS read; on miss, GenServer.call for coalesced refresh.
    * `__reset_for_tests__/0` — `@doc false`. Clears ETS + in-flight map.

  ## Error atoms

    * `:oidc_discovery_failed` — `.well-known/openid-configuration` fetch
      (or parse of `jwks_uri`) failed.
    * `:jwks_fetch_failed` — JWKS URL fetch (or key parsing) failed.
    * `:unknown_kid` — discovery + JWKS fetch succeeded, but no key in
      the returned set matches the requested kid. This is a valid
      terminal state — the issuer is reachable, the token just
      references a kid they've rotated away.

  ## Cross-references

    * `specs/002-standalone-gateway-vertical-slice/research.md` D2
      (OIDC discovery + JWKS caching pattern)
    * `specs/002-standalone-gateway-vertical-slice/contracts/recurse_broker_api.md`
      (JWKS + discovery rules; kid-miss refresh semantics)
    * `specs/002-standalone-gateway-vertical-slice/contracts/property_test_surface_catalog_f002.md`
      §Surface P (coalesced-refresh race property)
    * `specs/002-standalone-gateway-vertical-slice/tasks.md` T025, T082, T081

  ## See also

  `Recurse.Gateway.Identity.JwksCache` is a structurally similar JWKS-
  caching GenServer but differs in three ways: (1) it caches a
  statically-configured issuer list (set at boot); (2) it uses
  `Task.Supervisor.async_nolink` for refresh coalescing; (3) it flows
  through the `:jwks_pool` Finch pool. A shared abstraction was
  considered during Phase-10 refactor review and declined — the
  divergent cache-population models would force one cache into the
  other's shape.
  """

  use GenServer

  @ets_table :recurse_broker_oidc_cache
  @default_ttl_seconds 3600

  @type issuer :: String.t()
  @type kid :: String.t()
  @type jwk :: map()
  @type fetch_error :: :oidc_discovery_failed | :jwks_fetch_failed | :unknown_kid

  # ---------------------------------------------------------------------------
  # Public API
  # ---------------------------------------------------------------------------

  @doc """
  Start the DiscoveryCache GenServer registered under the module name.

  Opts:

    * `:req_opts` — keyword list passed straight into every `Req.get/2`
      call (e.g. `[plug: fn conn -> ... end]` for test stubbing).
    * `:now_monotonic` — arity-0 fn returning monotonic seconds. Test DI.
    * `:ttl_seconds` — cache TTL (default `3600`). Note: TTL is lazy —
      entries live in ETS past TTL until a miss triggers refresh.
  """
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Fetch a JWK for `{issuer, kid}`.

  Fast-path: direct ETS read (no GenServer round-trip). On miss, the
  request is routed through `GenServer.call/2` where identical in-flight
  fetches are coalesced.
  """
  @spec fetch_jwks(issuer(), kid()) :: {:ok, jwk()} | {:error, fetch_error() | :not_started}
  def fetch_jwks(issuer, kid) when is_binary(issuer) and is_binary(kid) do
    case ets_lookup(issuer, kid) do
      {:ok, jwk} ->
        {:ok, jwk}

      :miss ->
        # Route to GenServer for coalesced refresh. 10s timeout covers
        # worst-case OIDC discovery + JWKS fetch over a congested link
        # without letting a stuck fetcher hang the caller indefinitely.
        try do
          GenServer.call(__MODULE__, {:fetch, issuer, kid}, 10_000)
        catch
          :exit, {:noproc, _} -> {:error, :not_started}
          :exit, {:timeout, _} -> {:error, :jwks_fetch_failed}
        end
    end
  end

  @doc false
  # Test helper. Clears ETS + in-flight coalescing state so
  # contract/property tests can reset between scenarios without
  # restarting the GenServer.
  @spec __reset_for_tests__() :: :ok
  def __reset_for_tests__ do
    case :ets.whereis(@ets_table) do
      :undefined -> :ok
      _tid -> :ets.delete_all_objects(@ets_table)
    end

    GenServer.call(__MODULE__, :__reset_pending_for_tests__, 1000)
  catch
    :exit, _ -> :ok
  end

  # ---------------------------------------------------------------------------
  # GenServer callbacks
  # ---------------------------------------------------------------------------

  @impl true
  def init(opts) do
    # Create the shared ETS table. `:public` so read callers don't route
    # through the GenServer on cache hits; `:set` since `{issuer, kid}` is
    # a unique key; `read_concurrency: true` tunes for the read-heavy
    # workload per otp-thinking guidance.
    :ets.new(@ets_table, [:named_table, :public, :set, read_concurrency: true])

    state = %{
      req_opts: Keyword.get(opts, :req_opts, []),
      ttl_seconds: Keyword.get(opts, :ttl_seconds, @default_ttl_seconds),
      now_monotonic: Keyword.get(opts, :now_monotonic, &default_now_monotonic/0),
      # `pending` maps `issuer -> [ {from, kid} ]`. When a fetch for
      # `issuer` completes we drain the list and reply to every entry
      # (each with its own requested kid so kid-miss-within-known-issuer
      # still resolves correctly).
      pending: %{}
    }

    {:ok, state}
  end

  @impl true
  def handle_call({:fetch, issuer, kid}, from, state) do
    # Double-check ETS under the GenServer — a concurrent fetch may
    # have populated the key between the caller's fast-path miss and
    # our receiving their call.
    case ets_lookup(issuer, kid) do
      {:ok, jwk} ->
        {:reply, {:ok, jwk}, state}

      :miss ->
        case Map.get(state.pending, issuer) do
          nil ->
            # First request for this issuer — spawn an off-GenServer fetch.
            _task_pid = spawn_fetch(issuer, state)
            new_pending = Map.put(state.pending, issuer, [{from, kid}])
            {:noreply, %{state | pending: new_pending}}

          waiters when is_list(waiters) ->
            # Coalesce: append without spawning.
            new_pending = Map.put(state.pending, issuer, [{from, kid} | waiters])
            {:noreply, %{state | pending: new_pending}}
        end
    end
  end

  @impl true
  def handle_call(:__reset_pending_for_tests__, _from, state) do
    {:reply, :ok, %{state | pending: %{}}}
  end

  @impl true
  # Fetch-worker callback. `result` is `{:ok, [jwk_map]}` on success or
  # `{:error, atom}` on any failure. We write ETS + drain waiters.
  def handle_info({:__fetch_complete__, issuer, result}, state) do
    {waiters, new_pending} = Map.pop(state.pending, issuer, [])
    waiters = Enum.reverse(waiters)

    drain_waiters(issuer, waiters, result, state.now_monotonic)

    {:noreply, %{state | pending: new_pending}}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # ---------------------------------------------------------------------------
  # Private — ETS
  # ---------------------------------------------------------------------------

  defp ets_lookup(issuer, kid) do
    case :ets.whereis(@ets_table) do
      :undefined ->
        :miss

      _tid ->
        case :ets.lookup(@ets_table, {issuer, kid}) do
          [{_, {jwk, _inserted_at}}] -> {:ok, jwk}
          [] -> :miss
        end
    end
  end

  # Reply to every coalesced waiter for this issuer. Extracted out of
  # `handle_info/2` to keep its depth within Credo's default `max_depth: 2`.
  defp drain_waiters(issuer, waiters, {:ok, jwks_list}, now_monotonic) do
    now = now_monotonic.()
    write_ets(issuer, jwks_list, now)
    Enum.each(waiters, fn waiter -> reply_to_waiter(issuer, waiter) end)
  end

  defp drain_waiters(_issuer, waiters, {:error, reason}, _now_monotonic) do
    Enum.each(waiters, fn {from, _kid} -> GenServer.reply(from, {:error, reason}) end)
  end

  defp reply_to_waiter(issuer, {from, kid}) do
    reply =
      case ets_lookup(issuer, kid) do
        {:ok, jwk} -> {:ok, jwk}
        :miss -> {:error, :unknown_kid}
      end

    GenServer.reply(from, reply)
  end

  defp write_ets(issuer, jwks_list, now) do
    Enum.each(jwks_list, fn jwk ->
      case Map.get(jwk, "kid") do
        kid when is_binary(kid) ->
          :ets.insert(@ets_table, {{issuer, kid}, {jwk, now}})

        _ ->
          # A JWKS entry with no kid is useless for our keying scheme
          # (we need `{issuer, kid}` lookups). Skip rather than crash
          # the whole fetch — other keys in the same set may be fine.
          :ok
      end
    end)
  end

  # ---------------------------------------------------------------------------
  # Private — fetch task
  # ---------------------------------------------------------------------------

  # Spawn a fresh process to do the HTTP work off-GenServer. We use
  # `Task.Supervisor.start_child/2` (not `spawn/1` and not
  # `Task.async/1`) so the fetcher is supervised — observable +
  # gracefully shut down on app stop — but NOT linked to this
  # GenServer (a fetcher crash must surface via a missing send-back,
  # not a GenServer EXIT). The supervisor is started by
  # `RecurseBroker.Application` ahead of this cache; if it's missing
  # we fall back to a bare `spawn/1` so unsupervised tests still work.
  defp spawn_fetch(issuer, state) do
    parent = self()
    req_opts = state.req_opts

    fun = fn ->
      result = do_fetch(issuer, req_opts)
      send(parent, {:__fetch_complete__, issuer, result})
    end

    case Process.whereis(RecurseBroker.OIDC.TaskSupervisor) do
      nil ->
        # Test posture or boot race — fall back to unsupervised spawn.
        # Production always has the supervisor live (started before
        # this cache in the application tree).
        spawn(fun)

      _pid ->
        {:ok, task_pid} =
          Task.Supervisor.start_child(RecurseBroker.OIDC.TaskSupervisor, fun)

        task_pid
    end
  end

  defp do_fetch(issuer, req_opts) do
    with {:ok, jwks_uri} <- fetch_discovery(issuer, req_opts),
         {:ok, keys} <- fetch_jwks_document(jwks_uri, req_opts) do
      {:ok, keys}
    end
  end

  defp fetch_discovery(issuer, req_opts) do
    url = issuer |> String.trim_trailing("/") |> Kernel.<>("/.well-known/openid-configuration")

    case Req.get(url, req_opts) do
      {:ok, %Req.Response{status: 200, body: body}} ->
        case extract_jwks_uri(body) do
          {:ok, uri} -> {:ok, uri}
          :error -> {:error, :oidc_discovery_failed}
        end

      {:ok, %Req.Response{}} ->
        {:error, :oidc_discovery_failed}

      {:error, _reason} ->
        {:error, :oidc_discovery_failed}
    end
  rescue
    _ -> {:error, :oidc_discovery_failed}
  end

  # Req is configured via `:json` header default to decode application/json.
  # Some IdPs return text/plain anyway — accept both shapes.
  defp extract_jwks_uri(%{"jwks_uri" => uri}) when is_binary(uri), do: {:ok, uri}

  defp extract_jwks_uri(body) when is_binary(body) do
    case JSON.decode(body) do
      {:ok, %{"jwks_uri" => uri}} when is_binary(uri) -> {:ok, uri}
      _ -> :error
    end
  rescue
    _ -> :error
  end

  defp extract_jwks_uri(_), do: :error

  defp fetch_jwks_document(uri, req_opts) do
    case Req.get(uri, req_opts) do
      {:ok, %Req.Response{status: 200, body: body}} ->
        case extract_keys(body) do
          {:ok, keys} -> {:ok, keys}
          :error -> {:error, :jwks_fetch_failed}
        end

      {:ok, %Req.Response{}} ->
        {:error, :jwks_fetch_failed}

      {:error, _reason} ->
        {:error, :jwks_fetch_failed}
    end
  rescue
    _ -> {:error, :jwks_fetch_failed}
  end

  defp extract_keys(%{"keys" => keys}) when is_list(keys), do: {:ok, keys}

  defp extract_keys(body) when is_binary(body) do
    case JSON.decode(body) do
      {:ok, %{"keys" => keys}} when is_list(keys) -> {:ok, keys}
      _ -> :error
    end
  rescue
    _ -> :error
  end

  defp extract_keys(_), do: :error

  defp default_now_monotonic do
    System.monotonic_time(:second)
  end
end
