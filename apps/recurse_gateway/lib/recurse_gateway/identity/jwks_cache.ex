defmodule Recurse.Gateway.Identity.JwksCache do
  @moduledoc """
  Per-issuer JWKS cache for Gateway-side JWT verification (F002 T042).

  ## Iron Law check (otp-thinking)

  This IS a legitimate GenServer. All three criteria met:

    1. Mutable state persisting across calls? YES — fetched JWKS
       mapped `{issuer_url => %{keys: %{kid => JWK}, last_fetch,
       ttl_seconds}}` plus the coalescing `from`-queue.
    2. Fault isolation? YES — a crashed refresh must not drag down the
       Gateway; supervisor restarts a clean cache state.
    3. Serialized access? YES — on `kid`-miss we MUST refresh exactly
       once across N concurrent callers (coalescing property, Surface P).

  ## Coalescing pattern (Surface P)

  When a `fetch_jwk(issuer, kid)` call misses, the GenServer checks
  whether a refresh is already in flight:

    - If NOT, kick off an async `Task` for that issuer's refresh and
      stash the caller's `from` under `refresh_coalescing[issuer]`.
    - If YES, append the caller's `from` to the same list.

  When the refresh completes (`handle_info/2` on a `Task` ref), EVERY
  stashed `from` is replied to with the result derived from the refreshed
  keys. Exactly one upstream HTTP request covers N concurrent callers.

  Why async `Task` + `handle_info` instead of blocking inside
  `handle_call`: a blocking `handle_call` with `GenServer.reply/2` from
  a spawned helper works, but we want to keep the GenServer responsive
  to OTHER issuers' requests during a slow JWKS fetch. Task supervision
  under `Task.Supervisor` gives us both.

  ## State shape

      %{
        issuers: %{
          issuer_url => %{
            jwks_url: String.t(),
            keys: %{kid => %JOSE.JWK{} | map()},
            last_fetch: DateTime.t() | nil,
            ttl_seconds: pos_integer()
          }
        },
        refresh_coalescing: %{
          issuer_url => %{
            task_ref: reference() | nil,
            waiters: [from]
          }
        },
        task_supervisor: Task.Supervisor | atom(),
        finch_pool: atom()
      }

  ## Boot config

      JwksCache.start_link(
        issuers: [
          %{
            issuer_url: "https://recurse-broker.corp.example",
            jwks_url: "https://recurse-broker.corp.example/oidc/jwks",
            ttl_seconds: 300
          }
        ],
        finch_pool: :jwks_pool,
        task_supervisor: Recurse.Gateway.Identity.JwksCache.TaskSupervisor
      )

  The `:jwks_pool` named Finch pool must already be started by
  `RecurseGateway.Application` (F002 T016). The Task supervisor is
  expected to live adjacent to the cache in the Gateway supervision tree
  (started by the same application).

  ## Cross-references

    * `specs/002-standalone-gateway-vertical-slice/research.md` D2
    * `specs/002-standalone-gateway-vertical-slice/contracts/property_test_surface_catalog_f002.md` §Surface P
    * `contracts/recurse_broker_api.md` GET /oidc/jwks response shape
    * F002 FR-007 (alg allowlist — enforced at JwtValidator, not here)

  ## See also

  `RecurseBroker.OIDC.DiscoveryCache` is a structurally similar JWKS-
  caching GenServer but differs in three ways: (1) it discovers issuers
  dynamically via OIDC well-known endpoints; (2) it uses a public ETS
  fast-path read that bypasses the GenServer; (3) it runs without a
  configured Finch pool (DI via `:req_opts`). A shared abstraction was
  considered during Phase-10 refactor review and declined — the
  divergent cache-population models would force one cache into the
  other's shape.
  """

  use GenServer

  require Logger

  @default_ttl_seconds 300
  @default_finch_pool :jwks_pool
  # 3s HTTP timeout matches :jwks_pool's configured transport timeout
  # (RecurseGateway.Application T016).
  @http_timeout_ms 3_000

  @type issuer_config :: %{
          required(:issuer_url) => String.t(),
          required(:jwks_url) => String.t(),
          optional(:ttl_seconds) => pos_integer()
        }

  @type init_opts :: [
          issuers: [issuer_config()],
          finch_pool: atom(),
          task_supervisor: module() | atom(),
          name: GenServer.name(),
          req_opts: keyword()
        ]

  # `:req_opts` is a keyword list merged into every `Req.new/1` call made
  # by the refresh task. Production leaves it `[]`; tests can pass
  # `[plug: fn conn, _opts -> ... end]` to redirect the upstream JWKS
  # fetch at an in-process stub without binding a real port. Matches the
  # shape exposed by `RecurseBroker.OIDC.DiscoveryCache` (sibling broker-
  # side cache) so the two caches share one DI convention. See F002 T096
  # (`jwks_cache_property_test.exs`) for the coalescing property that
  # exercises this seam under 2–50 concurrent callers.

  # ---------------------------------------------------------------------------
  # Public API
  # ---------------------------------------------------------------------------

  @doc """
  Start the cache. See moduledoc for `opts` schema.
  """
  @spec start_link(init_opts()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    name = Keyword.get(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, opts, name: name)
  end

  @doc """
  Resolve a `(issuer_url, kid)` to a JWK.

  Returns `{:ok, jwk}` if present in cache, `{:error, :unknown_issuer}`
  if the issuer was not configured at boot, or `{:error, :unknown_kid}`
  after a forced refresh still does not contain the kid, or
  `{:error, :jwks_fetch_failed}` if the refresh itself failed.

  Concurrent callers on the same `(issuer_url, unknown_kid)` coalesce
  behind a single refresh — Surface P invariant.

  `:infinity` call timeout: the refresh itself is bounded by the
  `:jwks_pool` HTTP timeout (3s per T016) + a small ceiling in this
  module; a misbehaving cache could still stall callers longer than a
  regular `GenServer.call` default (5s). Using `:infinity` makes the
  caller-side behavior "wait as long as the cache does," which is the
  desired semantic — the caller's request plug owns the outer
  request-deadline budget, not the cache.
  """
  @spec fetch_jwk(GenServer.server(), String.t(), String.t()) ::
          {:ok, map() | JOSE.JWK.t()}
          | {:error, :unknown_issuer | :unknown_kid | :jwks_fetch_failed}
  def fetch_jwk(server, issuer_url, kid)
      when is_binary(issuer_url) and is_binary(kid) do
    GenServer.call(server, {:fetch_jwk, issuer_url, kid}, :infinity)
  end

  @doc """
  Arity-2 convenience used by `JwtValidator.validate/2` when configured
  with `{:cache, __MODULE__}` — delegates to `fetch_jwk/3` on the
  default-named process.
  """
  @spec fetch_jwk(String.t(), String.t()) ::
          {:ok, map() | JOSE.JWK.t()}
          | {:error, :unknown_issuer | :unknown_kid | :jwks_fetch_failed}
  def fetch_jwk(issuer_url, kid) when is_binary(issuer_url) and is_binary(kid) do
    fetch_jwk(__MODULE__, issuer_url, kid)
  end

  @doc """
  Force-refresh the cache for a specific issuer. Blocks until the
  upstream JWKS fetch completes (or fails).
  """
  @spec refresh(GenServer.server(), String.t()) ::
          :ok | {:error, :unknown_issuer | :jwks_fetch_failed}
  def refresh(server \\ __MODULE__, issuer_url) do
    GenServer.call(server, {:refresh, issuer_url}, :infinity)
  end

  # ---------------------------------------------------------------------------
  # GenServer callbacks
  # ---------------------------------------------------------------------------

  @impl GenServer
  def init(opts) do
    issuers = Keyword.get(opts, :issuers, [])
    finch_pool = Keyword.get(opts, :finch_pool, @default_finch_pool)
    task_supervisor = Keyword.get(opts, :task_supervisor, Task.Supervisor)
    req_opts = Keyword.get(opts, :req_opts, [])

    issuers_state =
      Map.new(issuers, fn cfg ->
        {cfg.issuer_url,
         %{
           jwks_url: cfg.jwks_url,
           keys: %{},
           last_fetch: nil,
           ttl_seconds: Map.get(cfg, :ttl_seconds, @default_ttl_seconds)
         }}
      end)

    state = %{
      issuers: issuers_state,
      refresh_coalescing: %{},
      task_supervisor: task_supervisor,
      finch_pool: finch_pool,
      req_opts: req_opts
    }

    {:ok, state}
  end

  @impl GenServer
  def handle_call({:fetch_jwk, issuer_url, kid}, from, state) do
    case Map.fetch(state.issuers, issuer_url) do
      :error ->
        {:reply, {:error, :unknown_issuer}, state}

      {:ok, issuer_state} ->
        handle_fetch_attempt(issuer_url, issuer_state, kid, from, state)
    end
  end

  @impl GenServer
  def handle_call({:refresh, issuer_url}, from, state) do
    case Map.fetch(state.issuers, issuer_url) do
      :error ->
        {:reply, {:error, :unknown_issuer}, state}

      {:ok, _issuer_state} ->
        {:noreply, enqueue_refresh(issuer_url, {:refresh, from}, state)}
    end
  end

  # Task completion from `Task.Supervisor.async_nolink/2` — fired in
  # two shapes:
  #
  #   - `{ref, result}` — the actual refresh result
  #   - `{:DOWN, ref, :process, _pid, _reason}` — the task shut down
  #     after replying (`async_nolink` guarantees separation). We
  #     ignore these; coalesced state is cleared in the `{ref, result}`
  #     clause.
  @impl GenServer
  def handle_info({ref, result}, state) when is_reference(ref) do
    case find_by_task_ref(state, ref) do
      {:ok, issuer_url} ->
        Process.demonitor(ref, [:flush])
        {:noreply, complete_refresh(issuer_url, result, state)}

      :error ->
        {:noreply, state}
    end
  end

  def handle_info({:DOWN, _ref, :process, _pid, _reason}, state) do
    {:noreply, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # ---------------------------------------------------------------------------
  # Refresh orchestration.
  # ---------------------------------------------------------------------------

  # `{fetch, from, kid}` keeps us from replying `:unknown_kid` prematurely
  # when a caller hits a cache-miss and a refresh is already in flight —
  # we need to re-check the kid against the POST-refresh keys. The
  # `{:refresh, from}` shape is for explicit `refresh/1` callers who just
  # want :ok / {:error, _}.

  defp handle_fetch_attempt(issuer_url, issuer_state, kid, from, state) do
    if Map.has_key?(issuer_state.keys, kid) do
      {:reply, {:ok, issuer_state.keys[kid]}, state}
    else
      {:noreply, enqueue_refresh(issuer_url, {:fetch, from, kid}, state)}
    end
  end

  defp enqueue_refresh(issuer_url, waiter, state) do
    entry = Map.get(state.refresh_coalescing, issuer_url, %{task_ref: nil, waiters: []})
    entry = %{entry | waiters: [waiter | entry.waiters]}

    entry =
      if entry.task_ref == nil do
        start_refresh_task(issuer_url, entry, state)
      else
        entry
      end

    %{state | refresh_coalescing: Map.put(state.refresh_coalescing, issuer_url, entry)}
  end

  defp start_refresh_task(issuer_url, entry, state) do
    %{jwks_url: jwks_url} = state.issuers[issuer_url]
    finch_pool = state.finch_pool
    req_opts = state.req_opts

    task =
      Task.Supervisor.async_nolink(
        state.task_supervisor,
        fn -> do_http_fetch(jwks_url, finch_pool, req_opts) end
      )

    %{entry | task_ref: task.ref}
  end

  defp find_by_task_ref(state, ref) do
    Enum.find_value(state.refresh_coalescing, :error, fn
      {issuer_url, %{task_ref: ^ref}} -> {:ok, issuer_url}
      # Expected non-match: a different in-flight refresh's task_ref. Keep
      # iterating by returning nil. Any other shape is a programmer bug —
      # let it crash.
      {_issuer_url, %{task_ref: _other_ref}} -> nil
    end) || :error
  end

  defp complete_refresh(issuer_url, result, state) do
    %{waiters: waiters} = state.refresh_coalescing[issuer_url]
    now = DateTime.utc_now()

    {reply_state, reply_keys} =
      case result do
        {:ok, keys_map} ->
          issuers =
            Map.update!(state.issuers, issuer_url, fn entry ->
              %{entry | keys: keys_map, last_fetch: now}
            end)

          {%{state | issuers: issuers}, {:ok, keys_map}}

        {:error, reason} ->
          Logger.warning(fn ->
            "JWKS refresh failed for #{inspect(issuer_url)}: #{inspect(reason)}"
          end)

          {state, {:error, :jwks_fetch_failed}}
      end

    Enum.each(waiters, fn waiter -> reply_waiter(waiter, reply_keys) end)

    %{
      reply_state
      | refresh_coalescing: Map.delete(reply_state.refresh_coalescing, issuer_url)
    }
  end

  # Reply to a fetch waiter with the resolved kid (post-refresh lookup),
  # or `:unknown_kid` if the refreshed JWKS still doesn't carry it, or
  # `:jwks_fetch_failed` if refresh errored.
  defp reply_waiter({:fetch, from, kid}, {:ok, keys_map}) do
    case Map.fetch(keys_map, kid) do
      {:ok, jwk} -> GenServer.reply(from, {:ok, jwk})
      :error -> GenServer.reply(from, {:error, :unknown_kid})
    end
  end

  defp reply_waiter({:fetch, from, _kid}, {:error, :jwks_fetch_failed}) do
    GenServer.reply(from, {:error, :jwks_fetch_failed})
  end

  defp reply_waiter({:refresh, from}, {:ok, _keys_map}) do
    GenServer.reply(from, :ok)
  end

  defp reply_waiter({:refresh, from}, {:error, :jwks_fetch_failed}) do
    GenServer.reply(from, {:error, :jwks_fetch_failed})
  end

  # ---------------------------------------------------------------------------
  # HTTP fetch — runs under Task.Supervisor, NOT on the GenServer process.
  # Returns `{:ok, keys_map}` or `{:error, reason}`. No GenServer state is
  # touched here — we're a leaf in the supervision tree for the duration
  # of the fetch.
  # ---------------------------------------------------------------------------

  defp do_http_fetch(jwks_url, finch_pool, req_opts) do
    # Req disallows mixing `:finch` (named pool) with `:connect_options`
    # because connection options belong to the owning Finch pool's config,
    # not to the per-request call. Timeouts for :jwks_pool are set at the
    # pool level in RecurseGateway.Application (T016); we keep the
    # per-request receive_timeout as an upper bound.
    #
    # `req_opts` is caller-supplied DI (empty in production). When tests
    # pass `plug: fn conn, _ -> ... end`, Req short-circuits the entire
    # HTTP layer — we MUST drop `:finch` when a `:plug` is provided
    # because Req raises on the combination. That drop is pure test
    # seam; production `req_opts` is `[]` and the `:finch` pool remains.
    base =
      [
        url: jwks_url,
        receive_timeout: @http_timeout_ms,
        # JWKS endpoints respond with JSON; Req decodes automatically.
        decode_body: true,
        # We handle retry policy at the JwksCache / OIDC layer; Req's
        # default retries are too aggressive for a cache-miss hot path.
        retry: false
      ]

    base =
      if Keyword.has_key?(req_opts, :plug) do
        base
      else
        Keyword.put(base, :finch, finch_pool)
      end

    req = Req.new(Keyword.merge(base, req_opts))

    case Req.get(req) do
      {:ok, %Req.Response{status: status, body: body}} when status in 200..299 ->
        parse_jwks_body(body)

      {:ok, %Req.Response{status: status}} ->
        {:error, {:http_status, status}}

      {:error, reason} ->
        {:error, {:http_error, reason}}
    end
  rescue
    # Req can raise on malformed URLs / TLS handshake failures; collapse
    # to {:error, _} rather than crash the Task (async_nolink isolates
    # the cache from the crash, but we want cleaner telemetry).
    exception -> {:error, {:exception, Exception.message(exception)}}
  end

  # JWKS body per RFC 7517: `{"keys": [JWK, JWK, ...]}`. Each JWK has a
  # `"kid"` field; we index by it. Req decodes JSON for us when
  # `decode_body: true` (default), so `body` is already a map.
  defp parse_jwks_body(%{"keys" => keys}) when is_list(keys) do
    indexed =
      Map.new(keys, fn
        %{"kid" => kid} = jwk when is_binary(kid) -> {kid, jwk}
        _jwk -> {nil, nil}
      end)
      |> Map.delete(nil)

    {:ok, indexed}
  end

  defp parse_jwks_body(_other), do: {:error, :malformed_jwks}
end
