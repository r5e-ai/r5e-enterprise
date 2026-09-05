defmodule Recurse.Gateway.LlmProxy.BypassDnsResolver do
  @moduledoc """
  Resolves upstream LLM API hostnames (e.g. `chatgpt.com`,
  `auth.openai.com`, `api.openai.com`) to their **real** IP addresses,
  even when the customer's corp DNS is overriding those names back to
  recurse-gateway's IP (the customer's whole-host-routing primitive
  per R-001 / R-011).

  Spec source of truth:
  `specs/009-llm-api-proxy/contracts/streaming_proxy.md`
  §"Upstream connection (bypass DNS)" + research.md R-011.

  The resolver:

    * Uses `:inet_res.lookup/4` against an explicit upstream-resolver
      IP list — bypassing whatever's in `/etc/resolv.conf` (the corp
      DNS is hostile for our purposes).
    * Sane defaults: `[{8, 8, 8, 8}, {1, 1, 1, 1}]` (Google + Cloudflare
      public resolvers). Operators override per-deployment via
      `config :recurse_gateway, :llm_proxy_bypass_dns_resolvers, [...]`
      to point at corp-internal trusted resolvers when public DNS is
      egress-restricted.
    * Caches resolution results in a public ETS table keyed on
      `{hostname, family}` with a per-record TTL. We cap TTLs at 5
      minutes (300s) so stale upstream IPs get retired even when the
      authoritative DNS keeps a high TTL — important for the Phase-3
      use case where upstream IPs occasionally rotate.
    * Returns one or more IP addresses (a record OR multiple) — callers
      can pick the first or implement their own load-balancing.

  ## Error returns

    * `{:error, :nxdomain}` — name does not resolve
    * `{:error, :servfail}` — resolver returned SERVFAIL or refused
    * `{:error, :timeout}` — resolver did not respond in the budget
    * `{:error, {:resolver_error, reason}}` — anything else propagated
      from `:inet_res`

  ## Test seam

  The DNS module is dispatched via `Application.get_env/3` so test code
  can inject a stub:

      Application.put_env(:recurse_gateway, :bypass_dns_module, FakeDns)

  The stub MUST implement the same `lookup/4` arity as `:inet_res`.
  Production runs use the default `:inet_res` and the real network.

  ## ETS table

  Lazily created on first use as a public, read-optimized table named
  `:r5e_bypass_dns_cache`. Subsequent calls hit the existing table.
  In the long-run-supervision-tree picture (Phase 3.3 wires the LLM
  proxy router into `recurse_gateway/application.ex`), a supervisor
  child can pre-create this table to eliminate the lazy path; for now
  the lazy path keeps this module self-contained for Sub-3.2 unit
  tests.

  ## Why no GenServer

  Reads dominate, the cache is a pure derived state, and writes are
  short-lived self-publications. Per `otp-thinking`'s ETS pattern: a
  process-less public ETS table with `:read_concurrency` outperforms
  a GenServer-owning serialization point. There is no behavior to
  serialize beyond ETS's own atomic puts.
  """

  @table :r5e_bypass_dns_cache

  # Cap any DNS-supplied TTL at 5 minutes so a misconfigured upstream
  # zone can't pin stale IPs into our cache for hours.
  @max_ttl_seconds 300

  # Fallback TTL when the resolver does not give us one (e.g. our
  # `:inet_res.lookup/4` path returns the address list without TTLs;
  # we treat 60s as the safe default).
  @default_ttl_seconds 60

  # Default :inet_res.lookup/4 timeout per resolver attempt.
  @default_timeout_ms 2_000

  @typedoc """
  IPv4 address tuple (we focus on A records; AAAA support is a Phase-2+
  extension per R-007 IPv6 caveat).
  """
  @type ip_address :: :inet.ip_address()

  @typedoc "Hostname as a string (e.g. `\"chatgpt.com\"`). UTF-8."
  @type hostname :: String.t()

  @type resolve_error :: :nxdomain | :servfail | :timeout | {:resolver_error, term()}

  @doc """
  Resolve `hostname` to its real upstream IPs, bypassing corp DNS.

  Returns `{:ok, [ip_address]}` on success, `{:error, reason}` on
  failure. The first cache hit short-circuits the network call.

  ## Examples

      iex> Recurse.Gateway.LlmProxy.BypassDnsResolver.resolve("chatgpt.com")
      {:ok, [{104, 18, 32, 47}, ...]}
  """
  @spec resolve(hostname()) :: {:ok, [ip_address()]} | {:error, resolve_error()}
  def resolve(hostname) when is_binary(hostname) do
    ensure_table!()

    case cache_lookup(hostname) do
      {:hit, ips} -> {:ok, ips}
      :miss -> resolve_and_cache(hostname)
    end
  end

  @doc """
  Drop a hostname from the cache. Useful for ops triage and tests.
  Idempotent — deleting a non-cached entry is a no-op.
  """
  @spec invalidate(hostname()) :: :ok
  def invalidate(hostname) when is_binary(hostname) do
    ensure_table!()
    :ets.delete(@table, hostname)
    :ok
  end

  @doc """
  Drop the entire cache. Test-only; production paths should prefer
  per-key invalidation.
  """
  @spec clear() :: :ok
  def clear do
    ensure_table!()
    :ets.delete_all_objects(@table)
    :ok
  end

  # ---------------------------------------------------------------------------
  # Cache plumbing
  # ---------------------------------------------------------------------------

  defp ensure_table! do
    case :ets.whereis(@table) do
      :undefined ->
        try do
          :ets.new(@table, [:set, :public, :named_table, read_concurrency: true])
        rescue
          # Race window — another process created it between our
          # whereis and new. The table now exists; success.
          ArgumentError -> :ok
        end

      _ref ->
        :ok
    end
  end

  defp cache_lookup(hostname) do
    case :ets.lookup(@table, hostname) do
      [{^hostname, ips, expires_at}] ->
        if monotonic_seconds() < expires_at, do: {:hit, ips}, else: :miss

      [] ->
        :miss
    end
  end

  defp cache_put(hostname, ips, ttl_seconds) do
    expires_at = monotonic_seconds() + clamp_ttl(ttl_seconds)
    :ets.insert(@table, {hostname, ips, expires_at})
    :ok
  end

  defp clamp_ttl(ttl) when is_integer(ttl) and ttl > 0,
    do: min(ttl, @max_ttl_seconds)

  defp clamp_ttl(_), do: @default_ttl_seconds

  defp monotonic_seconds do
    System.monotonic_time(:second)
  end

  # ---------------------------------------------------------------------------
  # Resolver — :inet_res.lookup/4 against the configured upstream IPs
  # ---------------------------------------------------------------------------

  defp resolve_and_cache(hostname) do
    resolvers = configured_resolvers()
    dns_module = configured_dns_module()
    timeout = configured_timeout_ms()

    charlist = String.to_charlist(hostname)

    case dns_module.lookup(charlist, :in, :a, nameservers: resolvers, timeout: timeout) do
      [] ->
        {:error, :nxdomain}

      ips when is_list(ips) ->
        # `:inet_res.lookup/4` returns a list of address tuples directly
        # (not full RR records). It does not surface per-record TTLs in
        # this arity, so we cache at the default TTL.
        cache_put(hostname, ips, @default_ttl_seconds)
        {:ok, ips}

      {:error, :timeout} ->
        {:error, :timeout}

      {:error, :nxdomain} ->
        {:error, :nxdomain}

      {:error, {:servfail, _}} ->
        {:error, :servfail}

      {:error, reason} ->
        {:error, {:resolver_error, reason}}
    end
  rescue
    e ->
      # I-001 totality on the public-API surface: any unexpected raise
      # in the test stub or :inet_res internals degrades to a typed
      # error rather than crashing the proxy worker.
      {:error, {:resolver_error, e}}
  catch
    kind, reason ->
      {:error, {:resolver_error, {kind, reason}}}
  end

  defp configured_resolvers do
    Application.get_env(:recurse_gateway, :llm_proxy_bypass_dns_resolvers, [
      {8, 8, 8, 8},
      {1, 1, 1, 1}
    ])
    |> Enum.map(&normalize_nameserver/1)
  end

  # `:inet_res.lookup/4` requires its `:nameservers` as `{ip, port}`
  # pairs. Bare IP tuples — the shape this module documents and defaults
  # to — raise ArgumentError inside `:inet_res`, which `resolve_and_cache/1`
  # catches and returns as `{:error, {:resolver_error, _}}`.
  #
  # That failure is indistinguishable from "DNS is unreachable", and
  # every caller responds by falling back to system DNS — which is the
  # exact resolver this module exists to bypass. The bypass therefore
  # never ran, and nothing noticed, because system DNS returns the
  # right answers whenever the host isn't also the machine running the
  # DNS override. It only surfaces in the local-demo topology, where
  # /etc/hosts points the upstream names at 127.0.0.1 and the fallback
  # loops the gateway back into its own listener.
  #
  # Accept both shapes so operator configs written either way work.
  @dns_port 53
  defp normalize_nameserver({_, _, _, _} = ipv4), do: {ipv4, @dns_port}
  defp normalize_nameserver({_, _, _, _, _, _, _, _} = ipv6), do: {ipv6, @dns_port}
  defp normalize_nameserver({ip, port} = pair) when is_tuple(ip) and is_integer(port), do: pair
  defp normalize_nameserver(other), do: other

  defp configured_dns_module do
    Application.get_env(:recurse_gateway, :bypass_dns_module, :inet_res)
  end

  defp configured_timeout_ms do
    Application.get_env(:recurse_gateway, :bypass_dns_timeout_ms, @default_timeout_ms)
  end
end
