defmodule RecurseBroker.Application do
  @moduledoc """
  Standalone Identity Broker supervision tree (F002 T025).

  Per research D2, the broker is a narrow HTTP service with a small
  set of legitimate children — nothing more. Adding a process without
  a runtime reason would violate the otp-thinking Iron Law
  ("GenServer is a bottleneck by design"). The `Task.Supervisor`
  itself is structural (it owns transient fetch tasks) and is not a
  state-bearing child.

  ## Children, in `:one_for_one` startup order

    1. `RecurseBroker.OIDC.TaskSupervisor` — `Task.Supervisor` that owns
       the off-GenServer JWKS/discovery fetch tasks spawned by
       `RecurseBroker.OIDC.DiscoveryCache`. We use a dedicated supervisor
       (rather than `spawn/1`) so the tasks are observable, properly
       shut down, and don't leak processes on application stop.
    2. `RecurseBroker.OIDC.DiscoveryCache` — GenServer owning the ETS
       table that caches `{issuer}/.well-known/openid-configuration` +
       JWKS material keyed `{issuer, kid}`. Legitimate: remote-fetch
       TTL refresh and on-miss coalescing is intrinsically serialized
       state. Real impl lands in T082; in this task the module is a
       stub returning `{:error, :not_implemented_yet}` from its public
       lookup fn so the tree compiles + supervises clean.
    3. `RecurseBroker.JWT.KeyRing` — GenServer holding the broker's
       signing keys (`%{active_kid, keys: %{kid => JWK}}`). Legitimate:
       key-rotation overlap window is intrinsically stateful. Real
       impl lands in T086; stubbed here.
    4. `RecurseBroker.Endpoint` — Bandit child spec wrapping
       `Plug.Router`. Bandit manages its own internal supervision
       (acceptors, conn processes); we register it as one child of
       this tree. Routes return 501 placeholders in this task; real
       handlers land in T087/T088.

  Endpoint is listed LAST because its future handlers depend on
  DiscoveryCache + KeyRing being live; `:one_for_one` plus this
  declaration order gives us that without a stricter `:rest_for_one`
  policy (we don't want a DiscoveryCache crash to knock the port
  offline — we want the port to keep serving /healthz while the
  cache restarts).

  ## HTTP gating

  Endpoint is only started when `config :recurse_broker, start_http?: true`
  (set by the `standalone_gateway` Mix env; `false` in default/test so
  umbrella `mix test` doesn't bind port 4001). Mirrors the pattern in
  `RecurseGateway.Application`.

  ## Cross-references

    * `specs/002-standalone-gateway-vertical-slice/research.md` D2
    * `specs/002-standalone-gateway-vertical-slice/contracts/recurse_broker_api.md`
    * `specs/002-standalone-gateway-vertical-slice/tasks.md` T025/T082/T086/T088
  """

  use Application

  @impl true
  def start(_type, _args) do
    children =
      finch_children() ++
        [
          # MUST start before DiscoveryCache — DiscoveryCache spawns
          # off-GenServer fetch tasks under this supervisor.
          {Task.Supervisor, name: RecurseBroker.OIDC.TaskSupervisor},
          RecurseBroker.OIDC.DiscoveryCache,
          {RecurseBroker.JWT.KeyRing, Application.get_env(:recurse_broker, :keyring, [])}
        ] ++ endpoint_children()

    opts = [strategy: :one_for_one, name: RecurseBroker.Supervisor]
    Supervisor.start_link(children, opts)
  end

  # The named Finch pool for JWKS fetches is OPT-IN via
  # `config :recurse_broker, :jwks_finch_pool, :broker_jwks_pool`. When
  # unset, `RecurseBroker.OIDC.DiscoveryCache` falls back to Req's
  # built-in default pool — fine for tests + first-run demos where
  # JWKS QPS is near zero. When set (prod), this child starts BEFORE
  # DiscoveryCache so the pool exists by the time the first fetch
  # lands. See `discovery_cache.ex` moduledoc "HTTP layer".
  defp finch_children do
    case Application.get_env(:recurse_broker, :jwks_finch_pool, nil) do
      nil -> []
      name when is_atom(name) -> [{Finch, name: name, pools: %{default: [size: 10]}}]
    end
  end

  defp endpoint_children do
    if Application.get_env(:recurse_broker, :start_http?, false) do
      port = Application.get_env(:recurse_broker, :http_port, 4001)
      [{RecurseBroker.Endpoint, port: port}]
    else
      []
    end
  end
end
