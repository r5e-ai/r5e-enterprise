# Contract: MCP Server Lifecycle (DynamicSupervisor + Port)

**Module**: `Recurse.Runtime.McpServerHosting.DynamicSupervisor` + `Recurse.Runtime.McpServerHosting.Instance` + `Recurse.Runtime.McpServerHosting.PortInstance`
**Phase**: 4 (MCP server hosting)

## Purpose

Recurse-hosted MCP servers (Hub-vouched servers spawned per-tenant) live as supervised processes under a per-tenant `DynamicSupervisor`. Two flavors:

- **In-BEAM**: pure-Elixir MCP implementations (the Recurse-as-MCP-server adapter from Phase 2 IS one of these). GenServer with MCP protocol handler. Cheap, fast.
- **Port-wrapped**: `npx @org/server`, `uvx package-name`, etc. Spawned via `Port.open`, communicates via stdio with packet-4 framing. Heavier, but covers the long tail of MCP servers we don't author ourselves.

## Per-tenant DynamicSupervisor

```elixir
defmodule Recurse.Runtime.McpServerHosting.DynamicSupervisor do
  use DynamicSupervisor

  # One supervisor per tenant. Started under the global Recurse.Runtime
  # supervision tree on tenant provisioning.
  @spec start_link(tenant_id :: String.t()) :: Supervisor.on_start()

  # Spawn or get existing instance for (tenant, server_name).
  # Globally-coordinated via :global registration so two BEAM nodes in
  # the same tenant cluster converge on one instance.
  @spec spawn_or_get(tenant_id :: String.t(), server_name :: String.t(), opts :: map()) ::
          {:ok, pid()} | {:ok, :existing, pid()} | {:error, :policy_denied | term()}

  # Reap an idle instance.
  @spec reap(tenant_id :: String.t(), server_name :: String.t()) :: :ok | {:error, :not_found}

  # List all instances for a tenant.
  @spec list_instances(tenant_id :: String.t()) :: [%{server_name: String.t(), pid: pid(), state: atom(), last_active_at: DateTime.t()}]
end
```

## Instance lifecycle

```
caller invokes spawn_or_get
        ↓
[Cedar policy gate: principal × server_name × tenant]
        ↓ allow                                  ↓ deny
        ↓                                        ↓
[:global.register_name conflict?]              return {:error, :policy_denied}
        ↓ no                  ↓ yes                (no spawn cost paid)
        ↓                     ↓
[start_child(Instance)]    [return existing pid]
        ↓
[Instance.init: cold-start]
        ↓
[for in-BEAM: MCP handler GenServer ready]
[for Port: spawn npx/uvx, wait for ready signal]
        ↓
[insert hosted_mcp_server_instances row]
[emit mcp_server_spawn predicate]
        ↓
[active]
        ↓
[handle JSON-RPC requests; update last_active_at on each]
        ↓
[idle (no requests for idle_timeout_seconds)]
        ↓
[reaper sweeps; if last_active_at older than threshold AND warm_pool_minimum allows → reap]
        ↓
[reaping]
        ↓
[for Port: send shutdown signal, await graceful exit, kill if exceeds timeout]
        ↓
[update hosted_mcp_server_instances row → reaped]
[emit mcp_server_reap predicate]
        ↓
[reaped]
```

## Cold-start optimization

- Per-tenant install caches at `/var/lib/r5e/<tenant>/mcp-cache/{npm,uv}/`. `npx`/`uvx` honor the cache; second cold-start of the same package is bash-spawn-time.
- Pre-warm on tenant provision: when a tenant is provisioned + trust dial allows the Hub starter set, asynchronously install the 5 starter set packages. First-cold-start for those is ~bash-spawn-time.
- Cache invalidation on Hub takedown: when an entry is taken down, the tenant's cached install is removed.

## Warm-pool override

For server types that need to stay warm:

```elixir
# Per-server-type config (in apps/recurse_runtime/config/mcp_servers.exs or DB)
config :recurse_runtime, :mcp_servers, %{
  "ast-analyzer" => %{
    idle_timeout_seconds: 3600,    # 1 hour
    warm_pool_minimum: 2           # always keep at least 2 instances per tenant
  },
  "embedding-cache" => %{
    idle_timeout_seconds: 7200,
    warm_pool_minimum: 1
  },
  "github" => %{
    idle_timeout_seconds: 300,     # 5 min default
    warm_pool_minimum: 0
  }
}
```

Reaper logic respects `warm_pool_minimum`: if reaping an instance would drop below the minimum, skip the reap.

## Per-tenant resource limits

Process spawning is wrapped in `systemd-run --scope --user=beam --slice=mcp-tenant-<tenant_id>.slice -p MemoryHigh=512M -p CPUQuota=200%`. Per-tenant slice + per-server cgroup limits prevent runaway resource consumption.

## Globally-coordinated registration

`:global.register_name({:hosted_mcp, tenant_id, server_name}, pid())` — `:global` is BEAM-native, handles network partitions via existing OTP machinery. Two BEAM nodes racing to spawn converge on one instance via `:global`'s atomic registration semantics.

## Tests required

**Contract**:
- Spawn → idle → reap → re-spawn cycle is deterministic and observable via `hosted_mcp_server_instances` rows
- Cedar deny prevents spawn (no `mcp_server_spawn` predicate, no DB row, no OS process created)
- Warm-pool minimum respected: reaper skips reap if reaping would drop below minimum

**Property tests**:
- Per-tenant isolation: arbitrary cross-tenant request patterns produce zero observable cross-tenant data
- Lifecycle state machine: every state has a defined transition; no orphaned states; reaping is idempotent

**Integration**:
- Cold-start latency for `npx @modelcontextprotocol/server-filesystem` (a small known MCP server) under 2s p95 (per SC-004)
- Warm-pool kept N instances when configured, even after extended idle
- Two BEAM nodes spawn simultaneously → exactly one instance results

## Constitution alignment

- **Principle II** (Kernel-Level Enforcement): hosted MCP servers run in OUR process space, NOT in customer agent containers. They're downstream targets of the intercept path, not bypasses of the netns jail. Compliance.
- **Principle III**: every spawn + reap emits a predicate. Compliance.
- **Principle V**: no new vendor abstraction; this is internal infrastructure.
- **Principle VI**: state machine is property-tested.
