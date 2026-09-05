defmodule Recurse.Gateway.Boot.EnvProviderInstaller do
  @moduledoc """
  Boot-time installer for `Recurse.Gateway.ProviderRegistry` via
  `Recurse.Gateway.Config.EnvProviderRegistry.install!/0`.

  ## Why this module exists

  The original wiring called `EnvProviderRegistry.install!/0` inline
  in `Recurse.Gateway.Application.start/2` BEFORE
  `Supervisor.start_link/2`. That worked when `install!` was a pure
  env-var read, but provider impls now do eager I/O at `init/1` —
  `Recurse.Providers.Impls.AwsKmsSecretsProvider` calls Finch via
  `:imds_pool` to fetch IRSA credentials + validate the KMS key on
  startup. Finch pools are CHILDREN of the application's main
  supervisor, so they can't be available during the inline-in-start/2
  install. Result: pod boot crashes with
  `ArgumentError: unknown registry: :imds_pool`.

  Moving `install!` into a supervised GenServer's `init/1` fixes the
  ordering: place this module's child spec AFTER `finch_pool_children()`
  in the supervisor's children list, and the supervisor blocks on
  this `init/1` until install completes. Subsequent workers — which
  consume `ProviderRegistry.fetch/0` — start AFTER the registry is
  installed, preserving the "install before any provider-consuming
  child" contract noted in `Recurse.Gateway.Application`'s start/2
  comment block.

  ## GenServer (not Task) on purpose

  `Task.start_link` returns as soon as the wrapped function STARTS,
  not when it completes. We need supervisor-blocking semantics so
  later children don't start until install is done — that's only
  available via GenServer's synchronous `init/1` contract.

  Iron-Law check (per `elixir-thinking`): the GenServer earns its
  process by encoding a runtime sequencing requirement (block
  subsequent children until install finishes). It holds no state
  beyond the install-completed marker. It's not for code organization.

  ## Failure semantics

  `EnvProviderRegistry.install!/0` raises on bad config (missing
  required env, unknown impl shorthand, AWS auth failure during
  KMS validation, etc.). The raise propagates out of `init/1`,
  crashes this child's start, and — given the supervisor's restart
  policy — eventually crashes the supervisor (max_restarts), which
  crashes the BEAM (no top supervisor to fall back to), which causes
  K8s to restart the pod with a clean slate. That's the canonical
  fail-fast posture per Constitution Principle III: a misconfigured
  deploy never accepts traffic.

  ## Gating

  This module is added to the children list ONLY when both gates
  pass (`audit_console_enabled?` AND `R5E_PROVIDER_LEDGER_IMPL`
  presence). The gating logic stays in
  `Recurse.Gateway.Application.env_provider_installer_children/0`
  so the test suites that bypass the env path (via
  `ProviderRegistry.install_raw!/1`) don't trigger this module's
  child spec at all.
  """

  use GenServer

  alias Recurse.Gateway.Config.EnvProviderRegistry

  @doc false
  @spec start_link(any()) :: GenServer.on_start()
  def start_link(_init_arg) do
    GenServer.start_link(__MODULE__, [], name: __MODULE__)
  end

  @impl GenServer
  def init(_init_arg) do
    EnvProviderRegistry.install!()
    {:ok, :installed}
  end
end
