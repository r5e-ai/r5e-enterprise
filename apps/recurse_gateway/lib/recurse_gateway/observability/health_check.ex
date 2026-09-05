defmodule Recurse.Gateway.Observability.HealthCheck do
  @moduledoc """
  Unified probe surface for `/healthz` + `/readyz` — F002 T091 / FR-028.

  ## Role

  The Gateway exposes two separate endpoints (`Healthz`, `Readyz`) whose
  plug functions render JSON directly. This module provides an
  **endpoint-independent** data function: `check/2` returns a structured
  `{:ok, map()} | {:error, map()}` shape so tests, internal audits, and
  future surfaces (CLI probe tools, operator scripts) can consume the
  aggregated component status without parsing HTTP JSON.

  The two probe modes match the task's signature:

      HealthCheck.check(:healthz, opts) :: {:ok, map()} | {:error, map()}
      HealthCheck.check(:readyz,  opts) :: {:ok, map()} | {:error, map()}

  `opts` is currently unused — reserved so we can inject test-only
  overrides (e.g. stub probe functions) without breaking callers.

  ## Iron Law check (`elixir:elixir-thinking`)

  Pure module. Every call re-runs probes; no cached state. Process
  boundaries are inside the probe callees (`ProviderRegistry`,
  `JwksCache`, `Repo`) — this module is only a composer.

  ## Contract

  `{:ok, map}` means every probed component is `:ok` (for `/healthz`) or
  every readiness check returned `:ready` (for `/readyz`). The map
  always includes a `:components` or `:checks` sub-map so callers get a
  uniform shape regardless of healthy/unhealthy outcome:

      {:ok, %{status: :ok,      components: %{gateway: :ok, ledger: :ok, ...}}}
      {:error, %{status: :down, components: %{gateway: :ok, ledger: {:down, :connection_refused}, ...}}}
      {:ok, %{ready: true,  checks: %{llm_pool: :ready, ...}}}
      {:error, %{ready: false, checks: %{llm_pool: {:pending, :not_started}, ...}}}

  ## Cross-references

    * `apps/recurse_gateway/lib/recurse_gateway/observability/healthz.ex`
      — the Plug surface that renders JSON. Internal probe fns live
      there; this module calls them.
    * `apps/recurse_gateway/lib/recurse_gateway/observability/readyz.ex`
      — same for `/readyz`.
  """

  alias Recurse.Gateway.Observability.Healthz
  alias Recurse.Gateway.Observability.Readyz

  @type mode :: :healthz | :readyz

  @doc """
  Run probes for the requested mode and return the structured result.

  `:healthz` aggregates component liveness; `:readyz` aggregates
  readiness checks.
  """
  @spec check(mode(), keyword()) :: {:ok, map()} | {:error, map()}
  def check(mode, opts \\ [])

  def check(:healthz, _opts) do
    components = %{
      gateway: Healthz.probe_gateway(),
      ledger: Healthz.probe_ledger(),
      kms: Healthz.probe_kms(),
      storage: Healthz.probe_storage(),
      broker_jwks: Healthz.probe_broker_jwks(),
      cedar_policy: Healthz.probe_cedar_policy()
    }

    status = aggregate_health(components)

    result = %{status: status, components: components}

    if status == :down, do: {:error, result}, else: {:ok, result}
  end

  def check(:readyz, _opts) do
    checks = %{
      llm_pool: Readyz.check_llm_pool(),
      jwks_warm: Readyz.check_jwks_warm(),
      policy_bundle: Readyz.check_policy_bundle(),
      db_pool: Readyz.check_db_pool()
    }

    ready? = Enum.all?(Map.values(checks), &(&1 == :ready))

    result = %{ready: ready?, checks: checks}

    if ready?, do: {:ok, result}, else: {:error, result}
  end

  # ---------------------------------------------------------------------------
  # Internal — aggregation
  # ---------------------------------------------------------------------------

  defp aggregate_health(components) do
    vals = Map.values(components)

    cond do
      Enum.any?(vals, &match?({:down, _}, &1)) -> :down
      Enum.any?(vals, &match?({:degraded, _}, &1)) -> :degraded
      true -> :ok
    end
  end
end
