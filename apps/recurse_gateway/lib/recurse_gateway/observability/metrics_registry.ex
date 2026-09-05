defmodule Recurse.Gateway.Observability.MetricsRegistry do
  @moduledoc """
  Registers the Gateway's canonical Prometheus metric set with
  `telemetry_metrics_prometheus_core` (F002 T091).

  ## Iron Law check (`elixir:otp-thinking`)

  `TelemetryMetricsPrometheus.Core.start_link/1` is itself a supervised
  process tree — the registry owns ETS tables for every counter /
  gauge / histogram. We do NOT wrap a GenServer around it; we mount
  its supervisor-spec as a direct child of `RecurseGateway.Supervisor`.

  The `:name` passed to `TelemetryMetricsPrometheus.Core` identifies
  the registry instance. We pin it to `__MODULE__` so the scrape path
  (`Metrics.scrape/0`) can address a single well-known instance.

  ## Why `Core` and not the full `telemetry_metrics_prometheus` exporter

  The full exporter boots a Cowboy endpoint on its own port. The
  Gateway already owns a Bandit HTTP endpoint (`Recurse.Gateway.Router`)
  that serves `/metrics` as a plain GET — letting the exporter stand
  up its own listener would fight with Standalone's single-listener
  expectation. `Core` gives us the storage + scrape surface without
  the listener. The gateway depends directly on
  `telemetry_metrics_prometheus_core`; the full exporter is not a
  production dependency. Cowboy is used only by test mock servers.

  ## Cross-references

    * `apps/recurse_gateway/lib/recurse_gateway/observability/metrics.ex`
    * `apps/recurse_gateway/lib/recurse_gateway/application.ex`
    * `specs/002-standalone-gateway-vertical-slice/spec.md` FR-029
  """

  alias Recurse.Gateway.Observability.Metrics

  @doc """
  Supervisor child spec — mounts `TelemetryMetricsPrometheus.Core` with
  the metric list from `Metrics.definitions/0`.

  Uses the plain `child_spec/1` shape so it can be placed directly into
  an application children list.
  """
  @spec child_spec(keyword()) :: Supervisor.child_spec()
  def child_spec(_opts) do
    %{
      id: __MODULE__,
      start:
        {TelemetryMetricsPrometheus.Core, :start_link,
         [
           [
             name: __MODULE__,
             metrics: Metrics.definitions()
           ]
         ]},
      type: :supervisor,
      restart: :permanent,
      shutdown: 5_000
    }
  end
end
