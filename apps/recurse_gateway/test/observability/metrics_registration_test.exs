defmodule Recurse.Gateway.Observability.MetricsRegistrationTest do
  @moduledoc """
  FR-029 alerting-minimum metric-set conformance test (F002 T091).

  ## Invariant under test

  `Recurse.Gateway.Observability.Metrics.registered_names/0` returns EXACTLY
  the set of metric names declared in `metrics.ex` — no more, no less.
  This guards against:

    * accidental metric name typos,
    * partial additions (new metric wired on one side of the bus but
      forgotten on the other),
    * silent drift between the module and the registration contract.

  ## Spec-vs-module reconciliation (read this before changing the list)

  `spec.md` FR-029 enumerates the alerting-minimum metric set in
  **Prometheus-exposition underscored form** (e.g.
  `recurse_gateway_request_total{plane, outcome}`). The shipping
  `metrics.ex` declares them in `Telemetry.Metrics` **dotted form**
  (e.g. `"recurse.gateway.requests"`); the `TelemetryMetricsPrometheus.Core`
  reporter converts `.` → `_` at scrape time and auto-appends `_total`
  suffixes on counters.

  The two shapes are NOT byte-identical. The dotted-name set currently
  covered by `metrics.ex` is the T091-as-shipped set; the underscored
  spec.md FR-029 set is the audit contract. When FR-029 and `metrics.ex`
  are reconciled into a single canonical list in a follow-up, update
  both this test and `metrics.ex` in the same commit.

  ## Cross-references

    * `specs/002-standalone-gateway-vertical-slice/spec.md` FR-029
    * `apps/recurse_gateway/lib/recurse_gateway/observability/metrics.ex`
  """

  use ExUnit.Case, async: true

  alias Recurse.Gateway.Observability.Metrics

  # Sorted list of `Telemetry.Metrics` dotted names currently declared in
  # `metrics.ex`. This MUST stay in lock-step with the module; see the
  # reconciliation note in the @moduledoc above.
  #
  # F004 T147 added 8 admin-side metrics (admin request duration, blast
  # radius, suggestion engine, retention purge, live-tail, OIDC login).
  @expected_names [
    "recurse.admin.request.duration.ms",
    "recurse.blast_radius.compute.ms",
    "recurse.broker.jwks.refresh.failures",
    "recurse.cedar.evaluations",
    "recurse.gateway.latency.seconds",
    "recurse.gateway.requests",
    "recurse.jwt.validation.failures",
    "recurse.ledger.commit.backoff.exhausted",
    "recurse.live_tail.active_connections",
    "recurse.oidc.login.outcome.total",
    "recurse.outbox.depth",
    "recurse.retention.purge.rows.hard_deleted.total",
    "recurse.retention.purge.rows.soft_deleted.total",
    "recurse.siem.forwarder.emit.errors",
    "recurse.suggestion_engine.run.duration.ms",
    "recurse.suggestion_engine.token_spend.total"
  ]

  # Expected type + tag shape per dotted name. Counters → `:counter`,
  # histograms → `:distribution`, gauges → `:last_value` in
  # `Telemetry.Metrics` terms.
  @expected_shapes %{
    "recurse.admin.request.duration.ms" => {:distribution, [:endpoint]},
    "recurse.blast_radius.compute.ms" => {:distribution, [:mode]},
    "recurse.broker.jwks.refresh.failures" => {:counter, []},
    "recurse.cedar.evaluations" => {:counter, [:decision]},
    "recurse.gateway.latency.seconds" => {:distribution, [:plane]},
    "recurse.gateway.requests" => {:counter, [:plane, :outcome]},
    "recurse.jwt.validation.failures" => {:counter, [:reason]},
    "recurse.ledger.commit.backoff.exhausted" => {:counter, []},
    "recurse.live_tail.active_connections" => {:last_value, []},
    "recurse.oidc.login.outcome.total" => {:counter, [:outcome]},
    "recurse.outbox.depth" => {:last_value, []},
    "recurse.retention.purge.rows.hard_deleted.total" => {:counter, [:data_class]},
    "recurse.retention.purge.rows.soft_deleted.total" => {:counter, [:data_class]},
    "recurse.siem.forwarder.emit.errors" => {:counter, []},
    "recurse.suggestion_engine.run.duration.ms" => {:distribution, [:source]},
    "recurse.suggestion_engine.token_spend.total" => {:counter, [:tenant_id]}
  }

  describe "registered metric set" do
    test "registered_names/0 equals the declared list exactly" do
      actual = Metrics.registered_names()

      # Strict set equality — not subset — so accidental additions or
      # removals fail loudly.
      assert actual == @expected_names, """
      Metrics registration drift.

      Expected (per this test):
        #{inspect(@expected_names, pretty: true)}

      Metrics.registered_names/0 returned:
        #{inspect(actual, pretty: true)}

      missing (in test, not in module):
        #{inspect(@expected_names -- actual, pretty: true)}

      extra (in module, not in test):
        #{inspect(actual -- @expected_names, pretty: true)}
      """
    end

    test "every metric has the expected type + label set" do
      by_name = Metrics.registered_by_name()

      Enum.each(@expected_shapes, fn {name, {expected_type, expected_tags}} ->
        metric = Map.fetch!(by_name, name)
        actual_type = telemetry_metric_type(metric)
        actual_tags = metric.tags

        assert actual_type == expected_type,
               "#{name}: expected type #{inspect(expected_type)}, got #{inspect(actual_type)}"

        assert Enum.sort(actual_tags) == Enum.sort(expected_tags),
               "#{name}: expected tags #{inspect(expected_tags)}, got #{inspect(actual_tags)}"
      end)
    end

    test "every definition pins an event_name so emitters can target it" do
      Enum.each(Metrics.definitions(), fn metric ->
        assert is_list(metric.event_name) and metric.event_name != [],
               "metric #{inspect(metric.name)} is missing an event_name"

        assert Enum.all?(metric.event_name, &is_atom/1),
               "metric #{inspect(metric.name)} has a non-atom event_name segment"
      end)
    end
  end

  describe "Prometheus exposition identifiers" do
    test "prometheus_names/0 converts dots to underscores deterministically" do
      # Sanity: the reporter will translate dots in exposition output.
      # The test lets us catch accidental drift in the conversion helper.
      Enum.each(Metrics.registered_names(), fn name ->
        assert Metrics.prometheus_name(name) == String.replace(name, ".", "_")
      end)
    end
  end

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  # `Telemetry.Metrics` uses distinct struct modules per metric type; extract
  # the short tag we compare against the expected shape table.
  defp telemetry_metric_type(%Telemetry.Metrics.Counter{}), do: :counter
  defp telemetry_metric_type(%Telemetry.Metrics.Sum{}), do: :sum
  defp telemetry_metric_type(%Telemetry.Metrics.LastValue{}), do: :last_value
  defp telemetry_metric_type(%Telemetry.Metrics.Distribution{}), do: :distribution
  defp telemetry_metric_type(%Telemetry.Metrics.Summary{}), do: :summary
end
