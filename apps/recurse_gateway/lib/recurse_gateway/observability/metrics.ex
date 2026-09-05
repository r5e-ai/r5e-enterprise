defmodule Recurse.Gateway.Observability.Metrics do
  @moduledoc """
  Declarative `Telemetry.Metrics` registry for the Gateway's
  Prometheus-scraped metric surface (F002 T091 / FR-028 / FR-029).

  ## Responsibility

  `all/0` returns the ordered list of `Telemetry.Metrics` structs that
  `TelemetryMetricsPrometheus.Core` registers at supervisor start.

  The set is the **FR-029 alerting-minimum** per the T091 task spec —
  i.e. the baseline the `/metrics` endpoint MUST expose. Additional
  drill-down metrics (request-duration percentiles beyond p95,
  per-provider counters) land on observed need, not upfront.

  The canonical set is the SAME list the test at
  `test/observability/metrics_registration_test.exs` asserts verbatim
  against — that test is the single source of truth; this module MUST
  match it byte-for-byte.

  ### Naming convention note (reconciliation with spec FR-029)

  FR-029 in `spec.md` lists Prometheus-exposition names using
  underscore-separated identifiers (e.g. `recurse_gateway_request_total`).
  This module uses **dotted `Telemetry.Metrics` names** (e.g.
  `"recurse.gateway.requests"`). `TelemetryMetricsPrometheus.Core`
  converts dots to underscores at scrape time — so both shapes end up
  in the exposition text as `recurse_gateway_requests`. The dotted
  form here is the T091 spec shape (aligns with event-name
  conventions across the umbrella); the underscored Prometheus
  identifier is asserted in a separate test via `prometheus_name/1`.

  ## Iron Law check (`elixir:elixir-thinking`)

  Pure module. `all/0` returns a fresh list of structs on every call;
  the caller (the supervisor spec for `TelemetryMetricsPrometheus.Core`)
  materializes them exactly once at boot. No process, no state.

  ## The registered set

  ### F002 baseline (T091)

    1. `recurse.broker.jwks.refresh.failures` — counter. Event:
       `[:recurse, :broker, :jwks, :refresh_failure]`. FR-029.
    2. `recurse.cedar.evaluations` — counter, tags: `decision`. Event:
       `[:recurse, :cedar, :evaluation]`. FR-029.
    3. `recurse.gateway.latency.seconds` — distribution (histogram),
       tags: `plane`. Event: `[:recurse, :gateway, :request]`. FR-029.
    4. `recurse.gateway.requests` — counter, tags: `plane, outcome`.
       Event: `[:recurse, :gateway, :request]`. FR-029.
    5. `recurse.jwt.validation.failures` — counter, tags: `reason`.
       Event: `[:recurse, :jwt, :validation_failure]`. FR-029.
    6. `recurse.ledger.commit.backoff.exhausted` — counter. Event:
       `[:recurse, :ledger, :commit, :backoff_exhausted]`. FR-029.
    7. `recurse.outbox.depth` — last-value gauge. Event:
       `[:recurse, :outbox, :depth]` (poller-driven). FR-029 + FR-032.
    8. `recurse.siem.forwarder.emit.errors` — counter. Event:
       `[:recurse, :siem, :emit_error]`. FR-029.

  ### F004 additions (T147, Phase-9 polish)

    9.  `recurse.admin.request.duration.ms` — distribution (histogram),
        tags: `endpoint`. Event:
        `[:recurse, :admin, :request, :stop]`. Per-endpoint admin-API
        latency.
    10. `recurse.blast_radius.compute.ms` — distribution (histogram),
        tags: `mode`. Event:
        `[:recurse, :blast_radius, :compute, :stop]`. `mode` is
        `sync` | `async`.
    11. `recurse.suggestion_engine.run.duration.ms` — distribution
        (histogram), tags: `source`. Event:
        `[:recurse, :suggestion_engine, :run, :stop]`. `source` is
        `heuristic` | `llm`.
    12. `recurse.suggestion_engine.token_spend.total` — counter, tags:
        `tenant_id`. Event:
        `[:recurse, :suggestion_engine, :token_spend]`.
    13. `recurse.retention.purge.rows.soft_deleted.total` — counter,
        tags: `data_class`. Event:
        `[:recurse, :retention, :purge, :soft_deleted]`. `data_class` is
        `policy_drafts` | `policy_suggestions` | `chat_history`.
    14. `recurse.retention.purge.rows.hard_deleted.total` — counter,
        tags: `data_class`. Event:
        `[:recurse, :retention, :purge, :hard_deleted]`.
    15. `recurse.live_tail.active_connections` — last-value gauge. Event:
        `[:recurse, :live_tail, :connections]` (handler-driven).
    16. `recurse.oidc.login.outcome.total` — counter, tags: `outcome`.
        Event: `[:recurse, :oidc, :login, :outcome]`. `outcome` is
        `success` | `denied` | `expired_state` | `tampered_state`.

  ## Cross-references

    * `specs/002-standalone-gateway-vertical-slice/spec.md` FR-028, FR-029.
    * `specs/004-audit-console/tasks.md` T147.
    * `apps/recurse_gateway/test/observability/metrics_registration_test.exs`
      — binding conformance test.
    * `apps/recurse_gateway/lib/recurse_gateway/observability/endpoint.ex`
      — the `/metrics` HTTP surface.
  """

  alias Telemetry.Metrics

  @typedoc """
  A `Telemetry.Metrics` definition — one of the concrete metric struct
  types. Returned as an opaque list; callers should treat elements as
  `Telemetry.Metrics.t()`-conformant.
  """
  @type metric_definition ::
          Telemetry.Metrics.Counter.t()
          | Telemetry.Metrics.Sum.t()
          | Telemetry.Metrics.LastValue.t()
          | Telemetry.Metrics.Distribution.t()
          | Telemetry.Metrics.Summary.t()

  @doc """
  Declarative list of `Telemetry.Metrics` structs backing the Prometheus
  exposition. Order is alphabetical by metric name so the registration
  test can compare against a sorted expected list deterministically.
  """
  @spec all() :: [metric_definition()]
  def all do
    [
      Metrics.counter("recurse.broker.jwks.refresh.failures",
        event_name: [:recurse, :broker, :jwks, :refresh_failure],
        measurement: :count,
        description: "JWKS refresh failures at the broker boundary (FR-029)."
      ),
      Metrics.counter("recurse.cedar.evaluations",
        event_name: [:recurse, :cedar, :evaluation],
        measurement: :count,
        tags: [:decision],
        description: "Cedar evaluations by decision (allow|deny) — FR-029."
      ),
      Metrics.distribution("recurse.gateway.latency.seconds",
        event_name: [:recurse, :gateway, :request],
        measurement: :duration_ms,
        unit: {:millisecond, :second},
        tags: [:plane],
        reporter_options: [
          buckets: [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
        ],
        description: "End-to-end request latency bucketed per plane (FR-029)."
      ),
      Metrics.counter("recurse.gateway.requests",
        event_name: [:recurse, :gateway, :request],
        measurement: :count,
        tags: [:plane, :outcome],
        description: "Request counter per plane + outcome (FR-029)."
      ),
      Metrics.counter("recurse.jwt.validation.failures",
        event_name: [:recurse, :jwt, :validation_failure],
        measurement: :count,
        tags: [:reason],
        description: "JWT validation failures by reason (FR-029)."
      ),
      Metrics.counter("recurse.ledger.commit.backoff.exhausted",
        event_name: [:recurse, :ledger, :commit, :backoff_exhausted],
        measurement: :count,
        description: "Ledger commit retries that exhausted the backoff budget (FR-029)."
      ),
      Metrics.last_value("recurse.outbox.depth",
        event_name: [:recurse, :outbox, :depth],
        measurement: :depth,
        description: "Current pending-row count in payload_outbox (FR-029 / FR-032)."
      ),
      Metrics.counter("recurse.siem.forwarder.emit.errors",
        event_name: [:recurse, :siem, :emit_error],
        measurement: :count,
        description: "SIEM forwarder NDJSON emit errors (FR-029)."
      ),
      # F004 T147 — admin-API request latency per endpoint.
      Metrics.distribution("recurse.admin.request.duration.ms",
        event_name: [:recurse, :admin, :request, :stop],
        measurement: :duration_ms,
        unit: :millisecond,
        tags: [:endpoint],
        reporter_options: [
          buckets: [5, 10, 25, 50, 100, 250, 500, 1_000, 2_500, 5_000]
        ],
        description: "F004 admin-API per-endpoint request latency."
      ),
      # F004 T147 — Blast Radius compute latency, sync vs async path.
      Metrics.distribution("recurse.blast_radius.compute.ms",
        event_name: [:recurse, :blast_radius, :compute, :stop],
        measurement: :duration_ms,
        unit: :millisecond,
        tags: [:mode],
        reporter_options: [
          buckets: [50, 100, 250, 500, 1_000, 2_500, 5_000, 10_000, 30_000, 60_000]
        ],
        description: "F004 Blast Radius compute duration by mode (sync|async)."
      ),
      # F004 T147 — heuristic + LLM suggestion-engine run duration.
      Metrics.distribution("recurse.suggestion_engine.run.duration.ms",
        event_name: [:recurse, :suggestion_engine, :run, :stop],
        measurement: :duration_ms,
        unit: :millisecond,
        tags: [:source],
        reporter_options: [
          buckets: [100, 250, 500, 1_000, 2_500, 5_000, 10_000, 30_000, 60_000, 120_000]
        ],
        description: "F004 suggestion engine run duration by source (heuristic|llm)."
      ),
      # F004 T147 — LLM token spend by suggestion-engine runs.
      Metrics.counter("recurse.suggestion_engine.token_spend.total",
        event_name: [:recurse, :suggestion_engine, :token_spend],
        measurement: :tokens,
        tags: [:tenant_id],
        description: "F004 LLM token spend by tenant for suggestion engine."
      ),
      # F004 T147 — retention purge soft-delete row counts.
      Metrics.counter("recurse.retention.purge.rows.soft_deleted.total",
        event_name: [:recurse, :retention, :purge, :soft_deleted],
        measurement: :rows,
        tags: [:data_class],
        description: "F004 retention soft-deleted rows by data class."
      ),
      # F004 T147 — retention purge hard-delete row counts.
      Metrics.counter("recurse.retention.purge.rows.hard_deleted.total",
        event_name: [:recurse, :retention, :purge, :hard_deleted],
        measurement: :rows,
        tags: [:data_class],
        description: "F004 retention hard-deleted rows by data class."
      ),
      # F004 T147 — live-tail WebSocket active connections (gauge).
      Metrics.last_value("recurse.live_tail.active_connections",
        event_name: [:recurse, :live_tail, :connections],
        measurement: :active,
        description: "F004 live-tail WebSocket active connection gauge."
      ),
      # F004 T147 — OIDC login outcomes by outcome label.
      Metrics.counter("recurse.oidc.login.outcome.total",
        event_name: [:recurse, :oidc, :login, :outcome],
        measurement: :count,
        tags: [:outcome],
        description: "F004 OIDC login outcomes (success|denied|expired_state|tampered_state)."
      )
    ]
  end

  @doc """
  Alias for `all/0` retained for compatibility with the existing
  `MetricsRegistry` child spec.
  """
  @spec definitions() :: [metric_definition()]
  def definitions, do: all()

  @doc """
  Return the sorted list of metric names (dotted Telemetry.Metrics form)
  registered by this module. Used by `metrics_registration_test.exs` to
  assert the FR-029 set is neither extended nor reduced without an
  explicit code change + spec update.
  """
  @spec registered_names() :: [String.t()]
  def registered_names do
    all()
    |> Enum.map(& &1.name)
    |> Enum.map(&name_to_string/1)
    |> Enum.sort()
  end

  @doc """
  Sorted list of Prometheus-exposition identifiers — dots converted to
  underscores. Handy for tests that want to assert the scrape-output
  shape independent of the Telemetry.Metrics convention.
  """
  @spec prometheus_names() :: [String.t()]
  def prometheus_names do
    registered_names()
    |> Enum.map(&prometheus_name/1)
    |> Enum.sort()
  end

  @doc """
  Return `%{name => metric_struct}` for every definition, for tests that
  want to assert on metric type + tags as well as name.
  """
  @spec registered_by_name() :: %{String.t() => metric_definition()}
  def registered_by_name do
    all()
    |> Enum.map(fn metric -> {name_to_string(metric.name), metric} end)
    |> Map.new()
  end

  @doc """
  Convert a dotted `Telemetry.Metrics` name to its Prometheus-exposition
  shape (dots become underscores). The reporter auto-appends `_total`
  for counters at scrape time; we only produce the base identifier here.
  """
  @spec prometheus_name(String.t()) :: String.t()
  def prometheus_name(dotted) when is_binary(dotted) do
    String.replace(dotted, ".", "_")
  end

  @doc """
  Render the current metric state as Prometheus text-format bytes.
  Delegates to `TelemetryMetricsPrometheus.Core.scrape/1`.
  """
  @spec scrape() :: binary()
  def scrape do
    TelemetryMetricsPrometheus.Core.scrape(Recurse.Gateway.Observability.MetricsRegistry)
  end

  @doc """
  `:telemetry_poller` measurement callbacks — list of `{module, function, args}`
  tuples that the poller invokes at each tick. Used by the supervisor to
  drive gauge-shaped measurements that aren't event-native
  (`:outbox_depth`).
  """
  @spec poller_measurements() :: [{module(), atom(), list()}]
  def poller_measurements do
    [
      {__MODULE__, :emit_outbox_depth, []}
    ]
  end

  @doc """
  Poller callback — reads the current outbox depth from the ledger and
  emits it as a telemetry event so the `recurse.outbox.depth` gauge
  reflects reality.

  Gracefully handles the case where the Repo is not available (e.g. in
  test envs without a DB); the gauge simply reports 0.
  """
  @spec emit_outbox_depth() :: :ok
  def emit_outbox_depth do
    depth =
      try do
        Recurse.Providers.Impls.PostgresMerkleLedger.outbox_depth()
      rescue
        _ -> 0
      end

    :telemetry.execute([:recurse, :outbox, :depth], %{depth: depth}, %{})
    :ok
  end

  # ---------------------------------------------------------------------------
  # Internal — Telemetry.Metrics stores names as lists of atoms; convert
  # back to the canonical dotted form for assertion + exposition use.
  # ---------------------------------------------------------------------------

  defp name_to_string(name) when is_list(name) do
    name
    |> Enum.map(&Atom.to_string/1)
    |> Enum.join(".")
  end

  defp name_to_string(name) when is_binary(name), do: name
end
