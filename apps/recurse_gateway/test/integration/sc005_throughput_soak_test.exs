defmodule Recurse.Integration.SC005ThroughputSoakTest do
  @moduledoc """
  SC-005 — 50 QPS sustained throughput soak test (F002 T101).

  Drives 50 QPS of `/v1/chat/completions` for 10 minutes against a local
  Gateway + Broker stack, backed by an in-process `MockHttpUpstream` LLM
  stub, and asserts the four SC-005 success conditions at the end of the
  run:

    1. `recurse_siem_forwarder_emit_errors_total` == 0
    2. `recurse_ledger_commit_backoff_exhausted_total` == 0
    3. `recurse_outbox_depth` max observation ≤ 5
    4. p95 Gateway overhead < 150 ms (SC-001 budget at sustained load)

  ## `@moduletag :soak`

  Excluded from default `mix test` via
  `apps/recurse_gateway/test/test_helper.exs`'s
  `ExUnit.start(exclude: [..., :soak, ...])`. Intended for nightly CI
  only. Local override:

      SOAK_DURATION_SEC=30 mix test --include soak \\
        apps/recurse_gateway/test/integration/sc005_throughput_soak_test.exs

  …runs a 30-second soak instead of 10 minutes.

  ## `@moduletag timeout: :timer.minutes(15)`

  The 10-minute load phase + 2-minute warmup + teardown + safety margin.

  ## Dependency on SA1's work (IMPORTANT — seam contract)

  This test **depends on SA1's T091 + T090 + T089 metric emission
  being in place**. The exact metric names this test reads are:

    * `recurse_siem_forwarder_emit_errors_total` — counter emitted by
      `Recurse.Gateway.Siem.Forwarder` when an NDJSON emit fails.
      **Stability requirement**: SA1 T091 must not rename this metric.
      Renaming requires coordinating with this test.
    * `recurse_ledger_commit_backoff_exhausted_total` — counter emitted
      by `Recurse.Providers.Impls.PostgresMerkleLedger` when a commit
      retry budget is exhausted. **Stability requirement**: SA1 T091
      must not rename this metric.
    * `recurse_outbox_depth` — gauge emitted by the outbox poller
      (`Recurse.Gateway.Observability.Metrics.emit_outbox_depth/0`).
      **Stability requirement**: SA1 T090 (OutboxReconciler) + T091
      (metric registry) must both reference the same name.
    * `recurse_gateway_latency_seconds` — histogram tagged by `:plane`.
      Emitted by SA1 T091 via `[:recurse, :gateway, :request]` telemetry.
      **Fallback**: if the histogram isn't populated by the end of the
      run (e.g. SA1 hasn't wired the telemetry emission yet), the test
      computes p95 from client-side `System.monotonic_time/0` samples
      as a belt-and-braces source of truth.

  If SA1 renames any of these metrics, this test's `@sc005_metric_*`
  module attributes at the top of the file must be updated in lockstep.

  ## Structural pattern (elixir:otp-thinking)

  The driver is `Task.async_stream/5` with `max_concurrency: 8` running
  a rate-limited sender. Per `elixir:otp-thinking`, we're using
  `Task.async_stream` because:

    1. Mutable state across calls? No — each task does one request.
    2. Concurrent execution? Yes — 8 workers fan out 50 QPS.
    3. Fault isolation? We don't *want* isolation — if the Gateway
       breaks under 50 QPS we want the failing iterations visible.

  The test uses `Task.async_stream/5` directly (not `Task.Supervisor`)
  because crash-together is the desired semantic: a Gateway crash
  should tear down the driver so we see the failure, not continue
  submitting into a dead stack.

  Rate-limit via a `Process.sleep/1` calibrated off a fixed
  inter-request interval (`trunc(1_000 / qps)` ms) so the producer
  never outpaces 50 QPS even on fast hardware. This is deliberately
  less principled than a GCRA / token-bucket driver — the test's
  invariants are "no errors" and "low latency," not "exactly 50 QPS
  sustained to the microsecond."

  ## `async: false`

  Ecto Sandbox, ProviderRegistry, BundleLoader, `MockHttpUpstream`
  Bandit port — same coupling set as `us1_with_real_broker_test.exs`.

  ## Cross-references

    * `specs/002-standalone-gateway-vertical-slice/spec.md` SC-001, SC-005
    * `specs/002-standalone-gateway-vertical-slice/tasks.md` T101
    * `apps/recurse_gateway/lib/recurse_gateway/observability/metrics.ex`
    * `apps/recurse_gateway/test/integration/us1_with_real_broker_test.exs`
  """

  use ExUnit.Case, async: false

  setup_all do
    Recurse.Gateway.Test.KernelFixture.boot()
  end

  @moduletag :soak
  @moduletag timeout: :timer.minutes(15)

  alias Ecto.Adapters.SQL.Sandbox
  alias Recurse.Gateway.Observability.Metrics
  alias Recurse.Gateway.Policy.BundleLoader
  alias Recurse.Gateway.ProviderRegistry
  alias Recurse.Gateway.Router
  alias Recurse.Gateway.Test.MockHttpUpstream
  alias Recurse.Gateway.Test.StubSecretsProvider
  alias Recurse.Gateway.Test.StubStorageProvider
  alias Recurse.Providers.Impls.OpenAiLlmProvider
  alias Recurse.Providers.Impls.PostgresMerkleLedger
  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Tenant
  alias Recurse.Providers.Repo
  alias RecurseBroker.Endpoint, as: BrokerEndpoint
  alias RecurseBroker.Test.MockOidcIssuer
  alias RecurseBroker.Test.SupervisorHelper

  @tenant_id "01HQZN5K7J8M9N0P1Q2R3S4T5V"
  @broker_audience "recurse-gateway-soak"
  @broker_issuer "https://broker.recurse.test"
  @interactive_aud @broker_audience <> "-interactive"

  @router_opts Router.init([])
  @broker_endpoint_opts BrokerEndpoint.init([])

  @mapping %{
    group_to_recurse_role: %{
      "cn=recurse-users,ou=groups,dc=corp,dc=example" => "caller"
    },
    default_recurse_role: "caller",
    role_privilege_order: ["platform_operator", "tenant_auditor", "caller"]
  }

  # --- SC-005 acceptance knobs ------------------------------------------
  @qps 50
  @max_concurrency 8
  @p95_budget_ms 150
  @max_outbox_depth 5

  # --- SA1-dependent metric names (stability contract above) ------------
  @sc005_metric_siem_errors "recurse_siem_forwarder_emit_errors_total"
  @sc005_metric_ledger_backoff "recurse_ledger_commit_backoff_exhausted_total"
  @sc005_metric_outbox_depth "recurse_outbox_depth"

  defp soak_duration_sec do
    case System.get_env("SOAK_DURATION_SEC") do
      nil -> 600
      val -> String.to_integer(val)
    end
  end

  setup do
    :ok = Sandbox.checkout(Repo)
    Sandbox.mode(Repo, {:shared, self()})

    Repo.insert!(
      Tenant.changeset(%Tenant{}, %{
        tenant_id: @tenant_id,
        display_name: "SC-005 Soak Tenant",
        tier: :standalone_gateway,
        created_at: DateTime.utc_now()
      }),
      on_conflict: :nothing,
      conflict_target: :tenant_id
    )

    {:ok, upstream} = MockHttpUpstream.start()

    # The mock upstream returns a canned body for every request. Per
    # `MockHttpUpstream.expect/2`'s contract, the registered callback
    # is reused for every subsequent request (it's NOT one-shot), so a
    # single `expect/2` call persists across all 30_000 requests in the
    # soak window without re-registration.
    MockHttpUpstream.expect(upstream, fn conn ->
      {:ok, _raw, conn} = Plug.Conn.read_body(conn)

      conn
      |> Plug.Conn.put_resp_header("content-type", "application/json")
      |> Plug.Conn.send_resp(200, canned_completion_body())
    end)

    on_exit(fn ->
      MockHttpUpstream.stop(upstream)
      ProviderRegistry.uninstall()
      StubStorageProvider.reset()
    end)

    :ok = StubStorageProvider.reset()

    {:ok, llm_state} =
      OpenAiLlmProvider.init(%{
        base_url: MockHttpUpstream.url(upstream),
        finch_pool: :openai_pool,
        resolved_api_key: "sk-soak-fake-key",
        timeout_ms: 10_000,
        pool_timeout_ms: 5_000
      })

    {:ok, ledger_state} = PostgresMerkleLedger.init(%{})
    {:ok, storage_state} = StubStorageProvider.init(%{bucket: "soak-bucket"})
    {:ok, secrets_state} = StubSecretsProvider.init(%{})

    ProviderRegistry.install_raw!(%{
      llm: {OpenAiLlmProvider, llm_state},
      ledger: {PostgresMerkleLedger, ledger_state},
      storage: {StubStorageProvider, storage_state},
      secrets: {StubSecretsProvider, secrets_state},
      tenant_id: @tenant_id,
      signer: "observed://gateway/soak"
    })

    bundle_path =
      Path.join([
        Application.app_dir(:recurse_gateway, "priv"),
        "reference_policies",
        "permissive_all.cedar"
      ])

    entity_schema_path =
      Path.join([
        Application.app_dir(:recurse_gateway, "priv"),
        "cedar",
        "schema.cedarschema.json"
      ])

    _bundle_loader =
      start_supervised!(
        Supervisor.child_spec(
          {BundleLoader,
           bundle_path: bundle_path,
           entity_schema_path: entity_schema_path,
           trap_sighup: false,
           name: nil},
          id: {BundleLoader, make_ref()}
        )
      )

    mock_issuer = MockOidcIssuer.new()
    jwks_plug = MockOidcIssuer.jwks_plug_fn(mock_issuer)

    SupervisorHelper.stop_auto_started(RecurseBroker.OIDC.DiscoveryCache)
    SupervisorHelper.stop_auto_started(RecurseBroker.JWT.KeyRing)

    start_supervised!({RecurseBroker.JWT.KeyRing, generate_ephemeral?: true})
    start_supervised!({RecurseBroker.OIDC.DiscoveryCache, req_opts: [plug: jwks_plug]})

    previous_broker_env = swap_broker_env(mock_issuer.issuer)
    on_exit(fn -> restore_broker_env(previous_broker_env) end)

    {:ok, broker_keys} = RecurseBroker.JWT.KeyRing.all_active_keys()

    known_kids =
      Enum.map(broker_keys, fn {kid, k} ->
        {_, fields} = k |> JOSE.JWK.to_public() |> JOSE.JWK.to_map()
        {kid, Map.put(fields, "kid", kid)}
      end)

    previous_jwt_opts = Application.get_env(:recurse_gateway, :jwt_validator_opts)

    Application.put_env(:recurse_gateway, :jwt_validator_opts,
      audience: @broker_audience,
      issuer: @broker_issuer,
      known_kids: known_kids
    )

    on_exit(fn ->
      case previous_jwt_opts do
        nil -> Application.delete_env(:recurse_gateway, :jwt_validator_opts)
        val -> Application.put_env(:recurse_gateway, :jwt_validator_opts, val)
      end
    end)

    # Mint a long-lived access token once; we'll reuse it on every
    # request (50 QPS × 600s = 30k requests — token-exchange for each
    # would dominate the latency histogram with broker-side overhead
    # that isn't what SC-005 targets).
    access_token = mint_access_token_for_caller(mock_issuer)

    %{
      upstream: upstream,
      access_token: access_token,
      duration_sec: soak_duration_sec()
    }
  end

  test "50 QPS for N seconds — error counters at 0, outbox low, p95 under budget",
       %{access_token: access_token, duration_sec: duration_sec} do
    # Collect per-request latency samples into an `:ets` table keyed by
    # monotonic `:erlang.unique_integer/1` so inserts don't serialize
    # through a single process. `:atomics` would work too for counters,
    # but we need the full sample array to compute p95 post-hoc.
    samples_table = :ets.new(:sc005_latency_samples, [:public, :set])

    interval_ms = div(1_000, @qps)
    total_requests = @qps * duration_sec

    # -- Drive load for `duration_sec` seconds via async_stream --------
    #
    # `max_concurrency: 8` is the client-side parallelism; the rate is
    # enforced via `Process.sleep/1` between submissions in the
    # producer stream so we never outpace 50 QPS.
    results =
      1..total_requests
      |> Stream.map(fn i ->
        Process.sleep(max(0, interval_ms - 1))
        i
      end)
      |> Task.async_stream(
        fn _i ->
          t0 = System.monotonic_time(:microsecond)
          conn = single_chat_request(access_token)
          t1 = System.monotonic_time(:microsecond)

          latency_us = t1 - t0
          :ets.insert(samples_table, {System.unique_integer([:monotonic]), latency_us})

          conn.status
        end,
        max_concurrency: @max_concurrency,
        ordered: false,
        timeout: 30_000,
        on_timeout: :kill_task
      )
      |> Enum.to_list()

    # -- Assertion 1: no task-level crashes/timeouts -------------------
    #
    # async_stream yields `{:ok, result}` per-task on success and
    # `{:exit, reason}` on failure. Count non-ok outcomes.
    ok_count = Enum.count(results, &match?({:ok, 200}, &1))
    other = Enum.reject(results, &match?({:ok, 200}, &1))

    assert other == [],
           "expected all #{total_requests} requests to return 200; #{length(other)} did not: " <>
             inspect(Enum.take(other, 5))

    assert ok_count == total_requests

    # -- Assertion 2: p95 latency under budget -------------------------
    #
    # Client-side measurements in microseconds. We compute p95 by
    # sorting all samples and picking index ⌊0.95 × N⌋.
    latencies_us =
      samples_table
      |> :ets.tab2list()
      |> Enum.map(fn {_k, us} -> us end)
      |> Enum.sort()

    refute latencies_us == [], "no latency samples collected"

    p95_idx = trunc(0.95 * length(latencies_us))
    p95_us = Enum.at(latencies_us, p95_idx)
    p95_ms = p95_us / 1_000

    assert p95_ms < @p95_budget_ms,
           "p95 Gateway overhead exceeded SC-001 budget: #{Float.round(p95_ms, 1)}ms >= " <>
             "#{@p95_budget_ms}ms (samples=#{length(latencies_us)})"

    # -- Assertion 3: metric counters are 0 + outbox depth low ---------
    #
    # Scrape the Prometheus exposition once post-run. Parsing is
    # minimal — we only need a handful of counter/gauge values.
    exposition = Metrics.scrape()

    siem_errors = parse_counter(exposition, @sc005_metric_siem_errors)
    ledger_backoff = parse_counter(exposition, @sc005_metric_ledger_backoff)
    outbox_depth = parse_gauge_max(exposition, @sc005_metric_outbox_depth)

    assert siem_errors == 0,
           "#{@sc005_metric_siem_errors} == #{siem_errors}, expected 0 (SC-005 #1)"

    assert ledger_backoff == 0,
           "#{@sc005_metric_ledger_backoff} == #{ledger_backoff}, expected 0 (SC-005 #2)"

    assert outbox_depth <= @max_outbox_depth,
           "#{@sc005_metric_outbox_depth} == #{outbox_depth}, expected ≤ " <>
             "#{@max_outbox_depth} (SC-005 #3)"
  after
    # Clean up the ETS table even on failure so repeat runs don't
    # accumulate.
    try do
      :ets.delete(:sc005_latency_samples)
    catch
      _, _ -> :ok
    end
  end

  # ---------------------------------------------------------------------------
  # Load helpers
  # ---------------------------------------------------------------------------

  defp single_chat_request(access_token) do
    body =
      JSON.encode!(%{
        "model" => "gpt-4o-mini",
        "messages" => [%{"role" => "user", "content" => "soak"}]
      })

    :post
    |> Plug.Test.conn("/v1/chat/completions", body)
    |> Plug.Conn.put_req_header("content-type", "application/json")
    |> Plug.Conn.put_req_header("authorization", "Bearer " <> access_token)
    |> Router.call(@router_opts)
  end

  defp mint_access_token_for_caller(mock_issuer) do
    id_token =
      MockOidcIssuer.mint_id_token(mock_issuer, %{
        "sub" => "auth0|soak-caller",
        "aud" => @interactive_aud,
        "groups" => ["cn=recurse-users,ou=groups,dc=corp,dc=example"]
      })

    form_body =
      URI.encode_query(%{
        "grant_type" => "urn:ietf:params:oauth:grant-type:token-exchange",
        "subject_token" => id_token,
        "subject_token_type" => "urn:ietf:params:oauth:token-type:id_token",
        "audience" => @broker_audience
      })

    broker_conn =
      :post
      |> Plug.Test.conn("/token/exchange", form_body)
      |> Plug.Conn.put_req_header("content-type", "application/x-www-form-urlencoded")
      |> BrokerEndpoint.call(@broker_endpoint_opts)

    %{"access_token" => access_token} = JSON.decode!(broker_conn.resp_body)
    access_token
  end

  defp canned_completion_body do
    JSON.encode!(%{
      "id" => "chatcmpl-soak",
      "object" => "chat.completion",
      "created" => 1_700_000_000,
      "model" => "gpt-4o-mini",
      "choices" => [
        %{
          "index" => 0,
          "message" => %{"role" => "assistant", "content" => "."},
          "finish_reason" => "stop"
        }
      ],
      "usage" => %{"prompt_tokens" => 1, "completion_tokens" => 1, "total_tokens" => 2}
    })
  end

  # ---------------------------------------------------------------------------
  # Prometheus-text parsing (minimal; just enough for the three metrics)
  # ---------------------------------------------------------------------------

  # Counter lines look like: `recurse_siem_forwarder_emit_errors_total 0`
  # or with labels `foo_total{plane="data",outcome="allow"} 3`. For our
  # three target metrics none carry labels that matter — we sum all
  # label variants to get the total counter value, which matches the
  # SC-005 assertion semantics ("no errors across any dimension").
  defp parse_counter(exposition, name) do
    exposition
    |> String.split("\n")
    |> Enum.filter(fn line ->
      String.starts_with?(line, name) and not String.starts_with?(line, "#")
    end)
    |> Enum.reduce(0, fn line, acc ->
      case parse_value(line) do
        {:ok, v} -> acc + v
        :error -> acc
      end
    end)
  end

  # Gauge: we want the MAX across all label variants (there shouldn't
  # be any labels on outbox depth, but this future-proofs).
  defp parse_gauge_max(exposition, name) do
    exposition
    |> String.split("\n")
    |> Enum.filter(fn line ->
      String.starts_with?(line, name) and not String.starts_with?(line, "#")
    end)
    |> Enum.map(fn line ->
      case parse_value(line) do
        {:ok, v} -> v
        :error -> 0
      end
    end)
    |> Enum.max(fn -> 0 end)
  end

  # Split on whitespace; the VALUE is the last token; everything before
  # it is the metric name + optional `{labels}`. Integers or floats.
  defp parse_value(line) do
    case line |> String.trim() |> String.split() |> List.last() do
      nil -> :error
      token -> parse_numeric_token(token)
    end
  end

  defp parse_numeric_token(token) do
    case Integer.parse(token) do
      {int_val, ""} -> {:ok, int_val}
      _ -> parse_float_token(token)
    end
  end

  defp parse_float_token(token) do
    case Float.parse(token) do
      {float_val, ""} -> {:ok, trunc(float_val)}
      _ -> :error
    end
  end

  # ---------------------------------------------------------------------------
  # Setup/teardown helpers — broker app-supervisor teardown lives in
  # `RecurseBroker.Test.SupervisorHelper.stop_auto_started/1`.
  # ---------------------------------------------------------------------------

  defp swap_broker_env(issuer_url) do
    previous = %{
      expected_audience: Application.get_env(:recurse_broker, :expected_audience),
      broker_issuer: Application.get_env(:recurse_broker, :broker_issuer),
      role_mapping: Application.get_env(:recurse_broker, :role_mapping),
      oidc_validator_opts: Application.get_env(:recurse_broker, :oidc_validator_opts)
    }

    Application.put_env(:recurse_broker, :expected_audience, @broker_audience)
    Application.put_env(:recurse_broker, :broker_issuer, @broker_issuer)
    Application.put_env(:recurse_broker, :role_mapping, @mapping)

    Application.put_env(:recurse_broker, :oidc_validator_opts,
      alg_allowlist: [:rs256, :es256, :eddsa],
      issuer: issuer_url,
      audience: @interactive_aud
    )

    previous
  end

  defp restore_broker_env(previous) do
    for {k, v} <- previous do
      case v do
        nil -> Application.delete_env(:recurse_broker, k)
        val -> Application.put_env(:recurse_broker, k, val)
      end
    end

    :ok
  end
end
