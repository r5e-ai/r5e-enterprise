defmodule Recurse.Gateway.SuggestionEngine.RetentionPurger.Receipt do
  @moduledoc """
  Per-cycle receipt emission for the three retention purgers (F004 T055a).

  Each retention worker emits exactly one `:ui_retention_purge` attestation
  per cycle with the aggregate counts in the predicate. This module is the
  single point of indirection so the three workers (`PolicyDrafts`,
  `PolicySuggestions`, `ChatHistory`) don't duplicate the envelope-build +
  ledger-commit boilerplate.

  ## Iron Law check (`elixir:elixir-thinking`)

    1. Mutable state? No — pure helper invoked from the Oban worker
       process; no per-call BEAM state.
    2. Concurrent execution? No — runs synchronously inside the worker's
       `perform/1`. The `:retention` Oban queue concurrency is 1 so cycles
       never overlap (per `retention_lifecycle.md`).
    3. Fault isolation? No — failures rescue + log + emit telemetry so the
       worker continues to its `:ok` return. A failed receipt commit does
       NOT fail the purge cycle (the data deletion already happened); we
       surface the gap in Vector / SIEM via the telemetry event + an
       error-level log line per FR-031.

  All three NO → plain functions.

  ## Cross-references

    * `specs/004-audit-console/contracts/retention_lifecycle.md` §"Oban.Cron
      job schedule"
    * `apps/recurse_gateway/lib/recurse_gateway/attestation/envelope_builder.ex`
      `build_system/4`
    * `Recurse.Gateway.Admin.BrowserAuth.UiReceipts` — sibling pattern for
      browser-auth UI events.
  """

  require Logger

  alias Recurse.Gateway.Attestation.EnvelopeBuilder
  alias Recurse.Gateway.ProviderRegistry
  alias Recurse.Shared.IdentityContext
  alias Recurse.Shared.Principal

  @event_kind :ui_retention_purge
  @system_account_id "recurse-gateway-retention-purger"
  @telemetry_event [:recurse, :ui_retention_purge, :cycle]

  @typedoc """
  Cycle-summary metrics passed in by the worker. Keys mirror the F002 + F004
  retention metric vocabulary; `breakdown` is opaque per-worker detail that
  flows into the attested predicate verbatim.
  """
  @type metrics :: %{
          required(:data_class) => String.t(),
          required(:soft_deleted_count) => non_neg_integer(),
          required(:hard_deleted_count) => non_neg_integer(),
          required(:duration_ms) => non_neg_integer(),
          required(:started_at) => DateTime.t(),
          required(:completed_at) => DateTime.t(),
          optional(:breakdown) => map()
        }

  @doc """
  Build, sign, and commit one `:ui_retention_purge` attestation for a
  retention-cycle's metrics. Always returns `:ok` (failures do not raise).
  Also fires the `[:recurse, :ui_retention_purge, :cycle]` telemetry event
  so existing dashboards / SIEM tails keep observing the same shape.
  """
  @spec emit(metrics()) :: :ok
  def emit(%{} = metrics) do
    run_id = Ecto.UUID.generate()

    _ = safe_commit(metrics, run_id)
    safe_dispatch_telemetry(metrics)
    :ok
  end

  @doc """
  Telemetry event name for `:telemetry.attach/4` test fixtures.
  """
  @spec telemetry_event() :: [atom()]
  def telemetry_event, do: @telemetry_event

  defp safe_commit(metrics, run_id) do
    case ProviderRegistry.fetch() do
      {:ok, _registry} ->
        do_commit(metrics, run_id)

      {:error, :not_installed} ->
        # Worker may run before the Gateway's ProviderRegistry boot in some
        # test/dev scenarios. Telemetry-only emission is the documented
        # fallback (no audit gap reported because the deployment hasn't
        # finished initializing).
        :ok
    end
  rescue
    error ->
      Logger.error(fn ->
        "retention_purge receipt commit raised: #{inspect(error)} " <>
          "data_class=#{metrics.data_class} run_id=#{run_id}"
      end)

      :error
  end

  defp do_commit(metrics, run_id) do
    {secrets_mod, secrets_state} = ProviderRegistry.secrets_provider()
    {ledger_mod, _ledger_state} = ProviderRegistry.ledger_provider()
    tenant_id = ProviderRegistry.tenant_id()
    signer = ProviderRegistry.signer()

    identity_ctx =
      IdentityContext.new(%{
        machine_identity: signer,
        principal: Principal.service_account(%{
          issuer: signer,
          account_id: @system_account_id
        }),
        tenant_id: tenant_id,
        correlation_id: run_id
      })

    predicate_map = predicate_for(metrics)

    with {:ok, envelope} <-
           EnvelopeBuilder.build_system(
             @event_kind,
             identity_ctx,
             predicate_map,
             run_id: run_id,
             secrets_provider: {secrets_mod, secrets_state},
             signer: signer,
             timestamp: metrics.completed_at
           ),
         {:ok, _result} <- commit_envelope(ledger_mod, envelope) do
      :ok
    else
      {:error, reason} ->
        Logger.error(fn ->
          "retention_purge receipt ledger commit failed: #{inspect(reason)} " <>
            "data_class=#{metrics.data_class} run_id=#{run_id}"
        end)

        :error
    end
  end

  defp commit_envelope(Recurse.Providers.Impls.PostgresMerkleLedger = mod, envelope) do
    mod.commit_attestation(envelope, [])
  end

  defp commit_envelope(mod, envelope) do
    if function_exported?(mod, :commit_attestation, 2) do
      mod.commit_attestation(envelope, [])
    else
      {:error, {:ledger_provider_missing_commit_attestation, mod}}
    end
  end

  # The signed predicate carries the cycle's aggregate counts + duration.
  # Keys are stringified at JCS time; the breakdown (if any) flows through
  # verbatim. Timestamps render as RFC 3339 strings so the JCS output is
  # byte-stable and auditor-reproducible.
  defp predicate_for(metrics) do
    base = %{
      "data_class" => metrics.data_class,
      "soft_deleted_count" => metrics.soft_deleted_count,
      "hard_deleted_count" => metrics.hard_deleted_count,
      "duration_ms" => metrics.duration_ms,
      "started_at" => DateTime.to_iso8601(metrics.started_at),
      "completed_at" => DateTime.to_iso8601(metrics.completed_at)
    }

    case Map.get(metrics, :breakdown) do
      nil -> base
      breakdown when is_map(breakdown) -> Map.put(base, "breakdown", normalize_breakdown(breakdown))
    end
  end

  defp normalize_breakdown(breakdown) do
    Map.new(breakdown, fn
      {k, v} when is_atom(k) -> {Atom.to_string(k), v}
      {k, v} -> {k, v}
    end)
  end

  defp safe_dispatch_telemetry(metrics) do
    :telemetry.execute(
      @telemetry_event,
      %{
        soft_deleted_count: metrics.soft_deleted_count,
        hard_deleted_count: metrics.hard_deleted_count,
        duration_ms: metrics.duration_ms
      },
      metrics
      |> Map.take([:data_class, :started_at, :completed_at, :breakdown])
    )
  rescue
    error ->
      Logger.error(fn ->
        "retention_purge telemetry emission failed: #{inspect(error)} " <>
          "data_class=#{metrics.data_class}"
      end)
  end
end
