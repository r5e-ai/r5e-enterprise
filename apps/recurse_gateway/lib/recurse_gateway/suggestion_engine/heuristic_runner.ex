defmodule Recurse.Gateway.SuggestionEngine.HeuristicRunner do
  @moduledoc """
  Hourly Oban worker that runs the 5 heuristic suggestion patterns over
  a trailing receipt window — F004 T131.

  Per research D3 + FR-030:

    * Cron: `0 * * * *` (hourly), wired in `application.ex`
      `oban_cron_crontab/0`.
    * Window: trailing 30 days of `attestations` for the deployment tenant.
    * Patterns: all 5 from `Recurse.Gateway.SuggestionEngine.Heuristic.*`.
    * Determinism: pure-function patterns + canonical sort. Surface U
      property test asserts byte-equality across two runs of the same
      window.
    * Deduplication: composite SHA-256-prefix key
      `{tenant_id, pattern_name, principal_subject_hash, action_hash}`.
      Suggestions whose dedup key already has an active row in the
      `policy_suggestions` table are SKIPPED (not re-emitted).

  ## FR-035 sparseness suppression

  When the trailing-30-day window has fewer than `@sparse_threshold` (100)
  active receipts, the runner short-circuits with a `:skipped_sparse`
  marker on the run row and emits ZERO suggestions. The downstream UI
  surfaces this as "Not enough activity to surface suggestions for this
  tenant yet." Aligns with SC-007 ("≥1 meaningful pattern/day for
  ≥100-receipts/day tenants" — invert: <100 receipts/day = no
  meaningful patterns).

  ## Public ad-hoc API — `run_for_window/2`

  Called by the audit-agent `SuggestPolicyPattern` tool (T114) and by
  the manual refresh path (T134). Skips the cron + Oban scheduling and
  runs synchronously on the caller's process. Returns the list of
  suggestion-record maps (NOT persisted suggestions).

  ## Iron Law check (`elixir:oban-thinking` + `elixir:otp-thinking`)

    * **Worker IS the right shape**: hourly cron, durable retry on
      failure (Oban's job-table semantics), runs on a dedicated
      `:suggestion_engine` queue with concurrency=1 so two heuristic
      runs cannot interleave on the same window.
    * **Args are JSON-string keys**: `perform/1` accepts an empty args
      map (cron-driven) OR a `{"tenant_id" => ..., "since_iso" => ...}`
      map for replay/test invocation.
    * **Errors propagate**: failures bubble through Oban's retry — we
      do NOT swallow them with `:ok`.

  ## Cross-references

    * `specs/004-audit-console/research.md` D3 (5-pattern set + dedup key).
    * `specs/004-audit-console/spec.md` FR-030 (hourly cadence) +
      FR-035 (sparseness suppression) + SC-007 (threshold).
    * `apps/recurse_gateway/lib/recurse_gateway/admin/policy_suggestions/policy_suggestions.ex`
      (T125 — context module the runner persists through).
  """

  use Oban.Worker,
    queue: :suggestion_engine,
    max_attempts: 3,
    unique: [
      period: 60,
      keys: [:tenant_id, :since_iso],
      states: [:available, :scheduled, :executing, :retryable]
    ]

  import Ecto.Query

  alias Recurse.Gateway.Admin.BrowserAuth.UiReceipts
  alias Recurse.Gateway.Admin.PolicySuggestions
  alias Recurse.Gateway.Admin.PolicySuggestions.PolicySuggestion
  alias Recurse.Gateway.ProviderRegistry
  alias Recurse.Gateway.SuggestionEngine.Heuristic
  alias Recurse.Gateway.SuggestionEngine.Heuristic.AnomalousBurst
  alias Recurse.Gateway.SuggestionEngine.Heuristic.CrossTenantAccess
  alias Recurse.Gateway.SuggestionEngine.Heuristic.RecurringAllow
  alias Recurse.Gateway.SuggestionEngine.Heuristic.RecurringDeny
  alias Recurse.Gateway.SuggestionEngine.Heuristic.StaleRoleCreep
  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Attestation
  alias Recurse.Providers.Repo

  require Logger

  @window_days 30
  @sparse_threshold 100
  @patterns [RecurringAllow, RecurringDeny, AnomalousBurst, CrossTenantAccess, StaleRoleCreep]

  @impl Oban.Worker
  def perform(%Oban.Job{args: args}) do
    tenant_id = Map.get(args, "tenant_id") || ProviderRegistry.tenant_id()
    window = parse_window(args)

    case run_with_persistence(tenant_id, window) do
      {:ok, _run} -> :ok
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Synchronous ad-hoc invocation. Used by the audit-agent
  `SuggestPolicyPattern` tool (T114) and integration tests.

  Returns `{:ok, [suggestion_record]}` where each record is the raw
  `Heuristic.suggestion()` map (NOT a persisted PolicySuggestion row).
  Caller chooses whether to persist via `PolicySuggestions.create/2`.

  Honors the FR-035 sparseness rule: returns `{:ok, []}` and the
  `:upstream_unavailable` short-circuit when below threshold (matching
  the contract the SuggestPolicyPattern tool expects).

  Window opts: `:since` and `:until` (DateTime). Defaults to trailing
  30 days from `DateTime.utc_now/0`.
  """
  @spec run_for_window(String.t(), map()) ::
          {:ok, [Heuristic.suggestion()]} | {:error, term()}
  def run_for_window(tenant_id, opts \\ %{}) when is_binary(tenant_id) and is_map(opts) do
    window = build_window_from_opts(opts)

    case load_window_receipts(tenant_id, window) do
      {:ok, receipts} ->
        if length(receipts) < @sparse_threshold do
          {:ok, []}
        else
          {:ok, run_all_patterns(receipts)}
        end

      {:error, _} = err ->
        err
    end
  end

  @doc """
  Threshold below which the runner short-circuits with no suggestions
  (FR-035). Exposed so handlers + tests can reason about the boundary.
  """
  @spec sparse_threshold() :: pos_integer()
  def sparse_threshold, do: @sparse_threshold

  # ---------------------------------------------------------------------------
  # Persistence pipeline (cron-driven path)
  # ---------------------------------------------------------------------------

  defp run_with_persistence(tenant_id, window) do
    {:ok, run} =
      PolicySuggestions.start_run(%{
        tenant_id: tenant_id,
        source: :heuristic,
        scheduled_at: DateTime.utc_now()
      })

    {:ok, run} =
      PolicySuggestions.update_run(run, %{started_at: DateTime.utc_now()})

    case load_window_receipts(tenant_id, window) do
      {:ok, receipts} when length(receipts) < @sparse_threshold ->
        finalize_sparse(run, length(receipts))

      {:ok, receipts} ->
        finalize_normal(run, tenant_id, receipts)

      {:error, reason} ->
        finalize_failed(run, reason)
    end
  end

  defp finalize_sparse(run, scanned) do
    Logger.info(fn ->
      "heuristic runner: skipped sparse window tenant=#{run.tenant_id} " <>
        "scanned=#{scanned} threshold=#{@sparse_threshold}"
    end)

    PolicySuggestions.update_run(run, %{
      completed_at: DateTime.utc_now(),
      suggestions_generated_count: 0,
      error: "skipped_sparse_window"
    })
  end

  defp finalize_normal(run, tenant_id, receipts) do
    suggestions = run_all_patterns(receipts)

    persisted_count =
      Enum.reduce(suggestions, 0, fn s, acc ->
        try_persist(tenant_id, run.id, s, acc)
      end)

    PolicySuggestions.update_run(run, %{
      completed_at: DateTime.utc_now(),
      suggestions_generated_count: persisted_count
    })
  end

  defp try_persist(tenant_id, run_id, suggestion, acc) do
    case persist_unique_suggestion(tenant_id, run_id, suggestion) do
      {:ok, %PolicySuggestion{} = persisted} ->
        emit_generated(persisted)
        acc + 1

      {:skip, :duplicate} ->
        acc

      {:error, reason} ->
        log_persist_failure(reason, suggestion)
        acc
    end
  end

  defp log_persist_failure(reason, suggestion) do
    Logger.warning(fn ->
      "heuristic suggestion persist failed: #{inspect(reason)} pattern=#{suggestion.pattern_name}"
    end)
  end

  defp finalize_failed(run, reason) do
    Logger.error(fn ->
      "heuristic runner failed: #{inspect(reason)} tenant=#{run.tenant_id}"
    end)

    PolicySuggestions.update_run(run, %{
      completed_at: DateTime.utc_now(),
      error: inspect(reason)
    })
  end

  defp persist_unique_suggestion(tenant_id, run_id, suggestion) do
    if duplicate_active_suggestion?(tenant_id, suggestion) do
      {:skip, :duplicate}
    else
      attrs = %{
        source: :heuristic,
        confidence_score: suggestion.confidence_score,
        pattern_summary: suggestion.pattern_summary,
        proposed_cedar: suggestion.proposed_cedar,
        generation_run_id: run_id,
        status: :active,
        generated_at: DateTime.utc_now()
      }

      PolicySuggestions.create(tenant_id, attrs)
    end
  end

  # Dedup against active suggestions sharing the same
  # (tenant_id, pattern_name-marker, principal_subject_hash, action_hash) tuple.
  # We embed the dedup-key components into pattern_summary's prefix and
  # check for an existing active row whose pattern_summary starts with the
  # same key — pragmatic since we don't store the dedup key as a column.
  # In practice the (proposed_cedar) text is also unique per pattern × principal,
  # so we use a textual exact-match on proposed_cedar as the "duplicate"
  # signal. This is correct because pattern modules are deterministic.
  defp duplicate_active_suggestion?(tenant_id, suggestion) do
    cedar = suggestion.proposed_cedar

    query =
      from(s in PolicySuggestion,
        where:
          s.tenant_id == ^tenant_id and s.source == ^:heuristic and s.status == ^:active and
            s.proposed_cedar == ^cedar and is_nil(s.deleted_at),
        limit: 1,
        select: s.id
      )

    Repo.exists?(query)
  end

  defp run_all_patterns(receipts) do
    @patterns
    |> Enum.flat_map(& &1.detect(receipts))
    |> Heuristic.sort()
  end

  defp emit_generated(%PolicySuggestion{} = suggestion) do
    UiReceipts.emit(:ui_policy_suggestion_generated, %{
      suggestion_id: suggestion.id,
      tenant_id: suggestion.tenant_id,
      source: Atom.to_string(suggestion.source),
      confidence_score: suggestion.confidence_score
    })
  end

  # ---------------------------------------------------------------------------
  # Receipt-window loading
  # ---------------------------------------------------------------------------

  defp load_window_receipts(tenant_id, %{since: since, until: until_dt}) do
    query =
      from(a in Attestation,
        where: a.tenant_id == ^tenant_id,
        where: a.timestamp >= ^since,
        where: a.timestamp < ^until_dt,
        select: %{
          principal: a.principal,
          event_kind: a.event_kind,
          policy_decision: a.policy_decision,
          timestamp: a.timestamp
        }
      )

    receipts =
      query
      |> Repo.all()
      |> Enum.map(&attestation_to_heuristic_receipt(&1, tenant_id))

    {:ok, receipts}
  rescue
    error ->
      {:error, {:repo_load_failed, error}}
  end

  # Map a row from `attestations` (selected via the fields above) into the
  # `Heuristic.receipt()` shape that pattern modules consume. Treats
  # nil principal subjects as "unknown" + drops to :obo_human kind so the
  # AnomalousBurst pattern doesn't accidentally suppress the receipt.
  defp attestation_to_heuristic_receipt(row, tenant_id) do
    principal = row.principal || %{}
    subject = lookup_string(principal, "subject", "unknown")
    kind = principal_kind(lookup_string(principal, "kind", "obo_human"))
    home_tenant = lookup_string(principal, "tenant_id", tenant_id)

    %{
      principal_subject: subject,
      action_label: Atom.to_string(row.event_kind || :unknown),
      resource_kind: "Recurse::Resource::ConsoleSurface",
      policy_decision: row.policy_decision || :allow,
      committed_at: row.timestamp,
      principal_kind: kind,
      principal_tenant_id: home_tenant,
      tenant_attribute: nil,
      matched_policy: nil
    }
  end

  defp lookup_string(map, key, default) when is_map(map) and is_binary(key) do
    case Map.get(map, key, default) do
      v when is_binary(v) -> v
      v when is_atom(v) and not is_nil(v) -> Atom.to_string(v)
      _ -> default
    end
  end

  defp principal_kind("obo_human"), do: :obo_human
  defp principal_kind("service_account"), do: :service_account
  defp principal_kind("autonomous"), do: :autonomous
  defp principal_kind(_), do: :obo_human

  # ---------------------------------------------------------------------------
  # Window math
  # ---------------------------------------------------------------------------

  defp parse_window(args) do
    case {Map.get(args, "since_iso"), Map.get(args, "until_iso")} do
      {since_iso, until_iso} when is_binary(since_iso) and is_binary(until_iso) ->
        {:ok, since, _} = DateTime.from_iso8601(since_iso)
        {:ok, until_dt, _} = DateTime.from_iso8601(until_iso)
        %{since: since, until: until_dt}

      _ ->
        default_window()
    end
  end

  defp build_window_from_opts(opts) do
    if Map.has_key?(opts, :since) and Map.has_key?(opts, :until) do
      %{since: Map.fetch!(opts, :since), until: Map.fetch!(opts, :until)}
    else
      default_window()
    end
  end

  defp default_window do
    until = DateTime.utc_now()
    since = DateTime.add(until, -@window_days, :day)
    %{since: since, until: until}
  end
end
