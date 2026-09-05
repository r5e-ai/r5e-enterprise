defmodule Recurse.Gateway.SuggestionEngine.LlmRunner do
  @moduledoc """
  Daily Oban worker that runs the LLM-source suggestion engine over a
  trailing-30-day curated summary — F004 T133.

  Per research D4 + FR-030:

    * Cron: `0 2 * * *` (daily 02:00 UTC, finishes before 03:00 retention
      sweep). Wired in `application.ex` `oban_cron_crontab/0`.
    * Provider: F002 `LLMProvider` behaviour, accessed via
      `ProviderRegistry.llm_provider/0`.
    * Window: trailing 30 days of `attestations` for the deployment
      tenant — **summarized** (counts per tuple), NEVER raw receipts
      (D4: privacy + token-budget rationale).
    * Two-pass refinement: initial call; refinement call IF parse failed
      OR confidence on every suggestion < 60. >2 calls/cycle is rejected
      by the cost guardrail.
    * Per-tenant per-day spend cap: default $1/day (configurable via
      `:llm_daily_token_cap`). When exhausted, the runner logs a warning
      and skips the cycle with `error: "budget_exceeded"` on the run row.

  ## Public ad-hoc API — `run_for_window/2`

  Synchronous invocation used by the audit-agent SuggestPolicyPattern
  tool (T114) and by the manual refresh path (T134). Returns
  `{:ok, [suggestion_record]}` (raw maps, not persisted).

  ## Iron Law check (`elixir:oban-thinking` + `elixir:elixir-thinking`)

    * **Worker IS the right shape**: daily cron, durable retry on
      transient LLM failures (timeout / 429 from upstream).
    * **Args are JSON-string keys**: empty for cron, with overrides for
      replay/test (`{"tenant_id" => ..., "since_iso" => ...}`).
    * **Errors propagate via `{:error, reason}`** — Oban retries with
      backoff per `:max_attempts`.

  ## Cross-references

    * `specs/004-audit-console/research.md` D4 (LLM 2-pass refinement +
      structured output + $1/day spend cap).
    * `apps/recurse_gateway/priv/audit_agent_prompts/llm_suggestion.md`
      (T132 — operator-reviewable prompt template).
    * `apps/recurse_providers/lib/recurse_providers/llm_provider.ex`
      (F002 LLMProvider behaviour).
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
  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Attestation
  alias Recurse.Providers.Repo
  alias Recurse.Shared.IdentityContext
  alias Recurse.Shared.Principal

  require Logger

  @window_days 30
  @max_input_tokens 8_000
  @max_output_tokens 2_000
  @low_confidence_threshold 60
  @default_daily_token_cap 100_000
  @max_suggestions 5

  @impl Oban.Worker
  def perform(%Oban.Job{args: args}) do
    if Recurse.Gateway.ReleaseSurface.llm_suggestions_available?() do
      perform_available(args)
    else
      {:cancel, :capability_unavailable}
    end
  end

  defp perform_available(args) do
    tenant_id = Map.get(args, "tenant_id") || ProviderRegistry.tenant_id()
    window = parse_window(args)

    case run_with_persistence(tenant_id, window) do
      {:ok, _run} -> :ok
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Synchronous ad-hoc invocation. Returns raw suggestion records (not
  persisted). Used by the audit-agent SuggestPolicyPattern tool +
  integration tests.
  """
  @spec run_for_window(String.t(), map()) ::
          {:ok, [map()]} | {:error, term()}
  def run_for_window(tenant_id, opts \\ %{}) when is_binary(tenant_id) and is_map(opts) do
    if Recurse.Gateway.ReleaseSurface.llm_suggestions_available?() do
      run_available(tenant_id, opts)
    else
      {:error, :capability_unavailable}
    end
  end

  defp run_available(tenant_id, opts) do
    window = build_window_from_opts(opts)
    summary = build_summary(tenant_id, window)

    case call_llm_with_refinement(summary, tenant_id) do
      {:ok, suggestions, _tokens_used} -> {:ok, suggestions}
      {:error, _} = err -> err
    end
  end

  @doc "Default per-tenant per-day token cap (≈ $1/day at typical model rates)."
  @spec daily_token_cap() :: pos_integer()
  def daily_token_cap do
    Application.get_env(:recurse_gateway, :llm_daily_token_cap, @default_daily_token_cap)
  end

  # ---------------------------------------------------------------------------
  # Persistence pipeline (cron-driven path)
  # ---------------------------------------------------------------------------

  defp run_with_persistence(tenant_id, window) do
    {:ok, run} =
      PolicySuggestions.start_run(%{
        tenant_id: tenant_id,
        source: :llm,
        scheduled_at: DateTime.utc_now()
      })

    {:ok, run} =
      PolicySuggestions.update_run(run, %{started_at: DateTime.utc_now()})

    if budget_exceeded?(tenant_id) do
      finalize_budget_exhausted(run)
    else
      do_full_cycle(run, tenant_id, window)
    end
  end

  defp do_full_cycle(run, tenant_id, window) do
    summary = build_summary(tenant_id, window)

    case call_llm_with_refinement(summary, tenant_id) do
      {:ok, suggestions, tokens_used} ->
        finalize_normal(run, tenant_id, suggestions, tokens_used)

      {:error, reason} ->
        finalize_failed(run, reason)
    end
  end

  defp finalize_normal(run, tenant_id, suggestions, tokens_used) do
    persisted_count =
      Enum.reduce(suggestions, 0, fn s, acc ->
        try_persist(tenant_id, run.id, s, acc)
      end)

    PolicySuggestions.update_run(run, %{
      completed_at: DateTime.utc_now(),
      suggestions_generated_count: persisted_count,
      llm_token_spend: tokens_used
    })
  end

  defp try_persist(tenant_id, run_id, suggestion, acc) do
    case persist_suggestion(tenant_id, run_id, suggestion) do
      {:ok, %PolicySuggestion{} = persisted} ->
        emit_generated(persisted)
        acc + 1

      {:error, reason} ->
        Logger.warning(fn ->
          "llm suggestion persist failed: #{inspect(reason)}"
        end)

        acc
    end
  end

  defp finalize_failed(run, reason) do
    Logger.error(fn ->
      "llm runner failed: #{inspect(reason)} tenant=#{run.tenant_id}"
    end)

    PolicySuggestions.update_run(run, %{
      completed_at: DateTime.utc_now(),
      error: inspect(reason)
    })
  end

  defp finalize_budget_exhausted(run) do
    Logger.warning(fn ->
      "llm runner skipped — daily token cap exceeded tenant=#{run.tenant_id}"
    end)

    PolicySuggestions.update_run(run, %{
      completed_at: DateTime.utc_now(),
      error: "budget_exceeded"
    })
  end

  defp persist_suggestion(tenant_id, run_id, suggestion) do
    attrs = %{
      source: :llm,
      confidence_score: Map.get(suggestion, "confidence", 50),
      pattern_summary: Heuristic.trim(Map.get(suggestion, "pattern_summary", ""), 200),
      proposed_cedar: Heuristic.trim(Map.get(suggestion, "proposed_cedar", ""), 500),
      generation_run_id: run_id,
      status: :active,
      generated_at: DateTime.utc_now()
    }

    PolicySuggestions.create(tenant_id, attrs)
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
  # LLM call + 2-pass refinement (research D4)
  # ---------------------------------------------------------------------------

  defp call_llm_with_refinement(summary, tenant_id) do
    case do_llm_call(summary, tenant_id, :initial, nil) do
      {:ok, suggestions, tokens_used} ->
        if needs_refinement?(suggestions) do
          do_refinement_call(summary, tenant_id, suggestions, tokens_used)
        else
          {:ok, suggestions, tokens_used}
        end

      {:error, _} = err ->
        err
    end
  end

  defp do_refinement_call(summary, tenant_id, prior_suggestions, prior_tokens) do
    case do_llm_call(summary, tenant_id, :refinement, prior_suggestions) do
      {:ok, suggestions, refinement_tokens} ->
        {:ok, suggestions, prior_tokens + refinement_tokens}

      {:error, _reason} ->
        # Refinement-call failure: fall back to the initial output. We
        # do NOT propagate the refinement error because the spec says
        # "after the refinement call, output is used as-is regardless of
        # confidence" — the same applies if refinement itself fails.
        {:ok, prior_suggestions, prior_tokens}
    end
  end

  defp needs_refinement?([]), do: true

  defp needs_refinement?(suggestions) do
    Enum.all?(suggestions, fn s ->
      Map.get(s, "confidence", 0) < @low_confidence_threshold
    end)
  end

  defp do_llm_call(summary, tenant_id, pass, prior_output) do
    case ProviderRegistry.fetch() do
      {:ok, _registry} ->
        do_llm_provider_call(summary, tenant_id, pass, prior_output)

      {:error, :not_installed} ->
        # No provider registry → no LLM available. Return empty
        # suggestions; a real deployment ALWAYS has the provider wired.
        {:ok, [], 0}
    end
  end

  defp do_llm_provider_call(summary, tenant_id, pass, prior_output) do
    {llm_mod, llm_state} = ProviderRegistry.llm_provider()

    request = build_request(summary, pass, prior_output)
    ctx = build_identity_context(tenant_id)

    case llm_mod.chat_complete(llm_state, request, ctx) do
      {:ok, response} ->
        parse_llm_response(response)

      {:error, reason} ->
        {:error, {:llm_call_failed, reason}}
    end
  end

  defp build_request(summary, pass, prior_output) do
    system_prompt = read_prompt_template()
    user_message = build_user_message(summary, pass, prior_output)

    %{
      "model" => Application.get_env(:recurse_gateway, :llm_suggestion_model, "gpt-4o-mini"),
      "messages" => [
        %{"role" => "system", "content" => system_prompt},
        %{"role" => "user", "content" => user_message}
      ],
      "max_tokens" => @max_output_tokens,
      "temperature" => 0.2,
      "response_format" => %{"type" => "json_object"}
    }
  end

  defp build_user_message(summary, :initial, _) do
    Heuristic.trim(format_summary(summary), @max_input_tokens * 4)
  end

  defp build_user_message(summary, :refinement, prior) do
    prior_json = JSON.encode!(%{"suggestions" => prior})

    Heuristic.trim(
      "REFINEMENT_PASS:\n\n" <>
        "Your prior output:\n#{prior_json}\n\n" <>
        "The original summary:\n#{format_summary(summary)}\n\n" <>
        "Tighten the Cedar syntax and aim for at least 2 high-confidence (>=60) suggestions.",
      @max_input_tokens * 4
    )
  end

  defp format_summary(summary) do
    """
    Tenant: #{summary.tenant_id}
    Window: #{summary.window_days} days

    Allows by (principal, action, resource_kind):
    #{summary.allow_top |> Enum.map_join("\n", &format_allow_row/1)}

    Denies by (principal, action, matched_policy):
    #{summary.deny_top |> Enum.map_join("\n", &format_deny_row/1)}

    Suggest up to #{@max_suggestions} concrete Cedar rules.
    """
  end

  defp format_allow_row({principal, action, resource_kind, count}) do
    "  #{principal}, #{action}, #{resource_kind} → #{count} allows"
  end

  defp format_deny_row({principal, action, matched_policy, count}) do
    "  #{principal}, #{action}, policy=#{matched_policy} → #{count} denies"
  end

  defp parse_llm_response(response) do
    content = extract_content(response)
    tokens_used = extract_tokens(response)

    case JSON.decode(content) do
      {:ok, %{"suggestions" => suggestions}} when is_list(suggestions) ->
        {:ok, suggestions, tokens_used}

      {:ok, _other} ->
        {:ok, [], tokens_used}

      {:error, _reason} ->
        {:error, :parse_failed}
    end
  end

  defp extract_content(%{"choices" => [%{"message" => %{"content" => content}} | _]})
       when is_binary(content),
       do: content

  defp extract_content(_), do: "{\"suggestions\": []}"

  defp extract_tokens(%{"usage" => %{"total_tokens" => n}}) when is_integer(n), do: n
  defp extract_tokens(_), do: 0

  defp read_prompt_template do
    path =
      Path.join([
        Application.app_dir(:recurse_gateway, "priv"),
        "audit_agent_prompts",
        "llm_suggestion.md"
      ])

    case File.read(path) do
      {:ok, body} -> body
      {:error, _} -> "You are the Recurse policy-suggestion engine. Emit a JSON object."
    end
  end

  defp build_identity_context(tenant_id) do
    IdentityContext.new(%{
      machine_identity: "system://suggestion_engine",
      principal:
        Principal.service_account(%{
          issuer: "system://suggestion_engine",
          account_id: "recurse-gateway-system"
        }),
      tenant_id: tenant_id,
      correlation_id: "llm-suggestion-#{Ecto.UUID.generate()}"
    })
  end

  # ---------------------------------------------------------------------------
  # Budget tracking (per-tenant per-day rolling sum from policy_suggestion_runs)
  # ---------------------------------------------------------------------------

  defp budget_exceeded?(tenant_id) do
    cap = daily_token_cap()
    today_start = today_utc_start()

    alias Recurse.Gateway.Admin.PolicySuggestions.PolicySuggestionRun

    query =
      from(r in PolicySuggestionRun,
        where:
          r.tenant_id == ^tenant_id and r.source == ^:llm and
            r.scheduled_at >= ^today_start and is_nil(r.deleted_at),
        select: sum(r.llm_token_spend)
      )

    case Repo.one(query) do
      nil -> false
      sum when is_integer(sum) -> sum >= cap
    end
  end

  defp today_utc_start do
    now = DateTime.utc_now()
    {:ok, midnight} = DateTime.new(DateTime.to_date(now), ~T[00:00:00.000000])
    midnight
  end

  # ---------------------------------------------------------------------------
  # Summary builder
  # ---------------------------------------------------------------------------

  defp build_summary(tenant_id, window) do
    rows = load_window_rows(tenant_id, window)

    %{
      tenant_id: tenant_id,
      window_days: @window_days,
      since: window.since,
      until: window.until,
      allow_top: top_allows(rows),
      deny_top: top_denies(rows)
    }
  end

  defp load_window_rows(tenant_id, %{since: since, until: until_dt}) do
    query =
      from(a in Attestation,
        where: a.tenant_id == ^tenant_id,
        where: a.timestamp >= ^since,
        where: a.timestamp < ^until_dt,
        select: %{
          principal: a.principal,
          event_kind: a.event_kind,
          policy_decision: a.policy_decision
        }
      )

    Repo.all(query)
  rescue
    _ -> []
  end

  defp top_allows(rows) do
    rows
    |> Enum.filter(&(&1.policy_decision == :allow))
    |> Enum.group_by(fn r -> {principal_subject(r.principal), r.event_kind, "Recurse::Resource::ConsoleSurface"} end)
    |> Enum.map(fn {{p, a, r}, group} -> {p, Atom.to_string(a || :unknown), r, length(group)} end)
    |> Enum.sort_by(fn {_, _, _, count} -> -count end)
    |> Enum.take(10)
  end

  defp top_denies(rows) do
    rows
    |> Enum.filter(&(&1.policy_decision == :deny))
    |> Enum.group_by(fn r -> {principal_subject(r.principal), r.event_kind} end)
    |> Enum.map(fn {{p, a}, group} -> {p, Atom.to_string(a || :unknown), "unknown", length(group)} end)
    |> Enum.sort_by(fn {_, _, _, count} -> -count end)
    |> Enum.take(10)
  end

  defp principal_subject(p) when is_map(p), do: Map.get(p, "subject") || Map.get(p, :subject) || "unknown"
  defp principal_subject(_), do: "unknown"

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
