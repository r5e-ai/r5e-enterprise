defmodule Recurse.Gateway.Admin.AuditAgent.Tools.SuggestPolicyPattern do
  @moduledoc """
  Audit Agent Tool 6 — `suggest_policy_pattern` (F004 T114).

  Returns one or more proposed Cedar policy rules informed by a receipt
  window, with optional Blast Radius previews. Two sources:

    * `heuristic` — zero LLM tokens, deterministic pattern detection.
    * `llm`       — calls `LLMProvider`, ≤2K input / ≤1K output tokens.

  **Operator-only.** Cedar denies for `tenant_auditor` (write-adjacent
  capability per `audit_agent_tools.md` §"Tool 6").

  ## Cross-phase dependency (Phase 7)

  This tool wraps `Recurse.Gateway.SuggestionEngine.HeuristicRunner` and
  `Recurse.Gateway.SuggestionEngine.LlmRunner` — modules that DO NOT YET
  EXIST as of Phase 6. The integration is forward-stubbed via
  `Code.ensure_loaded?/1`; until Phase 7 lands, both source paths return
  `{:error, :runners_not_yet_implemented}` and the tool is exercised in
  Phase 6 tests only via the negative path (input validation, Cedar
  deny, missing-runner short-circuit).

  When Phase 7 ships these modules, the existence checks here go green
  and the tool starts dispatching real work — no edits required to this
  file.

  Cross-references:
    * `specs/004-audit-console/contracts/audit_agent_tools.md` §"Tool 6"
  """

  @behaviour Recurse.Gateway.Admin.AuditAgent.Tool

  @heuristic_runner Recurse.Gateway.SuggestionEngine.HeuristicRunner
  @llm_runner Recurse.Gateway.SuggestionEngine.LlmRunner

  @input_schema %{
    "type" => "object",
    "additionalProperties" => false,
    "required" => ["source"],
    "properties" => %{
      "source" => %{"type" => "string", "enum" => ["heuristic", "llm"]},
      "window_days" => %{
        "type" => "integer",
        "minimum" => 1,
        "maximum" => 30,
        "default" => 7
      },
      "scope_hint" => %{
        "type" => "object",
        "properties" => %{
          "principal_subject" => %{"type" => "string"},
          "tool_name" => %{"type" => "string"}
        }
      },
      "limit" => %{"type" => "integer", "minimum" => 1, "maximum" => 5, "default" => 3}
    }
  }

  @output_schema %{
    "type" => "object",
    "required" => ["suggestions", "source", "window_days"],
    "properties" => %{
      "source" => %{"type" => "string"},
      "window_days" => %{"type" => "integer"},
      "suggestions" => %{"type" => "array"}
    }
  }

  @impl true
  def name, do: "suggest_policy_pattern"

  @impl true
  def cedar_action, do: ~s|Recurse::Action::"AuditAgentToolSuggestPolicyPattern"|

  @impl true
  def event_kind, do: :ui_chat_skill_invoked_suggest_policy_pattern

  @impl true
  def input_schema, do: @input_schema

  @impl true
  def output_schema, do: @output_schema

  @impl true
  def call(input, %{tenant_id: tenant_id}) when is_map(input) and is_binary(tenant_id) do
    source = Map.fetch!(input, "source")
    window_days = Map.get(input, "window_days", 7)
    scope_hint = Map.get(input, "scope_hint", %{})
    limit = Map.get(input, "limit", 3)

    window = build_window(window_days)

    case dispatch_runner(source, tenant_id, window, scope_hint, limit) do
      {:ok, suggestions} ->
        {:ok,
         %{
           "source" => source,
           "window_days" => window_days,
           "suggestions" => suggestions
         }}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp dispatch_runner("heuristic", tenant_id, window, scope_hint, limit) do
    if Code.ensure_loaded?(@heuristic_runner) and
         function_exported?(@heuristic_runner, :run_for_window, 2) do
      apply(@heuristic_runner, :run_for_window, [
        tenant_id,
        Map.merge(window, %{scope_hint: scope_hint, limit: limit})
      ])
    else
      # Phase-7 forward-ref. Return graceful "not yet" so contract tests
      # can exercise the structural path without depending on Phase-7
      # modules.
      {:error, :runners_not_yet_implemented}
    end
  end

  defp dispatch_runner("llm", tenant_id, window, scope_hint, limit) do
    if Code.ensure_loaded?(@llm_runner) and
         function_exported?(@llm_runner, :run_for_window, 2) do
      apply(@llm_runner, :run_for_window, [
        tenant_id,
        Map.merge(window, %{scope_hint: scope_hint, limit: limit})
      ])
    else
      {:error, :runners_not_yet_implemented}
    end
  end

  defp dispatch_runner(_, _, _, _, _), do: {:error, :invalid_source}

  defp build_window(days) do
    until = DateTime.utc_now()
    since = DateTime.add(until, -days, :day)
    %{since: since, until: until}
  end
end
