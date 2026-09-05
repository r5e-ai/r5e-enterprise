defmodule Recurse.Gateway.Admin.AuditAgent.Tools.ExplainDenial do
  @moduledoc """
  Audit Agent Tool 3 — `explain_denial` (F004 T111).

  Natural-language explanation of why a deny fired for a given receipt
  — which policy + line + condition tripped, in plain English. Calls
  the F002 `LLMProvider`; bounded at **≤2K input tokens / ≤1K output
  tokens per call**.

  Cedar action: `Recurse::Action::"AuditAgentToolExplainDenial"`.
  Required roles: `tenant_auditor` or `platform_operator`.

  Cross-references:
    * `specs/004-audit-console/contracts/audit_agent_tools.md` §"Tool 3"
    * `apps/recurse_providers/lib/recurse_providers/llm_provider.ex`
      (F002 LLMProvider behaviour)
  """

  @behaviour Recurse.Gateway.Admin.AuditAgent.Tool

  alias Recurse.Gateway.ProviderRegistry
  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Attestation
  alias Recurse.Providers.Repo
  alias Recurse.Shared.IdentityContext

  @per_call_max_input_tokens 2_000
  @per_call_max_output_tokens 1_000

  # 4 chars / token rough estimator (used to bound prompt size before sending
  # — actual token counts are reconciled from upstream usage when available).
  @chars_per_token 4

  @input_schema %{
    "type" => "object",
    "additionalProperties" => false,
    "required" => ["run_id"],
    "properties" => %{
      "run_id" => %{"type" => "string", "format" => "uuid"}
    }
  }

  @output_schema %{
    "type" => "object",
    "required" => ["explanation", "model", "tokens_in", "tokens_out"],
    "properties" => %{
      "explanation" => %{"type" => "string"},
      "referenced_policy_lines" => %{"type" => "array"},
      "model" => %{"type" => "string"},
      "tokens_in" => %{"type" => "integer"},
      "tokens_out" => %{"type" => "integer"}
    }
  }

  @impl true
  def name, do: "explain_denial"

  @impl true
  def cedar_action, do: ~s|Recurse::Action::"AuditAgentToolExplainDenial"|

  @impl true
  def event_kind, do: :ui_chat_skill_invoked_explain_denial

  @impl true
  def input_schema, do: @input_schema

  @impl true
  def output_schema, do: @output_schema

  @impl true
  def call(%{"run_id" => run_id}, %{tenant_id: tenant_id, identity_ctx: %IdentityContext{} = ctx})
      when is_binary(run_id) and is_binary(tenant_id) do
    with {:ok, att} <- fetch_receipt(run_id, tenant_id),
         {:ok, request_body} <- build_llm_request(att),
         :ok <- ensure_under_input_budget(request_body),
         {:ok, response, tokens_in, tokens_out, model} <- call_llm(request_body, ctx) do
      explanation = response |> bound_to_output_budget()

      {:ok,
       %{
         "explanation" => explanation,
         "referenced_policy_lines" => [],
         "model" => model,
         "tokens_in" => tokens_in,
         "tokens_out" => tokens_out,
         "attested_run_ids" => [run_id]
       }}
    end
  end

  defp fetch_receipt(run_id, tenant_id) do
    case safe_get(run_id) do
      nil ->
        {:error, :not_found}

      %Attestation{tenant_id: tid} when tid != tenant_id ->
        {:error, :not_found}

      %Attestation{} = att ->
        {:ok, att}
    end
  end

  defp safe_get(run_id) do
    Repo.get(Attestation, run_id)
  rescue
    Ecto.Query.CastError -> nil
  end

  defp build_llm_request(%Attestation{} = att) do
    summary = build_summary(att)

    body = %{
      "model" => "gpt-4o-mini",
      "max_tokens" => @per_call_max_output_tokens,
      "messages" => [
        %{
          "role" => "system",
          "content" =>
            "You are an audit assistant. Explain in 100-300 words of plain English why the receipt below was denied. Cite the matched policy by id when available. Do not include identifying personal information beyond what is in the receipt."
        },
        %{
          "role" => "user",
          "content" => summary
        }
      ]
    }

    {:ok, body}
  end

  defp build_summary(%Attestation{} = att) do
    """
    Receipt run_id: #{att.run_id}
    Event kind: #{att.event_kind}
    Policy decision: #{att.policy_decision}
    Outcome: #{att.outcome}
    Principal: #{inspect(att.principal)}
    Tenant: #{att.tenant_id}
    Timestamp: #{att.timestamp}
    """
    |> String.slice(0, @per_call_max_input_tokens * @chars_per_token)
  end

  defp ensure_under_input_budget(%{"messages" => messages}) do
    total_chars =
      messages
      |> Enum.map(fn %{"content" => c} -> byte_size(c) end)
      |> Enum.sum()

    estimated_tokens = div(total_chars, @chars_per_token)

    if estimated_tokens <= @per_call_max_input_tokens do
      :ok
    else
      {:error, :agent_token_budget_exceeded}
    end
  end

  defp call_llm(request_body, ctx) do
    {llm_mod, llm_state} = ProviderRegistry.llm_provider()

    case llm_mod.chat_complete(llm_state, request_body, ctx) do
      {:ok, response} ->
        text = extract_response_text(response)
        usage = Map.get(response, "usage", %{})
        tokens_in = Map.get(usage, "prompt_tokens", 0)
        tokens_out = Map.get(usage, "completion_tokens", 0)
        model = Map.get(response, "model", "unknown")
        {:ok, text, tokens_in, tokens_out, model}

      {:error, reason} ->
        {:error, {:upstream_unavailable, reason}}
    end
  end

  defp extract_response_text(%{"choices" => [%{"message" => %{"content" => content}} | _]})
       when is_binary(content),
       do: content

  defp extract_response_text(_), do: ""

  # Hard cap on output text length — even if upstream emitted >1K tokens worth
  # of text, we slice to the budget so the receipt's predicate hash is bounded.
  defp bound_to_output_budget(text) when is_binary(text) do
    max_bytes = @per_call_max_output_tokens * @chars_per_token

    if byte_size(text) > max_bytes do
      String.slice(text, 0, max_bytes)
    else
      text
    end
  end

  defp bound_to_output_budget(_), do: ""

  @doc """
  Public for tests: per-call input-token bound (used by token-budget
  property assertions).
  """
  @spec per_call_max_input_tokens() :: pos_integer()
  def per_call_max_input_tokens, do: @per_call_max_input_tokens

  @doc """
  Public for tests: per-call output-token bound.
  """
  @spec per_call_max_output_tokens() :: pos_integer()
  def per_call_max_output_tokens, do: @per_call_max_output_tokens
end
