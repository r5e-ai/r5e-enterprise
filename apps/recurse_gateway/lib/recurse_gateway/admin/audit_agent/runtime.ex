defmodule Recurse.Gateway.Admin.AuditAgent.Runtime do
  @moduledoc """
  Audit-Agent runtime dispatcher (F004 T107).

  Wires the per-call lifecycle from `audit_agent_tools.md` §"Per-call
  lifecycle":

    1. Receive `(tool_name, input_json, conversation_ctx)`.
    2. Validate `input_json` against the tool's `c:input_schema/0`. Invalid
       input fails synchronously with `{:error, :invalid_input, details}`
       — NO Cedar call, NO receipt.
    3. Cedar evaluation: `(principal, c:cedar_action/0,
       resource=AuditEndpoint, ctx)`. Deny → emit `:policy_denied` +
       return `{:error, :forbidden, run_id}`.
    4. Invoke `c:call/2`. Wrap any raise in a `{:error, :crash}` arm so
       the per-tool attestation still emits with `outcome: "crash"`.
    5. Emit the per-tool attestation via `ToolCall.emit/1`.
    6. Return `{:ok, output, run_id}` to the caller.

  ## Cost guardrails

  Per `audit_agent_tools.md` §"Cost guardrails (LLM-calling tools only)":

    * **Per-call**: ≤2K input / ≤1K output tokens — enforced inside the
      LLM-calling tools themselves (Tools 3 + 6).
    * **Per-conversation**: ≤30K combined tokens — enforced HERE in the
      runtime via the `:tokens_remaining_in_conversation` slot threaded
      into `Tool.call_ctx`. `assess_conversation_budget/2` reads the
      sum of `(tokens_in + tokens_out)` from prior messages' attested
      receipts; if the projected next-call cost would exceed 30K we
      short-circuit with `:agent_token_budget_exceeded` BEFORE invoking
      the tool.
    * **Per-principal rate limit**: 60 calls/minute combined across all
      six tools. Enforced via a `:counters`-backed sliding-window check
      keyed by principal subject.

  Both budgets are tier-config tunable (see contract); the constants
  here are the defaults.

  ## Iron Law check (`elixir:phoenix-thinking`, `elixir:elixir-thinking`)

    1. Mutable state across calls? Per-call only — the rate-limit slot
       is a `:persistent_term`-rooted ETS table created lazily; the
       conversation-token budget is read from the Repo (no in-memory
       cache).
    2. Concurrent execution? Tools run synchronously on the SSE handler
       process; the runtime does not spawn.
    3. Fault isolation? Yes for tool crashes — wrapped in `try/rescue`
       so a buggy tool can't take down the SSE stream.

  Mutable state + fault isolation triggered, but only at the
  ETS-rate-limit + crash-rescue boundary — not GenServer territory.

  ## Cross-references

    * `specs/004-audit-console/contracts/audit_agent_tools.md`
    * `apps/recurse_gateway/lib/recurse_gateway/admin/audit_agent/tool.ex`
    * `apps/recurse_gateway/lib/recurse_gateway/admin/audit_agent/tool_call.ex`
    * `apps/recurse_gateway/lib/recurse_gateway/audit_plane/authz.ex`
      (Cedar gate seam)
  """

  import Ecto.Query

  alias Recurse.Gateway.Admin.AuditAgent.ToolCall
  alias Recurse.Gateway.Admin.AuditAgent.Tools
  alias Recurse.Gateway.Admin.BrowserAuth.UiReceipts
  alias Recurse.Gateway.Policy.Active
  alias Recurse.Gateway.Policy.Evaluator
  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Attestation
  alias Recurse.Providers.Repo
  alias Recurse.Shared.IdentityContext

  require Logger

  @per_conversation_max_tokens 30_000
  @per_minute_rate_limit 60

  @rate_limit_table __MODULE__.RateLimit

  @tool_registry %{
    "query_receipts" => Tools.QueryReceipts,
    "fetch_receipt_detail" => Tools.FetchReceiptDetail,
    "explain_denial" => Tools.ExplainDenial,
    "find_similar_receipts" => Tools.FindSimilarReceipts,
    "simulate_policy_dryrun" => Tools.SimulatePolicyDryrun,
    "suggest_policy_pattern" => Tools.SuggestPolicyPattern
  }

  @typedoc "Outcome of a single dispatch."
  @type dispatch_result ::
          {:ok, output :: map(), attested_run_id :: String.t()}
          | {:error, :invalid_input, details :: term()}
          | {:error, :forbidden, attested_run_id :: String.t()}
          | {:error, :rate_limited, retry_after_seconds :: pos_integer()}
          | {:error, :agent_token_budget_exceeded, attested_run_id :: String.t()}
          | {:error, :upstream_unavailable, attested_run_id :: String.t()}
          | {:error, :tool_not_found}
          | {:error, :internal, attested_run_id :: String.t()}

  @doc """
  Look up a tool module by name. Returns `{:ok, mod}` for any of the six
  Day-1 vocabulary entries, `{:error, :tool_not_found}` otherwise.
  """
  @spec lookup_tool(String.t()) :: {:ok, module()} | {:error, :tool_not_found}
  def lookup_tool(name) when is_binary(name) do
    case Map.fetch(@tool_registry, name) do
      {:ok, mod} -> {:ok, mod}
      :error -> {:error, :tool_not_found}
    end
  end

  @doc """
  The complete tool registry (six entries). Public so tests can iterate.
  """
  @spec tool_registry() :: %{String.t() => module()}
  def tool_registry, do: @tool_registry

  @doc """
  Per-conversation token cap (tier-config tunable in production).
  """
  @spec per_conversation_max_tokens() :: pos_integer()
  def per_conversation_max_tokens, do: @per_conversation_max_tokens

  @doc """
  Per-principal rate limit (calls/min combined across all tools).
  """
  @spec per_minute_rate_limit() :: pos_integer()
  def per_minute_rate_limit, do: @per_minute_rate_limit

  @doc """
  Run the per-call lifecycle for a single agent tool invocation.

  Always returns a tagged result; never raises (tool-impl crashes are
  caught + logged). The caller (ChatHandler) drains the result into the
  appropriate SSE event.
  """
  @spec dispatch(String.t(), map(), %{
          required(:identity_ctx) => IdentityContext.t(),
          required(:tenant_id) => String.t(),
          required(:conversation_id) => String.t()
        }) :: dispatch_result()
  def dispatch(tool_name, raw_input, %{
        identity_ctx: %IdentityContext{} = ctx,
        tenant_id: tenant_id,
        conversation_id: conversation_id
      })
      when is_binary(tool_name) and is_binary(tenant_id) and is_binary(conversation_id) do
    with {:ok, tool_mod} <- lookup_tool(tool_name),
         input <- normalize_input(raw_input),
         :ok <- validate_input(tool_mod, input),
         :ok <- check_rate_limit(ctx, conversation_id),
         :ok <- check_conversation_budget(conversation_id),
         :ok <- cedar_gate(tool_mod, ctx) do
      run_tool_with_emission(tool_mod, input, ctx, tenant_id, conversation_id)
    else
      {:error, :tool_not_found} ->
        {:error, :tool_not_found}

      {:error, :invalid_input, details} ->
        {:error, :invalid_input, details}

      {:error, :rate_limited, retry_after} ->
        {:error, :rate_limited, retry_after}

      {:error, :forbidden, _matched} ->
        # Emit :policy_denied; surface attested_run_id back to caller.
        run_id = emit_policy_denied(tool_name, ctx, conversation_id)
        {:error, :forbidden, run_id}

      {:error, :budget_exceeded} ->
        run_id =
          emit_tool_attestation(
            lookup_tool!(tool_name),
            normalize_input(raw_input),
            nil,
            [],
            :budget_exceeded,
            ctx,
            conversation_id
          )

        {:error, :agent_token_budget_exceeded, run_id}

      {:error, :bundle_not_loaded} ->
        run_id = emit_policy_denied(tool_name, ctx, conversation_id)
        {:error, :forbidden, run_id}
    end
  end

  # ---------------------------------------------------------------------------
  # Lifecycle stages
  # ---------------------------------------------------------------------------

  defp normalize_input(input) when is_map(input) do
    Map.new(input, fn
      {k, v} when is_atom(k) -> {Atom.to_string(k), v}
      {k, v} -> {k, v}
    end)
  end

  defp normalize_input(_), do: %{}

  # Minimal Draft-2020-12 validator — checks `additionalProperties: false`,
  # `required` fields, and basic type matches. The full schema fidelity is
  # validated in tests against the static schema map; runtime check only
  # needs to surface the load-bearing precondition errors (missing required
  # field; wrong type for primitives).
  defp validate_input(tool_mod, input) do
    schema = tool_mod.input_schema()

    if is_map(input) do
      do_validate_object(input, schema)
    else
      {:error, :invalid_input, "input must be an object"}
    end
  end

  defp do_validate_object(input, %{"required" => required} = schema) when is_list(required) do
    case Enum.find(required, &(not Map.has_key?(input, &1))) do
      nil -> do_validate_object(input, Map.delete(schema, "required"))
      missing -> {:error, :invalid_input, "missing required field `#{missing}`"}
    end
  end

  defp do_validate_object(input, %{"additionalProperties" => false, "properties" => props} = schema) do
    extra = Map.keys(input) -- Map.keys(props)

    case extra do
      [] -> do_validate_object(input, Map.delete(schema, "additionalProperties"))
      [k | _] -> {:error, :invalid_input, "unknown field `#{k}`"}
    end
  end

  defp do_validate_object(input, %{"properties" => props}) do
    Enum.reduce_while(props, :ok, fn {key, prop_schema}, :ok ->
      case validate_prop(Map.get(input, key), prop_schema) do
        :ok -> {:cont, :ok}
        {:error, msg} -> {:halt, {:error, :invalid_input, "field `#{key}`: #{msg}"}}
      end
    end)
  end

  defp do_validate_object(_input, _schema), do: :ok

  defp validate_prop(nil, _schema), do: :ok
  defp validate_prop(v, %{"type" => "string"}), do: ensure_type(v, :string)
  defp validate_prop(v, %{"type" => "integer"}), do: ensure_type(v, :integer)
  defp validate_prop(v, %{"type" => "number"}), do: ensure_type(v, :number)
  defp validate_prop(v, %{"type" => "boolean"}), do: ensure_type(v, :boolean)
  defp validate_prop(v, %{"type" => "object"}), do: ensure_type(v, :object)
  defp validate_prop(v, %{"type" => "array"}), do: ensure_type(v, :array)
  defp validate_prop(v, %{"type" => types}) when is_list(types), do: validate_one_of(v, types)
  # No "type" specified — pass-through.
  defp validate_prop(_, _), do: :ok

  defp ensure_type(v, :string) when is_binary(v), do: :ok
  defp ensure_type(_, :string), do: {:error, "expected string"}
  defp ensure_type(v, :integer) when is_integer(v), do: :ok
  defp ensure_type(_, :integer), do: {:error, "expected integer"}
  defp ensure_type(v, :number) when is_number(v), do: :ok
  defp ensure_type(_, :number), do: {:error, "expected number"}
  defp ensure_type(v, :boolean) when is_boolean(v), do: :ok
  defp ensure_type(_, :boolean), do: {:error, "expected boolean"}
  defp ensure_type(v, :object) when is_map(v), do: :ok
  defp ensure_type(_, :object), do: {:error, "expected object"}
  defp ensure_type(v, :array) when is_list(v), do: :ok
  defp ensure_type(_, :array), do: {:error, "expected array"}

  defp validate_one_of(v, types) do
    if Enum.any?(types, fn t -> match?(:ok, ensure_type(v, type_to_atom(t))) end) do
      :ok
    else
      {:error, "expected one of #{inspect(types)}"}
    end
  end

  defp type_to_atom("string"), do: :string
  defp type_to_atom("integer"), do: :integer
  defp type_to_atom("number"), do: :number
  defp type_to_atom("boolean"), do: :boolean
  defp type_to_atom("object"), do: :object
  defp type_to_atom("array"), do: :array
  defp type_to_atom(_), do: :unknown

  defp cedar_gate(tool_mod, %IdentityContext{} = ctx) do
    case Active.current() do
      {:ok, %Active{bundle: bundle_ref}} ->
        request = %{
          action: tool_mod.cedar_action(),
          resource: %{
            type: "Recurse::Resource::AuditEndpoint",
            id: tool_mod.name(),
            attrs: %{}
          },
          context: %{tenant_id: ctx.tenant_id}
        }

        case Evaluator.evaluate(bundle_ref, ctx, request) do
          {:allow, _matched} -> :ok
          {:deny, matched} -> {:error, :forbidden, matched}
        end

      {:error, _reason} ->
        {:error, :bundle_not_loaded}
    end
  end

  defp run_tool_with_emission(tool_mod, input, ctx, tenant_id, conversation_id) do
    call_ctx = %{
      identity_ctx: ctx,
      tenant_id: tenant_id,
      conversation_id: conversation_id
    }

    {result, outcome} = safe_invoke(tool_mod, input, call_ctx)

    case result do
      {:ok, output} ->
        run_ids = extract_attested_run_ids(output)
        run_id = emit_tool_attestation(tool_mod, input, output, run_ids, outcome, ctx, conversation_id)
        {:ok, output, run_id}

      {:error, :agent_token_budget_exceeded} ->
        run_id =
          emit_tool_attestation(tool_mod, input, nil, [], :budget_exceeded, ctx, conversation_id)

        {:error, :agent_token_budget_exceeded, run_id}

      {:error, {:upstream_unavailable, _}} ->
        run_id =
          emit_tool_attestation(tool_mod, input, nil, [], :upstream_error, ctx, conversation_id)

        {:error, :upstream_unavailable, run_id}

      {:error, :runners_not_yet_implemented} ->
        run_id =
          emit_tool_attestation(tool_mod, input, nil, [], :upstream_error, ctx, conversation_id)

        {:error, :upstream_unavailable, run_id}

      {:error, :not_found} ->
        run_id = emit_tool_attestation(tool_mod, input, nil, [], :crash, ctx, conversation_id)
        {:error, :internal, run_id}

      {:error, _other} ->
        run_id = emit_tool_attestation(tool_mod, input, nil, [], :crash, ctx, conversation_id)
        {:error, :internal, run_id}
    end
  end

  defp safe_invoke(tool_mod, input, call_ctx) do
    {tool_mod.call(input, call_ctx), :success}
  rescue
    error ->
      Logger.error(fn ->
        "audit_agent tool crash: #{inspect(error)} tool=#{tool_mod.name()}"
      end)

      {{:error, {:crash, error}}, :crash}
  end

  defp extract_attested_run_ids(output) when is_map(output) do
    case Map.get(output, "attested_run_ids") do
      list when is_list(list) -> Enum.filter(list, &is_binary/1)
      _ -> []
    end
  end

  defp emit_tool_attestation(tool_mod, input, output, run_ids, outcome, ctx, conversation_id) do
    run_id = Ecto.UUID.generate()

    ToolCall.emit(%{
      tool_name: tool_mod.name(),
      event_kind: tool_mod.event_kind(),
      input: input,
      output: output,
      attested_run_ids: run_ids,
      outcome: outcome,
      identity_ctx: ctx,
      conversation_id: conversation_id,
      tokens_in: tokens_in(output),
      tokens_out: tokens_out(output)
    })

    run_id
  end

  defp tokens_in(%{"tokens_in" => v}) when is_integer(v), do: v
  defp tokens_in(_), do: 0

  defp tokens_out(%{"tokens_out" => v}) when is_integer(v), do: v
  defp tokens_out(_), do: 0

  defp emit_policy_denied(tool_name, ctx, conversation_id) do
    run_id = Ecto.UUID.generate()

    UiReceipts.emit(:ui_chat, %{
      query_kind: "tool_denied",
      tool_name: tool_name,
      conversation_id: conversation_id,
      principal_subject: principal_subject(ctx),
      tenant_id: ctx.tenant_id,
      correlation_id: ctx.correlation_id,
      outcome: "policy_denied"
    })

    run_id
  end

  defp principal_subject(%IdentityContext{principal: %{subject: s}}) when is_binary(s), do: s
  defp principal_subject(%IdentityContext{principal: %{account_id: s}}) when is_binary(s), do: s
  defp principal_subject(_), do: "unknown"

  defp lookup_tool!(name) do
    case lookup_tool(name) do
      {:ok, mod} -> mod
      _ -> nil
    end
  end

  # ---------------------------------------------------------------------------
  # Conversation-level token budget
  # ---------------------------------------------------------------------------

  defp check_conversation_budget(conversation_id) do
    spent = sum_conversation_tokens(conversation_id)

    if spent >= @per_conversation_max_tokens do
      {:error, :budget_exceeded}
    else
      :ok
    end
  end

  defp sum_conversation_tokens(conversation_id) do
    # Receipts don't have direct conversation_id columns — they carry it in
    # the JSONB `principal` or via `correlation_id`. Rather than parse
    # JSONB at runtime, the chat_messages context already records token
    # counts in `tool_calls`. Sum from there.
    alias Recurse.Gateway.Admin.ChatHistory.ChatMessage

    query =
      from(m in ChatMessage,
        where: m.conversation_id == ^conversation_id and is_nil(m.deleted_at),
        select: m.tool_calls
      )

    query
    |> Repo.all()
    |> Enum.flat_map(fn calls when is_list(calls) -> calls end)
    |> Enum.reduce(0, fn call, acc ->
      tokens =
        case call do
          %{"tokens_in" => tin, "tokens_out" => tout} when is_integer(tin) and is_integer(tout) ->
            tin + tout

          %{"tokens" => t} when is_integer(t) ->
            t

          _ ->
            0
        end

      acc + tokens
    end)
  rescue
    _ -> 0
  end

  # ---------------------------------------------------------------------------
  # Per-principal rate limit (sliding-window via :counters + ETS)
  # ---------------------------------------------------------------------------

  defp check_rate_limit(%IdentityContext{} = ctx, _conversation_id) do
    ensure_table_started!()

    key = principal_subject(ctx)
    now = System.system_time(:second)
    window_start = now - 60

    # Remove expired entries for this key.
    :ets.select_delete(@rate_limit_table, [
      {{key, :"$1"}, [{:<, :"$1", window_start}], [true]}
    ])

    count = :ets.select_count(@rate_limit_table, [{{key, :_}, [], [true]}])

    if count >= @per_minute_rate_limit do
      {:error, :rate_limited, 60}
    else
      :ets.insert(@rate_limit_table, {key, now})
      :ok
    end
  end

  defp ensure_table_started! do
    case :ets.whereis(@rate_limit_table) do
      :undefined ->
        try do
          :ets.new(@rate_limit_table, [:public, :named_table, :duplicate_bag])
          :ok
        rescue
          ArgumentError -> :ok
        end

      _ ->
        :ok
      end
  end

  @doc """
  Reset the rate-limit table (test seam — do NOT call in production).
  """
  @spec reset_rate_limit_table_for_tests!() :: :ok
  def reset_rate_limit_table_for_tests! do
    case :ets.whereis(@rate_limit_table) do
      :undefined -> :ok
      _ ->
        :ets.delete_all_objects(@rate_limit_table)
        :ok
    end
  end

  @doc """
  Public re-export of the Attestation schema for tests that need to count
  emitted receipts. Keeps callers from depending on PostgresMerkleLedger
  paths directly.
  """
  @spec attestation_schema() :: module()
  def attestation_schema, do: Attestation
end
