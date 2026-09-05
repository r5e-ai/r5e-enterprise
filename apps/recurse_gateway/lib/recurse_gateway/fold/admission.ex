defmodule Recurse.Gateway.Fold.Admission do
  @moduledoc """
  Mandatory admission boundary for the enterprise proxy.

  `open/3` precedes the upstream request. `admit_tool/3` precedes release of
  executable tool bytes. `complete/3` records the outcome against those actual
  admissions; it never re-evaluates the original request or tool intents.

  The fold signs for the gateway's observations. Client identity and group
  metadata remain claims observed by the gateway, not verified client keys.
  """

  alias Recurse.Fold
  alias Recurse.Gateway.Fold.Submitter
  alias Recurse.Shared.LlmProxy.ToolUseIntent

  @group "gateway.r5e.io/v1alpha1/"

  @doc "Availability is informational; every operation still goes through admission."
  def ready? do
    Fold.Application.enabled?() and
      Process.whereis(R5e.Supervisor) != nil and
      R5e.Policy.KernelCedar.ready?() and
      is_binary(Fold.authority()) and
      match?({:ok, _}, Fold.Policy.Cedar.active_bundle())
  rescue
    _ -> false
  catch
    :exit, _ -> false
  end

  @doc "Retain and admit the exact request before it can leave the gateway."
  def open(body, context, metadata \\ %{})

  def open(body, context, metadata) when is_binary(body) and is_map(context) do
    safely(fn ->
      limit = Application.get_env(:r5e, :cas_max_bytes, 16 * 1024 * 1024)

      with true <- ready?() or {:error, :admission_unavailable},
           {:ok, context} <- current_policy_context(context),
           true <- byte_size(body) <= limit or {:error, :request_evidence_too_large},
           {:ok, params} when is_map(params) <- Jason.decode(body),
           model when is_binary(model) and model != "" <- params["model"] || context[:model],
           call =
             Map.merge(metadata, %{
               model: model,
               started_at: context.started_at,
               principal_id: get_in(context, [:principal, :id]) || context[:principal_id]
             }),
           {:ok, session} <- admitted("AgentSession", Submitter.spec_for_agent_session(call)),
           session_ref = @group <> "AgentSession/" <> session["name"],
           {:ok, bytes_ref} <- put(body, "application/json"),
           {:ok, prompt} <-
             admitted("Prompt", Submitter.spec_for_prompt(call, bytes_ref, session_ref)),
           spec =
             Submitter.spec_for_llm_call(call, prompt["name"], session_ref, metadata[:trace_id]),
           spec = Map.put(spec, "gatewayContext", request_context(context, model)),
           {:ok, receipt} <- admitted("LlmCall", spec),
           {:ok, context} <- policy_context(context, get_in(receipt, ["policy", "source"])) do
        {:ok,
         %{
           llm_call_ref: receipt["eventRef"],
           session_ref: session_ref,
           opening_receipt: receipt,
           context: context,
           request_hash: :crypto.hash(:sha256, body)
         }}
      else
        {:error, _} = failure -> failure
        _ -> {:error, :invalid_model_request}
      end
    end)
  end

  def open(_, _, _), do: {:error, :invalid_model_request}

  @doc "Obtain the one authorization decision for a held tool intent."
  def admit_tool(
        %{llm_call_ref: call_ref, session_ref: session_ref} = opening,
        %ToolUseIntent{} = intent,
        context
      ) do
    safely(fn ->
      # A hash-only sentinel is not the arguments the model supplied. It cannot
      # be substituted for them and then forwarded under a policy over {}.
      with true <- is_map(intent.tool_args) or {:error, :tool_arguments_unavailable},
           true <-
             Regex.match?(~r/\A[A-Za-z0-9_.:-]{1,128}\z/, intent.tool_name) or
               {:error, :invalid_tool_name} do
        index = max(context[:admission_index] || intent.parallel_index || 0, 0)
        spec = Submitter.spec_for_tool_call(intent, call_ref, index, session_ref)
        spec = Map.put(spec, "gatewayContext", tool_context(intent, context, opening))
        tool_decision(Fold.admit(@group <> "ToolCall", spec))
      end
    end)
  end

  def admit_tool(_, _, _), do: {:error, :missing_opening_admission}

  defp tool_decision({:ok, receipt}), do: {:ok, {:allow}, receipt}

  defp tool_decision({:denied, %{"policy" => %{"decision" => "deny"}} = receipt}) do
    {:ok,
     {:deny,
      %{
        rule_id: first_rule(receipt),
        reason: "denied_by_admission_policy",
        suggested_alternative: nil
      }}, receipt}
  end

  defp tool_decision({:denied, receipt}), do: {:error, {:tool_admission_failed, receipt}}
  defp tool_decision({:refused, reason}), do: {:error, {:tool_admission_refused, reason}}

  @doc "Record completion using existing request/tool references, without re-admission."
  def complete(%{llm_call_ref: call_ref}, call_state, tool_receipts)
      when is_list(tool_receipts) do
    safely(fn ->
      with {:ok, completion_name} <- completion(call_state),
           refs <- Enum.map(tool_receipts, & &1["eventRef"]),
           spec <- Submitter.spec_for_llm_response(call_state, call_ref, completion_name, refs),
           {:ok, receipt} <- admitted("LlmResponse", spec) do
        {:ok, receipt}
      end
    end)
  end

  def complete(_, _, _), do: {:error, :missing_opening_admission}

  # The chain owns policy identity. A loader projection may be missing or
  # stale, and a WebSocket can outlive multiple policy activations. Submitted
  # context is an observation; the receipt binds the policy actually used.
  defp current_policy_context(context) do
    case Fold.Policy.Cedar.active_bundle() do
      {:ok, bundle} -> policy_context(context, get_in(bundle, ["spec", "sourceRef", "$ref"]))
      _ -> {:error, :admission_policy_unavailable}
    end
  end

  defp policy_context(context, source) when is_binary(source) do
    with {:ok, bytes} <- R5e.CAS.get(source),
         {:ok, hash} <- Recurse.Cedar.canonical_hash_result(bytes) do
      {:ok, Map.put(context, :cedar_bundle_hash, hash)}
    else
      _ -> {:error, :admission_policy_unavailable}
    end
  end

  defp policy_context(_, _), do: {:error, :admission_policy_unavailable}

  defp completion(%{response_payload: {:ok, bytes}} = state) when is_binary(bytes),
    do: completion(%{state | response_payload: bytes})

  defp completion(%{response_payload: bytes} = state) when is_binary(bytes) do
    expected = state[:response_hash]

    with true <- expected == :crypto.hash(:sha256, bytes) or {:error, :response_hash_mismatch},
         {:ok, address} <- put(bytes, "application/octet-stream"),
         {:ok, receipt} <- admitted("Completion", Submitter.spec_for_completion(state, address)) do
      {:ok, receipt["name"]}
    end
  end

  defp completion(%{error_kind: error}) when is_binary(error), do: {:ok, nil}
  defp completion(_), do: {:error, :completion_evidence_unavailable}

  defp admitted(kind, spec) do
    case Fold.admit(@group <> kind, spec) do
      {:ok, receipt} -> {:ok, receipt}
      other -> {:error, {:admission_failed, kind, other}}
    end
  end

  defp put(bytes, type) do
    case Fold.put_cas(bytes, media_type: type) do
      {:ok, _receipt, address} -> {:ok, address}
      other -> {:error, {:evidence_failed, other}}
    end
  end

  defp request_context(context, model) do
    principal = context[:principal] || %{}

    %{
      "principal_id" => principal[:id] || "anonymous",
      "principal_kind" => to_string(principal[:kind] || :service_account),
      # R1-F4 (RC review 2026-09-05): where the gateway got this identity
      # from — `jwt`, `client_metadata`, `mtls_svid` or `anonymous`. It
      # used to be the constant `"gateway-observed-client"`, which said
      # only what the `epistemicScope` already says (the gateway observed
      # it, nothing authenticated it) and threw away the one distinction
      # the gateway had actually made: a bearer token and the anonymous
      # fail-open path recorded the same string. `"unknown"` when a caller
      # supplies no principal at all, which is not the same claim as
      # `anonymous` (the extractor's own verdict).
      "principal_source" => to_string(principal[:source] || "unknown"),
      "principal_groups" => groups(principal),
      "chatgpt_account_id" => principal[:chatgpt_account_id] || "",
      "model" => model,
      "tenant" => value_or(context, :tenant, ""),
      "session_id" => value_or(context, :session_id, ""),
      "prompt_hash" => hex(context[:prompt_hash]),
      "response_so_far_hash" => hex(context[:response_so_far_hash]),
      "estimated_completion_tokens" => context[:estimated_completion_tokens] || 0,
      "upstream_domain" => value_or(context, :upstream_domain, ""),
      "transport" => to_string(context[:transport] || :https_sse),
      "started_at" => DateTime.to_iso8601(context.started_at)
    }
  end

  defp tool_context(intent, context, opening) do
    request_context(context, context.model)
    |> Map.merge(%{
      # This identifies the actual opening receipt's policy, not the policy
      # governing this later tool. The tool receipt and evaluation bind that
      # decision's current policy; a pre-admission reread would introduce a race.
      "opening_model_policy_hash" => hex(get_in(opening, [:context, :cedar_bundle_hash])),
      "tool_args_hash" => hex(intent.tool_args_hash),
      "tool_args_size_bytes" => intent.tool_args_size_bytes,
      "parallel_tool_call_index" => intent.parallel_index || -1
    })
  end

  defp groups(%{claims: claims}) when is_map(claims) do
    case claims["groups"] || claims[:groups] do
      groups when is_list(groups) -> Enum.filter(groups, &is_binary/1)
      _ -> []
    end
  end

  defp groups(_), do: []
  defp value_or(context, key, default), do: context[key] || default

  defp hex(bytes) when is_binary(bytes), do: Base.encode16(bytes, case: :lower)
  defp hex(_), do: ""

  defp first_rule(receipt),
    do: List.first(get_in(receipt, ["policy", "matched"]) || []) || "admission.denied"

  defp safely(fun) do
    fun.()
  rescue
    _ -> {:error, :admission_exception}
  catch
    :exit, _ -> {:error, :admission_unavailable}
    :throw, _ -> {:error, :admission_failure}
  end
end
