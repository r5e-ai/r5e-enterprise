defmodule Recurse.Gateway.Admin.AuditAgent.Tools.SimulatePolicyDryrun do
  @moduledoc """
  Audit Agent Tool 5 — `simulate_policy_dryrun` (F004 T113).

  Agent-callable equivalent of `POST /v1/policy/simulate` — wraps the
  Cedar NIF directly so the tool runtime doesn't have to spin up a
  separate HTTP loopback. Note: auditors CAN simulate (read-only), even
  though they cannot save drafts.

  Cost: zero LLM tokens (Cedar NIF only). Cedar action:
  `Recurse::Action::"AuditAgentToolSimulatePolicyDryrun"`. Required
  roles: `tenant_auditor` or `platform_operator`.

  Cross-references:
    * `specs/004-audit-console/contracts/audit_agent_tools.md` §"Tool 5"
    * `specs/004-audit-console/contracts/audit_api_extensions.md`
      §"POST /v1/policy/simulate" (the HTTP-side surface this tool mirrors)
  """

  @behaviour Recurse.Gateway.Admin.AuditAgent.Tool

  alias Recurse.Cedar

  @input_schema %{
    "type" => "object",
    "additionalProperties" => false,
    "required" => ["cedar_source", "principal", "action", "resource"],
    "properties" => %{
      "cedar_source" => %{"type" => "string"},
      "principal" => %{
        "type" => "object",
        "required" => ["kind", "id"],
        "properties" => %{
          "kind" => %{"type" => "string"},
          "id" => %{"type" => "string"},
          "attrs" => %{"type" => "object"}
        }
      },
      "action" => %{"type" => "string"},
      "resource" => %{
        "type" => "object",
        "required" => ["kind", "id"],
        "properties" => %{
          "kind" => %{"type" => "string"},
          "id" => %{"type" => "string"},
          "attrs" => %{"type" => "object"}
        }
      },
      "context" => %{"type" => "object"}
    }
  }

  @output_schema %{
    "type" => "object",
    "required" => ["decision"],
    "properties" => %{
      "decision" => %{"type" => "string", "enum" => ["allow", "deny"]},
      "matched_policies" => %{"type" => "array"},
      "reasoning" => %{"type" => "string"}
    }
  }

  @impl true
  def name, do: "simulate_policy_dryrun"

  @impl true
  def cedar_action, do: ~s|Recurse::Action::"AuditAgentToolSimulatePolicyDryrun"|

  @impl true
  def event_kind, do: :ui_chat_skill_invoked_simulate_policy_dryrun

  @impl true
  def input_schema, do: @input_schema

  @impl true
  def output_schema, do: @output_schema

  @impl true
  def call(input, %{tenant_id: tenant_id}) when is_map(input) and is_binary(tenant_id) do
    cedar_source = Map.fetch!(input, "cedar_source")
    principal = normalize_principal(Map.fetch!(input, "principal"))
    action_uid = Map.fetch!(input, "action")
    resource = normalize_resource(Map.fetch!(input, "resource"))
    context = Map.get(input, "context", %{})

    with :ok <- validate_cedar(cedar_source) do
      run_simulation(cedar_source, principal, action_uid, resource, context, tenant_id)
    end
  end

  defp validate_cedar(source) do
    case Cedar.validate_policy_syntax(source) do
      :ok -> :ok
      {:error, message} -> {:error, {:cedar_parse_error, message}}
    end
  end

  defp run_simulation(cedar_source, principal, action_uid, resource, context, tenant_id) do
    entities = build_entities(principal, resource)
    entities_json = JSON.encode!(entities)

    request_json =
      JSON.encode!(%{
        "principal" => ~s[#{principal.type}::"#{principal.id}"],
        "action" => action_uid,
        "resource" => ~s[#{resource.type}::"#{resource.id}"],
        "context" => merged_context(context, tenant_id)
      })

    case Cedar.evaluate_with_entities(cedar_source, request_json, entities_json) do
      {:ok, %{decision: decision, matched_policies: matched}} ->
        {:ok,
         %{
           "decision" => Atom.to_string(decision),
           "matched_policies" => normalize_matched(matched),
           "reasoning" => build_reasoning(decision, matched)
         }}

      {:error, message} ->
        {:error, {:cedar_eval_error, message}}
    end
  end

  defp normalize_principal(%{"kind" => kind, "id" => id} = p) do
    %{
      type: kind_to_type(kind),
      id: id,
      attrs: stringify_keys(Map.get(p, "attrs", %{}))
    }
  end

  defp normalize_resource(%{"kind" => kind, "id" => id} = r) do
    %{
      type: kind,
      id: id,
      attrs: stringify_keys(Map.get(r, "attrs", %{}))
    }
  end

  defp kind_to_type("obo_human"), do: "Recurse::Principal::Human"
  defp kind_to_type("service_account"), do: "Recurse::Principal::ServiceAccount"
  defp kind_to_type("autonomous"), do: "Recurse::Principal::Autonomous"
  defp kind_to_type("Recurse::Principal::" <> _ = t), do: t
  defp kind_to_type(other) when is_binary(other), do: other

  defp build_entities(principal, resource) do
    [
      %{
        "uid" => %{"type" => principal.type, "id" => principal.id},
        "attrs" =>
          Map.put_new(principal.attrs, "tenant_id", Map.get(principal.attrs, "tenant_id", "")),
        "parents" => []
      },
      %{
        "uid" => %{"type" => resource.type, "id" => resource.id},
        "attrs" => resource.attrs,
        "parents" => []
      }
    ]
  end

  defp merged_context(context, tenant_id) do
    base = stringify_keys(context)

    base
    |> Map.put_new("tenant_id", tenant_id)
    |> Map.put_new("correlation_id", "agent-tool")
    |> Map.put_new("timestamp", System.system_time(:second))
    |> Map.put_new("client_ip", "0.0.0.0")
  end

  defp normalize_matched(matched) when is_list(matched) do
    Enum.map(matched, fn
      m when is_binary(m) -> %{"id" => m}
      m when is_map(m) -> m
      other -> %{"id" => to_string(other)}
    end)
  end

  defp normalize_matched(_), do: []

  defp build_reasoning(:allow, []), do: "no policy matched but Cedar returned :allow"

  defp build_reasoning(:allow, matched),
    do: "permit policies matched: #{describe(matched)}"

  defp build_reasoning(:deny, []), do: "no policy matched; default deny applied"
  defp build_reasoning(:deny, matched), do: "forbid or unmatched: #{describe(matched)}"

  defp describe(matched) when is_list(matched) do
    matched
    |> Enum.map(fn
      m when is_binary(m) -> m
      %{"id" => id} -> id
      other -> to_string(other)
    end)
    |> Enum.join(", ")
  end

  defp stringify_keys(map) when is_map(map) do
    Map.new(map, fn
      {k, v} when is_atom(k) -> {Atom.to_string(k), v}
      {k, v} -> {k, v}
    end)
  end

  defp stringify_keys(_), do: %{}
end
