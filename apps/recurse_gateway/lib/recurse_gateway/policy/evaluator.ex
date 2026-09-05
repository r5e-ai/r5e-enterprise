defmodule Recurse.Gateway.Policy.Evaluator do
  @moduledoc """
  Pure Cedar policy evaluator (F002 T047, FR-039).

  ## Responsibility

  Given a `%PolicyBundleRef{}` (from `Recurse.Gateway.Policy.BundleLoader`),
  an `IdentityContext`, and a request map describing action + resource +
  context, build the Cedar entity set + request JSON and call
  `Recurse.Cedar.evaluate_with_entities/3`.

  This module is PURE — no processes, no persistent state, no side effects
  beyond the Cedar NIF call (which is itself stateless). It's called
  directly from request-handling processes.

  ## Request shape

      %{
        action: "Recurse::Action::ChatCompletion",
        resource: %{
          type: "Recurse::Resource::LLMEndpoint",
          id: "openai_chat_completions",
          attrs: %{model: "gpt-4o-mini", provider: "openai"}
        },
        context: %{streaming: true, model: "gpt-4o-mini"}
      }

  The `context` map is merged with common context fields pulled from the
  `IdentityContext` (`tenant_id`, `correlation_id`, `timestamp`, `client_ip`)
  per the Cedar entity schema at
  `apps/recurse_gateway/priv/cedar/schema.cedarschema.json`.

  ## Principal mapping

  Maps `Recurse.Shared.Principal.kind` to a Cedar entity type:

    | Principal.kind       | Cedar entity type                  |
    |----------------------|------------------------------------|
    | `:obo_human`         | `Recurse::Principal::Human`        |
    | `:service_account`   | `Recurse::Principal::ServiceAccount` |
    | `:autonomous`        | `Recurse::Principal::Autonomous`   |

  Attributes copied onto the Cedar entity per the entity schema:

    * Human — `subject`, `issuer`, `groups`, `recurse_role` (+ optional `display_name`).
    * ServiceAccount — `subject`, `issuer`, `account_id`, `scope`, `recurse_role`.
    * Autonomous — `subject`, `recurse_role` (+ optional `spiffe_id`).

  Missing attributes receive safe defaults (`""` for strings, `[]` for
  sets) so policies that reference them never fault the NIF. Production
  principals always carry a `recurse_role` — the default is only a
  defense-in-depth guard.

  ## Fail-closed behavior

  If Cedar returns `{:error, _}` (malformed entity JSON, schema violation,
  NIF exception), the evaluator returns `{:deny, [:cedar_error]}`. Per
  Constitution Principle III, policy-plane failures are fail-closed.

  ## Return shape

    * `{:allow, matched_policies}` — Cedar decision was `Allow`.
      `matched_policies` is a sorted, deduped list of policy IDs from the
      Cedar diagnostics. Empty list is valid (e.g. forbid-only policy sets).
    * `{:deny, matched_policies}` — Cedar decision was `Deny`. Includes the
      sentinel `[:cedar_error]` on evaluation errors.

  ## Cross-references

    * `apps/recurse_shared/lib/recurse_shared/cedar.ex`
    * `apps/recurse_gateway/priv/cedar/schema.cedarschema.json`
    * `specs/002-standalone-gateway-vertical-slice/tasks.md` T047
    * `specs/002-standalone-gateway-vertical-slice/contracts/cedar_entity_schema.cedarschema.json`
    * Constitution Principle III (Fail-Closed on Policy)
  """

  alias Recurse.Gateway.PolicyBundleRef
  alias Recurse.Shared.IdentityContext
  alias Recurse.Shared.Principal

  @type request :: %{
          required(:action) => String.t(),
          required(:resource) => %{
            required(:type) => String.t(),
            required(:id) => String.t(),
            optional(:attrs) => map()
          },
          required(:context) => map()
        }

  @type decision :: :allow | :deny
  @type matched_policies :: [String.t() | atom()]

  @doc """
  Evaluate `request` against `bundle_ref` in the authority context of `identity_ctx`.

  Returns `{:allow, matched_policies}` or `{:deny, matched_policies}`.
  Evaluation errors return `{:deny, [:cedar_error]}` (fail-closed).
  """
  @spec evaluate(PolicyBundleRef.t(), IdentityContext.t(), request()) ::
          {decision(), matched_policies()}
  def evaluate(%PolicyBundleRef{} = bundle_ref, %IdentityContext{} = identity_ctx, request)
      when is_map(request) do
    with {:ok, principal_entity} <- build_principal_entity(identity_ctx.principal),
         principal_entity = inject_tenant_id(principal_entity, identity_ctx),
         {:ok, resource_entity} <- build_resource_entity(request.resource),
         {:ok, entities_json} <- encode_entities([principal_entity, resource_entity]),
         {:ok, request_json} <-
           encode_request(principal_entity, resource_entity, request, identity_ctx),
         {:ok, %{decision: decision, matched_policies: matched}} <-
           Recurse.Cedar.evaluate_with_entities(
             bundle_ref.bundle_bytes,
             request_json,
             entities_json
           ) do
      {decision, matched}
    else
      {:error, _reason} -> {:deny, [:cedar_error]}
    end
  end

  # F004: Cedar policies for the audit-console actions require
  # `principal.tenant_id == context.tenant_id`. The deployment-resolved
  # tenant_id lives on the IdentityContext (set at ingress per F001
  # FR-026); we inject it into the principal's Cedar attrs so the policy
  # check evaluates without operators having to add `tenant_id` to every
  # principal claim manually. Single-tenant-per-BEAM Phase-1 makes this a
  # tautology (caller's tenant is always the deployment tenant); Phase-2
  # federation will see real cross-tenant deny paths fire here.
  defp inject_tenant_id(%{attrs: attrs} = entity, %IdentityContext{tenant_id: tid})
       when is_binary(tid) do
    %{entity | attrs: Map.put(attrs, "tenant_id", tid)}
  end

  defp inject_tenant_id(entity, _ctx), do: entity

  # ---------------------------------------------------------------------------
  # Principal entity construction
  # ---------------------------------------------------------------------------

  defp build_principal_entity(%Principal{kind: :obo_human} = p) do
    {:ok,
     %{
       type: "Recurse::Principal::Human",
       id: principal_id(p),
       attrs:
         compact(%{
           "subject" => safe_string(p.subject),
           "issuer" => safe_string(p.issuer),
           "display_name" => p.display_name,
           "groups" => safe_string_list(p.groups),
           "recurse_role" => recurse_role(p)
         })
     }}
  end

  defp build_principal_entity(%Principal{kind: :service_account} = p) do
    {:ok,
     %{
       type: "Recurse::Principal::ServiceAccount",
       id: principal_id(p),
       attrs: %{
         "subject" => safe_string(p.subject || p.account_id),
         "issuer" => safe_string(p.issuer),
         "account_id" => safe_string(p.account_id),
         "scope" => safe_string_list(p.scope),
         "recurse_role" => recurse_role(p)
       }
     }}
  end

  defp build_principal_entity(%Principal{kind: :autonomous} = p) do
    {:ok,
     %{
       type: "Recurse::Principal::Autonomous",
       id: principal_id(p),
       attrs:
         compact(%{
           "subject" => safe_string(p.spiffe_id || p.subject),
           "spiffe_id" => p.spiffe_id,
           "recurse_role" => recurse_role(p)
         })
     }}
  end

  defp build_principal_entity(other), do: {:error, {:invalid_principal, other}}

  defp principal_id(%Principal{subject: s}) when is_binary(s) and s != "", do: s
  defp principal_id(%Principal{account_id: a}) when is_binary(a) and a != "", do: a
  defp principal_id(%Principal{spiffe_id: sp}) when is_binary(sp) and sp != "", do: sp
  defp principal_id(_), do: "unknown"

  defp recurse_role(%Principal{} = p) do
    # F002 extends Principal's backing with a `recurse_role` field via JWT
    # claim extraction. `Map.get/3` on the struct covers both the case where
    # the field is part of the struct and where it's attached via the
    # tagged-map extension path.
    role =
      case Map.get(p, :recurse_role) do
        nil -> Map.get(p, "recurse_role")
        v -> v
      end

    safe_string(role)
  end

  defp safe_string(nil), do: ""
  defp safe_string(s) when is_binary(s), do: s
  defp safe_string(s), do: to_string(s)

  defp safe_string_list(nil), do: []
  defp safe_string_list(list) when is_list(list), do: Enum.map(list, &safe_string/1)

  defp compact(map) do
    map
    |> Enum.reject(fn {_k, v} -> is_nil(v) end)
    |> Map.new()
  end

  # ---------------------------------------------------------------------------
  # Resource entity construction
  # ---------------------------------------------------------------------------

  defp build_resource_entity(%{type: type, id: id} = resource)
       when is_binary(type) and is_binary(id) do
    attrs = stringify_keys(Map.get(resource, :attrs, %{}))
    {:ok, %{type: type, id: id, attrs: attrs}}
  end

  defp build_resource_entity(other), do: {:error, {:invalid_resource, other}}

  defp stringify_keys(map) when is_map(map) do
    Map.new(map, fn
      {k, v} when is_atom(k) -> {Atom.to_string(k), stringify_value(v)}
      {k, v} when is_binary(k) -> {k, stringify_value(v)}
    end)
  end

  defp stringify_value(v) when is_map(v) and not is_struct(v), do: stringify_keys(v)
  defp stringify_value(v) when is_list(v), do: Enum.map(v, &stringify_value/1)
  defp stringify_value(v), do: v

  # ---------------------------------------------------------------------------
  # JSON encoding for the NIF
  # ---------------------------------------------------------------------------

  defp encode_entities(entities) do
    json =
      entities
      |> Enum.map(fn e ->
        %{
          "uid" => %{"type" => e.type, "id" => e.id},
          "attrs" => e.attrs,
          "parents" => []
        }
      end)
      |> JSON.encode!()

    {:ok, json}
  rescue
    error -> {:error, {:entities_encode_error, Exception.message(error)}}
  end

  defp encode_request(principal_entity, resource_entity, request, identity_ctx) do
    context =
      request.context
      |> stringify_keys()
      |> Map.merge(%{
        "tenant_id" => identity_ctx.tenant_id,
        "correlation_id" => identity_ctx.correlation_id,
        "timestamp" => System.system_time(:second),
        "client_ip" => Map.get(stringify_keys(request.context), "client_ip", "0.0.0.0")
      })

    json =
      JSON.encode!(%{
        "principal" => ~s[#{principal_entity.type}::"#{principal_entity.id}"],
        "action" => action_uid(request.action),
        "resource" => ~s[#{resource_entity.type}::"#{resource_entity.id}"],
        "context" => context
      })

    {:ok, json}
  rescue
    error -> {:error, {:request_encode_error, Exception.message(error)}}
  end

  # Accept both the bare action string (`"Recurse::Action::ChatCompletion"`)
  # and the quoted-id form (`Recurse::Action::"ChatCompletion"`). Cedar's
  # EntityUid::from_str expects the quoted-id form; we normalize here so
  # callers don't have to know the grammar.
  defp action_uid(action) when is_binary(action) do
    case String.split(action, "::", trim: true) do
      parts when length(parts) >= 2 ->
        {namespace, [name]} = Enum.split(parts, length(parts) - 1)
        namespace_str = Enum.join(namespace, "::")

        if String.starts_with?(name, ~s(")) do
          "#{namespace_str}::#{name}"
        else
          ~s[#{namespace_str}::"#{name}"]
        end

      _ ->
        action
    end
  end
end
