defmodule Recurse.Gateway.Admin.PolicySimulateHandler do
  @moduledoc """
  `POST /v1/policy/simulate` (F004 T092).

  Evaluates an arbitrary Cedar source against a caller-supplied synthetic
  `(principal, action, resource, context)` tuple. Used by the Policy
  Simulator "Simulate" mode (FR-022).

  ## Request

      {
        "cedar_source": "permit(...) when {...};",
        "principal": {"kind": "Recurse::Principal::Human", "id": "alice", "attrs": {...}},
        "action": "Recurse::Action::\\"ChatCompletion\\"",
        "resource": {"kind": "Recurse::Resource::LLMEndpoint", "id": "openai/gpt-4o", "attrs": {...}},
        "context": {"tenant_id": "...", "timestamp": 1714000000, ...}
      }

  ## Response (200)

      {
        "decision": "allow|deny",
        "matched_policies": [...],
        "reasoning": "...",
        "attested_run_id": "..."
      }

  ## Cedar action + receipt

  Cedar action `PolicySimulate`; emits `:ui_policy_simulate`. Cedar parse
  errors return 400 with `error_description` carrying the line/col
  diagnostic from the NIF.

  ## Iron Law check (`elixir:phoenix-thinking`)

  Pure module — no GenServer. Cedar evaluation is a stateless NIF call.

  ## Cross-references

    * `specs/004-audit-console/contracts/audit_api_extensions.md`
      §"Policy simulation"
    * `specs/004-audit-console/data-model.md` §0
    * `apps/recurse_shared/lib/recurse_shared/cedar.ex` —
      `Recurse.Cedar.evaluate_with_entities/3` and
      `Recurse.Cedar.validate_policy_syntax/1`.
  """

  alias Recurse.Gateway.Admin.BrowserAuth.UiReceipts
  alias Recurse.Gateway.AuditPlane.Authz
  alias Recurse.Shared.IdentityContext

  require Logger

  @action "Recurse::Action::\"PolicySimulate\""

  @doc """
  Plug-shaped entry point.
  """
  @spec handle(Plug.Conn.t()) :: Plug.Conn.t()
  def handle(%Plug.Conn{} = conn) do
    resource = %{
      type: "Recurse::Resource::ConsoleSurface",
      id: "policy_simulate",
      attrs: %{"endpoint" => "/v1/policy/simulate"}
    }

    case Authz.gate(conn, @action, resource) do
      {:ok, conn_after, ctx, _bundle_ref} ->
        # T146 — per-tenant rate-limit on POST /v1/policy/simulate.
        # Default 60/min/tenant; configurable via `:policy_simulate_rate_limit`
        # application env. Reuses the F002 audit-plane envelope shape on 429.
        case apply_simulate_rate_limit(conn_after) do
          %Plug.Conn{halted: true} = halted -> halted
          conn_after_rl -> do_handle(conn_after_rl, ctx)
        end

      err ->
        Authz.dispatch_gate_error(conn, err)
    end
  end

  # T146 — pass-through when rate-limiting is disabled (the test posture)
  # or when the config key is unset; otherwise dispatch to the F002
  # RateLimiter plug with audit-plane (per-tenant) keys.
  defp apply_simulate_rate_limit(conn) do
    if Application.get_env(:recurse_gateway, :rate_limit_enabled?, false) do
      opts =
        Application.get_env(:recurse_gateway, :policy_simulate_rate_limit, [])
        |> Keyword.put_new(:plane, :audit)
        |> Keyword.put_new(:limit, 60)

      plug_opts = Recurse.Gateway.Plug.RateLimiter.init(opts)
      Recurse.Gateway.Plug.RateLimiter.call(conn, plug_opts)
    else
      conn
    end
  end

  defp do_handle(conn, %IdentityContext{} = ctx) do
    body = conn.body_params || %{}

    with {:ok, cedar_source} <- fetch_string(body, "cedar_source"),
         :ok <- validate_cedar(cedar_source),
         {:ok, principal} <- fetch_principal(body),
         {:ok, action_uid} <- fetch_action(body),
         {:ok, resource} <- fetch_resource(body),
         context <- Map.get(body, "context", %{}) do
      run_simulation(conn, ctx, cedar_source, principal, action_uid, resource, context)
    else
      {:error, {:cedar_parse_error, message}} ->
        Authz.send_bad_request(conn, "cedar parse error: #{message}")

      {:error, {:missing, field}} ->
        Authz.send_bad_request(conn, "field `#{field}` is required")

      {:error, {:invalid, field, message}} ->
        Authz.send_bad_request(conn, "field `#{field}` invalid: #{message}")
    end
  end

  defp run_simulation(conn, ctx, cedar_source, principal, action_uid, resource, context) do
    entities = build_entities(principal, resource)
    entities_json = JSON.encode!(entities)

    request_json =
      JSON.encode!(%{
        "principal" => ~s[#{principal.type}::"#{principal.id}"],
        "action" => action_uid,
        "resource" => ~s[#{resource.type}::"#{resource.id}"],
        "context" => merge_context(context, ctx)
      })

    case Recurse.Cedar.evaluate_with_entities(cedar_source, request_json, entities_json) do
      {:ok, %{decision: decision, matched_policies: matched}} ->
        run_id = Ecto.UUID.generate()
        emit_simulate(ctx, cedar_source, decision, run_id)

        body = %{
          "decision" => Atom.to_string(decision),
          "matched_policies" => Enum.map(matched, &normalize_matched_policy/1),
          "reasoning" => build_reasoning(decision, matched),
          "attested_run_id" => run_id
        }

        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.send_resp(200, JSON.encode!(body))

      {:error, message} ->
        Logger.warning(fn -> "policy simulate eval failed: #{inspect(message)}" end)
        Authz.send_bad_request(conn, "cedar eval error: #{inspect(message)}")
    end
  end

  # ---------------------------------------------------------------------------
  # Field extraction
  # ---------------------------------------------------------------------------

  defp fetch_string(body, key) do
    case Map.get(body, key) do
      s when is_binary(s) and s != "" -> {:ok, s}
      _ -> {:error, {:missing, key}}
    end
  end

  defp validate_cedar(source) do
    case Recurse.Cedar.validate_policy_syntax(source) do
      :ok -> :ok
      {:error, message} -> {:error, {:cedar_parse_error, message}}
    end
  end

  defp fetch_principal(body) do
    case Map.get(body, "principal") do
      %{"kind" => kind, "id" => id} = p when is_binary(kind) and is_binary(id) ->
        {:ok,
         %{
           type: kind_to_type(kind),
           id: id,
           attrs: stringify_keys(Map.get(p, "attrs", %{}))
         }}

      nil ->
        {:error, {:missing, "principal"}}

      _ ->
        {:error, {:invalid, "principal", "expected map with :kind and :id"}}
    end
  end

  defp fetch_action(body) do
    case Map.get(body, "action") do
      s when is_binary(s) and s != "" -> {:ok, s}
      _ -> {:error, {:missing, "action"}}
    end
  end

  defp fetch_resource(body) do
    case Map.get(body, "resource") do
      %{"kind" => kind, "id" => id} = r when is_binary(kind) and is_binary(id) ->
        {:ok,
         %{
           type: kind,
           id: id,
           attrs: stringify_keys(Map.get(r, "attrs", %{}))
         }}

      nil ->
        {:error, {:missing, "resource"}}

      _ ->
        {:error, {:invalid, "resource", "expected map with :kind and :id"}}
    end
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

  defp merge_context(context, %IdentityContext{} = ctx) do
    base = stringify_keys(context)

    base
    |> Map.put_new("tenant_id", ctx.tenant_id || "")
    |> Map.put_new("correlation_id", ctx.correlation_id || "simulate")
    |> Map.put_new("timestamp", System.system_time(:second))
    |> Map.put_new("client_ip", "0.0.0.0")
  end

  defp normalize_matched_policy(policy) when is_binary(policy) do
    %{"id" => policy, "effect" => nil, "line_start" => nil, "line_end" => nil}
  end

  defp normalize_matched_policy(policy) when is_map(policy), do: policy
  defp normalize_matched_policy(other), do: %{"id" => to_string(other)}

  defp build_reasoning(:allow, []),
    do:
      "no policy matched but Cedar default-allow returned :allow (this should not happen with the Recurse bundle)"

  defp build_reasoning(:allow, matched),
    do: "permit policies matched: #{Enum.join(matched, ", ")}"

  defp build_reasoning(:deny, []), do: "no policy matched; default deny applied"
  defp build_reasoning(:deny, matched), do: "forbid or unmatched: #{Enum.join(matched, ", ")}"

  # ---------------------------------------------------------------------------
  # Receipt emission
  # ---------------------------------------------------------------------------

  defp emit_simulate(%IdentityContext{} = ctx, cedar_source, decision, run_id) do
    UiReceipts.emit(:ui_policy_simulate, %{
      cedar_source_hash: cedar_source_hash_safe(cedar_source),
      decision: Atom.to_string(decision),
      simulate_run_id: run_id,
      principal_subject: principal_subject_from_ctx(ctx),
      tenant_id: ctx.tenant_id,
      correlation_id: ctx.correlation_id
    })
  end

  defp cedar_source_hash_safe(source) do
    Recurse.Cedar.canonical_hash_hex(source)
  rescue
    # `Recurse.Cedar.canonical_hash/1` raises `ArgumentError` on parse
    # failure (the documented expected error case). Receipt emission
    # must not crash on malformed Cedar — fall back to nil so the audit
    # plane still records the simulate attempt. Any other exception is
    # an unexpected bug — let it propagate.
    ArgumentError -> nil
  end

  defp principal_subject_from_ctx(%IdentityContext{principal: %{subject: sub}})
       when is_binary(sub),
       do: sub

  defp principal_subject_from_ctx(%IdentityContext{principal: %{account_id: id}})
       when is_binary(id),
       do: id

  defp principal_subject_from_ctx(_), do: "unknown"

  defp stringify_keys(map) when is_map(map) do
    Map.new(map, fn
      {k, v} when is_atom(k) -> {Atom.to_string(k), v}
      {k, v} -> {k, v}
    end)
  end

  defp stringify_keys(_), do: %{}
end
