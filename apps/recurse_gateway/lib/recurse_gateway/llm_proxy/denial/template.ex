defmodule Recurse.Gateway.LlmProxy.DenialInjector.Template do
  @moduledoc """
  Denial-message rendering shared by every per-API denial injector
  (Constitution Principle VII: the Anthropic Messages injector was the
  second consumer of the OpenAI Responses renderer, so it moved here).

  `render/4` builds the radical-transparency bindings (R5E-102: the tool,
  the call id, the Cedar rule, the bundle hash, the audit-substrate
  identifiers, the per-tenant appeal pointers) from a denied
  `ToolUseIntent` + deny payload + the caller's `:audit_context`, and
  substitutes them into the template. `render_template/2` is the pure
  substitution grammar:

    * `{var}` — substituted with the binding (missing / nil → `""`).
    * `{? … }` — optional clause, kept only when EVERY `{var}` inside
      resolves to a non-empty string; otherwise the whole clause
      vanishes (no half-empty "ping  ()" artefacts).

  Pure-functional and total: no input raises.
  """

  alias Recurse.Shared.LlmProxy.ToolUseIntent

  # Default denial template — radical-transparency-by-default (R5E-102).
  # The agent (and the human appealing the denial) sees the rule that
  # fired, the call_id, the policy bundle version, and enough audit-
  # substrate identifiers to file an exception request without
  # archeology. Per-tenant override via
  # `LlmProviderConfig.metadata["denial_template"]`.
  #
  # The anti-pattern this replaces is the "your call was blocked,
  # contact your administrator" message — opaque, unactionable,
  # escalation-hostile. Every identifier here is already public-shaped:
  # the rule_id is the Cedar rule's identifier, the bundle hash is the
  # immutable canonical hash of the policy bundle (on every audit row),
  # the principal_id is who-we-acted-for (visible in the agent's own
  # JWT), tenant_id + session_id locate the audit row.
  #
  # The appeal line exists only when the tenant configured somewhere to
  # appeal to (`metadata["appeal_uri"]` and/or `metadata["appeal_contact"]`,
  # folded into `{appeal_pointer}`); with neither, nothing is rendered for
  # it (spec 012 S7). The `{? … }` clauses carry their own leading newline
  # so a vanished clause leaves no blank line behind.
  @default_template """
                    Tool call '{tool_name}' (call_id: {call_id}) was blocked by org policy.

                    - Rule: {rule_id}
                    - Reason: {reason}
                    - Policy bundle: {cedar_bundle_hash_short}
                    - Tenant: {tenant_id}
                    - Principal: {principal_id} ({principal_kind})
                    - Session: {session_id}{?
                    - Try alternative: {suggested_alternative}}{?
                    - To appeal: {appeal_pointer} and cite the rule_id + bundle hash above.}
                    """
                    |> String.trim()

  @doc """
  The default denial template every injector renders when the tenant's
  `LlmProviderConfig.metadata["denial_template"]` is unset.
  """
  @spec default() :: String.t()
  def default, do: @default_template

  @doc """
  Render the denial text for `intent`. `opts[:audit_context]` may carry
  `tenant_id`, `principal_id`, `principal_kind`, `session_id`,
  `cedar_bundle_hash` (32 raw bytes), `appeal_uri`, `appeal_contact`,
  `policy_source_uri`.
  """
  @spec render(ToolUseIntent.t(), map(), String.t(), keyword()) :: String.t()
  def render(%ToolUseIntent{} = intent, deny, template, opts \\ [])
      when is_map(deny) and is_binary(template) and is_list(opts) do
    audit_context = Keyword.get(opts, :audit_context, %{}) || %{}

    bindings = %{
      tool_name: intent.tool_name,
      call_id: intent.call_id,
      rule_id: Map.get(deny, :rule_id),
      reason: Map.get(deny, :reason),
      suggested_alternative: Map.get(deny, :suggested_alternative),
      tenant_id: Map.get(audit_context, :tenant_id),
      principal_id: Map.get(audit_context, :principal_id),
      principal_kind: Map.get(audit_context, :principal_kind),
      session_id: Map.get(audit_context, :session_id),
      cedar_bundle_hash_hex: hex_or_nil(Map.get(audit_context, :cedar_bundle_hash)),
      cedar_bundle_hash_short: short_hex_or_nil(Map.get(audit_context, :cedar_bundle_hash)),
      appeal_uri: Map.get(audit_context, :appeal_uri),
      appeal_contact: Map.get(audit_context, :appeal_contact),
      appeal_pointer:
        appeal_pointer(Map.get(audit_context, :appeal_contact), Map.get(audit_context, :appeal_uri)),
      policy_source_uri: Map.get(audit_context, :policy_source_uri)
    }

    render_template(template, bindings)
  end

  @doc """
  Substitute `bindings` into `template` (see the module doc for the
  grammar).

      iex> Recurse.Gateway.LlmProxy.DenialInjector.Template.render_template(
      ...>   "Tool '{tool_name}' blocked: {reason}.{? Alt: {suggested_alternative}}",
      ...>   %{tool_name: "shell", rule_id: "r1", reason: "denied", suggested_alternative: nil}
      ...> )
      "Tool 'shell' blocked: denied."

      iex> Recurse.Gateway.LlmProxy.DenialInjector.Template.render_template(
      ...>   "Tool '{tool_name}' blocked: {reason}.{? Alt: {suggested_alternative}}",
      ...>   %{tool_name: "shell", rule_id: "r1", reason: "denied", suggested_alternative: "py"}
      ...> )
      "Tool 'shell' blocked: denied. Alt: py"
  """
  @spec render_template(String.t(), map()) :: String.t()
  def render_template(template, bindings) when is_binary(template) and is_map(bindings) do
    template
    |> render_optional_clause(bindings)
    |> render_variables(bindings)
  end

  # Pass 1: `{? … }` clauses. The body may contain zero-or-more non-nested
  # `{var}` placeholders; the clause is kept only when all of them bind.
  defp render_optional_clause(template, bindings) do
    Regex.replace(~r/\{\?((?:[^{}]|\{[^{}]*\})*?)\}/, template, fn _full, body ->
      if all_referenced_bindings_present?(body, bindings), do: body, else: ""
    end)
  end

  defp all_referenced_bindings_present?(body, bindings) do
    Regex.scan(~r/\{([a-zA-Z_][a-zA-Z0-9_]*)\}/, body, capture: :all_but_first)
    |> List.flatten()
    |> Enum.all?(fn var_name ->
      case lookup(bindings, var_name) do
        {:ok, value} -> is_binary(value) and value != ""
        :error -> false
      end
    end)
  end

  # Pass 2: `{var}` substitution. Unknown names stay in place (totality).
  defp render_variables(template, bindings) do
    Regex.replace(~r/\{([a-zA-Z_][a-zA-Z0-9_]*)\}/, template, fn _full, var_name ->
      case lookup(bindings, var_name) do
        {:ok, value} -> stringify(value)
        :error -> "{" <> var_name <> "}"
      end
    end)
  end

  # Bindings are atom-keyed; only atoms that already exist are looked up
  # so a template cannot grow the atom table.
  defp lookup(bindings, var_name) do
    key = String.to_existing_atom(var_name)
    if Map.has_key?(bindings, key), do: {:ok, Map.get(bindings, key)}, else: :error
  rescue
    ArgumentError -> :error
  end

  # `{appeal_pointer}`: whichever of contact / uri the tenant configured,
  # in one phrase; nil (so a `{? … }` clause around it vanishes) when neither.
  defp appeal_pointer(contact, uri) do
    case {nonempty(contact), nonempty(uri)} do
      {nil, nil} -> nil
      {c, nil} -> "ping " <> c
      {nil, u} -> u
      {c, u} -> "ping " <> c <> " (" <> u <> ")"
    end
  end

  defp nonempty(s) when is_binary(s) and s != "", do: s
  defp nonempty(_), do: nil

  defp stringify(nil), do: ""
  defp stringify(s) when is_binary(s), do: s
  defp stringify(other), do: to_string(other)

  defp hex_or_nil(<<bin::binary>>) when byte_size(bin) > 0, do: Base.encode16(bin, case: :lower)
  defp hex_or_nil(_), do: nil

  # First 12 hex chars — enough to name a bundle in a denial message.
  defp short_hex_or_nil(<<bin::binary>>) when byte_size(bin) >= 6,
    do: bin |> binary_part(0, 6) |> Base.encode16(case: :lower)

  defp short_hex_or_nil(_), do: nil
end
