defmodule RecurseBroker.RoleMapper do
  @moduledoc """
  Resolve an identity's `recurse_role` from its customer-IdP `groups` claim
  (F002 T084). Pure module.

  Iron Law check (elixir-thinking):

    1. Mutable state persisting across calls? No — every `resolve_role/2`
       call is a pure function of `(claims, mapping)`.
    2. Concurrent execution? No — resolution is a handful of map lookups.
    3. Fault isolation? No — mapping errors return `{:error, _}`.

  All three NO → plain functions. The mapping itself (loaded from
  `broker-role-mapping.yaml`) is owned by the caller — typically a
  config reader in the TokenExchange plug (T088), which re-reads on
  SIGHUP per `contracts/recurse_broker_api.md`.

  ## Algorithm

  Per the contract:

    1. Extract `groups` from claims (list-of-strings; missing → `[]`).
    2. Look each group up in `mapping.group_to_recurse_role`.
    3. Collect all matching roles.
    4. Of those matches, return the HIGHEST-PRIVILEGE one per the fixed
       order `["platform_operator", "tenant_auditor", "caller"]` (lower
       index = more privilege).
    5. If no group matched, fall back to `default_recurse_role`. If that
       is `nil`, return `{:error, :no_role_match_no_default}` — the
       TokenExchange plug maps this to HTTP 403 `unauthorized_client`
       per the contract.

  The privilege order is intentionally hard-coded in `role_privilege_order`
  rather than inferred from YAML — this keeps it auditable from this one
  file + prevents a misconfigured YAML from inverting the privilege
  lattice. If a future role is added it MUST also be added to this list
  in the right priority position; `resolve_role/2` will error out on
  unknown roles in the mapping before they're ever returned.

  ## `broker-role-mapping.yaml` loading

  `load_mapping_file/1` reads + validates the YAML file per the schema in
  `contracts/recurse_broker_api.md`. Validations:

    * Top-level `group_to_recurse_role` is a map (may be empty).
    * Every value in `group_to_recurse_role` is one of `platform_operator`,
      `tenant_auditor`, `caller`. Any other value fails boot with
      `{:error, {:invalid_role_in_mapping, bad_role}}` per the contract.
    * `default_recurse_role` (optional) if present must also be one of
      the three allowed strings or `nil`.
    * Duplicate YAML map keys are rejected by YamlElixir with a parse
      error (documented here rather than re-implementing).

  ## Cross-references

    * `specs/002-standalone-gateway-vertical-slice/contracts/recurse_broker_api.md`
      (broker-role-mapping.yaml schema)
    * F002 FR-008, FR-009 (role resolution semantics)
    * Clarifications Q3 (three roles: platform_operator | tenant_auditor | caller)
  """

  @type role :: String.t()

  @type role_mapping :: %{
          group_to_recurse_role: %{String.t() => role()},
          default_recurse_role: role() | nil,
          role_privilege_order: [role()]
        }

  @default_privilege_order ["platform_operator", "tenant_auditor", "caller"]

  @allowed_roles MapSet.new(@default_privilege_order)

  @doc """
  Resolve the `recurse_role` for a set of OIDC `claims` against a loaded
  `mapping`.

  Returns `{:ok, role_string}` or `{:error, :no_role_match_no_default}`.
  """
  @spec resolve_role(map(), role_mapping()) ::
          {:ok, role()} | {:error, :no_role_match_no_default}
  def resolve_role(claims, mapping) when is_map(claims) and is_map(mapping) do
    group_to_role = Map.fetch!(mapping, :group_to_recurse_role)
    default = Map.get(mapping, :default_recurse_role)
    order = Map.get(mapping, :role_privilege_order, @default_privilege_order)

    claims
    |> extract_groups()
    |> Enum.flat_map(fn group ->
      case Map.fetch(group_to_role, group) do
        {:ok, role} -> [role]
        :error -> []
      end
    end)
    |> pick_highest_privilege(order)
    |> case do
      nil when is_binary(default) -> {:ok, default}
      nil -> {:error, :no_role_match_no_default}
      role -> {:ok, role}
    end
  end

  # `groups` claim is spec'd as a list of strings, but real IdPs are
  # inconsistent — some emit a single-string "groups" instead of a list.
  # We normalize via pattern match rather than runtime branching.
  defp extract_groups(%{"groups" => groups}) when is_list(groups), do: groups
  defp extract_groups(%{"groups" => group}) when is_binary(group), do: [group]
  defp extract_groups(_), do: []

  # Return the role with the lowest index in `order` (lower = more
  # privilege). Nil when no matches. Unknown roles are silently filtered
  # — defense-in-depth against a mapping validator bug; in practice
  # `validate_mapping/1` has already rejected them at load time.
  defp pick_highest_privilege([], _order), do: nil

  defp pick_highest_privilege(roles, order) do
    roles
    |> Enum.uniq()
    |> Enum.filter(&(&1 in order))
    |> Enum.min_by(&Enum.find_index(order, fn r -> r == &1 end), fn -> nil end)
  end

  @doc """
  Load + validate a `broker-role-mapping.yaml` file.

  Returns `{:ok, role_mapping()}` or `{:error, reason}` where reason is:

    * `{:yaml_parse_error, term()}` — malformed YAML (duplicate keys,
      unclosed block, etc.)
    * `{:missing_key, :group_to_recurse_role}` — required top-level
      mapping absent.
    * `{:invalid_role_in_mapping, bad_value}` — a value in
      `group_to_recurse_role` is not one of the three allowed roles.
    * `{:invalid_default_role, bad_value}` — `default_recurse_role` is
      present but not a valid role string.
    * `{:file_read_error, reason}` — IO failure on `path`.

  The returned struct always has `:role_privilege_order` populated with
  the fixed `["platform_operator", "tenant_auditor", "caller"]` list so
  downstream callers don't have to remember to set it.
  """
  @spec load_mapping_file(Path.t()) :: {:ok, role_mapping()} | {:error, term()}
  def load_mapping_file(path) when is_binary(path) do
    with {:ok, yaml} <- read_file(path),
         {:ok, parsed} <- parse_yaml(yaml) do
      validate_mapping(parsed)
    end
  end

  defp read_file(path) do
    case File.read(path) do
      {:ok, contents} -> {:ok, contents}
      {:error, reason} -> {:error, {:file_read_error, reason}}
    end
  end

  defp parse_yaml(yaml) do
    case YamlElixir.read_from_string(yaml) do
      {:ok, parsed} when is_map(parsed) -> {:ok, parsed}
      {:ok, _} -> {:error, {:yaml_parse_error, :not_a_map}}
      {:error, reason} -> {:error, {:yaml_parse_error, reason}}
    end
  rescue
    # YamlElixir raises on some malformed inputs rather than returning
    # `{:error, _}` — rescue and collapse to the same error shape.
    e -> {:error, {:yaml_parse_error, Exception.message(e)}}
  end

  defp validate_mapping(%{"group_to_recurse_role" => g2r} = parsed) when is_map(g2r) do
    with :ok <- validate_group_role_values(g2r),
         {:ok, default} <- validate_default(Map.get(parsed, "default_recurse_role")) do
      {:ok,
       %{
         group_to_recurse_role: g2r,
         default_recurse_role: default,
         role_privilege_order: @default_privilege_order
       }}
    end
  end

  defp validate_mapping(_), do: {:error, {:missing_key, :group_to_recurse_role}}

  defp validate_group_role_values(g2r) do
    Enum.reduce_while(g2r, :ok, fn {_group, role}, _acc ->
      if role in @allowed_roles,
        do: {:cont, :ok},
        else: {:halt, {:error, {:invalid_role_in_mapping, role}}}
    end)
  end

  defp validate_default(nil), do: {:ok, nil}

  defp validate_default(role) when is_binary(role) do
    if role in @allowed_roles,
      do: {:ok, role},
      else: {:error, {:invalid_default_role, role}}
  end

  defp validate_default(other), do: {:error, {:invalid_default_role, other}}
end
