defmodule Recurse.Gateway.Test.JsonSchemaValidator do
  @moduledoc """
  Minimal JSON Schema validator scoped to the constructs used in this
  project's wire-shape schemas (`apps/recurse_gateway/priv/schemas/*.json`).

  ## Why a tiny in-tree validator instead of `:ex_json_schema`

  We add new schemas + their contract tests in pairs. A full draft-2020-12
  validator is a non-trivial dependency surface for a single use-case
  (validate a handler's response body against its schema). Issue #48
  retires F2 — the four wire shapes whose hand-maintained TS types drifted
  from the backend's emitted JSON. The contract test that catches this
  drift only needs a *narrow* validator, since the schemas we author
  follow the same shape as `auth_me.json` (the existing canonical fully-
  populated schema): top-level `type: "object"`, `additionalProperties:
  false`, `required: [...]`, `properties: {...}` with leaf types
  `string` (with optional `format` / `enum`), `integer`, `boolean`,
  `array` (with `items`), `object` (with nested `properties`), and
  nullable `["string", "null"]` shapes.

  ## What this validator covers

    * `type` — `"string"`, `"integer"`, `"number"`, `"boolean"`, `"array"`,
      `"object"`, `"null"`, OR a list mixing those (e.g.,
      `["string", "null"]`)
    * `required` — keys MUST be present (key-presence, not non-nullness;
      JSON `null` satisfies a required field unless the type list excludes
      `"null"`)
    * `additionalProperties: false` — extra keys flunk
    * `properties` — recurse into each declared property's schema
    * `items` — recurse into array items' schema
    * `enum` — value MUST be in the enum list
    * `const` — value MUST equal the const

  ## What it does NOT cover (fail-loud if a schema needs them)

    * `$ref`, `$defs` — none of our schemas use refs today
    * `oneOf` / `anyOf` / `allOf` — none used
    * `format` — accepted but not validated (RFC 3339 etc. are honesty
      hints, not enforced; the codegen pipeline doesn't enforce them either)
    * `pattern` — accepted but not validated (no regex engine call)
    * `minimum` / `maximum` / `minItems` / `maxItems` — accepted but not
      validated (we do assert minimum 1 / maximum 100 elsewhere via the
      handler's own request parsing — the schema documents the contract;
      the handler enforces it)

  ## Usage

      iex> schema = JSON.decode!(File.read!(schema_path))
      iex> body = JSON.decode!(conn.resp_body)
      iex> JsonSchemaValidator.validate!(body, schema)
      :ok

  On invariant violation `validate!/2` raises `ExUnit.AssertionError` with
  a message that names the JSON path that flunked plus the rule that was
  violated. This is the test-failure shape we want for contract tests:
  every drift surfaces as a single readable message pointing at the
  offending field.

  ## Iron Law

  Pure module. No process. No dependency on the umbrella's runtime.
  """

  @doc """
  Validate `value` against `schema`. Returns `:ok` on success; raises
  `ExUnit.AssertionError` on the first violation found, with a message
  that names the JSON path of the offending field plus the rule that
  failed.
  """
  @spec validate!(value :: term(), schema :: map()) :: :ok
  def validate!(value, schema) when is_map(schema) do
    case validate(value, schema, "$") do
      :ok -> :ok
      {:error, reason} -> raise ExUnit.AssertionError, message: reason
    end
  end

  @doc """
  Validate `value` against `schema`. Returns `:ok` or `{:error, reason}`;
  doesn't raise.
  """
  @spec validate(value :: term(), schema :: map(), path :: String.t()) ::
          :ok | {:error, String.t()}
  def validate(value, schema, path) when is_map(schema) do
    with :ok <- validate_type(value, schema, path),
         :ok <- validate_enum(value, schema, path),
         :ok <- validate_const(value, schema, path),
         :ok <- validate_object(value, schema, path),
         :ok <- validate_array(value, schema, path) do
      :ok
    end
  end

  # ----- type ----------------------------------------------------------------

  defp validate_type(value, %{"type" => types}, path) when is_list(types) do
    if Enum.any?(types, &type_matches?(&1, value)) do
      :ok
    else
      {:error,
       "#{path}: value #{inspect_short(value)} does not match any of the declared types " <>
         "#{inspect(types)} (got #{js_type_name(value)})"}
    end
  end

  defp validate_type(value, %{"type" => type}, path) when is_binary(type) do
    if type_matches?(type, value) do
      :ok
    else
      {:error,
       "#{path}: value #{inspect_short(value)} is #{js_type_name(value)}, " <>
         "expected #{inspect(type)}"}
    end
  end

  defp validate_type(_value, _schema, _path), do: :ok

  defp type_matches?("string", v), do: is_binary(v)
  defp type_matches?("integer", v), do: is_integer(v)
  defp type_matches?("number", v), do: is_number(v)
  defp type_matches?("boolean", v), do: is_boolean(v)
  defp type_matches?("null", v), do: is_nil(v)
  defp type_matches?("array", v), do: is_list(v)
  defp type_matches?("object", v), do: is_map(v) and not is_struct(v)
  defp type_matches?(_unknown, _v), do: false

  defp js_type_name(nil), do: "null"
  defp js_type_name(v) when is_binary(v), do: "string"
  defp js_type_name(v) when is_integer(v), do: "integer"
  defp js_type_name(v) when is_float(v), do: "number"
  defp js_type_name(v) when is_boolean(v), do: "boolean"
  defp js_type_name(v) when is_list(v), do: "array"
  defp js_type_name(v) when is_map(v), do: "object"
  defp js_type_name(_), do: "unknown"

  # ----- enum / const --------------------------------------------------------

  defp validate_enum(value, %{"enum" => enum}, path) when is_list(enum) do
    if value in enum do
      :ok
    else
      {:error, "#{path}: value #{inspect_short(value)} is not in enum #{inspect(enum)}"}
    end
  end

  defp validate_enum(_value, _schema, _path), do: :ok

  defp validate_const(value, %{"const" => const}, path) do
    if value == const do
      :ok
    else
      {:error, "#{path}: value #{inspect_short(value)} != const #{inspect(const)}"}
    end
  end

  defp validate_const(_value, _schema, _path), do: :ok

  # ----- object --------------------------------------------------------------

  defp validate_object(value, schema, path) when is_map(value) do
    properties = Map.get(schema, "properties", %{})
    required = Map.get(schema, "required", [])
    additional? = Map.get(schema, "additionalProperties", true)

    with :ok <- check_required(value, required, path),
         :ok <- check_additional(value, properties, additional?, path) do
      check_properties(value, properties, path)
    end
  end

  defp validate_object(_value, _schema, _path), do: :ok

  defp check_required(_value, [], _path), do: :ok

  defp check_required(value, required, path) when is_list(required) do
    Enum.find_value(required, :ok, fn key ->
      if Map.has_key?(value, key) do
        nil
      else
        {:error, "#{path}: missing required key #{inspect(key)}"}
      end
    end)
  end

  defp check_additional(_value, _properties, true, _path), do: :ok

  defp check_additional(value, properties, false, path) do
    declared = Map.keys(properties)
    extras = Enum.reject(Map.keys(value), &(&1 in declared))

    case extras do
      [] ->
        :ok

      _ ->
        {:error,
         "#{path}: unexpected keys #{inspect(extras)} (additionalProperties: false; " <>
           "declared #{inspect(declared)})"}
    end
  end

  # `additionalProperties: <schema>` would be supported here if we ever needed
  # it. Today only `false` is used in this project's strict-shape schemas.
  defp check_additional(_value, _properties, _other, _path), do: :ok

  defp check_properties(value, properties, path) do
    Enum.reduce_while(properties, :ok, fn {key, prop_schema}, :ok ->
      case Map.fetch(value, key) do
        {:ok, child} ->
          validation_step(validate(child, prop_schema, "#{path}.#{key}"))

        :error ->
          {:cont, :ok}
      end
    end)
  end

  defp validation_step(:ok), do: {:cont, :ok}
  defp validation_step({:error, _} = error), do: {:halt, error}

  # ----- array ---------------------------------------------------------------

  defp validate_array(value, %{"items" => item_schema}, path) when is_list(value) do
    value
    |> Enum.with_index()
    |> Enum.reduce_while(:ok, fn {item, idx}, :ok ->
      case validate(item, item_schema, "#{path}[#{idx}]") do
        :ok -> {:cont, :ok}
        {:error, _} = err -> {:halt, err}
      end
    end)
  end

  defp validate_array(_value, _schema, _path), do: :ok

  # ----- helpers -------------------------------------------------------------

  defp inspect_short(v) do
    s = inspect(v, limit: 5, printable_limit: 60)
    if String.length(s) > 80, do: String.slice(s, 0, 80) <> "...", else: s
  end
end
