defmodule Recurse.Fold.Policy.Shape do
  @moduledoc """
  The `PolicyShape` path grammar of schema-lite v2 §8, and nothing else.

  A shape says how instances of one Kind are presented to a policy engine:
  an action, a resource type, a resource id, and a context map, each value
  either a **literal** or a **path** into the instance. This module owns the
  three things that makes true:

    * `parse/1` — the grammar, as syntax;
    * `validate/3` — typing a parsed path against the target Kind's
      *admitted* schema, which is what makes a shape admissible at all;
    * `evaluate/3` — reading the path out of a live admission request,
      through at most one hop.

  ## The grammar (§8, verbatim)

      path     := "spec" ("." name)+
                | hopProp ".spec" ("." name)+   # one hop through an event ref
                | bytesProp ".json" ("." name)* # one bounded bytes dereference
                | "@" envField
      name     := [A-Za-z_][A-Za-z0-9_]*
      envField := "actor.id" | "actor.identity" | "actor.authorityRefs"
                | "actor.authorityRoots" | "kind" | "group" | "version" | "name"
      literal  := a JSON string in double quotes

  ### Where the contract was silent, and what this implementation decided

  §8 defines `literal` but never says which of a shape's five string-valued
  slots (`action`, `resourceType`, `resourceId`, and each `context` entry's
  `path`) are path-valued, nor how a bare string that is *not* a path is to
  be read. The seeds force the question: `resourceType: "ToolUse"` is plainly
  a Cedar type name, and `resourceType: "@kind"` on the `cedar.*` shape is
  plainly a path. So:

    * a value that matches one of the four path productions **is** a path;
    * any other value is a **literal**;
    * a value wrapped in double quotes (`"\\"spec.tool\\""` in JSON) is a
      literal *even when it would parse as a path* — the escape hatch for a
      literal that happens to look like one.

  That is recorded as ambiguity **E1** in the fold's report; it is the one
  reading under which both seeds and the `*` restriction ("may use only `@`
  fields and literals") are simultaneously satisfiable.

  ## Terminating, not descending

  A path may terminate at a property declared `object` with no `properties`
  (it is passed whole) and at an `array` (passed whole; there is no
  indexing). Descending into either is refused at shape admission, naming
  the path — a shape that reads into an open object is asking the engine to
  depend on structure the Kind never declared, which is exactly the
  schema-in-the-validator failure §8 exists to close.
  """

  # Spec 011 §11 (KS-7). `actor.keyFingerprint` is **removed**: it named a
  # fingerprint the actor asserted about itself, and a shape reading it was
  # deciding on a claim rather than on a proof. What replaces it is what the
  # kernel now settles before `authorize` runs — the signed identity, the
  # authority the actor cited, and the roots those chains resolve to.
  @env_fields ~w(actor.id actor.identity actor.authorityRefs actor.authorityRoots
                 kind group version name)

  # Named so the refusal can say what happened rather than "unknown field":
  # a deployment upgrading through spec 011 has shapes on its chain that
  # cite this, and `stale-shape` is what the verifier prints about them.
  @retired_env_fields %{
    "actor.keyFingerprint" =>
      "spec 011 §11 (KS-7) removed it: it named a fingerprint the actor " <>
        "asserted about itself. Read \"@actor.id\" for the key that signed, " <>
        "or \"@actor.authorityRoots\" for the keys its authority resolves to."
  }
  @name_re ~r/\A[A-Za-z_][A-Za-z0-9_]*\z/

  @bytes_hop_limit 64 * 1024

  @typedoc """
  A parsed shape value. `:literal` carries the string itself; the three
  path forms carry the segments after the production's fixed prefix.
  """
  @type parsed ::
          {:literal, String.t()}
          | {:env, String.t()}
          | {:spec, [String.t()]}
          | {:hop, String.t(), [String.t()]}
          | {:bytes, String.t(), [String.t()]}

  @doc "The size ceiling on the one `bytes` dereference the grammar allows (§8)."
  @spec bytes_hop_limit() :: pos_integer()
  def bytes_hop_limit, do: @bytes_hop_limit

  @doc "The eight envelope fields `@` may name (§8, as amended by spec 011 §11)."
  @spec env_fields() :: [String.t()]
  def env_fields, do: @env_fields

  # -- parse -------------------------------------------------------------

  @doc """
  Parse one shape value. Never fails: a string that is not a path is a
  literal, and the only *errors* the grammar has are `@` fields that name
  nothing (which `validate/3` reports) — kept as `{:env, field}` here so the
  message can name the offending field rather than "not a path".
  """
  @spec parse(term()) :: parsed()
  def parse(value) when is_binary(value) do
    cond do
      quoted_literal?(value) -> {:literal, String.slice(value, 1..-2//1)}
      String.starts_with?(value, "@") -> {:env, String.trim_leading(value, "@")}
      true -> parse_path(value)
    end
  end

  def parse(value), do: {:literal, to_string(value)}

  defp quoted_literal?(value),
    do:
      byte_size(value) >= 2 and String.starts_with?(value, "\"") and
        String.ends_with?(value, "\"")

  defp parse_path(value) do
    case String.split(value, ".") do
      ["spec" | rest] when rest != [] ->
        if names?(rest), do: {:spec, rest}, else: {:literal, value}

      [prop, "spec" | rest] when rest != [] ->
        if names?([prop | rest]), do: {:hop, prop, rest}, else: {:literal, value}

      [prop, "json" | rest] ->
        if names?([prop | rest]), do: {:bytes, prop, rest}, else: {:literal, value}

      _ ->
        {:literal, value}
    end
  end

  defp names?(segments), do: Enum.all?(segments, &Regex.match?(@name_re, &1))

  @doc "Is this parsed value a path (as opposed to a literal)?"
  @spec path?(parsed()) :: boolean()
  def path?({:literal, _}), do: false
  def path?(_), do: true

  # -- validate ----------------------------------------------------------

  @doc """
  Type a parsed value against the target Kind, as `validate/4` with no
  terminal type requirement.
  """
  @spec validate(parsed(), R5e.Kind.t() | :any, String.t()) :: :ok | {:error, String.t()}
  def validate(parsed, kind, label), do: validate(parsed, kind, label, nil)

  @doc """
  Type a parsed value against the target Kind's admitted schema.

  `kind` is `:any` for a `<engine>.*` shape, which has no target schema; the
  only values admissible there are `@` fields and literals. `require_type`,
  when given, is the type the *terminal* must declare — `"string"` for
  `resourceId` (§8: it must resolve to a string).
  """
  @spec validate(parsed(), R5e.Kind.t() | :any, String.t(), String.t() | nil) ::
          :ok | {:error, String.t()}
  def validate({:literal, _}, _kind, _label, _require_type), do: :ok

  def validate({:env, field}, _kind, label, require_type) do
    cond do
      field in @env_fields ->
        env_type(field, label, require_type)

      why = @retired_env_fields[field] ->
        {:error, "#{label}: unknown envelope field #{inspect(field)} — #{why}"}

      true ->
        {:error,
         "#{label}: unknown envelope field #{inspect(field)}; §8 names exactly " <>
           Enum.join(@env_fields, ", ")}
    end
  end

  def validate(parsed, :any, label, _require_type) do
    {:error,
     "#{label}: #{describe(parsed)} is a path into a target instance, and a " <>
       "`<engine>.*` shape has no target Kind to type it against — §8 allows only " <>
       "@ envelope fields and literals there"}
  end

  def validate({:spec, names}, %R5e.Kind{} = kind, label, require_type) do
    with {:ok, prop} <- walk(top(kind.schema), names, label, "spec") do
      terminal(prop, label, require_type)
    end
  end

  def validate({:hop, prop_name, names}, %R5e.Kind{} = kind, label, require_type) do
    with {:ok, target_path} <- event_prop(kind, prop_name, label),
         {:ok, target} <- lookup_kind(target_path, label, prop_name),
         {:ok, prop} <- walk(top(target.schema), names, label, "#{prop_name}.spec") do
      terminal(prop, label, require_type)
    end
  end

  def validate({:bytes, prop_name, names}, %R5e.Kind{} = kind, label, require_type) do
    with {:ok, json} <- bytes_prop(kind, prop_name, label),
         {:ok, prop} <- walk(json, names, label, "#{prop_name}.json") do
      terminal(prop, label, require_type)
    end
  end

  # Two of §11's three additions are **lists** (`authorityRefs`,
  # `authorityRoots`), so the "every envelope field is a string" shortcut
  # is gone: `resourceId` must resolve to a string (§8) and a list of
  # refs is not one. Context values may be any JSON value, so both are
  # admissible there.
  defp env_type(field, label, "string")
       when field in ~w(actor.authorityRefs actor.authorityRoots),
       do:
         {:error,
          "#{label}: @#{field} is a list of key ids and #{label} must resolve to a string (§8)"}

  defp env_type(_field, _label, _require_type), do: :ok

  defp top(schema), do: %{"type" => "object", "properties" => schema["properties"] || %{}}

  defp event_prop(kind, prop_name, label) do
    case declared(kind, prop_name) do
      %{"ref" => %{"event" => path}} ->
        {:ok, path}

      %{} ->
        {:error,
         "#{label}: #{prop_name} is declared on #{R5e.Kind.name(kind)} but not as an event " <>
           "ref, so `.spec` cannot hop through it (§8)"}

      nil ->
        {:error, "#{label}: #{R5e.Kind.name(kind)} declares no property #{prop_name}"}
    end
  end

  defp bytes_prop(kind, prop_name, label) do
    case declared(kind, prop_name) do
      %{"ref" => %{"bytes" => true, "json" => json}} when is_map(json) ->
        {:ok, json}

      %{"ref" => %{"bytes" => true}} ->
        {:error,
         "#{label}: #{prop_name} is a bytes ref that declares no `json` schema, so its " <>
           "content has no type to read a path against (§8)"}

      %{} ->
        {:error,
         "#{label}: #{prop_name} is declared on #{R5e.Kind.name(kind)} but not as a bytes ref"}

      nil ->
        {:error, "#{label}: #{R5e.Kind.name(kind)} declares no property #{prop_name}"}
    end
  end

  defp declared(kind, prop_name), do: get_in(kind.schema, ["properties", prop_name])

  defp lookup_kind(path, label, prop_name) do
    case String.split(path, "/") do
      [g, v, k] ->
        case R5e.KindRegistry.get(g, v, k) do
          {:ok, kind} ->
            {:ok, kind}

          {:error, :unknown_kind} ->
            {:error,
             "#{label}: the hop through #{prop_name} targets #{path}, which is not an " <>
               "admitted Kind on this chain"}
        end

      _ ->
        {:error,
         "#{label}: #{prop_name} declares an event target #{inspect(path)} that is " <>
           "not a g/v/K path"}
    end
  end

  defp walk(prop, [], _label, _so_far), do: {:ok, prop}

  defp walk(prop, [name | rest], label, so_far) do
    types = types_of(prop)

    cond do
      "object" not in types ->
        {:error,
         "#{label}: #{so_far} is declared #{Enum.join(types, "|")}, and a path may terminate " <>
           "at it but not descend into it (§8) — #{so_far}.#{name} is not typable"}

      not is_map(prop["properties"]) ->
        {:error,
         "#{label}: #{so_far} is an object with no declared properties; §8 lets a path " <>
           "terminate there (the value is passed whole) but never descend — " <>
           "#{so_far}.#{name} is not typable"}

      not Map.has_key?(prop["properties"], name) ->
        {:error, "#{label}: #{so_far} declares no property #{inspect(name)}"}

      true ->
        walk(prop["properties"][name], rest, label, "#{so_far}.#{name}")
    end
  end

  defp terminal(_prop, _label, nil), do: :ok

  defp terminal(prop, label, required) do
    types = types_of(prop)

    if required in types do
      :ok
    else
      {:error,
       "#{label}: the path terminates at a property declared " <>
         "#{Enum.join(types, "|")}, and §8 requires #{required}"}
    end
  end

  defp types_of(prop) when is_map(prop), do: prop["type"] |> List.wrap() |> Enum.map(&to_string/1)
  defp types_of(_prop), do: []

  # -- evaluate ----------------------------------------------------------

  @doc """
  Read a parsed value out of a live admission request.

  Returns `{:ok, value}`, `:absent` (the terminal — or an intermediate on
  the `spec` branch — is not there), or `{:error, reason}` when a hop could
  not be taken. An error is **fail-closed**: the caller refuses the
  admission and names the path, because a shape that cannot be evaluated is
  a decision made on less than the shape asked for.

  `manifest` is the kernel's resolution manifest (`resolved` on the request,
  §4): the hops read what `resolve` already looked up rather than looking it
  up again, so the decision is made on the facts the receipt records.
  """
  @spec evaluate(parsed(), map(), [map()]) :: {:ok, term()} | :absent | {:error, String.t()}
  def evaluate({:literal, value}, _request, _manifest), do: {:ok, value}

  def evaluate({:env, field}, request, _manifest) do
    value = envelope_field(field, request)
    if is_nil(value), do: :absent, else: {:ok, value}
  end

  def evaluate({:spec, names}, request, _manifest), do: dig(request[:spec] || %{}, names)

  def evaluate({:hop, prop, names}, _request, manifest) do
    case entry_at(manifest, prop, "event") do
      nil ->
        :absent

      %{"value" => "event:" <> hash} ->
        with {:ok, payload} <- event_payload(hash, prop) do
          dig(payload["spec"] || %{}, names)
        end

      %{"value" => other} ->
        {:error,
         "#{prop}.spec: the manifest entry at /#{prop} is #{inspect(other)}, not an event ref"}
    end
  end

  def evaluate({:bytes, prop, names}, _request, manifest) do
    case entry_at(manifest, prop, "bytes") do
      nil ->
        :absent

      %{"value" => address} ->
        with {:ok, decoded} <- bytes_json(address, prop) do
          dig(decoded, names)
        end
    end
  end

  # These facts are settled by the kernel before authorize, including []
  # authorityRefs for an actor acting as itself.
  defp envelope_field("actor.id", request), do: get_in(request, [:actor, "id"])
  defp envelope_field("actor.identity", request), do: request[:identity]
  defp envelope_field("actor.authorityRefs", request), do: request[:authority_refs]
  defp envelope_field("actor.authorityRoots", request), do: request[:authority_roots]
  defp envelope_field("kind", request), do: request[:kind]
  defp envelope_field("group", request), do: request[:group]
  defp envelope_field("version", request), do: request[:version]
  defp envelope_field("name", request), do: request[:name]
  defp envelope_field(_, _request), do: nil

  defp entry_at(manifest, prop, class) do
    Enum.find(manifest, fn entry ->
      is_map(entry) and entry["path"] == "/" <> pointer_escape(prop) and entry["class"] == class
    end)
  end

  defp pointer_escape(name),
    do: name |> String.replace("~", "~0") |> String.replace("/", "~1")

  defp event_payload(hash, prop) do
    case Enum.find(R5e.Log.events(), &(&1["hash"] == hash)) do
      nil ->
        {:error, "#{prop}.spec: no event with hash #{hash} is on this chain"}

      event ->
        with {:ok, bytes} <- fetch(event["payload"], "#{prop}.spec: the event's payload"),
             {:ok, payload} <- decode(bytes, "#{prop}.spec: the event's payload") do
          {:ok, payload}
        end
    end
  end

  defp bytes_json(address, prop) do
    with {:ok, bytes} <- fetch(address, "#{prop}.json: the object at #{address}"),
         :ok <- within_limit(bytes, prop),
         {:ok, decoded} <- decode(bytes, "#{prop}.json: the object at #{address}") do
      {:ok, decoded}
    end
  end

  defp within_limit(bytes, prop) do
    if byte_size(bytes) <= @bytes_hop_limit do
      :ok
    else
      {:error,
       "#{prop}.json: the object is #{byte_size(bytes)} bytes, over §8's #{@bytes_hop_limit}-byte " <>
         "ceiling on a bytes dereference"}
    end
  end

  defp fetch(address, label) when is_binary(address) do
    case R5e.CAS.get(address) do
      {:ok, bytes} -> {:ok, bytes}
      {:error, _} -> {:error, "#{label} is not in this deployment's CAS"}
    end
  end

  defp fetch(_address, label), do: {:error, "#{label} has no address"}

  defp decode(bytes, label) do
    case Jason.decode(bytes) do
      {:ok, decoded} -> {:ok, decoded}
      {:error, _} -> {:error, "#{label} is not valid JSON"}
    end
  end

  # An absent intermediate on the `spec` branch reads as absent, not as an
  # error (§8): an optional property nobody filled in is not a broken shape.
  defp dig(value, []), do: if(is_nil(value), do: :absent, else: {:ok, value})

  defp dig(%{} = map, [name | rest]) do
    case Map.get(map, name) do
      nil -> :absent
      value -> dig(value, rest)
    end
  end

  defp dig(_value, _names), do: :absent

  # -- messages ----------------------------------------------------------

  defp describe({:spec, names}), do: "spec." <> Enum.join(names, ".")
  defp describe({:hop, prop, names}), do: "#{prop}.spec." <> Enum.join(names, ".")
  defp describe({:bytes, prop, names}), do: Enum.join([prop, "json" | names], ".")
  defp describe({:env, field}), do: "@" <> field
  defp describe({:literal, value}), do: inspect(value)

  @doc "The path as written, for a receipt or an evaluation record."
  @spec render(parsed()) :: String.t()
  def render(parsed), do: describe(parsed)
end
