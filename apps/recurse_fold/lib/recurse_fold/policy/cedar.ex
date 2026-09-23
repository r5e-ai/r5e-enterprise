defmodule Recurse.Fold.Policy.Cedar do
  @moduledoc """
  The gateway API group's policy engine: enterprise's Cedar, implementing
  the kernel's `R5e.Policy` behaviour, driven by an **admitted**
  `PolicyShape` rather than by a mapping written in this module.

  Configured as `config :r5e, policy: Recurse.Fold.Policy.Cedar`; the kernel
  calls it at the `authorize` stage, after `resolve` and before
  `validateConstraints`. The kernel does not know this app exists.

  ## What decides, and where each part of it lives

  | part | lives on the chain as | read at each decision |
  |---|---|---|
  | the policy text | a `CasObject`, cited by `PolicyBundle/active.sourceRef` | fetched from the CAS by address |
  | how the instance is presented | `PolicyShape/cedar.<g/v/K>`, or `cedar.*` | the §8 path grammar, evaluated against the request |
  | what the engine was | a `CasObject` build descriptor (§8) | cited by address on every receipt |
  | what was actually handed to the engine | a kernel-derived `PolicyEvaluationRecord` (§8) | written here, cited as `evaluation` |

  Nothing in that table is a file read at boot and nothing is a constant in
  this module. That is the whole of the change from milestone zero: the
  coded shape moved onto the chain, and the exact bytes handed to Cedar
  became a record a third party can replay.

  ## The receipt's policy block

      %{"engine"      => "cedar",
        "decision"    => "allow" | "deny" | "error",
        "bundle"      => "sha256:…" | nil,      # the admitted bundle's spec
        "bundleRef"   => "g/v/K/name" | nil,     # that bundle by path (§9)
        "source"      => "bytes:sha256:…" | nil, # the policy text itself
        "shape"       => "sha256:…" | nil,       # the admitted PolicyShape's spec
        "evaluation"  => "bytes:sha256:…" | nil, # the §8 evaluation record
        "engineBuild" => "bytes:sha256:…",       # the §8 build descriptor
        "matched"     => ["policy1", …],         # sorted
        "generations" => %{"g/v/K/name" => seq}, # §7, what this read
        "derivedObjects" => ["bytes:sha256:…"]}  # §5, what this wrote

  Two of those keys are the kernel's, not this engine's, and both are
  *reports* the gate acts on. `generations` (§7) is what this decision
  read, re-checked under the append lock. `derivedObjects` (§5) is what it
  wrote: the gate copies the list onto the event payload beside `policy`,
  so the kernel-derived class is rebuilt from the chain at the next boot
  rather than living in one process's memory. `bundleRef` names the bundle
  resource by path — the address says *which bytes*, the ref says *which
  resource*, and a reader chasing a supersession wants the second.

  `shape: nil` carries a `note`. The seven keys `engine`, `engineBuild`,
  `bundle`, `source`, `shape`, `decision` and `matched` are repeated inside
  the evaluation record, and §8 makes their equality an invariant the
  offline verifier checks: a receipt that says one thing and a record that
  says another is a finding, not a discrepancy to interpret.

  ## Fail-closed

  Three things refuse before Cedar runs, each naming the path or the
  address that could not be read: an unfetchable event or bytes hop, a
  `resourceId` that resolved to nothing, and a bundle whose source object
  is not in the CAS. All of them are `decision: "error"`, because "the
  engine could not be given the question" is not the same claim as "the
  engine answered no".

  ## PolicyShape admissions are validated here

  A `PolicyShape` is admitted through the same gate as everything else, and
  this engine refuses one whose paths do not type against the target Kind's
  admitted schema, whose `*` form reads a non-envelope path, or whose name
  is not the derived one. The name check is belt-and-braces: the kernel's
  `derived` naming settles the name at `validateStructure`, which runs
  *before* `authorize`, so on any request that reaches this module the name
  is already right and the kernel's message is the one a caller sees. The
  path typing has no kernel counterpart and fires only here.

  ## Matched policy ids

  Cedar 4.9.1 returns *positional* ids — `policy0`, `policy1`, … — for a
  policy set parsed from source. It parses an `@id("…")` annotation without
  complaint but does not adopt it, so receipts cite `policy1`. Pinned by
  `test/policy/cedar_test.exs`.
  """

  @behaviour R5e.Policy

  alias Recurse.Fold.Policy.EngineBuild
  alias Recurse.Fold.Policy.EvaluationRecord
  alias Recurse.Fold.Policy.Shape

  @group "gateway.r5e.io"
  @version "v1alpha1"
  @bundle_kind "PolicyBundle"
  @bundle_name "active"
  @shape_kind "PolicyShape"
  @bundle_ref "#{@group}/#{@version}/#{@bundle_kind}/#{@bundle_name}"

  @engine "cedar"

  @no_shape_note "no PolicyShape is admitted for this Kind and no #{@engine}.* fallback " <>
                   "shape either; the presentation came from this engine's coded fallback " <>
                   "(spec 010, Edge Cases). The evaluation record still carries the exact " <>
                   "bytes the engine was handed."

  @doc "The fixed upstream policy this fold narrows."
  def upstream, do: R5e.Policy.KernelCedar

  @doc "The `group/version/Kind/name` of the bundle this engine evaluates."
  def bundle_ref, do: @bundle_ref

  @doc "Coordinates of the active bundle, for seeding and for tests."
  def bundle_coordinates, do: {@group, @version, @bundle_kind, @bundle_name}

  @doc "Coordinates of the PolicyShape Kind, for seeding and for tests."
  def shape_coordinates, do: {@group, @version, @shape_kind}

  @doc "The name a shape for `kind` (an API path, or `*`) is admitted under (§8 `derived`)."
  @spec shape_name(String.t()) :: String.t()
  def shape_name(kind), do: "#{@engine}.#{kind}"

  # -- the R5e.Policy callback -------------------------------------------

  @impl true
  def authorize(%{group: @group, version: @version, kind: kind} = request)
      when kind in ["LlmCall", "ToolCall"] do
    # Upstream policy can narrow descendant work. A tenant permit cannot
    # override an upstream denial. Both evaluations belong to this one
    # admission, with all their reads checked under the same append lock.
    case R5e.Policy.KernelCedar.authorize(request) do
      {:ok, upstream} ->
        request |> authorize_workload() |> compose(upstream)

      {:deny, reason, upstream} ->
        meta =
          skipped_meta(upstream["decision"], "upstream refused; not evaluated here")
          |> Map.put("reason", "upstreamRefused")

        compose({:deny, reason, meta}, upstream)
    end
  end

  def authorize(request) do
    # No workload jurisdiction is not an allow. The upstream kernel policy
    # decides operational and policy-management admissions, including bootstrap.
    with :ok <- validate_management(request),
         {:ok, meta} <- R5e.Policy.KernelCedar.authorize(request) do
      {:ok, meta}
    end
  end

  defp authorize_workload(request) do
    case active_bundle() do
      :none ->
        {:deny, "gateway workload policy is not admitted",
         no_bundle_meta() |> Map.put("decision", "error")}

      {:ok, bundle} ->
        with :ok <- jurisdiction(bundle, request),
             {:ok, source, source_address} <- bundle_source(bundle) do
          decide(request, bundle, source, source_address)
        end
    end
  end

  # Public for composing already-evaluated results without evaluating Cedar
  # again; tests exercise impossible-to-schedule generation races at this seam.
  @doc false
  @spec compose({:ok, map()} | {:deny, String.t(), map()}, map()) ::
          {:ok, map()} | {:deny, String.t(), map()}
  def compose(result, upstream) do
    {meta, outcome} =
      case result do
        {:ok, meta} -> {meta, :ok}
        {:deny, reason, meta} -> {meta, {:deny, reason}}
      end

    upstream_generations = upstream["generations"] || %{}
    local_generations = meta["generations"] || %{}

    conflicts = generation_conflicts(upstream_generations, local_generations)

    derived = Enum.uniq((upstream["derivedObjects"] || []) ++ (meta["derivedObjects"] || []))
    nested = Map.put(meta, "upstreamPolicy", upstream)

    if map_size(conflicts) == 0 do
      composed =
        nested
        |> Map.put("generations", Map.merge(upstream_generations, local_generations))
        |> Map.put("derivedObjects", derived)

      composed_result(outcome, composed)
    else
      # The Cedar result remains intact: changing its decision would disagree
      # with its evaluation record. The outer block records composition only.
      meta =
        skipped_meta("error", "generation conflict during composition; no additional evaluation")
        |> Map.put("stage", "composition")
        |> Map.put("generationConflicts", conflicts)
        |> Map.put("upstreamPolicy", nested)
        |> Map.put(
          "generations",
          Map.merge(
            Map.drop(upstream_generations, Map.keys(conflicts)),
            Map.drop(local_generations, Map.keys(conflicts))
          )
        )
        |> Map.put("derivedObjects", derived)

      {:deny, "policy generation conflict (fail-closed)", meta}
    end
  end

  defp composed_result(:ok, meta), do: {:ok, meta}
  defp composed_result({:deny, reason}, meta), do: {:deny, reason, meta}

  defp generation_conflicts(upstream, local) do
    for {ref, generation} <- local,
        Map.has_key?(upstream, ref),
        upstream[ref] != generation,
        into: %{},
        do: {ref, %{"upstream" => upstream[ref], "local" => generation}}
  end

  defp skipped_meta(decision, note) do
    %{
      "engine" => @engine,
      "decision" => decision,
      "bundleRef" => @bundle_ref,
      "bundle" => nil,
      "source" => nil,
      "shape" => nil,
      "evaluation" => nil,
      "evaluated" => false,
      "engineBuild" => engine_build_address(),
      "matched" => [],
      "generations" => %{},
      "derivedObjects" => [],
      "note" => note
    }
  end

  @doc "The complete workload jurisdiction this extension may govern."
  def governed_kinds, do: Enum.map(["LlmCall", "ToolCall"], &"#{@group}/#{@version}/#{&1}")

  defp jurisdiction(bundle, request) do
    path = "#{request.group}/#{request.version}/#{request.kind}"
    scope = get_in(bundle, ["spec", "governs"])

    if is_list(scope) and path in scope and Enum.all?(scope, &(&1 in governed_kinds())) do
      :ok
    else
      # Not `error`: the engine was reachable and answered. It is not that
      # this bundle says no, it is that this bundle was never given the
      # question — the design note's third answer, in the note's own word.
      {:deny, "gateway policy has no admitted jurisdiction for #{path}",
       bundle
       |> error_meta(nil, nil, "missingJurisdiction", nil)
       |> Map.put("decision", "no-jurisdiction")}
    end
  end

  # -- policy-management admissions --------------------------------------

  defp validate_management(%{group: @group, version: @version, kind: @shape_kind} = request) do
    case check_shape(request.spec, request[:name]) do
      :ok -> :ok
      {:error, reason} -> management_refusal("policy shape refused: " <> reason)
    end
  end

  defp validate_management(%{group: @group, version: @version, kind: @bundle_kind} = request) do
    governs_within_authority(request)
  end

  defp validate_management(_request), do: :ok

  @doc """
  The Kinds an act's cited authority covers: the union of `kinds` over the
  cited chains, or `:all` when one of them names `*`.

  Only the **cited** entry of each chain is read — the head of §5's
  `chain`. Authority narrows monotonically (spec/03; the kernel enforces
  `kinds(e) ⊆ kinds(p)` at issuance), so the head is the narrowest link and
  the union of the heads is exactly what the actor was granted. Reading the
  parents too would widen the answer back to the root, which is the bug
  this function exists to prevent.

  `[]` — an actor citing nothing acts as itself — grants no Kinds. That is
  deliberate: a bundle is a jurisdiction claim, and "I am acting as myself"
  establishes no jurisdiction over anything.
  """
  @spec authority_kinds([map()] | nil) :: :all | [String.t()]
  def authority_kinds(resolved) when is_list(resolved) do
    granted =
      for entry <- resolved,
          link = List.first(entry["chain"] || []),
          is_map(link),
          kind <- link["kinds"] || [],
          is_binary(kind),
          do: kind

    if "*" in granted, do: :all, else: granted |> Enum.uniq() |> Enum.sort()
  end

  def authority_kinds(_), do: []

  # K3 (RC review 2026-09-05): jurisdiction derived from the admitting
  # authority, not from a list compiled into this module. A key endorsed
  # for `PolicyBundle` alone admitted a bundle governing `LlmCall` and
  # `ToolCall` — the endorsement narrowed which Kinds the key may *admit*
  # and nothing narrowed which Kinds the thing it admitted may *decide
  # for*. This is that second narrowing, at `authorize`, on the chain's own
  # `resolvedAuthority` rather than on compiled constants. The `governs`
  # enum in the KindDefinition and `governed_kinds/0` in `jurisdiction/2`
  # both stay: three checks, one of them derived.
  defp governs_within_authority(request) do
    scope = if is_map(request.spec), do: get_in(request.spec, ["governs"])
    granted = authority_kinds(request[:resolved_authority])

    cond do
      not is_list(scope) ->
        management_refusal(
          "governs exceeds the admitting authority: the candidate declares no governs list " <>
            "(#{inspect(scope)}), so nothing bounds what it would decide"
        )

      granted == :all ->
        :ok

      Enum.all?(scope, &(&1 in granted)) ->
        :ok

      true ->
        management_refusal(
          "governs exceeds the admitting authority: the candidate declares " <>
            "#{inspect(Enum.sort(scope))} and the cited authority covers #{inspect(granted)}"
        )
    end
  end

  # K8 (RC review 2026-09-05): a policy-management refusal is this engine's
  # answer, so it says so. The 2-tuple form reached the kernel as engine
  # `"unknown"` — documented as "a policy that predates the metadata
  # contract" — which left the one class of act the jurisdiction story is
  # about unable to name what refused it.
  defp management_refusal(reason) do
    bundle =
      case active_bundle() do
        {:ok, entry} -> entry
        :none -> nil
      end

    {:deny, reason,
     bundle
     |> error_meta(nil, nil, "candidate", nil)
     |> Map.put("decision", "deny")
     |> Map.put(
       "note",
       "this engine refused the candidate before any evaluation (candidate: #{reason}); " <>
         "the bundle named here is the one in force, not the one that refused"
     )}
  end

  # -- the bundle --------------------------------------------------------

  @doc """
  The admitted `PolicyBundle/active`, or `:none`. Read fresh on every
  decision: the bundle in force is whatever the log says it is right now,
  never a cached copy from boot. The generation it was read at is captured
  on the meta so `record` can re-check it under the append lock (§7).
  """
  @spec active_bundle() :: {:ok, map()} | :none
  def active_bundle do
    case R5e.ResourceStore.get(@group, @version, @bundle_kind, @bundle_name) do
      {:ok, entry, _lineage} -> {:ok, entry}
      {:error, :not_found} -> :none
    end
  end

  # §7 (FR-007): the policy text is detached and cited by address. The
  # bundle's spec is refs-first, so the address is read out of the stored
  # `$ref` and the bytes are fetched from the CAS — never inlined, never
  # cached.
  defp bundle_source(entry) do
    case get_in(entry, ["spec", "sourceRef", "$ref"]) do
      address when is_binary(address) ->
        case R5e.CAS.get(address) do
          {:ok, bytes} ->
            {:ok, bytes, address}

          {:error, _} ->
            {:deny, "the policy text at #{address} is not in this deployment's CAS (fail-closed)",
             error_meta(entry, nil, nil, "sourceObjectMissing", address)}
        end

      other ->
        {:deny,
         "#{@bundle_ref} carries no bytes sourceRef (found #{inspect(other)}); nothing to " <>
           "evaluate (fail-closed)", error_meta(entry, nil, nil, "sourceRefMalformed", nil)}
    end
  end

  # -- shape selection (§8: Kind-specific over `<engine>.*`) -------------

  @doc """
  The shape in force for one target Kind: the Kind-specific shape if one is
  admitted, otherwise `<engine>.*`, otherwise `:none` (the coded fallback).
  """
  @spec applicable_shape(String.t(), String.t(), String.t()) :: {:ok, map()} | :none
  def applicable_shape(group, version, kind) do
    with :none <- shape_entry(shape_name("#{group}/#{version}/#{kind}")),
         :none <- shape_entry(shape_name("*")) do
      :none
    end
  end

  defp shape_entry(name) do
    case R5e.ResourceStore.get(@group, @version, @shape_kind, name) do
      {:ok, entry, _lineage} -> {:ok, entry}
      {:error, :not_found} -> :none
    end
  end

  # -- shape admission validation (§8) -----------------------------------

  @doc """
  Type a submitted `PolicyShape` spec against the Kind it claims to present.

  Returns `:ok` or `{:error, reason}` naming the offending slot and path.
  `name` is the name the admission carries; when it is given it must equal
  the derived `{engine}.{kind}` (the kernel already enforces this at
  `validateStructure`, so this check is the belt to that braces).
  """
  @spec check_shape(map(), String.t() | nil) :: :ok | {:error, String.t()}
  def check_shape(spec, name \\ nil) do
    engine = spec["engine"]
    target = spec["kind"]

    with :ok <- check_name(name, engine, target),
         {:ok, kind} <- target_kind(target),
         :ok <- check_slot(spec["action"], kind, "action", nil),
         :ok <- check_slot(spec["resourceType"], kind, "resourceType", nil),
         :ok <- check_slot(spec["resourceId"], kind, "resourceId", "string") do
      check_context(spec["context"] || %{}, kind)
    end
  end

  defp check_name(nil, _engine, _target), do: :ok

  defp check_name(name, engine, target) when is_binary(engine) and is_binary(target) do
    derived = "#{engine}.#{target}"

    if name == derived,
      do: :ok,
      else:
        {:error,
         "the name #{inspect(name)} is not the derived name #{inspect(derived)} for this " <>
           "shape's engine and kind (schema-lite-v2 §2/§8)"}
  end

  defp check_name(_name, _engine, _target), do: :ok

  defp target_kind("*"), do: {:ok, :any}

  defp target_kind(path) when is_binary(path) do
    case String.split(path, "/") do
      [g, v, k] ->
        case R5e.KindRegistry.get(g, v, k) do
          {:ok, kind} ->
            {:ok, kind}

          {:error, :unknown_kind} ->
            {:error,
             "the target Kind #{path} is not admitted on this chain, so its schema cannot " <>
               "type this shape's paths (§8)"}
        end

      _ ->
        {:error, "the target #{inspect(path)} is neither a g/v/K path nor `*`"}
    end
  end

  defp target_kind(other), do: {:error, "the target #{inspect(other)} is not a string"}

  defp check_slot(value, kind, label, require_type) when is_binary(value),
    do: Shape.validate(Shape.parse(value), kind, label, require_type)

  defp check_slot(value, _kind, label, _require_type),
    do: {:error, "#{label}: #{inspect(value)} is not a string"}

  defp check_context(context, kind) when is_map(context) do
    Enum.reduce_while(context, :ok, fn {key, entry}, :ok ->
      case check_slot(is_map(entry) && entry["path"], kind, "context.#{key}", nil) do
        :ok -> {:cont, :ok}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
  end

  defp check_context(other, _kind), do: {:error, "context: #{inspect(other)} is not an object"}

  # -- presentation ------------------------------------------------------

  @doc """
  Build the Cedar request and entity store for one admission request.

  Returns `{:ok, presentation}` where `presentation` carries `:request`,
  `:entities`, `:resolution` (the §8 `[{path, value | "absent"}]` list,
  sorted) and `:shape` (the admitted entry, or `nil` for the coded
  fallback), or `{:error, reason}` when a path could not be evaluated —
  which is a refusal, not a deny.

  Public because the presentation is the interesting part of this module
  and is tested directly.
  """
  @spec present(map()) :: {:ok, map()} | {:error, String.t()}
  def present(request) do
    case applicable_shape(request[:group] || "", request[:version] || "", request[:kind] || "") do
      {:ok, entry} -> present_with_shape(request, entry)
      :none -> {:ok, coded_fallback(request)}
    end
  end

  defp present_with_shape(request, entry) do
    spec = entry["spec"] || %{}
    manifest = request[:resolved] || []
    acc = %{resolution: %{}}

    with {:ok, action, acc} <- slot(spec["action"], request, manifest, acc, "action"),
         {:ok, type, acc} <- slot(spec["resourceType"], request, manifest, acc, "resourceType"),
         {:ok, id, acc} <- slot(spec["resourceId"], request, manifest, acc, "resourceId"),
         {:ok, context, acc} <- context(spec["context"] || %{}, request, manifest, acc) do
      {:ok,
       %{
         request: cedar_request(request, action, type, id, context),
         entities: entities(request, type, id),
         resolution: resolution(acc),
         shape: entry
       }}
    end
  end

  # A required slot: absent is a refusal, because there is no request to ask
  # without it. §8 gives `resourceId` no `whenAbsent`, and the same reading
  # is applied to `action` and `resourceType`.
  defp slot(value, request, manifest, acc, label) when is_binary(value) do
    parsed = Shape.parse(value)

    case Shape.evaluate(parsed, request, manifest) do
      {:ok, resolved} when is_binary(resolved) ->
        {:ok, resolved, record(acc, parsed, resolved)}

      {:ok, resolved} ->
        {:error,
         "#{label}: #{Shape.render(parsed)} resolved to #{inspect(resolved)}, and a Cedar " <>
           "#{label} must be a string (fail-closed)"}

      :absent ->
        {:error,
         "#{label}: #{Shape.render(parsed)} is absent on this instance, and §8 gives " <>
           "#{label} no whenAbsent (fail-closed)"}

      {:error, reason} ->
        {:error, "#{label}: #{reason} (fail-closed)"}
    end
  end

  defp slot(value, _request, _manifest, _acc, label),
    do: {:error, "#{label}: #{inspect(value)} is not a string"}

  defp context(context, request, manifest, acc) do
    Enum.reduce_while(context, {:ok, %{}, acc}, fn {key, entry}, {:ok, built, acc} ->
      parsed = Shape.parse(entry["path"])
      when_absent = entry["whenAbsent"] || "absent"

      case Shape.evaluate(parsed, request, manifest) do
        {:ok, value} ->
          {:cont, {:ok, Map.put(built, key, value), record(acc, parsed, value)}}

        :absent when when_absent == "deny" ->
          {:halt,
           {:error,
            "context.#{key}: #{Shape.render(parsed)} is absent on this instance and the " <>
              "shape says whenAbsent: deny"}}

        :absent ->
          {:cont, {:ok, built, record(acc, parsed, :absent)}}

        {:error, reason} ->
          {:halt, {:error, "context.#{key}: #{reason} (fail-closed)"}}
      end
    end)
  end

  # Literals are not resolutions: nothing was read, so nothing is recorded.
  defp record(acc, parsed, value) do
    if Shape.path?(parsed) do
      put_in(acc, [:resolution, Shape.render(parsed)], value)
    else
      acc
    end
  end

  defp resolution(acc) do
    acc.resolution
    |> Enum.sort_by(fn {path, _value} -> path end)
    |> Enum.map(fn
      {path, :absent} -> %{"path" => path, "value" => "absent"}
      {path, value} -> %{"path" => path, "value" => value}
    end)
  end

  # -- the coded fallback (spec 010, Edge Cases) -------------------------
  #
  # Before any shape for a Kind is admitted — which includes every act of
  # the fold's own boot, since the shapes themselves have to be admitted
  # through this gate — the engine falls back to the milestone-zero mapping
  # and says so on the receipt (`shape: null` plus a note). The fallback
  # still produces an evaluation record: what was handed to Cedar is exactly
  # as replayable when this module chose the shape as when the chain did.
  defp coded_fallback(%{group: @group, version: @version, kind: "ToolCall"} = request) do
    spec = request[:spec] || %{}
    tool = spec["tool"] || ""

    presented(request, "invoke_tool", "ToolUse", tool, %{
      "tool_name" => tool,
      "tool_args" => spec["args"] || %{}
    })
  end

  defp coded_fallback(request) do
    kind = request[:kind] || ""
    name = request[:name] || R5e.Canonical.hash(request[:spec] || %{})

    presented(request, "admit", kind, name, %{})
  end

  defp presented(request, action, type, id, context) do
    %{
      request: cedar_request(request, action, type, id, context),
      entities: entities(request, type, id),
      resolution: [],
      shape: nil
    }
  end

  # -- the Cedar request -------------------------------------------------

  defp cedar_request(request, action, resource_type, resource_id, context) do
    {type, actor_id, _attrs} = policy_principal(request)

    %{
      "principal" => uid(type, actor_id),
      "action" => uid("Action", action),
      "resource" => uid(resource_type, resource_id),
      "context" => strip_nulls(context)
    }
  end

  defp entities(request, resource_type, resource_id) do
    {principal_type, actor_id, observed_attrs} = policy_principal(request)

    [
      entity(
        principal_type,
        actor_id,
        Map.merge(observed_attrs, %{
          "subject" => actor_id,
          # Spec 011 §11 (KS-7): `key_fingerprint` is gone. It carried a
          # fingerprint the actor asserted about itself, so a policy written
          # against it was deciding on a claim. These three are the kernel's
          # own answers, settled before `authorize` runs and recorded on the
          # receipt: whether the act was signed, the authority it cited, and
          # the root keys those chains resolve to. A rule that wants "acts
          # only under the node's endorsement" is now writable.
          "identity" => request[:identity] || "unsigned",
          "authority_refs" => request[:authority_refs] || [],
          "authority_roots" => request[:authority_roots] || [],
          "admission_signer" => get_in(request, [:actor, "id"]) || ""
        })
      ),
      entity(resource_type, resource_id, %{})
    ]
  end

  # User is the gateway's observed client, not the admission signer. Preserve
  # the established policy vocabulary without upgrading an unsigned claim to
  # a verified principal. The signer remains in the signed admission envelope.
  defp policy_principal(request) do
    case get_in(request, [:spec, "gatewayContext"]) do
      %{"principal_id" => id, "principal_kind" => kind} = context when is_binary(id) ->
        {"User", id,
         %{
           "kind" => kind,
           "groups" => context["principal_groups"] || [],
           "chatgpt_account_id" => context["chatgpt_account_id"] || "",
           "provenance" => "gateway-observed-client"
         }}

      _ ->
        actor = get_in(request, [:actor, "id"]) || ""
        {principal_type(actor), actor, %{}}
    end
  end

  defp principal_type("person:" <> _), do: "Recurse::Principal::Human"
  defp principal_type("agent:" <> _), do: "Recurse::Principal::Autonomous"
  defp principal_type(_), do: "Recurse::Principal::ServiceAccount"

  defp uid(type, id), do: type <> "::" <> Jason.encode!(id)

  defp entity(type, id, attrs),
    do: %{"uid" => %{"type" => type, "id" => id}, "attrs" => attrs, "parents" => []}

  @doc """
  Cedar has no null: a key whose value is nil is dropped rather than
  encoded as something the engine would have to guess at.
  """
  def strip_nulls(%{} = map) do
    map
    |> Enum.reject(fn {_k, v} -> is_nil(v) end)
    |> Map.new(fn {k, v} -> {k, strip_nulls(v)} end)
  end

  def strip_nulls(list) when is_list(list),
    do: list |> Enum.reject(&is_nil/1) |> Enum.map(&strip_nulls/1)

  def strip_nulls(other), do: other

  # -- decide ------------------------------------------------------------

  defp decide(request, bundle, source, source_address) do
    case {engine_build_available?(), present(request)} do
      {false, _} ->
        {:deny, "workload engine build descriptor is unavailable",
         error_meta(bundle, source_address, nil, "engineBuildUnavailable", nil)}

      {true, {:ok, presentation}} ->
        evaluate(request, bundle, source, source_address, presentation)

      {true, {:error, reason}} ->
        {:deny, reason, error_meta(bundle, source_address, nil, "shapeEvaluation", nil)}
    end
  end

  defp engine_build_available? do
    case engine_build_address() do
      address when is_binary(address) -> match?({:ok, _}, R5e.CAS.get(address))
      _ -> false
    end
  end

  defp evaluate(request, bundle, source, source_address, presentation) do
    request_json = JSON.encode!(presentation.request)
    entities_json = JSON.encode!(presentation.entities)

    case Recurse.Cedar.evaluate_with_entities(source, request_json, entities_json) do
      {:ok, %{decision: decision, matched_policies: matched}} ->
        answer(
          decision,
          Enum.sort(matched),
          request,
          bundle,
          source_address,
          presentation,
          {request_json, entities_json}
        )

      {:error, reason} ->
        answer(
          :error,
          [],
          request,
          bundle,
          source_address,
          presentation,
          {request_json, entities_json},
          to_string(reason)
        )
    end
  end

  defp answer(
         decision,
         matched,
         request,
         bundle,
         source_address,
         presentation,
         {request_json, entities_json},
         error \\ nil
       ) do
    label = to_string(decision)

    evaluation =
      EvaluationRecord.write(%{
        engine: @engine,
        engine_build: engine_build_address(),
        kind_definition: kind_definition_address(request),
        bundle: bundle["specAddress"],
        source: source_address,
        shape: presentation.shape && presentation.shape["specAddress"],
        request_bytes: request_json,
        entities_bytes: entities_json,
        resolution: presentation.resolution,
        decision: label,
        matched: matched,
        # Spec 011 §11 (KS-7): the record carries `resolvedAuthority`
        # **whole** — every cited authority with its chain of links to the
        # root, as the kernel derived it. A replayer therefore has the
        # actor's standing in the same bytes as the question, and does not
        # have to reach back into the chain to find out what the engine was
        # allowed to assume about who was asking.
        resolved_authority: request[:resolved_authority] || []
      })

    meta =
      meta(bundle, presentation.shape, label, matched, evaluation, source_address)
      |> put_if(error != nil, "error", error)

    case decision do
      :allow ->
        {:ok, meta}

      :deny ->
        {:deny, deny_reason(bundle, presentation, matched), meta}

      :error ->
        {:deny, "cedar evaluation error (fail-closed): #{error}", meta}
    end
  end

  defp deny_reason(bundle, presentation, matched) do
    matched_part =
      case matched do
        [] -> "no policy matched (Cedar is deny-by-default)"
        ids -> "matched " <> Enum.join(ids, ", ")
      end

    shape_part =
      case presentation.shape do
        nil -> "under the coded fallback shape"
        entry -> "under shape #{entry["name"]} (#{entry["specAddress"]})"
      end

    "cedar denied #{presentation.request["action"]} on #{presentation.request["resource"]} " <>
      "#{shape_part} and #{@bundle_ref} (#{bundle["specAddress"]}): #{matched_part}"
  end

  # -- what the engine read (§7) -----------------------------------------

  defp generations(bundle, shape) do
    %{}
    |> put_generation(@bundle_ref, bundle)
    |> then(fn map ->
      case shape do
        nil ->
          map

        entry ->
          put_generation(map, "#{@group}/#{@version}/#{@shape_kind}/#{entry["name"]}", entry)
      end
    end)
  end

  defp put_generation(map, ref, entry) do
    case entry && entry["admissionSeq"] do
      seq when is_integer(seq) -> Map.put(map, ref, seq)
      _ -> map
    end
  end

  # -- metadata ----------------------------------------------------------

  defp meta(bundle, shape, decision, matched, evaluation, source_address) do
    %{
      "engine" => @engine,
      "decision" => decision,
      "bundle" => bundle["specAddress"],
      "bundleRef" => @bundle_ref,
      "source" => source_address,
      "shape" => shape && shape["specAddress"],
      "evaluation" => evaluation,
      "engineBuild" => engine_build_address(),
      "matched" => matched,
      "generations" => generations(bundle, shape),
      "derivedObjects" => derived_objects(evaluation)
    }
    |> put_if(is_nil(shape), "note", @no_shape_note)
  end

  # §5: the objects this decision wrote. There is exactly one class of them
  # here — the evaluation record — and reporting it is what makes it
  # replayable: the kernel copies this list onto the event payload, so the
  # derived class is rebuilt from the chain at the next boot instead of
  # dying with this process. Before it landed, an export taken after a
  # restart listed `derivedObjects: []` while every receipt on the chain
  # still cited one, and the verifier read each citation as unbacked bytes.
  #
  # `[]` when no record was written (E3): a refusal that never reached the
  # engine wrote nothing, and saying so is not the same as saying nothing.
  defp derived_objects(nil), do: []
  defp derived_objects(address) when is_binary(address), do: [address]

  # A refusal that never reached the engine: no evaluation happened, so no
  # evaluation record is written and `evaluation` is null. Writing one with
  # empty `requestBytes` would assert an evaluation that did not occur.
  defp error_meta(bundle, source_address, shape, cause, address) do
    %{
      "engine" => @engine,
      "decision" => "error",
      "bundle" => bundle["specAddress"],
      "bundleRef" => @bundle_ref,
      "source" => source_address,
      "shape" => shape && shape["specAddress"],
      "evaluation" => nil,
      "engineBuild" => engine_build_address(),
      "matched" => [],
      "generations" => generations(bundle, shape),
      "derivedObjects" => [],
      "note" =>
        "nothing was handed to the engine (#{cause}#{if address, do: ": " <> address, else: ""}), " <>
          "so there is no evaluation record to cite; the refusal is fail-closed"
    }
  end

  defp no_bundle_meta do
    %{
      "engine" => @engine,
      "decision" => "error",
      "bundle" => nil,
      # No bundle is in force, so there is no resource for `bundleRef` to
      # name. The key is present and null rather than absent: "nothing
      # governed this" is an answer, and the receipt gives it.
      "bundleRef" => nil,
      "source" => nil,
      "shape" => nil,
      "evaluation" => nil,
      "engineBuild" => engine_build_address(),
      "matched" => [],
      "generations" => %{},
      "derivedObjects" => [],
      "note" =>
        "no PolicyBundle is admitted at #{@bundle_ref}; nothing was evaluated and the request " <>
          "was refused. Bootstrap is governed separately by kernel policy."
    }
  end

  # -- addresses ---------------------------------------------------------

  @doc """
  The `bytes:` address of the engine build descriptor this deployment
  admitted at boot (§8). `nil` before boot has admitted it — which is only
  ever the case in a bare unit test, since it is the fold's first act.
  """
  @spec engine_build_address() :: String.t() | nil
  def engine_build_address, do: EngineBuild.cached_address()

  # §8: the evaluation record names the target Kind's admitted
  # `specAddress`, so a reader can fetch the exact schema the paths were
  # typed against rather than the Kind's current definition.
  defp kind_definition_address(request) do
    case R5e.KindRegistry.get(request[:group], request[:version], request[:kind]) do
      {:ok, %R5e.Kind{spec_address: address}} -> address
      _ -> nil
    end
  end

  defp put_if(map, true, key, value), do: Map.put(map, key, value)
  defp put_if(map, false, _key, _value), do: map
end
