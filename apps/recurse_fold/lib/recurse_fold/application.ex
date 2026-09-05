defmodule Recurse.Fold.Application do
  @moduledoc """
  Starts the mandatory kernel dependency and admits the gateway vocabulary.

  Boot establishes the fold key's node-issued authority, archives the engine
  descriptor and reviewed specification, admits KindDefinitions, and installs
  the default workload bundle and shapes when they are absent. These acts
  pass through ordinary admission signed by the fold key.

  Kernel-owned policy governs this maintenance. Workload policy applies to
  the model and tool Kinds assigned to it; it cannot block upstream evidence,
  authority or policy maintenance. The workload engine descriptor identifies
  measured deployed files, not independent integrity of the running process.

  Kind definitions are compared by spec address: changed definitions require
  an admitted transition. Existing policy bundles and shapes are preserved
  at restart, including operator replacements (debt #47). Boot establishes
  the fold's authority the first time and never again: neither a live
  request nor a later restart mints a replacement endorsement for a revoked
  writer. See the release contract for the startup and request boundaries.
  """

  use Application

  require Logger

  alias Recurse.Fold.Policy.Cedar
  alias Recurse.Fold.Policy.EngineBuild

  # The reviewed natural-language document the nine definitions were derived
  # from (stance §9, FR-011). Resolved at compile time from this file's own
  # location; overridable so a deployment that vendors the document
  # elsewhere can say where.
  @natlang_spec Path.expand("../../../../specs/010-gateway-api-group/spec.md", __DIR__)

  @default_bundle_description """
  The fold's default policy, admitted at boot so that the very first governed
  act is governed: permit everything except destructive shell commands
  (`rm -rf`, `DROP DATABASE`) invoked through the `shell` or `exec_command`
  tools. Copied unchanged from the 2026-07-27 enterprise demo. Supersede it
  by admitting another PolicyBundle named `active`; that supersession is
  itself an act on this chain.
  """

  @impl true
  def start(_type, _args) do
    if enabled?() do
      # The fold owns startup of its runtime:false kernel dependency.
      # The enterprise release enables admission by default and refuses
      # an explicitly disabled fold before starting its listeners.
      {:ok, _} = Application.ensure_all_started(:r5e)
      seed()
    else
      raise "recurse_fold cannot be disabled in the governed enterprise release"
    end

    Supervisor.start_link([], strategy: :one_for_one, name: Recurse.Fold.Supervisor)
  end

  @doc """
  Whether the required fold is enabled (`config :recurse_fold, :enabled?`).
  The default is true. Startup refuses false; live admission also checks
  this flag. Restart does **not** re-establish a revoked role Endorsement
  (§10) — see `Recurse.Fold.endorse_at_boot/0`.
  """
  @spec enabled?() :: boolean()
  def enabled?, do: Application.get_env(:recurse_fold, :enabled?, true) == true

  @doc """
  Admit the group's vocabulary, its default policy and its shapes,
  idempotently. Exposed so tests can assert on it; called once at
  application start.
  """
  @spec seed() :: :ok
  def seed do
    # Spec 011 §10: before the fold admits anything, the node key endorses
    # the fold key. Every step below then signs with that key and cites
    # that Endorsement — there is no seeding door that skips the gate.
    #
    # **This is the only place a role Endorsement is minted**, and it
    # mints only for a (role, subject) this chain has never endorsed. A
    # revoked role is not restored by starting the process again (RC
    # review 2026-09-05, K4): the fold boots, seeds nothing, refuses every
    # act, and says so on `/readyz`. Booting on is deliberate — refusing
    # to start would take the readiness endpoint that explains the state
    # down with it, and the gateway already fails closed on an admission
    # it cannot obtain.
    # The engine descriptor's address is a function of the measured bytes,
    # not of an act, so it is cached before the authority question is
    # asked. Otherwise a boot that found no authority would leave the
    # engine unidentifiable and every decision would fail closed on
    # "workload engine build descriptor is unavailable" — even after an
    # operator re-endorsed the role, until the next restart.
    EngineBuild.cache_address(EngineBuild.address())

    case Recurse.Fold.endorse_at_boot() do
      {:ok, _authority} ->
        seed_engine_build()
        derived_from = seed_natlang_document()
        seed_kinds(derived_from)
        seed_default_bundle()
        seed_shapes()

      {:refused, reason} ->
        Logger.error("""
        recurse_fold has no effective authority and this boot did not mint one.

          #{reason}

        The gateway's vocabulary, policy bundle and shapes were not seeded
        and every admission will be refused until an operator admits a new
        Endorsement for this role under the node key. `/readyz` reports
        `fold.role_standing`.
        """)
    end

    :ok
  end

  # -- 1. the engine build descriptor (§8) -------------------------------

  defp seed_engine_build do
    bytes = EngineBuild.bytes()
    address = EngineBuild.address()

    unless object_admitted?(address) do
      put!(bytes, "application/json", "engine build descriptor")
    end

    :ok
  end

  # -- 2. the natural-language document ----------------------------------

  defp seed_natlang_document do
    path = natlang_spec_path()

    bytes =
      case File.read(path) do
        {:ok, bytes} ->
          bytes

        {:error, reason} ->
          raise """
          recurse_fold: could not read the reviewed specification at #{path}
          (#{:file.format_error(reason)}).

          FR-011 makes `derivedFrom` — the bytes address of that document —
          an envelope field on every one of this group's KindDefinitions.
          Seeding them without it would put nine definitions on the chain
          that claim to be derived from a document nobody can fetch.

          Set `config :recurse_fold, natlang_spec_path: "..."` if the
          document lives elsewhere in this deployment.
          """
      end

    address = "bytes:" <> R5e.Canonical.hash_bytes(bytes)

    unless object_admitted?(address) do
      put!(bytes, "text/markdown", "the reviewed specification (#{Path.basename(path)})")
    end

    address
  end

  @doc "Path to the reviewed natural-language document the seeds cite as `derivedFrom`."
  @spec natlang_spec_path() :: Path.t()
  def natlang_spec_path,
    do: Application.get_env(:recurse_fold, :natlang_spec_path, @natlang_spec)

  # -- 3. the nine KindDefinitions ---------------------------------------

  # §10 (r4.5): a co-located extension's seeds follow the same rule as the
  # kernel's own — idempotence keyed by **`specAddress`**, not by
  # presence, and a seed whose bytes changed is admitted as a
  # **same-identity transition** carrying `transition: "spec-011"`.
  #
  # Presence-keyed idempotence was the bug: a deployment that pulled a new
  # release kept the definitions of the old one for ever, and the only
  # symptom was an `epistemicScope` on the chain that said something the
  # chain no longer did. The kernel's `path` naming refuses a second
  # definition with different bytes precisely so that replacing one is an
  # act; the transition is that act, and it is on the record.
  defp seed_kinds(derived_from) do
    for path <- kind_paths() do
      spec = path |> File.read!() |> Jason.decode!()
      name = "#{spec["group"]}/#{spec["version"]}/#{spec["kind"]}"

      case seed_state("core.r5e.io", "v1", "KindDefinition", name, spec) do
        :current ->
          :ok

        state ->
          label = seed_label(name, state)

          admit!(
            %{
              group: "core.r5e.io",
              version: "v1",
              kind: "KindDefinition",
              name: name,
              spec: spec,
              derived_from: derived_from,
              transition: state == :changed && R5e.Bootstrap.transition_reason()
            },
            label
          )
      end
    end

    :ok
  end

  defp seed_label(name, :changed), do: "KindDefinition #{name} (transition)"
  defp seed_label(name, _state), do: "KindDefinition #{name}"

  # `:absent` (nothing under that name), `:current` (the admitted spec
  # hashes to the same address as the file — nothing to do), or `:changed`
  # (a definition is there and the file is not it).
  defp seed_state(group, version, kind, name, spec) do
    case R5e.ResourceStore.get(group, version, kind, name) do
      {:error, :not_found} ->
        :absent

      {:ok, entry, _lineage} ->
        if entry["specAddress"] == R5e.CAS.spec_address(spec),
          do: :current,
          else: :changed
    end
  end

  @doc "The nine seed files, sorted — the group's normative KindDefinitions."
  @spec kind_paths() :: [Path.t()]
  def kind_paths, do: priv_dir() |> Path.join("kinds/*.json") |> Path.wildcard() |> Enum.sort()

  # -- 4/5. the policy text and the default bundle -----------------------

  defp seed_default_bundle do
    {group, version, kind, name} = Cedar.bundle_coordinates()

    unless admitted?(group, version, kind, name) do
      source = File.read!(default_policy_path())
      address = "bytes:" <> R5e.Canonical.hash_bytes(source)

      unless object_admitted?(address) do
        put!(source, "text/plain", "the default policy text")
      end

      admit!(
        %{
          group: group,
          version: version,
          kind: kind,
          name: name,
          spec: %{
            "engine" => "cedar",
            "governs" => Cedar.governed_kinds(),
            "sourceRef" => %{"$ref" => address},
            "description" => String.trim(@default_bundle_description)
          }
        },
        "default PolicyBundle/#{name}"
      )
    end

    :ok
  end

  # -- 6. the shapes -----------------------------------------------------

  defp seed_shapes do
    {group, version, kind} = Cedar.shape_coordinates()

    for path <- shape_paths() do
      spec = path |> File.read!() |> Jason.decode!()
      name = Cedar.shape_name(spec["kind"])

      unless admitted?(group, version, kind, name) do
        admit!(
          %{group: group, version: version, kind: kind, name: name, spec: spec},
          "PolicyShape #{name}"
        )
      end
    end

    :ok
  end

  @doc "The shape seed files, sorted."
  @spec shape_paths() :: [Path.t()]
  def shape_paths, do: priv_dir() |> Path.join("shapes/*.json") |> Path.wildcard() |> Enum.sort()

  @doc "Path to the policy text the fold admits as its default bundle."
  @spec default_policy_path() :: Path.t()
  def default_policy_path, do: Path.join(priv_dir(), "policies/deny-destructive.cedar")

  @doc "Path to the permissive policy the demo and the tests admit."
  @spec permissive_policy_path() :: Path.t()
  def permissive_policy_path, do: Path.join(priv_dir(), "policies/permissive.cedar")

  @doc """
  The key these boot-time admissions are recorded under: the fold's own,
  endorsed by the node key. There is no seed *actor* any more — spec 011
  retired `system:recurse-fold`, which was a name with a placeholder
  fingerprint beside it and nothing a reader could check.
  """
  def seed_key_id, do: Recurse.Fold.key_id()

  # -- plumbing ----------------------------------------------------------

  defp put!(bytes, media_type, label) do
    case Recurse.Fold.put_cas(bytes, media_type: media_type) do
      {:ok, receipt, address} ->
        Logger.info(
          "recurse_fold: admitted #{label} as a CasObject #{address} " <>
            "(#{byte_size(bytes)} bytes, seq #{receipt["seq"]})"
        )

        address

      other ->
        raise seeding_failure("put #{label} on the record", other)
    end
  end

  defp admit!(request, label) do
    kind = "#{request.group}/#{request.version}/#{request.kind}"

    case Recurse.Fold.admit(kind, request.spec,
           name: request[:name],
           derived_from: request[:derived_from],
           transition: request[:transition] || nil
         ) do
      {:ok, receipt} ->
        Logger.info("recurse_fold: admitted #{label} (seq #{receipt["seq"]})")
        receipt

      other ->
        # A denial here is a real answer, not a crash to swallow: the fold's
        # own vocabulary was refused by the policy in force. Fail loudly —
        # booting into a half-seeded state would be worse than not booting.
        raise seeding_failure("seed #{label}", other)
    end
  end

  defp seeding_failure(what, {:denied, receipt}) do
    """
    recurse_fold could not #{what}: the kernel denied it.

      reason: #{receipt["reason"]}
      policy: #{inspect(receipt["policy"])}
    """
  end

  defp seeding_failure(what, {:refused, reason}) do
    """
    recurse_fold could not #{what}: the request was refused before it was an act.

      reason: #{reason}

    That means the envelope or the signature was wrong, not that the policy
    said no — nothing was recorded and no nonce was spent.
    """
  end

  defp admitted?(group, version, kind, name) do
    match?({:ok, _, _}, R5e.ResourceStore.get(group, version, kind, name))
  end

  # A `CasObject` re-put is a *new* admission of the same content-named spec
  # (§2, `content` naming): another event, the same address. Boot skips it
  # so a restart adds no events, which is what makes "seeding is idempotent"
  # a property of the chain rather than of the store.
  defp object_admitted?(address), do: match?({:ok, _}, R5e.RefIndex.cas_object(address))

  defp priv_dir, do: :code.priv_dir(:recurse_fold) |> to_string()
end
