defmodule Recurse.Fold.BootTest do
  @moduledoc """
  What a fresh boot of the fold put on the chain, read back off the chain.

  These assertions are order-independent on purpose: they read the recorded
  events rather than the current in-memory state, so they hold whether or
  not another test has already run and superseded the active bundle.
  """
  use ExUnit.Case, async: false

  setup_all do
    Recurse.Fold.FreshKernel.boot()
  end

  import Recurse.Fold.TestHelpers

  alias Recurse.Fold.Policy.Cedar
  alias Recurse.Fold.Policy.EngineBuild

  @kinds ~w(AgentSession Completion LlmCall LlmResponse PolicyBundle PolicyShape Prompt
            ToolCall ToolResult)

  defp granted_payloads(kind) do
    payloads()
    |> Enum.filter(&(&1["outcome"] == "admitted" and &1["target"]["kind"] == kind))
  end

  defp seeded_kind_definitions do
    granted_payloads("KindDefinition")
    |> Enum.filter(&(&1["spec"]["group"] == "gateway.r5e.io"))
  end

  test "boot admitted all nine spec-010 Kinds through the gate, with authored scopes" do
    definitions = seeded_kind_definitions()

    assert definitions |> Enum.map(& &1["spec"]["kind"]) |> Enum.sort() == @kinds

    for payload <- definitions do
      assert payload["actor"]["id"] == fold_key_id()
      assert payload["spec"]["version"] == "v1alpha1"
      assert payload["scopeDefaulted"] == false
      scope = payload["spec"]["epistemicScope"]
      assert is_list(scope["claims"]) and scope["claims"] != []
      assert is_list(scope["doesNotClaim"]) and scope["doesNotClaim"] != []
      # Schema-lite v2 requires all three; a seed missing one would have
      # been denied at validateStructure, but the assertion is cheap and
      # says what the seeds are supposed to carry.
      assert is_map(payload["spec"]["naming"])
      assert is_binary(payload["spec"]["description"])
      assert is_list(payload["spec"]["predicates"])
    end
  end

  test "the seed files in priv/kinds are the admitted bytes, verbatim" do
    definitions = Map.new(seeded_kind_definitions(), &{&1["spec"]["kind"], &1["spec"]})

    for path <- Recurse.Fold.Application.kind_paths() do
      spec = path |> File.read!() |> Jason.decode!()
      assert definitions[spec["kind"]] == spec, "#{Path.basename(path)} drifted from the chain"
    end
  end

  test "every Kind cites the reviewed natural-language document as derivedFrom" do
    document = File.read!(Recurse.Fold.Application.natlang_spec_path())
    address = "bytes:" <> R5e.Canonical.hash_bytes(document)

    for payload <- seeded_kind_definitions() do
      assert payload["derivedFrom"] == address,
             "#{payload["spec"]["kind"]} does not cite the reviewed document"

      # FR-011: an envelope field, never inside the spec, so the repo file
      # is byte-for-byte what was admitted.
      refute Map.has_key?(payload["spec"], "derivedFrom")
    end

    # And the document is on the record as a CasObject, not merely hashed.
    assert {:ok, %{"mediaType" => "text/markdown"}} = R5e.RefIndex.cas_object(address)
    assert {:ok, ^document} = R5e.CAS.get(address)
  end

  test "boot admitted the fold engine descriptor while kernel policy governed the seed acts" do
    address = EngineBuild.address()
    assert Cedar.engine_build_address() == address
    assert {:ok, _} = R5e.RefIndex.cas_object(address)

    kernel_address = R5e.Policy.EngineBuild.cached_address()
    assert is_binary(kernel_address)
    refute kernel_address == address
    assert {:ok, _} = R5e.RefIndex.cas_object(kernel_address)

    {:ok, bytes} = R5e.CAS.get(address)
    descriptor = Jason.decode!(bytes)

    assert descriptor["format"] == "r5e.engine-build/1"
    assert descriptor["engine"] == "cedar"
    assert descriptor["crate"] == "cedar-policy"
    assert descriptor["crateVersion"] == "4.9.1"
    assert descriptor["module"] == "Recurse.Fold.Policy.Cedar"
    assert descriptor["platform"] == to_string(:erlang.system_info(:system_architecture))

    for key <- ~w(cargoLockSha256 nifSha256 moduleSha256) do
      assert descriptor[key] =~ ~r/\A[0-9a-f]{64}\z/, "#{key} is not a bare sha256 hex digest"
    end

    # Measured, not declared: the lockfile hash is that file's bytes.
    assert descriptor["cargoLockSha256"] ==
             :crypto.hash(:sha256, File.read!(EngineBuild.cargo_lock_path()))
             |> Base.encode16(case: :lower)

    # The descriptor is available for workload decisions after boot. The
    # seed admissions themselves are policy-management acts, so their
    # authoritative policy record cites the kernel engine descriptor.
    {:ok, %{"seq" => first}} = R5e.RefIndex.cas_object(address)

    for payload <- payloads(), is_map(payload["policy"]) do
      seq = payload["_event"]["seq"]

      if seq >= first do
        assert payload["policy"]["engineBuild"] == kernel_address,
               "seq #{seq} cites #{inspect(payload["policy"]["engineBuild"])}"
      else
        if payload["policy"]["bootstrap"] do
          if get_in(payload, ["spec", "address"]) == kernel_address do
            assert payload["policy"]["engineBuild"] == kernel_address
          else
            assert payload["policy"]["engineBuild"] == nil
          end
        else
          assert payload["policy"]["engineBuild"] == kernel_address
        end
      end
    end
  end

  test "boot admitted a default PolicyBundle/active citing detached policy text" do
    [seeded] =
      granted_payloads("PolicyBundle")
      |> Enum.filter(&(&1["actor"]["id"] == fold_key_id()))

    assert seeded["target"]["name"] == "active"
    assert seeded["spec"]["engine"] == "cedar"
    assert seeded["spec"]["description"] =~ "permit everything except destructive shell commands"

    # FR-007: the text is detached and cited by address, never inline.
    address = seeded["spec"]["sourceRef"]["$ref"]
    assert {:ok, source} = R5e.CAS.get(address)
    assert source == deny_policy_source()
    refute Map.has_key?(seeded["spec"], "source")

    # The declaration's `retention: "public-record"` rode onto the record,
    # which is what makes those bytes inexpungible without re-reading the
    # Kind (schema-lite-v2 §4/§5).
    assert [%{"path" => "/sourceRef", "retention" => "public-record"}] = seeded["resolvedRefs"]
    assert [%{"retention" => "public-record"}] = R5e.RefIndex.public_record_citations(address)
  end

  test "boot admitted the three PolicyShapes under their derived names" do
    names =
      granted_payloads("PolicyShape")
      |> Enum.filter(&(&1["actor"]["id"] == fold_key_id()))
      |> Enum.map(& &1["target"]["name"])
      |> Enum.sort()

    assert names == [
             "cedar.*",
             "cedar.gateway.r5e.io/v1alpha1/LlmCall",
             "cedar.gateway.r5e.io/v1alpha1/ToolCall"
           ]

    tool_call = shape_entry("gateway.r5e.io/v1alpha1/ToolCall")
    assert tool_call["spec"]["action"] == "invoke_tool"
    assert tool_call["spec"]["resourceType"] == "ToolUse"
    assert tool_call["spec"]["resourceId"] == "spec.tool"

    assert tool_call["spec"]["context"]["tool_args"] == %{
             "path" => "spec.args",
             "whenAbsent" => "absent"
           }

    assert tool_call["spec"]["context"]["model"]["path"] == "spec.gatewayContext.model"

    fallback = shape_entry("*")
    assert fallback["spec"]["resourceType"] == "@kind"
    # E2: `@kind`, not `@name`. A `server`-named Kind has no name at
    # `authorize`, and `resourceId` has no `whenAbsent`, so a fallback
    # reading `@name` denied every AgentSession admission.
    assert fallback["spec"]["resourceId"] == "@kind"
    assert fallback["spec"]["description"] =~ "E2"

    # Spec 011 §11 (KS-7): every shape now carries the actor's standing
    # into the context, the fallback included — so a deployment can write
    # "only acts whose authority roots at the node key" against a chain
    # fact rather than against a fingerprint the actor asserted.
    assert fallback["spec"]["context"] == %{
             "identity" => %{"path" => "@actor.identity", "whenAbsent" => "absent"},
             "authority_roots" => %{
               "path" => "@actor.authorityRoots",
               "whenAbsent" => "absent"
             }
           }
  end

  test "kernel policy governs the fold's bundle and shape seed admissions" do
    seeded =
      granted_payloads("PolicyBundle")
      |> Enum.find(&(&1["actor"]["id"] == fold_key_id()))

    {:ok, kernel_bundle, _lineage} =
      R5e.ResourceStore.get("core.r5e.io", "v1", "PolicyBundle", "active")

    assert seeded["policy"]["engine"] == "cedar"
    assert seeded["policy"]["decision"] == "allow"
    assert seeded["policy"]["bundleRef"] == "core.r5e.io/v1/PolicyBundle/active"
    assert seeded["policy"]["bundle"] == kernel_bundle["specAddress"]
    assert is_binary(seeded["policy"]["evaluation"])

    # PolicyShape management stays upstream-governed; it is not evaluated
    # under the tenant bundle it helps configure.
    fallback =
      granted_payloads("PolicyShape")
      |> Enum.find(&(&1["target"]["name"] == "cedar.*"))

    assert fallback["policy"]["shape"] == nil
    assert fallback["policy"]["bundle"] == kernel_bundle["specAddress"]
    assert is_binary(fallback["policy"]["evaluation"])
  end

  test "the fold is governed from its first act: a destructive ToolCall is denied" do
    # Nothing here admits a bundle. The only policy in force is the one the
    # fold's own boot put on the chain.
    {:deny, reason, meta} =
      Cedar.authorize(%{
        actor: actor(),
        group: "gateway.r5e.io",
        version: "v1alpha1",
        kind: "ToolCall",
        name: nil,
        spec: %{"tool" => "shell", "args" => %{"command" => "rm -rf /tmp/scratch"}},
        identity: "signed",
        authority_roots: [R5e.DSSE.node_key_id()],
        resolved: []
      })

    assert reason =~ "cedar denied"
    assert meta["decision"] == "deny"
    assert String.starts_with?(meta["bundle"], "sha256:")
    assert String.starts_with?(meta["source"], "bytes:sha256:")
    assert String.starts_with?(meta["shape"], "sha256:")
    assert meta["matched"] != []
  end

  test "seeding is idempotent: running it again admits nothing new" do
    before = log_counts()
    :ok = Recurse.Fold.Application.seed()
    assert log_counts() == before
  end
end
