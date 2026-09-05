defmodule Recurse.Fold.Policy.CedarTest do
  @moduledoc """
  The presentation the engine builds — now from an admitted shape rather
  than from a clause in the module — and the two ways it refuses.

  These tests deliberately admit as little as possible: the presentation is
  a pure function of the request and the shape in force. The fail-closed
  test still installs its broken bundle straight into the resource store,
  and the reason is the load-bearing one rather than the bookkeeping one —
  with a broken bundle active *every* later admission fails closed,
  including the one that would put the good bundle back. This file boots
  its own kernel, so "it would perturb another file's chain" is no longer
  part of the argument.
  """
  use ExUnit.Case, async: false

  setup_all do
    Recurse.Fold.FreshKernel.boot()
  end

  import Recurse.Fold.TestHelpers

  alias Recurse.Fold.Policy.Cedar

  defp request(overrides) do
    Map.merge(
      %{
        actor: actor(),
        group: "gateway.r5e.io",
        version: "v1alpha1",
        kind: "ToolCall",
        name: nil,
        spec: %{"tool" => "shell"},
        # §11 (KS-7): the three the kernel settles before `authorize`.
        identity: "signed",
        authority_refs: [],
        authority_roots: [],
        resolved: []
      },
      overrides
    )
  end

  # Under spec 011 every actor id **is** a key id, so on a chain this fold
  # writes today the third clause is the only reachable one: a key id has
  # no `person:`/`agent:` prefix and every principal is a ServiceAccount.
  # The first two clauses stay live for a legacy chain and for a
  # deployment that maps key ids to types in its own policy. Debt: the
  # mapping wants to come from an admitted `Principal` profile rather than
  # from a string prefix.
  describe "principal type by actor-id prefix" do
    test "person: is a Human" do
      {:ok, p} = Cedar.present(request(%{actor: actor_id("person:thomas")}))
      assert p.request["principal"] == ~s(Recurse::Principal::Human::"person:thomas")
      [principal | _] = p.entities
      assert principal["uid"] == %{"type" => "Recurse::Principal::Human", "id" => "person:thomas"}
    end

    test "agent: is Autonomous" do
      {:ok, p} = Cedar.present(request(%{actor: actor_id("agent:fable")}))
      assert p.request["principal"] == ~s(Recurse::Principal::Autonomous::"agent:fable")
    end

    test "anything else is a ServiceAccount" do
      {:ok, p} = Cedar.present(request(%{actor: actor_id("key:ed25519:sha256:abc")}))

      assert p.request["principal"] ==
               ~s(Recurse::Principal::ServiceAccount::"key:ed25519:sha256:abc")
    end

    # Spec 011 §11 (KS-7): `key_fingerprint` is gone from the principal's
    # attributes and three kernel-settled facts stand in its place. A rule
    # that wants "only acts under the node's endorsement" is writable
    # against `authority_roots`; nothing was ever writable against a
    # fingerprint the actor asserted about itself.
    test "the principal entity carries the identity and the authority, no parents" do
      {:ok, p} =
        Cedar.present(
          request(%{
            identity: "signed",
            authority_refs: ["event:sha256:aa"],
            authority_roots: ["key:ed25519:sha256:bb"]
          })
        )

      [principal | _] = p.entities

      assert principal["attrs"] == %{
               "subject" => "person:thomas",
               "identity" => "signed",
               "authority_refs" => ["event:sha256:aa"],
               "authority_roots" => ["key:ed25519:sha256:bb"],
               "admission_signer" => "person:thomas"
             }

      assert principal["parents"] == []
    end

    test "an actor that cited nothing carries empty lists, not missing keys" do
      {:ok, p} = Cedar.present(request(%{identity: "signed"}))
      [principal | _] = p.entities

      assert principal["attrs"]["authority_refs"] == []
      assert principal["attrs"]["authority_roots"] == []
    end
  end

  describe "the ToolCall shape, read off the chain" do
    test "produces the 2026-07-27 demo's vocabulary from an admitted PolicyShape" do
      {:ok, p} =
        Cedar.present(
          request(%{
            spec: %{
              "tool" => "shell",
              "args" => %{"command" => "rm -rf /tmp/scratch"},
              "purpose" => "demo"
            }
          })
        )

      assert p.shape["name"] == "cedar.gateway.r5e.io/v1alpha1/ToolCall"
      assert p.request["action"] == ~s(Action::"invoke_tool")
      assert p.request["resource"] == ~s(ToolUse::"shell")

      # `model` reaches through the llmCall hop, which this request does not
      # cite, so the key is dropped: whenAbsent defaults to `absent`.
      assert p.request["context"] == %{
               "tool_name" => "shell",
               "tool_args" => %{"command" => "rm -rf /tmp/scratch"},
               # §11 (KS-7): the actor's standing, from a synthetic request
               # that carries none — so both keys are dropped rather than
               # guessed at, which is what `whenAbsent: absent` says.
               "identity" => "signed",
               "authority_roots" => []
             }

      assert [_principal, resource] = p.entities
      assert resource["uid"] == %{"type" => "ToolUse", "id" => "shell"}
      assert resource["parents"] == []
    end

    test "records what each declared path resolved to, sorted, absences included" do
      {:ok, p} = Cedar.present(request(%{spec: %{"tool" => "ls"}}))

      shape = shape_entry("gateway.r5e.io/v1alpha1/ToolCall")["spec"]

      declared_paths =
        [shape["resourceId"] | Enum.map(shape["context"], fn {_key, entry} -> entry["path"] end)]
        |> Enum.uniq()
        |> Enum.sort()

      assert Enum.map(p.resolution, & &1["path"]) == declared_paths
      assert %{"path" => "@actor.authorityRoots", "value" => []} in p.resolution
      assert %{"path" => "@actor.identity", "value" => "signed"} in p.resolution
      assert %{"path" => "spec.gatewayContext.model", "value" => "absent"} in p.resolution
      assert %{"path" => "spec.args", "value" => "absent"} in p.resolution
      assert %{"path" => "spec.tool", "value" => "ls"} in p.resolution
    end

    test "the gateway-provided model is presented to policy" do
      {:ok, p} =
        Cedar.present(
          request(%{
            spec: %{
              "tool" => "ls",
              "gatewayContext" => %{"model" => "claude-opus-5"}
            }
          })
        )

      assert p.request["context"]["model"] == "claude-opus-5"

      assert %{"path" => "spec.gatewayContext.model", "value" => "claude-opus-5"} in p.resolution
    end
  end

  describe "the `cedar.*` fallback shape" do
    test "any Kind with no shape of its own is an admission of that Kind" do
      {:ok, p} =
        Cedar.present(
          request(%{
            kind: "Completion",
            name: "sha256:" <> String.duplicate("a", 64),
            spec: %{"contentRef" => %{"$ref" => "bytes:sha256:" <> String.duplicate("b", 64)}}
          })
        )

      assert p.shape["name"] == "cedar.*"
      assert p.request["action"] == ~s(Action::"admit")
      # E2: `resourceId` reads `@kind`, not `@name`. The cost is on the
      # record and is stated in the shape's own description — under the
      # fallback the resource is the *Kind*, so a `cedar.*` policy cannot
      # tell two Completions apart. A Kind that needs that gets a shape.
      assert p.request["resource"] == ~s(Completion::"Completion")
      # §11 (KS-7): the fallback carries the actor's standing too, so a
      # deployment can govern the Kinds that have no shape of their own by
      # who is asking rather than only by what they are asking for.
      assert p.request["context"] == %{"identity" => "signed", "authority_roots" => []}
    end

    test "a `server`-named Kind is governed by it rather than refused (E2)" do
      # The whole point of the `@kind` change. A `server`-named instance
      # has no name until `record` — the name *is* the admission event's
      # hash — so a fallback reading `@name` had no id to present and
      # failed closed on every AgentSession admission. `@kind` exists on
      # every request, so the fallback governs this one too.
      assert {:ok, p} = Cedar.present(request(%{kind: "AgentSession", name: nil, spec: %{}}))

      assert p.shape["name"] == "cedar.*"
      assert p.request["resource"] == ~s(AgentSession::"AgentSession")
    end
  end

  describe "a required slot the engine cannot read" do
    # A shape is a chain fact: admitting one changes how its Kind is
    # presented for the rest of this file's chain. So this one is admitted
    # for `ToolResult`, which is the Kind no other test in this file
    # presents — a statement a reader can check by reading down the page,
    # rather than across the suite, because the file has a kernel of its
    # own.
    setup do
      {g, v, k} = Cedar.shape_coordinates()
      target = "gateway.r5e.io/v1alpha1/ToolResult"

      {:ok, _} =
        admit(g, v, k, Cedar.shape_name(target), %{
          "kind" => target,
          "engine" => "cedar",
          "action" => "record_result",
          "resourceType" => "ToolUse",
          "resourceId" => "spec.resultMediaType"
        })

      :ok
    end

    test "fails closed, naming the path — §8 gives resourceId no whenAbsent" do
      # Unchanged by E2: an id the engine cannot read is a refusal, not an
      # invented value. Only the way of reaching it moved, since the
      # fallback no longer reads anything that can be absent.
      assert {:error, reason} =
               Cedar.present(
                 request(%{kind: "ToolResult", name: nil, spec: %{"outcome" => "ok"}})
               )

      assert reason =~ "resourceId"
      assert reason =~ "is absent on this instance"
      assert reason =~ "§8 gives resourceId no whenAbsent"
      assert reason =~ "fail-closed"
    end
  end

  describe "null stripping — Cedar has no null" do
    test "nil-valued keys are dropped from the context, at every depth" do
      {:ok, p} =
        Cedar.present(
          request(%{
            spec: %{
              "tool" => "shell",
              "args" => %{
                "command" => "ls",
                "cwd" => nil,
                "env" => %{"HOME" => nil, "TZ" => "UTC"}
              }
            }
          })
        )

      assert p.request["context"]["tool_args"] == %{"command" => "ls", "env" => %{"TZ" => "UTC"}}
    end

    test "nils are dropped from lists too" do
      assert Cedar.strip_nulls(%{"a" => [1, nil, %{"b" => nil, "c" => 2}]}) == %{
               "a" => [1, %{"c" => 2}]
             }
    end

    test "a context carrying a null would otherwise break the NIF" do
      # Not a hypothetical: Cedar's Context::from_json_value rejects null.
      broken =
        JSON.encode!(%{
          "principal" => ~s(Recurse::Principal::Human::"person:thomas"),
          "action" => ~s(Action::"admit"),
          "resource" => ~s(Thing::"x"),
          "context" => %{"nope" => nil}
        })

      entities =
        JSON.encode!([
          %{
            "uid" => %{"type" => "Recurse::Principal::Human", "id" => "person:thomas"},
            "attrs" => %{},
            "parents" => []
          },
          %{"uid" => %{"type" => "Thing", "id" => "x"}, "attrs" => %{}, "parents" => []}
        ])

      assert {:error, reason} =
               Recurse.Cedar.evaluate_with_entities(
                 "permit(principal, action, resource);",
                 broken,
                 entities
               )

      assert reason =~ "context"
    end
  end

  describe "fail-closed" do
    setup do
      {group, version, kind, name} = Cedar.bundle_coordinates()
      {:ok, previous, _} = R5e.ResourceStore.get(group, version, kind, name)

      # Store-level fixture, NOT an admission: swapping a syntactically
      # broken bundle in through the gate would be unrestorable, because
      # with a broken bundle active every subsequent admission — including
      # the one that would restore the good bundle — fails closed. That is
      # the correct production behaviour and exactly why it is not
      # exercised through the gate here.
      on_exit(fn -> R5e.ResourceStore.put(group, version, kind, name, previous) end)

      broken_source = put_object("permit(principal, action  <<< this is not Cedar")

      broken =
        Map.put(
          previous,
          "spec",
          Map.merge(previous["spec"], %{
            "engine" => "cedar",
            "sourceRef" => %{"$ref" => broken_source}
          })
        )

      R5e.ResourceStore.put(group, version, kind, name, broken)
      %{broken: broken, broken_source: broken_source}
    end

    test "a syntactically broken bundle denies, loudly, and says so on the receipt", ctx do
      assert {:deny, reason, meta} =
               Cedar.authorize(request(%{authority_roots: [R5e.DSSE.node_key_id()]}))

      assert reason =~ "cedar evaluation error (fail-closed):"
      assert reason =~ "parse error"
      assert meta["engine"] == "cedar"
      assert meta["decision"] == "error"
      assert meta["bundle"] == ctx.broken["specAddress"]
      assert meta["source"] == ctx.broken_source
      assert meta["matched"] == []
      assert meta["error"] =~ "cedar parse error"
      # An engine error is still an evaluation: the bytes were handed over
      # and the record says what they were.
      assert is_binary(meta["evaluation"])
      assert evaluation_of(%{"policy" => meta})["decision"] == "error"
    end
  end

  describe "a bundle whose source object is gone" do
    setup do
      {group, version, kind, name} = Cedar.bundle_coordinates()
      {:ok, previous, _} = R5e.ResourceStore.get(group, version, kind, name)
      on_exit(fn -> R5e.ResourceStore.put(group, version, kind, name, previous) end)

      missing = "bytes:sha256:" <> String.duplicate("c", 64)

      R5e.ResourceStore.put(
        group,
        version,
        kind,
        name,
        Map.put(
          previous,
          "spec",
          Map.merge(previous["spec"], %{
            "engine" => "cedar",
            "sourceRef" => %{"$ref" => missing}
          })
        )
      )

      %{missing: missing}
    end

    test "fails closed, naming the address, with no evaluation record", ctx do
      assert {:deny, reason, meta} =
               Cedar.authorize(request(%{authority_roots: [R5e.DSSE.node_key_id()]}))

      assert reason =~ ctx.missing
      assert reason =~ "not in this deployment's CAS"
      assert meta["decision"] == "error"
      assert meta["evaluation"] == nil
      assert meta["note"] =~ "nothing was handed to the engine"
    end
  end

  describe "matched policy ids" do
    test "Cedar 4.9.1 returns positional ids and ignores @id annotations" do
      # Pins the finding recorded in the module doc: annotating a policy
      # with @id("...") parses, but the authorization response still cites
      # policy1. If a Cedar upgrade ever changes this, this test fails and
      # the receipts get readable ids — a welcome break, not a regression.
      annotated = """
      @id("baseline-permit")
      permit (principal, action, resource);

      @id("forbid-destructive-shell")
      forbid (principal, action == Action::"invoke_tool", resource == ToolUse::"shell")
      when { context has tool_args && context.tool_args has "command"
             && context.tool_args.command like "*rm -rf*" };
      """

      {:ok, p} =
        Cedar.present(
          request(%{spec: %{"tool" => "shell", "args" => %{"command" => "rm -rf /"}}})
        )

      assert {:ok, %{decision: :deny, matched_policies: matched}} =
               Recurse.Cedar.evaluate_with_entities(
                 annotated,
                 JSON.encode!(p.request),
                 JSON.encode!(p.entities)
               )

      assert matched == ["policy1"]
    end
  end

  defp actor_id(id), do: actor(id)
end
