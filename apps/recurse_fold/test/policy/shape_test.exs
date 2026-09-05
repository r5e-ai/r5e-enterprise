defmodule Recurse.Fold.Policy.ShapeTest do
  @moduledoc """
  The §8 path grammar: every production parsed, typed and evaluated, plus
  the three ways a path can refuse.
  """
  use ExUnit.Case, async: false

  setup_all do
    Recurse.Fold.FreshKernel.boot()
  end

  import Recurse.Fold.TestHelpers

  alias Recurse.Fold.Policy.Shape

  defp kind(name) do
    {:ok, kind} = R5e.KindRegistry.get("gateway.r5e.io", "v1alpha1", name)
    kind
  end

  describe "parse — the four productions plus literals" do
    test "spec paths" do
      assert Shape.parse("spec.tool") == {:spec, ["tool"]}
      assert Shape.parse("spec.usage.inputTokens") == {:spec, ["usage", "inputTokens"]}
    end

    test "one event hop" do
      assert Shape.parse("llmCall.spec.model") == {:hop, "llmCall", ["model"]}
    end

    test "one bytes dereference, with and without a tail" do
      assert Shape.parse("argsRef.json") == {:bytes, "argsRef", []}
      assert Shape.parse("argsRef.json.command") == {:bytes, "argsRef", ["command"]}
    end

    test "envelope fields" do
      for field <- Shape.env_fields() do
        assert Shape.parse("@" <> field) == {:env, field}
      end
    end

    test "anything that is not a path is a literal" do
      assert Shape.parse("ToolUse") == {:literal, "ToolUse"}
      assert Shape.parse("invoke_tool") == {:literal, "invoke_tool"}
      # `spec` alone is not a path: the grammar requires at least one name.
      assert Shape.parse("spec") == {:literal, "spec"}
    end

    test "double quotes force a literal reading of something that would parse as a path" do
      # E1: §8 defines `literal` but never says how a bare non-path string
      # is read. This implementation reads it as a literal and keeps the
      # quoted form as the escape hatch for the ambiguous case.
      assert Shape.parse(~s("spec.tool")) == {:literal, "spec.tool"}
      assert Shape.path?(Shape.parse(~s("spec.tool"))) == false
      assert Shape.path?(Shape.parse("spec.tool")) == true
    end

    test "a segment that is not a `name` is not a path" do
      assert Shape.parse("spec.9lives") == {:literal, "spec.9lives"}
      assert Shape.parse("spec.has-dash") == {:literal, "spec.has-dash"}
    end
  end

  describe "validate — typing against the target Kind's admitted schema" do
    test "a declared spec path types" do
      assert Shape.validate(Shape.parse("spec.tool"), kind("ToolCall"), "resourceId", "string") ==
               :ok
    end

    test "an undeclared property does not" do
      assert {:error, reason} =
               Shape.validate(Shape.parse("spec.nope"), kind("ToolCall"), "resourceId", nil)

      assert reason =~ "spec declares no property \"nope\""
    end

    test "a path may terminate at an open object but not descend into it" do
      # ToolCall.args is `{type: object}` with no declared properties.
      assert Shape.validate(Shape.parse("spec.args"), kind("ToolCall"), "context.a", nil) == :ok

      assert {:error, reason} =
               Shape.validate(
                 Shape.parse("spec.args.command"),
                 kind("ToolCall"),
                 "context.a",
                 nil
               )

      assert reason =~ "object with no declared properties"
      assert reason =~ "spec.args.command"
    end

    test "a path may terminate at an array but not index into it" do
      assert Shape.validate(Shape.parse("spec.toolCalls"), kind("LlmResponse"), "context.t", nil) ==
               :ok

      assert {:error, reason} =
               Shape.validate(
                 Shape.parse("spec.toolCalls.first"),
                 kind("LlmResponse"),
                 "context.t",
                 nil
               )

      assert reason =~ "declared array"
      assert reason =~ "not descend into it"
    end

    test "descending into a declared nested object is fine" do
      assert Shape.validate(
               Shape.parse("spec.usage.inputTokens"),
               kind("LlmResponse"),
               "context.n",
               nil
             ) == :ok
    end

    test "one event hop types against the target Kind" do
      assert Shape.validate(
               Shape.parse("llmCall.spec.model"),
               kind("ToolCall"),
               "context.model",
               nil
             ) == :ok

      assert {:error, reason} =
               Shape.validate(
                 Shape.parse("llmCall.spec.nope"),
                 kind("ToolCall"),
                 "context.model",
                 nil
               )

      assert reason =~ "llmCall.spec declares no property \"nope\""
    end

    test "a hop through a property that is not an event ref is refused" do
      assert {:error, reason} =
               Shape.validate(
                 Shape.parse("session.spec.harness"),
                 kind("ToolCall"),
                 "context",
                 nil
               )

      assert reason =~ "not as an event ref"
    end

    test "a bytes dereference needs a declared json schema" do
      # ToolCall.argsRef declares `{bytes: true, json: {type: object}}`.
      assert Shape.validate(Shape.parse("argsRef.json"), kind("ToolCall"), "context.a", nil) ==
               :ok

      # Prompt.contentRef declares no json.
      assert {:error, reason} =
               Shape.validate(Shape.parse("contentRef.json"), kind("Prompt"), "context.c", nil)

      assert reason =~ "declares no `json` schema"
    end

    test "resourceId must resolve to a string" do
      assert {:error, reason} =
               Shape.validate(Shape.parse("spec.index"), kind("ToolCall"), "resourceId", "string")

      assert reason =~ "declared integer"
      assert reason =~ "requires string"
    end

    test "a `*` shape may use only envelope fields and literals" do
      assert Shape.validate(Shape.parse("@kind"), :any, "resourceType", nil) == :ok
      assert Shape.validate(Shape.parse("admit"), :any, "action", nil) == :ok

      assert {:error, reason} = Shape.validate(Shape.parse("spec.tool"), :any, "resourceId", nil)
      assert reason =~ "only @ envelope fields and literals"
    end

    test "an @ field that names nothing is refused" do
      assert {:error, reason} =
               Shape.validate(Shape.parse("@actor"), kind("ToolCall"), "ctx", nil)

      assert reason =~ "unknown envelope field"
    end
  end

  describe "evaluate — reading a live request" do
    setup do
      %{
        request: %{
          actor: actor(),
          group: "gateway.r5e.io",
          version: "v1alpha1",
          kind: "ToolCall",
          name: "abc",
          spec: %{"tool" => "shell", "args" => %{"command" => "ls -la"}},
          identity: "signed",
          authority_refs: ["event:sha256:aa"],
          authority_roots: ["key:ed25519:sha256:bb"],
          resolved: []
        }
      }
    end

    test "literals and envelope fields", %{request: request} do
      assert Shape.evaluate(Shape.parse("ToolUse"), request, []) == {:ok, "ToolUse"}
      assert Shape.evaluate(Shape.parse("@kind"), request, []) == {:ok, "ToolCall"}
      assert Shape.evaluate(Shape.parse("@name"), request, []) == {:ok, "abc"}
      assert Shape.evaluate(Shape.parse("@actor.id"), request, []) == {:ok, "person:thomas"}

      # Spec 011 §11 (KS-7): three kernel-settled facts replace the
      # fingerprint the actor used to assert about itself.
      assert Shape.evaluate(Shape.parse("@actor.identity"), request, []) == {:ok, "signed"}

      assert Shape.evaluate(Shape.parse("@actor.authorityRefs"), request, []) ==
               {:ok, ["event:sha256:aa"]}

      assert Shape.evaluate(Shape.parse("@actor.authorityRoots"), request, []) ==
               {:ok, ["key:ed25519:sha256:bb"]}

      # And the retired field is gone from the grammar, with a message that
      # says what to read instead.
      assert {:error, reason} =
               Shape.validate(Shape.parse("@actor.keyFingerprint"), :any, "resourceId")

      assert reason =~ "unknown envelope field"
      assert reason =~ "KS-7"
    end

    test "spec paths, whole objects included", %{request: request} do
      assert Shape.evaluate(Shape.parse("spec.tool"), request, []) == {:ok, "shell"}

      assert Shape.evaluate(Shape.parse("spec.args"), request, []) ==
               {:ok, %{"command" => "ls -la"}}
    end

    test "an absent terminal, and an absent intermediate, both read as absent", %{
      request: request
    } do
      assert Shape.evaluate(Shape.parse("spec.purpose"), request, []) == :absent
      assert Shape.evaluate(Shape.parse("spec.args.nope"), request, []) == :absent
      assert Shape.evaluate(Shape.parse("spec.nothing.here"), request, []) == :absent
    end

    test "an unnamed server instance has no @name yet", %{request: request} do
      # E2: a `server`-named instance is named by its admission event hash,
      # which does not exist until `record`. At `authorize` the name is
      # absent, and a shape that reads `@name` sees it as such.
      assert Shape.evaluate(Shape.parse("@name"), %{request | name: nil}, []) == :absent
    end

    test "one event hop reads the cited event's payload spec" do
      prompt_ref = put_object("hop-test prompt")

      {:ok, prompt} =
        admit_gateway("Prompt", nil, %{"contentRef" => %{"$ref" => prompt_ref}})

      {:ok, call} =
        admit_gateway("LlmCall", nil, %{
          "model" => "claude-sonnet-4",
          "prompt" => %{"$ref" => "gateway.r5e.io/v1alpha1/Prompt/" <> prompt["name"]}
        })

      manifest = [
        %{"path" => "/llmCall", "class" => "event", "value" => call["eventRef"]}
      ]

      assert Shape.evaluate(Shape.parse("llmCall.spec.model"), %{}, manifest) ==
               {:ok, "claude-sonnet-4"}

      assert Shape.evaluate(Shape.parse("llmCall.spec.provider"), %{}, manifest) == :absent
    end

    test "a hop whose property the instance omits is absent, not an error" do
      assert Shape.evaluate(Shape.parse("llmCall.spec.model"), %{}, []) == :absent
    end

    test "a hop whose target is not on this chain fails closed, naming the path" do
      manifest = [
        %{
          "path" => "/llmCall",
          "class" => "event",
          "value" => "event:sha256:" <> String.duplicate("0", 64)
        }
      ]

      assert {:error, reason} = Shape.evaluate(Shape.parse("llmCall.spec.model"), %{}, manifest)
      assert reason =~ "llmCall.spec"
      assert reason =~ "is on this chain"
    end

    test "one bytes dereference decodes the object as JSON" do
      address = put_object(~s({"command":"ls -la"}), "application/json")

      manifest = [%{"path" => "/argsRef", "class" => "bytes", "value" => address}]

      assert Shape.evaluate(Shape.parse("argsRef.json"), %{}, manifest) ==
               {:ok, %{"command" => "ls -la"}}

      assert Shape.evaluate(Shape.parse("argsRef.json.command"), %{}, manifest) == {:ok, "ls -la"}
      assert Shape.evaluate(Shape.parse("argsRef.json.nope"), %{}, manifest) == :absent
    end

    test "a bytes object that is not JSON fails closed" do
      address = put_object("this is not json at all")
      manifest = [%{"path" => "/argsRef", "class" => "bytes", "value" => address}]

      assert {:error, reason} = Shape.evaluate(Shape.parse("argsRef.json"), %{}, manifest)
      assert reason =~ "argsRef.json"
      assert reason =~ "not valid JSON"
    end

    test "a bytes object over §8's 64 KiB ceiling fails closed" do
      big = "[\"" <> String.duplicate("x", Shape.bytes_hop_limit()) <> "\"]"
      address = put_object(big, "application/json")
      manifest = [%{"path" => "/argsRef", "class" => "bytes", "value" => address}]

      assert {:error, reason} = Shape.evaluate(Shape.parse("argsRef.json"), %{}, manifest)
      assert reason =~ "over §8's #{Shape.bytes_hop_limit()}-byte ceiling"
    end

    test "a bytes object missing from the CAS fails closed" do
      manifest = [
        %{
          "path" => "/argsRef",
          "class" => "bytes",
          "value" => "bytes:sha256:" <> String.duplicate("1", 64)
        }
      ]

      assert {:error, reason} = Shape.evaluate(Shape.parse("argsRef.json"), %{}, manifest)
      assert reason =~ "not in this deployment's CAS"
    end
  end
end
