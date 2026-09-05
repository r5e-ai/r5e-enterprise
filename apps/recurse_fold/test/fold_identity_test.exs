defmodule Recurse.Fold.IdentityTest do
  @moduledoc """
  Spec 011 §§10–11 in the fold: the fold's own key, the Endorsement the
  node key gave it, the two functions everything else goes through, and
  the KS-7 envelope fields.

  The whole of what this file asserts is one sentence: **every act the
  fold performs is signed by a key whose authority is on the same chain
  as the act, and a reader of the bundle can follow it to the node key
  without being told to.**
  """
  use ExUnit.Case, async: false

  setup_all do
    Recurse.Fold.FreshKernel.boot()
  end

  import Recurse.Fold.TestHelpers

  alias Recurse.Fold.Policy.Shape

  describe "the fold's key and its authority (§10)" do
    test "the fold holds its own key under the data directory, and it is not the node key" do
      assert %{public: public, private: private} = Recurse.Fold.key()
      assert byte_size(public) == 32
      assert byte_size(private) == 32
      assert Recurse.Fold.key_id() != R5e.DSSE.node_key_id()

      # Same custody as the node key, in the same place — and nowhere else.
      path = Path.join([Application.fetch_env!(:r5e, :data_dir), "keys", "fold_ed25519.key"])
      assert File.exists?(path)
      assert File.read!(path) == private
    end

    test "the node key endorsed the fold key for exactly the Kinds it admits, and no more" do
      ref = Recurse.Fold.authority()
      payload = payload_at(ref)

      assert payload["actor"]["id"] == R5e.DSSE.node_key_id()
      assert payload["target"]["kind"] == "Endorsement"
      assert payload["spec"]["subject"] == Recurse.Fold.key_id()
      assert payload["spec"]["role"] == "fold"

      # Contract r4.5 §10: the minimum the role exercises. Two core Kinds
      # (its seeds are KindDefinitions, its detached bytes are CasObjects)
      # and the nine of its own group — derived from the seed files, so a
      # tenth Kind widens the grant visibly rather than hiding under `*`.
      assert payload["spec"]["kinds"] == Recurse.Fold.kinds()
      refute "*" in payload["spec"]["kinds"]
      assert length(payload["spec"]["kinds"]) == 11

      # And no right to issue. `mayIssue: true` under the node key's own
      # root would have let the fold key hand out authority **rooted at
      # the node key** — which no reader pinning the node key consented to.
      assert payload["spec"]["mayIssue"] == false

      # A root endorsement: depth 0, no parent, and the node key is where
      # any chain rooted here ends.
      assert payload["depth"] == 0
      refute Map.has_key?(payload["spec"], "parent")
    end

    test "asking for the authority twice admits one Endorsement, not two" do
      before = Enum.count(payloads(), &(&1["target"]["kind"] == "Endorsement"))
      assert Recurse.Fold.authority() == Recurse.Fold.authority()
      assert Enum.count(payloads(), &(&1["target"]["kind"] == "Endorsement")) == before
    end

    test "every fold admission is signed by the fold key and cites a fold Endorsement" do
      fold = Recurse.Fold.key_id()

      seeded =
        payloads()
        |> Enum.filter(&(&1["actor"]["id"] == fold and &1["outcome"] == "admitted"))

      assert seeded != [], "the fold seeded nothing under its own key"

      for payload <- seeded do
        assert payload["identity"] == "signed"
        assert payload["signers"] == [fold]

        # Exactly one citation, and it is a `fold` Endorsement of this
        # key. Not *the current* one: a chain on which the grant has been
        # revoked and re-minted carries acts under each, and each was
        # effective when it was made — which is the whole point of
        # recording the derivation rather than the conclusion.
        assert [ref] = payload["authority"]
        cited = payload_at(ref)
        assert cited["target"]["kind"] == "Endorsement"
        assert cited["spec"]["role"] == "fold"
        assert cited["spec"]["subject"] == fold

        # §5: and the derivation is on the record, link by link.
        assert [%{"value" => ^ref, "chain" => chain}] = payload["resolvedAuthority"]
        assert List.last(chain)["actor"] == R5e.DSSE.node_key_id()
      end
    end
  end

  describe "seeds transition by specAddress (§10, r4.5)" do
    test "a changed definition is denied without a transition and admitted with one" do
      name = "gateway.r5e.io/v1alpha1/ToolResult"
      {:ok, entry, _} = R5e.ResourceStore.get("core.r5e.io", "v1", "KindDefinition", name)

      changed =
        update_in(entry["spec"], ["epistemicScope", "doesNotClaim"], &(&1 ++ ["a changed seed"]))

      # `path` naming refuses a second definition of one identity with
      # different bytes — which is what makes replacing one an act.
      assert {:denied, receipt} =
               Recurse.Fold.admit("core.r5e.io/v1/KindDefinition", changed, name: name)

      assert receipt["reason"] =~ "already admitted"

      # The transition is that act, and the payload declares it.
      assert {:ok, ok} =
               Recurse.Fold.admit("core.r5e.io/v1/KindDefinition", changed,
                 name: name,
                 transition: R5e.Bootstrap.transition_reason()
               )

      assert payload_for(ok)["transition"] == "spec-011"
      assert payload_for(ok)["actor"]["id"] == Recurse.Fold.key_id()

      {:ok, now, _} = R5e.ResourceStore.get("core.r5e.io", "v1", "KindDefinition", name)
      assert now["specAddress"] == R5e.CAS.spec_address(changed)
      refute now["specAddress"] == entry["specAddress"]
    end

    test "a stranger may not transition a definition it did not admit" do
      name = "gateway.r5e.io/v1alpha1/Prompt"
      {:ok, entry, _} = R5e.ResourceStore.get("core.r5e.io", "v1", "KindDefinition", name)
      changed = put_in(entry["spec"], ["description"], "rewritten by somebody else")

      # The same-identity transition is the *actor of record's* to make
      # (or the node key's). Root issuance is ungated, so any other
      # reading would let a stranger self-endorse and silently redefine
      # somebody else's vocabulary.
      assert {:denied, receipt} =
               admit_as("mallory", "core.r5e.io", "v1", "KindDefinition", name, changed)

      assert receipt["reason"] =~ "already admitted"
    end
  end

  describe "the public surface" do
    test "admit/3 returns a receipt for a grant and a receipt for a denial" do
      {:ok, receipt} =
        Recurse.Fold.admit("gateway.r5e.io/v1alpha1/Prompt", %{
          "contentRef" => %{"$ref" => put_object("hello", "text/plain")},
          "role" => "user"
        })

      assert receipt["outcome"] == "admitted"
      assert receipt["identity"] == "signed"
      assert receipt["signers"] == [Recurse.Fold.key_id()]

      # A denial is a **return value**. The receipt says who refused it and
      # under which bundle; raising would throw that evidence away.
      {:denied, denied} =
        Recurse.Fold.admit("gateway.r5e.io/v1alpha1/ToolCall", %{
          "tool" => "shell",
          "args" => %{"command" => "rm -rf /tmp/scratch"},
          "index" => 0
        })

      assert denied["outcome"] == "denied"
      assert denied["reason"] =~ "cedar denied"
      assert denied["policy"]["decision"] == "deny"
    end

    test "put_cas/2 returns the address the bytes landed at, and the label is optional" do
      {:ok, receipt, address} = Recurse.Fold.put_cas("some bytes", media_type: "text/plain")

      assert receipt["outcome"] == "admitted"
      assert address == "bytes:" <> R5e.Canonical.hash_bytes("some bytes")
      assert {:ok, "some bytes"} = R5e.CAS.get(address)
      assert {:ok, %{"mediaType" => "text/plain"}} = R5e.RefIndex.cas_object(address)

      # "no label" and "an empty label" are different claims, and only one
      # of them is true: the spec on the record carries no `mediaType` key
      # at all when the caller supplied none.
      {:ok, bare_receipt, bare} = Recurse.Fold.put_cas("unlabelled bytes")
      assert {:ok, _entry} = R5e.RefIndex.cas_object(bare)
      refute Map.has_key?(payload_for(bare_receipt)["spec"], "mediaType")
    end

    test "a malformed Kind path is refused, not raised" do
      assert {:refused, reason} = Recurse.Fold.admit("not-a-path", %{})
      assert reason =~ "is not a group/version/Kind path"
      assert {:refused, _} = Recurse.Fold.admit("too/many/segments/here", %{})
      assert {:refused, _} = Recurse.Fold.admit("gateway.r5e.io//Prompt", %{})
    end

    test "a name the naming mode forbids comes back as a denial, not an exception" do
      {:denied, receipt} =
        Recurse.Fold.admit(
          "gateway.r5e.io/v1alpha1/Prompt",
          %{"contentRef" => %{"$ref" => put_object("named", "text/plain")}, "role" => "user"},
          name: "a-name-a-content-named-kind-may-not-carry"
        )

      assert receipt["reason"] =~ "validateStructure"
    end
  end

  describe "KS-7: the envelope fields (§11)" do
    test "a shape citing actor.keyFingerprint is refused, and the reason names the removal" do
      {:denied, receipt} =
        Recurse.Fold.admit(
          "gateway.r5e.io/v1alpha1/PolicyShape",
          %{
            "kind" => "*",
            "engine" => "cedar",
            "action" => "admit",
            "resourceType" => "@kind",
            "resourceId" => "@actor.keyFingerprint",
            "context" => %{},
            "description" => "a shape written before spec 011 removed the field"
          },
          name: "cedar.*"
        )

      assert receipt["reason"] =~ "unknown envelope field"
      assert receipt["reason"] =~ "actor.keyFingerprint"
      assert receipt["reason"] =~ "KS-7"
    end

    test "the three new fields are readable, and two of them are lists" do
      for field <- ~w(actor.identity actor.authorityRefs actor.authorityRoots) do
        assert Shape.validate(Shape.parse("@" <> field), :any, "context.x") == :ok
      end

      # §8: `resourceId` must resolve to a string, and a list of key ids
      # is not one — so the two list-valued fields are context-only.
      assert Shape.validate(Shape.parse("@actor.identity"), :any, "resourceId", "string") == :ok

      for field <- ~w(actor.authorityRefs actor.authorityRoots) do
        assert {:error, reason} =
                 Shape.validate(Shape.parse("@" <> field), :any, "resourceId", "string")

        assert reason =~ "must resolve to a string"
      end
    end

    test "the evaluation record carries resolvedAuthority whole (§11)" do
      {:denied, receipt} =
        Recurse.Fold.admit("gateway.r5e.io/v1alpha1/ToolCall", %{
          "tool" => "shell",
          "args" => %{"command" => "rm -rf /var"},
          "index" => 0
        })

      record = evaluation_of(receipt)
      payload = payload_for(receipt)

      # Whole, and byte-identical to the payload's own — one derivation,
      # written twice, and a replayer holding only the record has the
      # actor's standing without reaching back into the chain.
      assert record["resolvedAuthority"] == payload["resolvedAuthority"]
      assert [%{"chain" => chain}] = record["resolvedAuthority"]
      assert List.last(chain)["actor"] == R5e.DSSE.node_key_id()
    end
  end

  defp payload_at("event:" <> hash), do: Enum.find(payloads(), &(&1["_event"]["hash"] == hash))
end
