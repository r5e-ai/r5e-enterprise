defmodule Recurse.Fold.Policy.BundleSuccessionTest do
  @moduledoc """
  K5 (RC review 2026-09-05): tenant policy follows the key that owns it
  across a key change.

  `PolicyBundle/active` is named `literal: "active"` with a `readmitBy`
  rule, so who may supersede it is settled by the Kind, not by policy. It
  shipped as `actorOfRecord`: whoever admitted `active` first owned tenant
  policy for ever, a fold-key rotation through `Succession` did **not**
  carry it, and there was no node-key override — losing the fold key froze
  tenant policy permanently. The reviewer read that as an availability
  trap rather than a security property, and it is: the actor binding is
  worth keeping, the immobility is not.

  `actorOfRecordOrSuccessor` is the kernel's own §0 `matches/3` — "is the
  key on the record still speaking, through this key?" — and it is
  one-directional: authority flows forward to the key the record's key
  named, never backward. So a successor may supersede the bundle its
  predecessor admitted, and nothing else changes.
  """
  use ExUnit.Case, async: false

  setup_all do
    Recurse.Fold.FreshKernel.boot()
  end

  import Recurse.Fold.TestHelpers

  alias Recurse.Fold.Policy.Cedar

  defp successor_key, do: key_for("the fold's next key")

  # Two signers, predecessor first: §0's shape rules are checked by the
  # kernel, and a node-key Endorsement covering `Succession` is what makes
  # the act admissible under kernel policy.
  #
  # The fold's own role grant deliberately does **not** cover
  # `core.r5e.io/v1/Succession` — it is the minimum the role exercises
  # (contract r4.5 §10), and rotating the fold key is an operator's
  # decision, not something the fold does in the course of its work. So a
  # rotation begins the way every widening does: the node key admits an
  # Endorsement for it. `matchesSigner: 1` on `predecessor` means that
  # grant lets the fold key succeed itself and nothing else.
  defp endorse_rotation do
    {:ok, receipt} =
      R5e.Bootstrap.endorse_role(Recurse.Fold.key().public, "fold-rotation",
        kinds: ["core.r5e.io/v1/Succession"],
        may_issue: false
      )

    receipt["eventRef"]
  end

  defp succeed_fold_key do
    successor = successor_key()

    spec = %{
      "predecessor" => Recurse.Fold.key_id(),
      "successor" => R5e.Request.key_id(successor),
      "successorKey" => %{
        "algorithm" => "ed25519",
        "bytes" => Base.encode64(successor.public)
      }
    }

    target = %{
      "group" => "core.r5e.io",
      "version" => "v1",
      "kind" => "Succession",
      "name" => nil
    }

    authority = [endorse_rotation()]

    R5e.Admission.admit(%{
      envelope:
        R5e.Request.sign(%{target: target, spec: spec, authority: authority}, [
          Recurse.Fold.key(),
          successor
        ]),
      group: "core.r5e.io",
      version: "v1",
      kind: "Succession",
      name: nil,
      spec: spec,
      authority: authority
    })
  end

  # Supersede `active` as some key, citing the fold's Endorsement — whose
  # subject is the fold key, and which therefore resolves for a successor
  # of it too.
  defp supersede_bundle_as(key, description) do
    address = put_object(permissive_policy_source(), "text/plain")

    spec = %{
      "engine" => "cedar",
      "governs" => Cedar.governed_kinds(),
      "sourceRef" => %{"$ref" => address},
      "description" => description
    }

    {group, version, kind, name} = Cedar.bundle_coordinates()
    target = %{"group" => group, "version" => version, "kind" => kind, "name" => name}
    authority = [Recurse.Fold.authority()]

    R5e.Admission.admit(%{
      envelope: R5e.Request.sign(%{target: target, spec: spec, authority: authority}, [key]),
      group: group,
      version: version,
      kind: kind,
      name: name,
      spec: spec,
      authority: authority
    })
  end

  test "the Kind says the successor may readmit, and the chain says the same" do
    {:ok, definition, _lineage} =
      R5e.ResourceStore.get(
        "core.r5e.io",
        "v1",
        "KindDefinition",
        "gateway.r5e.io/v1alpha1/PolicyBundle"
      )

    assert get_in(definition, ["spec", "naming", "readmitBy"]) == "actorOfRecordOrSuccessor"
  end

  test "a fold-key succession carries the tenant bundle" do
    entry = bundle_entry()
    assert entry["actor"] == Recurse.Fold.key_id(), "the fold key is the actor of record"

    # A key that is neither the actor of record nor a successor of it is
    # refused — the binding the RC shipped is kept, not loosened.
    stranger = key_for("a stranger with the fold's endorsement in hand")

    assert {:denied, refusal} = supersede_bundle_as(stranger, "by a stranger")
    assert refusal["reason"] =~ "readmitBy: actorOfRecordOrSuccessor"
    assert refusal["reason"] =~ "nor a key it"

    assert {:ok, _} = succeed_fold_key()

    assert R5e.Succession.matches(
             Recurse.Fold.key_id(),
             R5e.Request.key_id(successor_key()),
             R5e.Succession.next_seq()
           )

    assert {:ok, receipt} = supersede_bundle_as(successor_key(), "admitted by the successor")
    assert receipt["outcome"] == "admitted"

    # The bundle is the successor's now, and the record carries both the
    # succession and the supersession.
    assert bundle_entry()["actor"] == R5e.Request.key_id(successor_key())
    assert bundle_entry()["spec"]["description"] == "admitted by the successor"
  end
end
