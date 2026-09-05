defmodule Recurse.Fold.Policy.AuthorityJurisdictionTest do
  @moduledoc """
  K3 (RC review 2026-09-05): what a `PolicyBundle` may declare it governs
  is bounded by the authority that admitted it.

  The RC shipped `requiresAuthority: true` on the Kind and left the
  narrowing out, so an endorsement narrowed which Kinds a key may *admit*
  and nothing narrowed which Kinds the bundle it admitted may *decide
  for*. The reviewer demonstrated it: a key endorsed for exactly
  `gateway.r5e.io/v1alpha1/PolicyBundle` admitted a bundle governing
  `LlmCall` and `ToolCall`.

  The vector below is that scenario on this deployment's own Kind. The
  Kind's naming is `literal: "active"` with `readmitBy`, so the acting key
  has to be the actor of record — the fold key — and the narrowing is
  supplied by the **Endorsement it cites**, not by which key it is. That is
  the shape of the real attack anyway: a key that legitimately holds the
  bundle resource, exercising a grant that does not reach the Kinds it
  writes into `governs`.

  Two coded bounds stay in place beside this one (the KindDefinition's
  `governs` enum at `validateConstraints`, and `governed_kinds/0` in
  `jurisdiction/2` at `authorize`), so the derived check is the third of
  three rather than the only one. It is the only one of the three a reader
  of the chain can check, because it reads the chain.
  """
  use ExUnit.Case, async: false

  setup_all do
    Recurse.Fold.FreshKernel.boot()
  end

  import Recurse.Fold.TestHelpers

  alias Recurse.Fold.Policy.Cedar

  @bundle_kinds ["gateway.r5e.io/v1alpha1/PolicyBundle"]

  # Sign as the fold key, citing a chosen Endorsement rather than the one
  # `Recurse.Fold.admit/3` looks up. Everything else is the ordinary path.
  defp supersede_bundle_citing(authority_ref, governs) do
    source = permissive_policy_source()
    address = put_object(source, "text/plain")

    spec = %{
      "engine" => "cedar",
      "governs" => governs,
      "sourceRef" => %{"$ref" => address},
      "description" => "admitted under a narrower authority than it declares"
    }

    {group, version, kind, name} = Cedar.bundle_coordinates()

    target = %{"group" => group, "version" => version, "kind" => kind, "name" => name}

    envelope =
      R5e.Request.sign(
        %{target: target, spec: spec, authority: [authority_ref]},
        [Recurse.Fold.key()]
      )

    R5e.Admission.admit(%{
      envelope: envelope,
      group: group,
      version: version,
      kind: kind,
      name: name,
      spec: spec,
      authority: [authority_ref]
    })
  end

  defp endorse(kinds) do
    {:ok, receipt} =
      R5e.Bootstrap.endorse_role(Recurse.Fold.key().public, "policy-admin",
        kinds: kinds,
        may_issue: false
      )

    receipt["eventRef"]
  end

  test "a key endorsed for PolicyBundle only cannot declare governs over LlmCall/ToolCall" do
    narrow = endorse(@bundle_kinds)

    assert {:denied, receipt} = supersede_bundle_citing(narrow, Cedar.governed_kinds())

    assert receipt["reason"] =~ "authorize: governs exceeds the admitting authority:"
    assert receipt["reason"] =~ "gateway.r5e.io/v1alpha1/LlmCall"
    assert receipt["reason"] =~ "the cited authority covers"
    assert receipt["reason"] =~ ~s(["gateway.r5e.io/v1alpha1/PolicyBundle"])

    # A recorded denial, by this engine, naming itself.
    assert receipt["outcome"] == "denied"
    assert receipt["policy"]["engine"] == "cedar"
    assert receipt["policy"]["decision"] == "deny"

    # And the bundle in force is untouched: a refused replacement leaves
    # the previous one effective.
    assert bundle_entry()["spec"]["governs"] == Cedar.governed_kinds()
  end

  test "the same act under an authority that covers those Kinds is admitted" do
    wide = endorse(@bundle_kinds ++ Cedar.governed_kinds())

    assert {:ok, receipt} = supersede_bundle_citing(wide, Cedar.governed_kinds())
    assert receipt["outcome"] == "admitted"
    assert receipt["policy"]["engine"] == "cedar"
  end

  test "the fold's own boot-time bundle is admitted under its own Endorsement" do
    # The shipped path: the fold's role Endorsement covers every Kind the
    # fold admits, `governs` is a subset of it, and the derived check is
    # silent. If this ever fails the deployment cannot seed itself.
    assert {:ok, _} = admit_bundle(permissive_policy_source(), "seeded again")
  end

  describe "authority_kinds/1" do
    test "reads the cited link, not its parents" do
      resolved = [
        %{
          "index" => 0,
          "value" => "event:sha256:aa",
          "chain" => [
            %{"kinds" => ["gateway.r5e.io/v1alpha1/PolicyBundle"]},
            %{"kinds" => ["*"]}
          ]
        }
      ]

      assert Cedar.authority_kinds(resolved) == ["gateway.r5e.io/v1alpha1/PolicyBundle"]
    end

    test "a cited `*` grant is every Kind" do
      assert Cedar.authority_kinds([%{"chain" => [%{"kinds" => ["*"]}]}]) == :all
    end

    test "several cited entries union" do
      resolved = [
        %{"chain" => [%{"kinds" => ["b"]}]},
        %{"chain" => [%{"kinds" => ["a", "b"]}]}
      ]

      assert Cedar.authority_kinds(resolved) == ["a", "b"]
    end

    test "citing nothing grants nothing" do
      assert Cedar.authority_kinds([]) == []
      assert Cedar.authority_kinds(nil) == []
    end
  end

  describe "the refusal at authorize, by direct call" do
    test "a bundle with no governs list is refused rather than left unbounded" do
      request = %{
        group: "gateway.r5e.io",
        version: "v1alpha1",
        kind: "PolicyBundle",
        name: "active",
        spec: %{"engine" => "cedar"},
        resolved_authority: [%{"chain" => [%{"kinds" => ["*"]}]}]
      }

      assert {:deny, reason, meta} = Cedar.authorize(request)
      assert reason =~ "the candidate declares no governs list"
      assert meta["engine"] == "cedar"
    end

    test "an act citing no authority declares no jurisdiction" do
      request = %{
        group: "gateway.r5e.io",
        version: "v1alpha1",
        kind: "PolicyBundle",
        name: "active",
        spec: %{"engine" => "cedar", "governs" => Cedar.governed_kinds()},
        resolved_authority: []
      }

      assert {:deny, reason, _meta} = Cedar.authorize(request)
      assert reason =~ "the cited authority covers []"
    end
  end
end
