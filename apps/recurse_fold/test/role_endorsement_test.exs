defmodule Recurse.Fold.RoleEndorsementTest do
  @moduledoc """
  K4 (RC review 2026-09-05): **a revocation a restart reverses is a
  suspension.**

  Spec 011 §10 says role Endorsements are minted at boot only, and the
  fold's refusal message used to say "an operator re-endorses at the next
  boot". The reviewer showed that no operator did anything: the boot mint
  fired whenever the *effective* lookup came back empty, and a revoked
  Endorsement is exactly an empty lookup, so a `systemctl restart`, a pod
  eviction or an OOM kill restored the authority the operator had just
  withdrawn. The words were met and the meaning was not.

  The rule now: mint only when the chain has **never** carried an
  Endorsement for this (role, subject). Anything else — revoked, expired,
  a broken parent — is a refusal with a named reason that survives every
  restart, and `/readyz` carries it as `fold.role_standing` so the state
  is visible without reading the log.

  Its own file, and its own kernel: a revocation is not undone here, so a
  test that revokes must not share a chain with tests that go on to admit
  things.
  """
  use ExUnit.Case, async: false

  setup_all do
    Recurse.Fold.FreshKernel.boot()
  end

  import ExUnit.CaptureLog
  import Recurse.Fold.TestHelpers

  # The node key made the grant, so the node key withdraws it —
  # `sameActor` on `Revocation.revokes` is what makes a Revocation a
  # withdrawal rather than an opinion.
  defp revoke(ref) do
    target = %{
      "group" => "core.r5e.io",
      "version" => "v1",
      "kind" => "Revocation",
      "name" => nil
    }

    spec = %{"revokes" => %{"$ref" => ref}}

    {:ok, receipt} =
      R5e.Admission.admit(%{
        envelope: R5e.Request.sign(%{target: target, spec: spec, authority: []}, [:node]),
        group: "core.r5e.io",
        version: "v1",
        kind: "Revocation",
        name: nil,
        spec: spec
      })

    receipt
  end

  defp endorsements_for_role do
    for payload <- payloads(),
        payload["outcome"] == "admitted",
        payload["target"]["kind"] == "Endorsement",
        payload["spec"]["role"] == "fold",
        payload["spec"]["subject"] == Recurse.Fold.key_id(),
        do: payload
  end

  # One test, not three: ExUnit shuffles the tests inside a module, and
  # this is one arc through one chain — endorsed, revoked, restarted,
  # re-endorsed — where every step's meaning is what the step before it
  # left behind.
  test "a revoked role survives a restart, and only an operator's act restores it" do
    assert is_binary(Recurse.Fold.authority())
    assert Recurse.Fold.role_standing() == "effective"
    assert Recurse.Fold.status()["role_standing"] == "effective"
    assert length(endorsements_for_role()) == 1

    ref = Recurse.Fold.authority()
    revoke(ref)

    assert Recurse.Fold.authority() == nil

    # The act is **refused**, not re-authorised: nothing submitted,
    # nothing recorded, and the caller is told why in the return type.
    before = length(payloads())

    assert {:refused, reason} = admit_a_tool_call()

    assert reason =~ "fold authority not effective"
    assert reason =~ "revoked at"
    assert reason =~ "minted at boot only"
    assert reason =~ "an operator admits a new Endorsement under the node key"
    assert length(payloads()) == before, "a refused act must put nothing on the chain"

    assert {:refused, _} = Recurse.Fold.put_cas("bytes under revoked authority")

    # The standing is legible before the restart …
    assert Recurse.Fold.role_standing() == "role revoked; explicit re-endorsement required"

    # … and a restart does not change it. This is the whole finding: the
    # boot mint is keyed on presence in history, so it does not fire for
    # a role this chain has endorsed and revoked.
    log = capture_log(fn -> :ok = Recurse.Fold.FreshKernel.bounce() end)
    assert log =~ "recurse_fold has no effective authority and this boot did not mint one"

    assert Recurse.Fold.authority() == nil
    assert Recurse.Fold.role_standing() == "role revoked; explicit re-endorsement required"
    assert length(endorsements_for_role()) == 1, "boot must not have minted a replacement"
    assert {:refused, _} = admit_a_tool_call()

    # /readyz reads exactly this map (`Readyz.fold_status/0` merges it),
    # so the operator sees the standing and the walk's own reason.
    status = Recurse.Fold.status()
    assert status["authority_effective"] == false
    assert status["role_standing"] == "role revoked; explicit re-endorsement required"
    assert status["last_refusal"]["reason"] =~ "revoked at"

    # The remedy is an act: the node key admits a new Endorsement. That is
    # the only thing that restores the fold, and it is on the record beside
    # the Revocation that removed it.
    {:ok, receipt} =
      R5e.Bootstrap.endorse_role(Recurse.Fold.key().public, "fold",
        kinds: Recurse.Fold.kinds(),
        may_issue: false
      )

    assert Recurse.Fold.authority() == receipt["eventRef"]
    assert Recurse.Fold.role_standing() == "effective"
    assert length(endorsements_for_role()) == 2
    assert {:ok, _} = admit_a_tool_call()
  end

  defp admit_a_tool_call do
    Recurse.Fold.admit("gateway.r5e.io/v1alpha1/ToolCall", %{
      "tool" => "shell",
      "args" => %{"command" => "ls"},
      "index" => 0
    })
  end
end
