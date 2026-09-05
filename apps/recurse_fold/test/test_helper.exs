ExUnit.start()

defmodule Recurse.Fold.TestHelpers do
  @moduledoc false

  @group "gateway.r5e.io"
  @version "v1alpha1"

  def group, do: @group
  def version, do: @version

  @doc "The key every act in this suite is signed by: the fold's own."
  def fold_key_id, do: Recurse.Fold.key_id()

  @doc """
  The `actor` block a **synthetic** request carries.

  The kernel writes `{id, algorithm, publicKey}` on a real one (spec 011
  §1). A test that hands the engine a request directly never goes through
  the gate, so the block is written down here rather than derived — and it
  is written in the shape the gate would have produced, so a shape reading
  `@actor.id` reads the same thing either way.
  """
  def actor(id \\ "person:thomas") do
    key = key_for(id)

    %{
      "id" => id,
      "algorithm" => "ed25519",
      "publicKey" => Base.encode64(key.public)
    }
  end

  @doc """
  A deterministic keypair for a test actor id — a key *other than* the
  fold's, for the cases that need one.

  An ed25519 private key is 32 arbitrary bytes, so `sha256(id)` is one.
  Nothing here is secret; these keys exist only inside a test's own
  throwaway data directory.
  """
  def key_for(id) when is_binary(id) do
    private = :crypto.hash(:sha256, "recurse-fold-test-key:" <> id)
    {public, ^private} = :crypto.generate_key(:eddsa, :ed25519, private)
    %{public: public, private: private, algorithm: "ed25519"}
  end

  @doc "Admit through the fold's public surface — signed, under the fold's Endorsement."
  def admit(group, version, kind, name, spec) do
    Recurse.Fold.admit("#{group}/#{version}/#{kind}", spec, name: name)
  end

  @doc "Admit an instance of a gateway-group Kind."
  def admit_gateway(kind, name \\ nil, spec), do: admit(@group, @version, kind, name, spec)

  @doc """
  Admit as some **other** key, acting as itself — the "another actor" case,
  which now means another key rather than another string.
  """
  def admit_as(id, group, version, kind, name, spec) do
    target = %{"group" => group, "version" => version, "kind" => kind, "name" => name}
    key = key_for(id)
    envelope = R5e.Request.sign(%{target: target, spec: spec, authority: []}, [key])

    R5e.Admission.admit(%{
      envelope: envelope,
      group: group,
      version: version,
      kind: kind,
      name: name,
      spec: spec
    })
  end

  @doc "Put raw bytes on the record the way `PUT /cas` does, returning the address."
  def put_object(bytes, media_type \\ "text/plain") do
    {:ok, _receipt, address} = Recurse.Fold.put_cas(bytes, media_type: media_type)
    address
  end

  @doc """
  Admit a `PolicyBundle` named `active` carrying the given Cedar source.
  The text is detached first, as FR-007 requires: a bundle cites its source
  by address and never inlines it.

  `governs` is the two workload Kinds, as the fold's own seed admits it.
  It is not optional: K3 (RC review 2026-09-05) refuses a bundle that
  declares no jurisdiction at `authorize`, before the schema gets to say
  the same thing, because a bundle with no `governs` is a policy nothing
  bounds.
  """
  def admit_bundle(source, description \\ "test bundle") do
    address = put_object(source, "text/plain")

    admit_gateway("PolicyBundle", "active", %{
      "engine" => "cedar",
      "governs" => Recurse.Fold.Policy.Cedar.governed_kinds(),
      "sourceRef" => %{"$ref" => address},
      "description" => description
    })
  end

  @doc "Admit a ToolCall."
  def admit_tool_call(spec, name \\ nil), do: admit_gateway("ToolCall", name, spec)

  @doc "The store entry for one admitted resource, or nil."
  def entry(group, version, kind, name) do
    case R5e.ResourceStore.get(group, version, kind, name) do
      {:ok, entry, _lineage} -> entry
      {:error, :not_found} -> nil
    end
  end

  def bundle_entry do
    {g, v, k, n} = Recurse.Fold.Policy.Cedar.bundle_coordinates()
    entry(g, v, k, n)
  end

  def shape_entry(kind) do
    {g, v, k} = Recurse.Fold.Policy.Cedar.shape_coordinates()
    entry(g, v, k, Recurse.Fold.Policy.Cedar.shape_name(kind))
  end

  @doc "Every recorded event payload, decoded, with its event envelope attached."
  def payloads do
    for event <- R5e.Log.events(),
        {:ok, bytes} <- [R5e.CAS.get(event["payload"])],
        {:ok, payload} <- [Jason.decode(bytes)] do
      Map.put(payload, "_event", event)
    end
  end

  @doc "Granted/denied counts over the whole chain as it stands right now."
  def log_counts do
    all = payloads()

    %{
      granted: Enum.count(all, &(&1["outcome"] == "admitted")),
      denied: Enum.count(all, &(&1["outcome"] == "denied"))
    }
  end

  def payload_for(receipt), do: Enum.find(payloads(), &(&1["_event"]["hash"] == receipt["event"]))

  @doc "The policy evaluation record a receipt cites, decoded."
  def evaluation_of(receipt) do
    {:ok, record} = Recurse.Fold.Policy.EvaluationRecord.fetch(receipt["policy"]["evaluation"])
    record
  end

  def deny_policy_source, do: File.read!(Recurse.Fold.Application.default_policy_path())
  def permissive_policy_source, do: File.read!(Recurse.Fold.Application.permissive_policy_path())
end
