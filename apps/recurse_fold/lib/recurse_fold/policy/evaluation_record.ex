defmodule Recurse.Fold.Policy.EvaluationRecord do
  @moduledoc """
  The `PolicyEvaluationRecord` of schema-lite v2 §8: the exact question the
  engine was asked, written as a **kernel-derived object** inside the
  admission that asked it.

      {format: "r5e.policy-evaluation/1",
       engine, engineBuild, kindDefinition, bundle, source, shape,
       requestBytes, entitiesBytes, resolution, decision, matched,
       resolvedAuthority}

  Closed schema — those thirteen keys, no others. The bytes are canonical
  JSON, so the address is a function of the content and two identical
  evaluations produce one object.

  The thirteenth is spec 011 §11's (KS-7): **`resolvedAuthority` whole** —
  every authority the actor cited, with its chain of links to the root, as
  the kernel derived it. It is here rather than left to a replayer to look
  up because the record's whole promise is that the bytes in it are the
  question the engine was asked; the actor's standing is part of that
  question the moment a policy can read `@actor.authorityRoots`. It carries
  `[]` when the actor acted as itself, which is a fact and not an absence.

  ## Why it is derived rather than admitted

  It is produced *during* `authorize` of another admission and cannot be
  its own admission: an admission of it would need a policy decision, which
  is the thing it is a record of. §5 names that class and the kernel gives
  it two doors — `R5e.CAS.put/1` writes the bytes, `R5e.RefIndex.register_derived/2`
  puts it in the class — and this module is the first member.

  ## What it makes possible, and what it does not

  A third party with the export can decode `requestBytes` and
  `entitiesBytes`, fetch the policy text at `source`, and run the engine at
  `engineBuild` over exactly the bytes this one ran over. That is *replay*.
  It is not proof the decision was right, nor that the engine at that
  address is the engine that ran: `engineBuild` is a measurement this
  deployment made of its own artifacts, and an operator who lies about it
  produces a record that replays under the engine they named.

  The verifier does not replay — it checks §8's equality invariant, that
  the seven shared keys agree with the receipt's policy block byte for
  byte. `test/policy/evaluation_record_test.exs` does replay, in-process,
  which is the difference between "the record is consistent" and "the
  record reproduces".
  """

  @format "r5e.policy-evaluation/1"

  @keys ~w(format engine engineBuild kindDefinition bundle source shape
           requestBytes entitiesBytes resolution decision matched
           resolvedAuthority)

  @doc "The thirteen keys §8 (as amended by spec 011 §11) closes the schema on."
  @spec keys() :: [String.t()]
  def keys, do: @keys

  @doc """
  Build the record, write its canonical bytes to the CAS, and register it as
  a kernel-derived object. Returns the `bytes:sha256:…` address a receipt
  cites as `evaluation`.
  """
  @spec write(map()) :: String.t()
  def write(fields) do
    bytes = fields |> build() |> R5e.Canonical.encode()
    address = "bytes:" <> R5e.CAS.put(bytes)
    :ok = R5e.RefIndex.register_derived(address)
    address
  end

  @doc "The record as a map, without writing anything. Public for tests."
  @spec build(map()) :: map()
  def build(fields) do
    %{
      "format" => @format,
      "engine" => fields.engine,
      "engineBuild" => fields.engine_build,
      "kindDefinition" => fields.kind_definition,
      "bundle" => fields.bundle,
      "source" => fields.source,
      "shape" => fields.shape,
      "requestBytes" => Base.encode64(fields.request_bytes),
      "entitiesBytes" => Base.encode64(fields.entities_bytes),
      # §8: sorted by path, and `matched` sorted too, so the record is a
      # function of what happened and not of map iteration order.
      "resolution" => Enum.sort_by(fields.resolution, & &1["path"]),
      "decision" => fields.decision,
      "matched" => Enum.sort(fields.matched),
      # §11: verbatim, in the order the request named its authority — the
      # kernel already fixed that order and re-sorting it here would make
      # the record disagree with the receipt beside it.
      "resolvedAuthority" => Map.get(fields, :resolved_authority, [])
    }
  end

  @doc """
  Read a record back from this deployment's CAS by the address a receipt
  cites. `{:error, reason}` when the object is gone (an erased evaluation
  record is §10's "input erased", not a false pass) or is not one.
  """
  @spec fetch(String.t()) :: {:ok, map()} | {:error, String.t()}
  def fetch(address) when is_binary(address) do
    with {:ok, bytes} <- object(address),
         {:ok, %{"format" => @format} = record} <- decode(bytes) do
      {:ok, record}
    end
  end

  def fetch(other), do: {:error, "#{inspect(other)} is not an address"}

  defp object(address) do
    case R5e.CAS.get(address) do
      {:ok, bytes} ->
        {:ok, bytes}

      {:error, _} ->
        {:error, "no object at #{address} — the evaluation input may have been erased"}
    end
  end

  defp decode(bytes) do
    case Jason.decode(bytes) do
      {:ok, %{"format" => @format} = record} -> {:ok, record}
      {:ok, other} -> {:error, "not a #{@format} record: #{inspect(Map.get(other, "format"))}"}
      {:error, _} -> {:error, "the object is not valid JSON"}
    end
  end
end
