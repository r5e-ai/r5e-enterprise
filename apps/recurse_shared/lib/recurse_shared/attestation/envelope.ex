defmodule Recurse.Shared.Attestation.Envelope do
  @moduledoc """
  Composing struct for the Recurse-native attestation container per
  FR-021.

  The v1.0 attestation receipt is a Recurse-native container
  (`mediaType: application/vnd.recurse.attestation+json;version=1.0`)
  with strict separation between **signed-immutable** content and
  **outer-mutable** state metadata:

    * `signed_predicate` — `%SignedPredicate{}` — the in-toto v1.0
      predicate payload; signed once at emission, immutable forever.
    * `outer_container` — `%OuterContainer{}` — mutable proof-state
      metadata (`verification_level`, inclusion proofs, etc.).
    * `dsse_envelope` — the DSSE-signed envelope bytes (or a decoded
      map) wrapping the signed predicate per DSSE ITE-5 / FR-021.

  The split is the reason a receipt verifies once and stays valid
  forever while outer metadata keeps advancing as commits land.

  ## Why not Sigstore Bundle?

  Sigstore Bundle's `verificationMaterial.tlogEntries[]` assumes a public
  Rekor-style log; Recurse ledgers are private. The Recurse-native
  container preserves DSSE + in-toto semantics without the public-log
  coupling. See spec.md FR-021 for the full rationale. Future opt-in:
  customers wanting public attestability MAY publish receipts to
  Sigstore Rekor as a secondary target.
  """

  alias Recurse.Shared.Attestation.{OuterContainer, SignedPredicate}

  @type dsse_envelope :: map() | binary()

  @type t :: %__MODULE__{
          signed_predicate: SignedPredicate.t(),
          outer_container: OuterContainer.t(),
          dsse_envelope: dsse_envelope()
        }

  @enforce_keys [:signed_predicate, :outer_container, :dsse_envelope]
  defstruct [:signed_predicate, :outer_container, :dsse_envelope]

  @doc """
  Compose an envelope from its three parts.
  """
  @spec new(SignedPredicate.t(), OuterContainer.t(), dsse_envelope()) :: t()
  def new(%SignedPredicate{} = sp, %OuterContainer{} = oc, dsse)
      when is_map(dsse) or is_binary(dsse) do
    %__MODULE__{
      signed_predicate: sp,
      outer_container: oc,
      dsse_envelope: dsse
    }
  end
end
