defmodule Recurse.Providers.Impls.OciPolicyProvider.CosignBehaviour do
  @moduledoc """
  Behaviour for cosign verifiers — separated from the impl so tests
  can supply a fake verifier via the Provider config's
  `:cosign_verifier` override.
  """

  alias Recurse.Providers.Impls.OciPolicyProvider.FetcherBehaviour

  @doc """
  Verify a cosign signature over the supplied manifest bytes against
  the KMS-backed public key referenced by `kms_key_arn`. Returns `:ok`
  on success; `{:error, reason}` on signature mismatch, KMS access
  failure, unsupported key type, or unrecognised signature artifact
  format.

  `kms_key_arn` accepts either a full ARN
  (`arn:aws:kms:us-west-2:123456789012:key/...`) or an alias
  (`alias/r5e-cosign`).

  `sig_artifact` is the tuple returned by
  `Recurse.Providers.Impls.OciPolicyProvider.FetcherBehaviour.fetch_signature_artifact/2`
  — i.e. the .sig manifest doc + the layer descriptor + the layer
  blob bytes. The verifier sniffs `sig_artifact.layer["mediaType"]`
  to decide between cosign-2.x (simplesigning) and cosign-3.x
  (sigstore Bundle v0.3) paths.
  """
  @callback verify(
              manifest_bytes :: binary(),
              sig_artifact :: FetcherBehaviour.signature_artifact(),
              kms_key_arn :: String.t()
            ) :: :ok | {:error, term()}
end
