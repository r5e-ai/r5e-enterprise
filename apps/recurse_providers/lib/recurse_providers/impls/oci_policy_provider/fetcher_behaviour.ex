defmodule Recurse.Providers.Impls.OciPolicyProvider.FetcherBehaviour do
  @moduledoc """
  Behaviour for OCI bundle fetchers — separated from the impl so tests
  can supply a fake fetcher via the Provider config's `:http_client`
  override without monkey-patching.
  """

  @typedoc "Fetch context — supplied by OciPolicyProvider."
  @type ctx :: %{
          registry: String.t(),
          repository: String.t(),
          ref: String.t(),
          auth: Recurse.Providers.Impls.OciPolicyProvider.auth_config(),
          cosign_key_arn: String.t(),
          config: map()
        }

  @typedoc "Decoded OCI image manifest (per OCI spec v1)."
  @type manifest_doc :: map()

  @typedoc "Manifest digest as raw 32-byte SHA-256."
  @type manifest_digest :: <<_::256>>

  @typedoc "Raw manifest bytes (the JSON body that was hashed to produce the digest)."
  @type manifest_bytes :: binary()

  @typedoc "A pulled layer with its declared filename + bytes."
  @type layer :: %{filename: String.t(), bytes: binary(), media_type: String.t()}

  @typedoc """
  A signature artifact bundle:

    * `:manifest` — the parsed OCI manifest of the `.sig` artifact
      (carries `layers[0]` descriptor with mediaType + optional
      annotations like `dev.cosignproject.cosign/signature` for the
      cosign-2.x simplesigning shape).
    * `:layer` — the SINGLE layer descriptor from `manifest.layers[0]`,
      lifted out for ergonomic access (carries `digest` + `mediaType`
      + cosign-2.x `annotations`).
    * `:layer_blob_bytes` — the raw blob at `layer.digest`. The
      verifier inspects `layer.mediaType` to decide what to do with
      these bytes:
        - `application/vnd.dev.cosign.simplesigning.v1+json` → bytes
          ARE the simplesigning JSON payload; signature is in
          `layer.annotations[\"dev.cosignproject.cosign/signature\"]`.
        - `application/vnd.dev.sigstore.bundle.v0.3+json` → bytes
          ARE the sigstore Bundle v0.3 JSON (with `dsseEnvelope`).
  """
  @type signature_artifact :: %{
          manifest: manifest_doc(),
          layer: map(),
          layer_blob_bytes: binary()
        }

  @callback fetch_manifest(ctx) ::
              {:ok, manifest_doc, manifest_digest, manifest_bytes} | {:error, term()}

  @callback fetch_layers(ctx, manifest_doc) :: {:ok, [layer]} | {:error, term()}

  @callback fetch_signature_artifact(ctx, manifest_digest) ::
              {:ok, signature_artifact()} | {:error, term()}
end
