defmodule Recurse.Providers.Impls.OciPolicyProvider.Fetcher do
  @moduledoc """
  OCI Distribution Spec HTTP client for Cedar bundles.

  Implements the subset of https://github.com/opencontainers/distribution-spec
  needed to:

    1. Resolve `<registry>/<repository>:<ref>` → manifest digest + bytes
    2. Pull each declared layer blob, verifying the registry-returned bytes
       hash to the declared digest (defense-in-depth — cosign verifies the
       manifest, manifest declares layer digests, this layer covers
       registry-side bit-flips before cosign sees them)
    3. Pull the cosign signature attached at the sibling tag
       `sha256-<hex>.sig` (per cosign convention)

  Per-registry auth handled by `auth_config()` shapes on the parent
  `OciPolicyProvider`. ECR uses pod creds (IRSA / Pod Identity, via
  ExAws's default credential resolver chain) to call the ECR
  `GetAuthorizationToken` API; the returned base64(`AWS:<password>`)
  string is cached in `:persistent_term` with a 1-hour TTL. Harbor /
  GitLab / generic registries use bearer or basic.

  ## ECR authentication mechanics

  Originally this code shelled out to `aws ecr get-authorization-token`,
  but that requires the `aws` CLI binary in the runtime image
  (`debian:bookworm-slim` in our case — no awscli installed). The
  shell-out was retired in favor of an inline ExAws.Operation.JSON
  request against the ECR API: same wire shape, but credential
  resolution goes through ExAws's chain
  (`{:system, AWS_*} -> :pod_identity -> :instance_role`) so the
  pod-identity-agent-injected
  `AWS_CONTAINER_CREDENTIALS_FULL_URI` /
  `AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE` environment is picked up
  automatically. No new dep needed (`ExAws.Operation.JSON` is in the
  base `:ex_aws` package) and no ~150MB awscli runtime install.

  The CLI returned a base64-encoded `AWS:<password>` string which
  decoded to the bearer token the registry expects. The ECR JSON API
  returns the same bytes under
  `authorizationData[0].authorizationToken`. We cache that bearer
  token in `:persistent_term` keyed by `{:ecr_token, region}` for one
  hour (the upstream token's actual TTL is twelve hours; one hour is a
  conservative refresh interval that still amortizes the API call
  across many bundle pulls).

  On a `401 Unauthorized` from the registry we invalidate the cache and
  retry once — this catches the edge where the cached token expired
  early or the IAM role rotated.

  ## Cosign signature mechanics

  Cosign attaches the signature as a *separate OCI artifact* tagged
  `sha256-<manifest-digest-hex>.sig`. That artifact is itself a manifest
  with a single layer; the layer blob contains the cosign signature
  payload (raw bytes that the `Cosign` verifier feeds into
  `:crypto.verify/4` against the KMS-backed public key).

  ## Test injection

  Two seams exist for tests:

    * `:aws_ecr_cmd` in the `ctx.config` map — overrides the default
      ECR-token-fetch path so tests don't reach AWS. The legacy
      shell-out signature (function takes a list of `aws`-CLI args) is
      preserved for backwards-compat with existing test fixtures; the
      args list is now ignored at the call site (the production runner
      doesn't shell out anymore) but the function's `{:ok, b64_token}`
      / `{:error, _}` return shape still drives caching + retry.
    * `:registry_base_url` in the `ctx.config` map — overrides the
      `https://<registry>` prefix so tests can point at a Plug.Cowboy
      mock running on `http://127.0.0.1:<random-port>`. (Production code
      omits this; the registry hostname is taken from the OCI
      `<registry>/<repo>` ref.)
  """

  @behaviour Recurse.Providers.Impls.OciPolicyProvider.FetcherBehaviour

  alias Recurse.Providers.Impls.OciPolicyProvider.FetcherBehaviour

  require Logger

  @oci_manifest_media_type "application/vnd.oci.image.manifest.v1+json"

  # ECR tokens are valid for 12 hours; we refresh once an hour to keep
  # cache misses bounded under bundle-pull pressure.
  @ecr_token_cache_ttl_ms :timer.hours(1)

  # Default per-request HTTP timeout. Callers can override via
  # `:fetch_timeout_ms` in the Provider config.
  @default_timeout_ms 30_000

  @impl true
  @spec fetch_manifest(FetcherBehaviour.ctx()) ::
          {:ok, FetcherBehaviour.manifest_doc(), FetcherBehaviour.manifest_digest(), binary()}
          | {:error, term()}
  def fetch_manifest(ctx) do
    url = manifest_url(ctx, ctx.ref)
    do_fetch_manifest(ctx, url)
  end

  @impl true
  @spec fetch_layers(FetcherBehaviour.ctx(), FetcherBehaviour.manifest_doc()) ::
          {:ok, [FetcherBehaviour.layer()]} | {:error, term()}
  def fetch_layers(ctx, %{"layers" => layers}) when is_list(layers) do
    layers
    |> Enum.reduce_while({:ok, []}, fn layer, {:ok, acc} ->
      case fetch_layer(ctx, layer) do
        {:ok, fetched} -> {:cont, {:ok, [fetched | acc]}}
        {:error, _} = err -> {:halt, err}
      end
    end)
    |> case do
      {:ok, fetched} -> {:ok, Enum.reverse(fetched)}
      err -> err
    end
  end

  def fetch_layers(_ctx, manifest), do: {:error, {:malformed_manifest, manifest}}

  @impl true
  @spec fetch_signature_artifact(
          FetcherBehaviour.ctx(),
          FetcherBehaviour.manifest_digest()
        ) :: {:ok, FetcherBehaviour.signature_artifact()} | {:error, term()}
  def fetch_signature_artifact(ctx, manifest_digest)
      when byte_size(manifest_digest) == 32 do
    sig_tag = "sha256-" <> Base.encode16(manifest_digest, case: :lower) <> ".sig"
    url = manifest_url(ctx, sig_tag)

    # Fetches BOTH halves of the cosign signature artifact:
    #
    #   1. The .sig manifest itself — carries the layer descriptor's
    #      mediaType (the cosign-2.x simplesigning vs cosign-3.x
    #      sigstore-bundle-v0.3 discriminator) and, in the simplesigning
    #      case, the `dev.cosignproject.cosign/signature` annotation.
    #   2. The layer blob bytes at `layers[0].digest` — for cosign 2.x
    #      this is the simplesigning JSON payload; for cosign 3.x
    #      sigstore Bundle v0.3 this is the bundle JSON itself
    #      (with `dsseEnvelope` etc.).
    #
    # Returning both is what lets the Cosign verifier sniff and
    # dispatch without a second round-trip.
    with {:ok, sig_manifest, _digest, _bytes} <- do_fetch_manifest(ctx, url),
         {:ok, layer} <- pluck_signature_layer(sig_manifest),
         {:ok, blob_bytes} <- fetch_blob_bytes(ctx, layer["digest"]) do
      {:ok, %{manifest: sig_manifest, layer: layer, layer_blob_bytes: blob_bytes}}
    end
  end

  def fetch_signature_artifact(_ctx, digest) do
    {:error, {:invalid_manifest_digest, byte_size: byte_size(digest)}}
  end

  # ---------------------------------------------------------------------------
  # Manifest fetch — shared between primary fetch + cosign signature fetch
  # ---------------------------------------------------------------------------

  defp do_fetch_manifest(ctx, url) do
    headers = [{"accept", @oci_manifest_media_type}]

    case request_with_auth_retry(ctx, :get, url, headers) do
      {:ok, %{status: 200, body: bytes}} when is_binary(bytes) ->
        with {:ok, doc} <- decode_manifest_json(bytes) do
          digest = :crypto.hash(:sha256, bytes)
          {:ok, doc, digest, bytes}
        end

      {:ok, %{status: 404}} ->
        {:error, {:manifest_not_found, url}}

      {:ok, %{status: status, body: body}} ->
        {:error, {:manifest_fetch_failed, status, summarize_body(body)}}

      {:error, reason} ->
        {:error, {:manifest_fetch_transport, reason}}
    end
  end

  defp decode_manifest_json(bytes) do
    case JSON.decode(bytes) do
      {:ok, doc} when is_map(doc) -> {:ok, doc}
      {:ok, other} -> {:error, {:manifest_not_object, other}}
      {:error, reason} -> {:error, {:manifest_json_invalid, reason}}
    end
  end

  defp pluck_signature_layer(%{"layers" => [%{"digest" => _} = layer | _]}), do: {:ok, layer}
  defp pluck_signature_layer(other), do: {:error, {:cosign_manifest_malformed, other}}

  # ---------------------------------------------------------------------------
  # Layer fetch — declared filename + digest verification
  # ---------------------------------------------------------------------------

  defp fetch_layer(ctx, layer) do
    with {:ok, digest} <- Map.fetch(layer, "digest"),
         {:ok, media_type} <- Map.fetch(layer, "mediaType"),
         {:ok, filename} <- layer_filename(layer),
         {:ok, bytes} <- fetch_blob_bytes(ctx, digest),
         :ok <- verify_blob_digest(bytes, digest) do
      {:ok, %{filename: filename, bytes: bytes, media_type: media_type}}
    else
      :error -> {:error, {:layer_missing_field, layer}}
      {:error, _} = err -> err
    end
  end

  defp layer_filename(%{"annotations" => %{"org.opencontainers.image.title" => title}})
       when is_binary(title) and title != "" do
    {:ok, title}
  end

  defp layer_filename(layer), do: {:error, {:layer_missing_filename_annotation, layer}}

  defp fetch_blob_bytes(ctx, "sha256:" <> _ = digest) do
    url = blob_url(ctx, digest)

    case request_with_auth_retry(ctx, :get, url, []) do
      {:ok, %{status: 200, body: bytes}} when is_binary(bytes) ->
        {:ok, bytes}

      {:ok, %{status: 404}} ->
        {:error, {:blob_not_found, digest}}

      {:ok, %{status: status, body: body}} ->
        {:error, {:blob_fetch_failed, status, summarize_body(body)}}

      {:error, reason} ->
        {:error, {:blob_fetch_transport, reason}}
    end
  end

  defp fetch_blob_bytes(_ctx, digest), do: {:error, {:invalid_blob_digest, digest}}

  defp verify_blob_digest(bytes, "sha256:" <> hex) do
    actual = Base.encode16(:crypto.hash(:sha256, bytes), case: :lower)
    expected = String.downcase(hex)

    if actual == expected do
      :ok
    else
      {:error, {:blob_digest_mismatch, expected: expected, actual: actual}}
    end
  end

  # ---------------------------------------------------------------------------
  # URL construction
  # ---------------------------------------------------------------------------

  defp manifest_url(ctx, ref) do
    "#{registry_base(ctx)}/v2/#{ctx.repository}/manifests/#{ref}"
  end

  defp blob_url(ctx, digest) do
    "#{registry_base(ctx)}/v2/#{ctx.repository}/blobs/#{digest}"
  end

  defp registry_base(%{config: config, registry: registry}) do
    case Map.get(config, :registry_base_url) do
      nil -> "https://" <> registry
      override when is_binary(override) -> String.trim_trailing(override, "/")
    end
  end

  # ---------------------------------------------------------------------------
  # Auth + retry — single 401-triggered token refresh for ECR
  # ---------------------------------------------------------------------------

  defp request_with_auth_retry(ctx, method, url, headers) do
    with {:ok, hdrs} <- auth_headers(ctx, refresh: false) do
      case do_request(ctx, method, url, headers ++ hdrs) do
        {:ok, %{status: 401}} = original ->
          retry_with_fresh_token(ctx, method, url, headers, original)

        other ->
          other
      end
    end
  end

  defp retry_with_fresh_token(%{auth: {:ecr_irsa, _}} = ctx, method, url, headers, _original) do
    with {:ok, fresh_headers} <- auth_headers(ctx, refresh: true) do
      do_request(ctx, method, url, headers ++ fresh_headers)
    end
  end

  defp retry_with_fresh_token(_ctx, _method, _url, _headers, original) do
    # Non-ECR auths (basic, bearer, none) cannot be refreshed in-band;
    # surface the original 401 response so the caller can route it to
    # the appropriate `*_fetch_failed` error tuple.
    original
  end

  defp do_request(ctx, method, url, headers) do
    timeout = Map.get(ctx.config, :fetch_timeout_ms, @default_timeout_ms)

    Req.request(
      method: method,
      url: url,
      headers: headers,
      receive_timeout: timeout,
      retry: false,
      decode_body: false
    )
  end

  defp auth_headers(%{auth: :none}, _opts), do: {:ok, []}

  defp auth_headers(%{auth: {:bearer, token}}, _opts) do
    {:ok, [{"authorization", "Bearer " <> token}]}
  end

  defp auth_headers(%{auth: {:basic_auth, user, pass}}, _opts) do
    encoded = Base.encode64(user <> ":" <> pass)
    {:ok, [{"authorization", "Basic " <> encoded}]}
  end

  defp auth_headers(%{auth: {:ecr_irsa, region}} = ctx, opts) do
    case ecr_bearer_token(ctx, region, Keyword.get(opts, :refresh, false)) do
      {:ok, token} -> {:ok, [{"authorization", "Basic " <> token}]}
      {:error, _} = err -> err
    end
  end

  defp auth_headers(%{auth: other}, _opts), do: {:error, {:unsupported_auth, other}}

  # ---------------------------------------------------------------------------
  # ECR token cache — :persistent_term keyed by {:ecr_token, region}
  # ---------------------------------------------------------------------------

  defp ecr_bearer_token(ctx, region, refresh?) do
    cache_key = {__MODULE__, :ecr_token, region}

    if refresh? do
      :persistent_term.erase(cache_key)
      fetch_and_cache_ecr_token(ctx, region, cache_key)
    else
      case lookup_cached_token(cache_key) do
        {:ok, token} -> {:ok, token}
        :miss -> fetch_and_cache_ecr_token(ctx, region, cache_key)
      end
    end
  end

  defp lookup_cached_token(cache_key) do
    case :persistent_term.get(cache_key, :miss) do
      :miss ->
        :miss

      {token, expires_at_ms} ->
        if System.monotonic_time(:millisecond) < expires_at_ms do
          {:ok, token}
        else
          :persistent_term.erase(cache_key)
          :miss
        end
    end
  end

  defp fetch_and_cache_ecr_token(ctx, region, cache_key) do
    with {:ok, raw_b64} <- run_ecr_get_authorization_token(ctx, region),
         :ok <- validate_ecr_token_shape(raw_b64) do
      expires_at_ms = System.monotonic_time(:millisecond) + @ecr_token_cache_ttl_ms
      :persistent_term.put(cache_key, {raw_b64, expires_at_ms})
      Logger.debug(fn -> "OciPolicyProvider.Fetcher: cached ECR token for #{region}" end)
      {:ok, raw_b64}
    else
      {:error, {:ecr_token_decode_failed, _}} = err -> err
      {:error, reason} -> {:error, {:ecr_token_fetch_failed, reason}}
    end
  end

  defp run_ecr_get_authorization_token(%{config: config}, region) do
    # Test seam — `:aws_ecr_cmd` is preserved for backwards compat with
    # existing fixtures (function takes a list of `aws`-CLI args; args
    # are ignored at the call site since production no longer shells
    # out, but the `{:ok, b64_token}` / `{:error, _}` return contract
    # is unchanged). Production path goes through ExAws.
    runner =
      Map.get(config, :aws_ecr_cmd, fn _args -> ecr_get_authorization_token_via_ex_aws(region) end)

    case runner.([
           "ecr",
           "get-authorization-token",
           "--region",
           region,
           "--query",
           "authorizationData[0].authorizationToken",
           "--output",
           "text"
         ]) do
      {:ok, token} when is_binary(token) and token != "" -> {:ok, token}
      {:ok, ""} -> {:error, :empty_authorization_token}
      {:error, _} = err -> err
      other -> {:error, {:unexpected_aws_cmd_return, other}}
    end
  end

  # Production runner — calls ECR's `GetAuthorizationToken` API via
  # ExAws.Operation.JSON. Credential resolution goes through ExAws's
  # default chain (`{:system, AWS_*} -> :pod_identity -> :instance_role`),
  # so EKS-Pod-Identity-injected creds are picked up without explicit
  # config.
  #
  # ECR's wire protocol: AWS JSON 1.1, single endpoint per region:
  #   POST https://api.ecr.<region>.amazonaws.com/
  #   X-Amz-Target: AmazonEC2ContainerRegistry_V20150921.GetAuthorizationToken
  #   Content-Type: application/x-amz-json-1.1
  #   Body: {}
  #
  # Response shape (relevant fields):
  #   {"authorizationData": [{"authorizationToken": "<base64-AWS:pwd>",
  #                            "expiresAt": ..., "proxyEndpoint": ...}]}
  defp ecr_get_authorization_token_via_ex_aws(region) do
    op =
      ExAws.Operation.JSON.new(
        :ecr,
        %{
          data: %{},
          headers: [
            {"x-amz-target", "AmazonEC2ContainerRegistry_V20150921.GetAuthorizationToken"},
            {"content-type", "application/x-amz-json-1.1"}
          ]
        }
      )

    case ExAws.request(op, region: region) do
      {:ok, %{"authorizationData" => [%{"authorizationToken" => token} | _]}}
      when is_binary(token) ->
        {:ok, token}

      {:ok, other} ->
        {:error, {:ecr_unexpected_response_shape, other}}

      {:error, reason} ->
        {:error, {:ecr_request_failed, reason}}
    end
  end

  # The token AWS returns is base64(`AWS:<password>`); registries accept
  # the raw base64 string as the Basic auth credential, but we round-trip
  # decode it once to validate format before caching.
  defp validate_ecr_token_shape(b64) do
    case Base.decode64(b64) do
      {:ok, "AWS:" <> _} -> :ok
      {:ok, _other} -> {:error, {:ecr_token_decode_failed, :missing_aws_prefix}}
      :error -> {:error, {:ecr_token_decode_failed, :base64_decode_failed}}
    end
  end

  # ---------------------------------------------------------------------------
  # Misc
  # ---------------------------------------------------------------------------

  # Truncate registry error bodies for logging — registries can return
  # multi-KB JSON error envelopes; we want the shape, not the whole
  # thing.
  defp summarize_body(body) when is_binary(body) do
    case byte_size(body) do
      n when n <= 256 -> body
      _ -> binary_part(body, 0, 256) <> "...(truncated)"
    end
  end

  defp summarize_body(body), do: inspect(body)
end
