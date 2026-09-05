defmodule Recurse.Providers.Impls.AwsKmsSecretsProvider do
  @moduledoc """
  `Recurse.Providers.SecretsProvider` implementation backed by AWS KMS
  (for document-signing key release) + AWS Secrets Manager (for arbitrary
  refs like `database_url`, `openai_api_key`).

  ## Status

  F002 Phase-3 Wave 3C (T036 + T037) — sign hot-path + public-key cache
  shipped. RFC 8693 downstream-token callbacks (`store_user_token/4`,
  `exchange_for_downstream_token/4`) remain Phase-2-deferred per spec
  (they compose with a `PrincipalProvider.supports_rfc8693?/1` advertiser
  that F002 does not ship). The rotation watcher (`LoopServer` polling
  `kms:DescribeKey`) lands in T074 / Wave 3G.

  ## Contracts

    * Impl contract — `specs/002-standalone-gateway-vertical-slice/contracts/provider_impls.md`
      (§ `AwsKmsSecretsProvider`).
    * Behaviour — `Recurse.Providers.SecretsProvider` (F001).

  ## Hot-path design (research D1)

    * `sign/3` is a caller-process call into `ExAws.KMS.sign/4` over the
      dedicated `:kms_pool` Finch pool (HTTP/2). NO GenServer gating —
      serialized signing would be a throughput cliff at 50 QPS target.
    * ex_aws's built-in full-jitter exponential backoff handles FR-034
      (3 attempts in a 2s budget). Retry config is carried in the
      per-call config overrides so global `ex_aws` config is untouched.
    * Algorithm `ECDSA_SHA_256` per research D4 — ECC is consistently
      ~2× faster than RSA-PSS in KMS (~40ms vs ~80ms p50) and its 64-byte
      raw-form (72-byte DER) signature is cheaper to ship + verify.
    * KMS PRIVATE material never crosses the provider boundary. The
      `sign/3` call keeps private key in KMS; we only ever cache the
      PUBLIC key.

  ## Public-key cache (research D1)

    * `:persistent_term` keyed by `{key_arn, key_version}` — cross-process
      read-without-copy on the BEAM, chosen over ETS because the cache is
      write-once-read-often (rotation is every ~90 days; reads happen
      every attestation-emit in the Audit Broker path).
    * Warmed at Gateway boot by `init/1` via a one-shot `kms:GetPublicKey`
      call. Boot fail-fast: if the key isn't fetchable at startup, the
      provider refuses to initialize — a Gateway without a verifiable
      signing key has no business serving receipts.
    * Rotation detection is T074 (Wave 3G). For now, `public_key/2`
      miss-path will fetch + cache, so a pre-T074 rotation still self-heals
      on first receipt verification.

  ## Configuration shape (per contract)

  ```
  secrets_provider:
    kind: aws_kms
    key_arn: arn:aws:kms:us-east-1:123456789012:key/abcd-...
    algorithm: ECDSA_SHA_256            # research D4 (ES256)
    region: us-east-1
    finch_pool: :kms_pool                # must match Gateway supervision tree
  ```
  """

  @behaviour Recurse.Providers.SecretsProvider

  alias Recurse.Providers.Impls.AwsKmsSecretsProvider.FinchHttpClient

  @typedoc """
  Opaque state.

    * `:config` — normalized config map.
    * `:key_arn` — resolved signing-key ARN (promoted out of config for fast
      access on the hot path).
    * `:algorithm` — KMS signing algorithm string (e.g. `"ECDSA_SHA_256"`).
    * `:finch_pool` — pool atom (defaults to `:kms_pool`).
    * `:region` — AWS region string.
    * `:key_version` — monotonic counter advanced on rotation; seeded at 1.
    * `:http_client` — `ExAws.Request.HttpClient` implementation. Defaults
      to `FinchHttpClient`; tests swap in a Mox-generated mock so KMS calls
      never leave the BEAM.
    * `:access_key_id` / `:secret_access_key` — optional static credentials
      carried through into the ExAws config overrides. In production these
      come from the AWS instance-metadata service; tests pass literal values
      so `ExAws.Config.new/2` doesn't touch the AuthCache ETS table.
  """
  @type state :: %{
          required(:config) => map(),
          required(:key_arn) => String.t(),
          required(:algorithm) => String.t(),
          required(:finch_pool) => atom(),
          required(:region) => String.t(),
          required(:key_version) => non_neg_integer(),
          required(:http_client) => module(),
          optional(:access_key_id) => String.t(),
          optional(:secret_access_key) => String.t()
        }

  # Per FR-034 — 3 attempts in a 2s budget. Base 100ms / cap 800ms gives a
  # worst-case schedule of 100ms -> 200ms -> [no retry], with jitter.
  @retry_config [
    max_attempts: 3,
    base_backoff_in_ms: 100,
    max_backoff_in_ms: 800
  ]

  @default_finch_pool :kms_pool
  # Tight per-call HTTP receive timeout — three of these plus backoff fit
  # inside the 2s FR-034 budget.
  @http_receive_timeout_ms 5_000

  # --- init / lifecycle ----------------------------------------------------

  @doc """
  Validate config, seed state, and warm the public-key cache via a
  one-shot `kms:GetPublicKey` against the configured key ARN.

  Fail-fast on cache-warm failure: a Gateway that can't fetch its own
  signing-key public half cannot produce verifiable receipts, so refusing
  to boot is safer than degraded-startup.
  """
  @impl true
  @spec init(Recurse.Providers.SecretsProvider.config()) :: {:ok, state()} | {:error, term()}
  def init(config) when is_map(config) do
    with {:ok, state} <- build_state(config),
         {:ok, state} <- warm_public_key_cache(state) do
      {:ok, state}
    end
  end

  @doc """
  Idempotent warm-up of the `:persistent_term` public-key cache for the
  configured signing key. Exposed for tests + for T074 rotation-watcher
  reuse.
  """
  @spec warm_public_key_cache(state()) :: {:ok, state()} | {:error, term()}
  def warm_public_key_cache(state) do
    handle = %{
      key_id: state.key_arn,
      key_version: state.key_version,
      algorithm: atomize_alg(state.algorithm)
    }

    case public_key(state, handle) do
      {:ok, _pem} -> {:ok, state}
      {:error, reason} -> {:error, {:public_key_warmup_failed, reason}}
    end
  end

  @impl true
  @spec active_signing_key(state()) ::
          {:ok, Recurse.Providers.SecretsProvider.signing_key_handle()} | {:error, term()}
  def active_signing_key(state) do
    {:ok,
     %{
       key_id: state.key_arn,
       key_version: state.key_version,
       algorithm: atomize_alg(state.algorithm)
     }}
  end

  # --- sign (T036) ---------------------------------------------------------

  @doc """
  Sign `payload` bytes with the KMS-backed key named by `signing_key_handle`.

  * Input `payload` is raw bytes (the DSSE PAE output from T048 once it lands).
  * Output is ECDSA DER signature bytes (~70–72 for `ECDSA_SHA_256`).

  Hot-path: runs in the caller process; ex_aws handles the 3-attempt
  full-jitter exponential backoff budget (FR-034).
  """
  @impl true
  @spec sign(
          state(),
          Recurse.Providers.SecretsProvider.signing_key_handle(),
          payload :: binary()
        ) :: {:ok, signature :: binary()} | {:error, term()}
  def sign(state, signing_key_handle, payload)
      when is_map(signing_key_handle) and is_binary(payload) do
    key_id = Map.fetch!(signing_key_handle, :key_id)
    algorithm = signing_algorithm_string(signing_key_handle, state)

    # AWS KMS Sign wants the `Message` field as a base64-STRING on the JSON
    # wire. `ex_aws_kms` does NOT do the encoding for us — it ships the
    # string verbatim. Raw-byte payloads would explode `Jason.encode!/2`
    # on any non-UTF8 byte, so we encode here. The `message_type: "RAW"`
    # hint tells KMS to hash the decoded bytes itself (vs treating them
    # as a pre-computed digest).
    message_b64 = Base.encode64(payload)

    message_b64
    |> ExAws.KMS.sign(key_id, algorithm, message_type: "RAW")
    |> ExAws.request(ex_aws_config_overrides(state))
    |> handle_sign_response()
  end

  # --- public_key (T037) ---------------------------------------------------

  @doc """
  Returns the PEM-encoded public half of `signing_key_handle`.

  First call for a given `{key_arn, key_version}` hits KMS via
  `kms:GetPublicKey`; subsequent calls are served from `:persistent_term`
  in O(1) without copying. The cache key includes `key_version` so a
  rotation (once T074 lands) produces a cache miss → fresh fetch.
  """
  @impl true
  @spec public_key(state(), Recurse.Providers.SecretsProvider.signing_key_handle()) ::
          {:ok, public_key_pem :: String.t()} | {:error, term()}
  def public_key(state, signing_key_handle) when is_map(signing_key_handle) do
    key_id = Map.fetch!(signing_key_handle, :key_id)
    key_version = Map.get(signing_key_handle, :key_version, state.key_version)
    cache_key = cache_key(key_id, key_version)

    case :persistent_term.get(cache_key, :miss) do
      :miss -> fetch_and_cache_public_key(state, key_id, cache_key)
      pem when is_binary(pem) -> {:ok, pem}
    end
  end

  # --- RFC 8693 downstream-token flow (Phase-2 deferred) -------------------

  @impl true
  @spec store_user_token(
          state(),
          Recurse.Shared.IdentityContext.t(),
          Recurse.Providers.SecretsProvider.oidc_token(),
          ttl_seconds :: pos_integer()
        ) :: :ok | {:error, term()}
  def store_user_token(_state, _identity_ctx, _oidc_token, _ttl_seconds) do
    {:error, :not_implemented_yet}
  end

  @impl true
  @spec exchange_for_downstream_token(
          state(),
          Recurse.Shared.IdentityContext.t(),
          Recurse.Providers.SecretsProvider.downstream_service_id(),
          requested_scope :: [String.t()]
        ) :: {:ok, Recurse.Providers.SecretsProvider.scoped_token()} | {:error, term()}
  def exchange_for_downstream_token(_state, _identity_ctx, _downstream_service_id, _scope) do
    {:error, :not_implemented_yet}
  end

  # --- introspection -------------------------------------------------------

  @impl true
  @spec capabilities(state()) :: [Recurse.Providers.SecretsProvider.capability()]
  def capabilities(_state), do: [:sign, :public_key_export, :hsm_backed]

  @impl true
  @spec healthcheck(state()) :: :ok | {:degraded, term()} | {:down, term()}
  def healthcheck(state) do
    state.key_arn
    |> ExAws.KMS.describe_key()
    |> ExAws.request(ex_aws_config_overrides(state))
    |> case do
      {:ok, _} -> :ok
      {:error, {:http_error, status, _}} when status >= 500 -> {:degraded, {:kms_5xx, status}}
      {:error, reason} -> {:down, reason}
    end
  end

  @impl true
  @spec terminate(state(), reason :: term()) :: :ok
  def terminate(_state, _reason) do
    # `:persistent_term` cache is deliberately NOT erased here — the cache
    # belongs to the BEAM process, not any one provider state; preserving
    # it across re-inits keeps warm-up idempotent.
    :ok
  end

  # --- private -------------------------------------------------------------

  @spec build_state(map()) :: {:ok, state()} | {:error, term()}
  defp build_state(config) do
    with {:ok, key_arn} <- require_string(config, :key_arn),
         {:ok, region} <- require_string(config, :region) do
      algorithm = config |> Map.get(:algorithm, :ecdsa_p256) |> alg_to_kms_string()
      finch_pool = Map.get(config, :finch_pool, @default_finch_pool)
      http_client = Map.get(config, :http_client, FinchHttpClient)

      state = %{
        config: config,
        key_arn: key_arn,
        region: region,
        algorithm: algorithm,
        finch_pool: finch_pool,
        http_client: http_client,
        key_version: 1
      }

      state =
        state
        |> maybe_put(:access_key_id, Map.get(config, :access_key_id))
        |> maybe_put(:secret_access_key, Map.get(config, :secret_access_key))

      {:ok, state}
    end
  end

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)

  defp require_string(map, key) do
    case Map.get(map, key) do
      value when is_binary(value) and byte_size(value) > 0 -> {:ok, value}
      _ -> {:error, {:invalid_config, key}}
    end
  end

  defp alg_to_kms_string(:ecdsa_p256), do: "ECDSA_SHA_256"
  defp alg_to_kms_string(:rsa_pss_2048), do: "RSASSA_PSS_SHA_256"
  defp alg_to_kms_string(alg) when is_binary(alg), do: alg

  defp alg_to_kms_string(other),
    do: raise(ArgumentError, "unsupported KMS algorithm: #{inspect(other)}")

  defp atomize_alg("ECDSA_SHA_256"), do: :ecdsa_p256
  defp atomize_alg("RSASSA_PSS_SHA_256"), do: :rsa_pss_2048
  defp atomize_alg(_), do: :ecdsa_p256

  # Prefer the algorithm carried in the handle (supports mixed-algorithm
  # fleets once rotation lands); fall back to state default.
  defp signing_algorithm_string(%{algorithm: alg}, _state) when is_atom(alg) and alg != nil,
    do: alg_to_kms_string(alg)

  defp signing_algorithm_string(%{algorithm: alg}, _state)
       when is_binary(alg) and byte_size(alg) > 0,
       do: alg

  defp signing_algorithm_string(_handle, state), do: state.algorithm

  # Route ex_aws through our Finch pool with FR-034 retry config.
  @spec ex_aws_config_overrides(state()) :: keyword()
  defp ex_aws_config_overrides(state) do
    base = [
      region: state.region,
      http_client: state.http_client,
      http_opts: [
        finch_pool: state.finch_pool,
        receive_timeout: @http_receive_timeout_ms
      ],
      retries: @retry_config
    ]

    base
    |> maybe_override(:access_key_id, Map.get(state, :access_key_id))
    |> maybe_override(:secret_access_key, Map.get(state, :secret_access_key))
  end

  defp maybe_override(kw, _key, nil), do: kw
  defp maybe_override(kw, key, value), do: Keyword.put(kw, key, value)

  # KMS `Sign` response shape:
  #   {:ok, %{"KeyId" => "...", "Signature" => "<base64>", "SigningAlgorithm" => "..."}}
  # ex_aws returns `{:error, reason}` after retries are exhausted; we map
  # that to the spec-mandated `:retries_exhausted` sentinel for the common
  # retryable-failure shape (5xx, throttle, timeouts) and pass other
  # errors through verbatim.
  defp handle_sign_response({:ok, %{"Signature" => sig_b64}}) when is_binary(sig_b64) do
    case Base.decode64(sig_b64) do
      {:ok, sig_bytes} -> {:ok, sig_bytes}
      :error -> {:error, {:kms_response_malformed, :signature_not_base64}}
    end
  end

  defp handle_sign_response({:ok, body}) do
    {:error, {:kms_response_malformed, body}}
  end

  defp handle_sign_response({:error, {:http_error, status, _body}}) when status >= 500 do
    {:error, :retries_exhausted}
  end

  defp handle_sign_response({:error, %{reason: reason}})
       when reason in [:timeout, :closed, :econnrefused, :nxdomain] do
    {:error, :retries_exhausted}
  end

  defp handle_sign_response({:error, reason}), do: {:error, reason}

  defp fetch_and_cache_public_key(state, key_id, cache_key) do
    key_id
    |> ExAws.KMS.get_public_key()
    |> ExAws.request(ex_aws_config_overrides(state))
    |> case do
      {:ok, %{"PublicKey" => der_b64}} when is_binary(der_b64) ->
        with {:ok, pem} <- der_b64_to_pem(der_b64) do
          :persistent_term.put(cache_key, pem)
          {:ok, pem}
        end

      {:ok, body} ->
        {:error, {:kms_response_malformed, body}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  # KMS returns the public key as base64-encoded DER (SubjectPublicKeyInfo).
  # Wrap in a standard PEM envelope (line length 64) so verifiers can feed
  # it straight into OpenSSL / JOSE without re-encoding.
  @spec der_b64_to_pem(String.t()) :: {:ok, String.t()} | {:error, term()}
  defp der_b64_to_pem(der_b64) do
    case Base.decode64(der_b64) do
      {:ok, der_bytes} ->
        {:ok, build_pem(der_bytes)}

      :error ->
        {:error, {:kms_response_malformed, :public_key_not_base64}}
    end
  end

  defp build_pem(der_bytes) do
    body =
      der_bytes
      |> Base.encode64()
      |> chunk_every_64()
      |> Enum.join("\n")

    "-----BEGIN PUBLIC KEY-----\n" <> body <> "\n-----END PUBLIC KEY-----\n"
  end

  # Split a base64 string into 64-char lines per RFC 7468 §2. Pattern-
  # matches the trailing remainder cleanly (the binary-pattern
  # comprehension alternative drops the non-64-aligned tail).
  defp chunk_every_64(binary), do: do_chunk(binary, 64, [])

  defp do_chunk(<<>>, _n, acc), do: Enum.reverse(acc)

  defp do_chunk(binary, n, acc) when byte_size(binary) <= n do
    Enum.reverse([binary | acc])
  end

  defp do_chunk(binary, n, acc) do
    <<head::binary-size(n), rest::binary>> = binary
    do_chunk(rest, n, [head | acc])
  end

  defp cache_key(key_arn, key_version), do: {__MODULE__, :public_key, key_arn, key_version}
end
