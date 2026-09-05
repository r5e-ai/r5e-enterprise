defmodule Recurse.Providers.Impls.LocalPemSecretsProvider do
  @moduledoc """
  `Recurse.Providers.SecretsProvider` backed by a single software signing
  key persisted as a PEM file on the local filesystem (spec 012 D4,
  registry shortname `local_pem`).

  This is the zero-cloud signer for the Docker Compose quickstart. The
  KMS-backed `Recurse.Providers.Impls.AwsKmsSecretsProvider` is the
  production shape; this module exists so a stranger's machine can boot
  the gateway and produce receipts that `docs/auditor/recurse-verify`
  verifies offline, with no AWS account.

  Ported from `FableDemo.DevSecretsProvider` (`scripts/fable_demo/demo.exs`).
  Deliberately thin: it will be swapped for the kernel's `R5e.Signer.Local`
  once the export paths converge.

  ## Config

    * `:key_path` — PEM file holding the private key. Default
      `/secrets/local-signing-key.pem` (the compose `secrets` volume).
      Generated on first boot if absent; persisted so receipts stay
      verifiable across restarts.
    * `:algorithm` — `:es256` (default) or `:ed25519`. Accepts the
      strings `"es256"` / `"ed25519"` too (the env-registry passes the
      raw `R5E_LOCAL_SIGNING_ALG` value through).

  ES256 is the default because it is the same algorithm family as the
  KMS signer (`ECDSA_SHA_256`), so every existing verifier — the
  `LocalVerifyHandler`, the export zip + `recurse-verify` — works
  unchanged. Ed25519 matches r5e-core's signer and is available behind
  the flag; the enterprise offline verifier does not yet verify it.

  ## Signature encoding

    * ES256 → `:public_key.sign/3` output, i.e. ASN.1 DER
      `SEQUENCE { INTEGER r, INTEGER s }` — byte-for-byte what KMS returns,
      which `Recurse.Shared.Attestation.Dsse.verify_es256/4` accepts.
    * Ed25519 → raw 64-byte signature (`:crypto.sign(:eddsa, ...)`).

  ## Key handle

  `active_signing_key/1` returns `key_version: 1` and a `key_id` that
  embeds a fingerprint of the public key (`local-pem-<alg>-<12 hex>`), so
  deleting the PEM and rebooting yields a *different* key id rather than
  silently reusing the old one in the `signing_keys` archive.

  ## Security posture

  The private key is plain on disk (mode 0600). That is the whole point
  of this provider (no KMS) and is stated in the quickstart's security
  notes. Never point production at it.

  In memory the key is held only inside the `:signer` closure, never as a
  bare term in the state map: `inspect(state)` (a crash report, a
  `FunctionClauseError` on a bad call, a `Logger` line that dumps the
  provider state) renders `#Function<...>`, not the ECDSA scalar or the
  Ed25519 seed. `sign/3` rescues inside the closure so a signing failure
  reports the exception type only, not the arguments.
  """

  @behaviour Recurse.Providers.SecretsProvider

  @default_key_path "/secrets/local-signing-key.pem"
  @default_algorithm :es256
  @algorithms [:es256, :ed25519]

  @type algorithm :: :es256 | :ed25519

  @typedoc """
  Provider state. `:signer` is a 1-arity closure over the private key
  (`payload -> signature`); see "Security posture" in the moduledoc.
  """
  @type state :: %{
          key_path: String.t(),
          algorithm: algorithm(),
          signer: (binary() -> binary()),
          public_pem: String.t(),
          key_id: String.t()
        }

  # ---------------------------------------------------------------------------
  # Lifecycle
  # ---------------------------------------------------------------------------

  @impl true
  def init(config) when is_map(config) do
    key_path = config |> Map.get(:key_path, @default_key_path) |> Path.expand()

    with {:ok, algorithm} <- normalize_algorithm(Map.get(config, :algorithm, @default_algorithm)),
         :ok <- ensure_parent_dir(key_path),
         {:ok, jwk} <- load_or_generate(key_path, algorithm),
         :ok <- assert_key_matches(jwk, algorithm, key_path) do
      public_pem = public_pem(jwk)

      {:ok,
       %{
         key_path: key_path,
         algorithm: algorithm,
         signer: signer_from_jwk(jwk, algorithm),
         public_pem: public_pem,
         key_id: key_id(algorithm, public_pem)
       }}
    end
  end

  def init(_config), do: {:error, :config_must_be_a_map}

  @impl true
  def terminate(_state, _reason), do: :ok

  # ---------------------------------------------------------------------------
  # Document-signing key release (FR-046)
  # ---------------------------------------------------------------------------

  @impl true
  def active_signing_key(%{key_id: key_id, algorithm: algorithm}) do
    {:ok, %{key_id: key_id, key_version: 1, algorithm: handle_algorithm(algorithm)}}
  end

  @impl true
  def sign(%{signer: signer}, _handle, payload)
      when is_function(signer, 1) and is_binary(payload) do
    {:ok, signer.(payload)}
  rescue
    # Never let the closure's arguments (the key) ride along in a raise.
    exception -> {:error, {:sign_failed, exception.__struct__}}
  end

  @impl true
  def public_key(%{public_pem: pem}, _handle), do: {:ok, pem}

  # ---------------------------------------------------------------------------
  # Downstream credential cache (FR-047) — not supported by a local signer.
  # ---------------------------------------------------------------------------

  @impl true
  def store_user_token(_state, _identity_ctx, _token, _ttl), do: :ok

  @impl true
  def exchange_for_downstream_token(_state, _identity_ctx, _service_id, _scope),
    do: {:error, :not_supported}

  @impl true
  def capabilities(_state), do: [:sign, :public_key_export]

  @impl true
  def healthcheck(%{key_path: key_path}) do
    if File.regular?(key_path) do
      :ok
    else
      {:degraded, {:signing_key_file_missing, key_path}}
    end
  end

  # ---------------------------------------------------------------------------
  # Internals
  # ---------------------------------------------------------------------------

  @doc """
  The algorithms this provider can generate + sign with. The env-registry
  reads this for its error message so the list lives in one place.
  """
  @spec algorithms() :: [algorithm()]
  def algorithms, do: @algorithms

  @doc """
  Normalise an algorithm given as an atom or an env-var string
  (`"es256"`, `"ED25519"`, ...). Shared with
  `Recurse.Gateway.Config.EnvProviderRegistry`, which raises with the env
  var name on `{:error, _}`.
  """
  @spec normalize_algorithm(term()) :: {:ok, algorithm()} | {:error, term()}
  def normalize_algorithm(alg) when alg in @algorithms, do: {:ok, alg}

  def normalize_algorithm(alg) when is_binary(alg) do
    case String.downcase(String.trim(alg)) do
      "es256" -> {:ok, :es256}
      "ed25519" -> {:ok, :ed25519}
      other -> {:error, {:unsupported_algorithm, other}}
    end
  end

  def normalize_algorithm(other), do: {:error, {:unsupported_algorithm, other}}

  defp handle_algorithm(:es256), do: :ecdsa_p256
  defp handle_algorithm(:ed25519), do: :ed25519

  defp ensure_parent_dir(key_path) do
    dir = Path.dirname(key_path)

    case File.mkdir_p(dir) do
      :ok -> :ok
      {:error, reason} -> {:error, {:key_dir_unavailable, dir, reason}}
    end
  end

  defp load_or_generate(key_path, algorithm) do
    if File.regular?(key_path) do
      load_pem(key_path)
    else
      generate_and_persist(key_path, algorithm)
    end
  end

  defp load_pem(key_path) do
    case JOSE.JWK.from_pem_file(key_path) do
      %JOSE.JWK{} = jwk -> {:ok, jwk}
      _ -> {:error, {:invalid_key_pem, key_path}}
    end
  rescue
    err -> {:error, {:invalid_key_pem, key_path, err}}
  end

  defp generate_and_persist(key_path, algorithm) do
    jwk = generate(algorithm)
    {_meta, pem} = JOSE.JWK.to_pem(jwk)
    tmp = key_path <> ".tmp-" <> Integer.to_string(System.unique_integer([:positive]))

    with :ok <- File.write(tmp, pem, [:exclusive]),
         :ok <- File.chmod(tmp, 0o600),
         :ok <- File.rename(tmp, key_path) do
      {:ok, jwk}
    else
      {:error, reason} ->
        _ = File.rm(tmp)
        {:error, {:key_write_failed, key_path, reason}}
    end
  end

  defp generate(:es256), do: JOSE.JWK.generate_key({:ec, :secp256r1})
  defp generate(:ed25519), do: JOSE.JWK.generate_key({:okp, :Ed25519})

  defp assert_key_matches(jwk, algorithm, key_path) do
    case {algorithm, JOSE.JWK.to_map(jwk)} do
      {:es256, {_, %{"kty" => "EC", "crv" => "P-256", "d" => _}}} ->
        :ok

      {:ed25519, {_, %{"kty" => "OKP", "crv" => "Ed25519", "d" => _}}} ->
        :ok

      {_, {_, %{"kty" => kty} = map}} ->
        {:error,
         {:key_algorithm_mismatch,
          expected: algorithm, found: {kty, Map.get(map, "crv")}, key_path: key_path}}
    end
  end

  # The private key is captured by the returned closure and nowhere else,
  # so it never appears in `inspect(state)`.
  defp signer_from_jwk(jwk, :es256) do
    {_kty, ec_private_key} = JOSE.JWK.to_key(jwk)
    fn payload -> :public_key.sign(payload, :sha256, ec_private_key) end
  end

  defp signer_from_jwk(jwk, :ed25519) do
    {_, %{"d" => d_b64}} = JOSE.JWK.to_map(jwk)
    seed = Base.url_decode64!(d_b64, padding: false)
    fn payload -> :crypto.sign(:eddsa, :none, payload, [seed, :ed25519]) end
  end

  defp public_pem(jwk) do
    {_meta, pem} = jwk |> JOSE.JWK.to_public() |> JOSE.JWK.to_pem()
    pem
  end

  defp key_id(algorithm, public_pem) do
    fingerprint =
      :sha256
      |> :crypto.hash(public_pem)
      |> Base.encode16(case: :lower)
      |> binary_part(0, 12)

    "local-pem-#{algorithm}-#{fingerprint}"
  end
end
