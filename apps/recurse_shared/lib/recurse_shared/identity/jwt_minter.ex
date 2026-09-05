defmodule Recurse.Shared.Identity.JwtMinter do
  @moduledoc """
  Mint Recurse-internal `X-Observed-Identity` JWTs from a precomputed
  signing key (PEM-on-disk) and an opts-supplied claim set.

  ## Why this lives in `recurse_shared`

  The Standalone Identity Broker (`apps/recurse_broker/`) is the canonical
  producer of `X-Observed-Identity` JWTs in the broker-mediated F002/F004
  path. Its `RecurseBroker.JWT.Signer` couples to the long-lived
  `RecurseBroker.JWT.KeyRing` GenServer for hot-rotation key management.

  The dogfood-deploy WorkOS path (`feat/dogfood-deploy-scaffolding`)
  needs the SAME JWT shape so downstream `IdentityContextBuilder` +
  `JwtValidator` + `Authz.gate/4` (Cedar evaluation) work unchanged after
  WorkOS sign-in. But the WorkOS adapter lives inside the Gateway OTP
  app, NOT the broker — and pulling broker into the gateway production
  release violates Constitution Principle V (Provider-Interface
  Neutrality; no hidden cross-app coupling) per the
  `Recurse.Credo.ProviderNeutrality` allowlist (`RecurseBroker.*` is
  intentionally NOT in the gateway-business-logic approved prefixes).

  Resolution: lift the pure mint logic — the JCS-stable claim assembly
  + JOSE compact serialization — into `recurse_shared` (which both
  broker and gateway already depend on as a peer). The broker keeps
  its KeyRing GenServer + `RecurseBroker.JWT.Signer` (which now
  delegates to this module) for hot-rotation; the WorkOS adapter
  loads its PEM directly via `JOSE.JWK.from_pem_file/1` at boot and
  calls `mint/1` per request.

  ## Iron Law check (`elixir:elixir-thinking`)

  Pure module — no process. Iron Law:

    1. Mutable state across calls? No — every `mint/1` call is a pure
       function of `opts` returning `{:ok, compact_jws} | {:error, _}`.
    2. Concurrent execution? No — JWS signing is CPU-bound crypto on
       the caller's process.
    3. Fault isolation? No — failures are tagged tuples; callers
       translate them into HTTP error responses.

  All three NO → plain functions. The signing key (legitimate state)
  is owned by the caller (`RecurseBroker.JWT.KeyRing` for broker,
  app env for gateway WorkOS path).

  ## Contract alignment

  Output shape exactly matches the F002
  `contracts/recurse_broker_api.md` "Minted X-Observed-Identity JWT
  shape":

    * Header: `%{"alg" => "ES256", "kid" => kid, "typ" => "JWT"}`.
    * Payload: `iss`, `sub`, `aud`, `iat`, `nbf = iat`,
      `exp = iat + ttl`, `jti`, `principal` (custom claim per F002
      FR-009 + Clarifications Q3).

  ES256 is hard-coded per F002 FR-007. Non-EC keys raise
  `{:error, :unexpected_signer_kty}` rather than silently producing
  an RS256 token.

  ## Cross-references

    * `apps/recurse_broker/lib/recurse_broker/jwt/signer.ex` (delegates
      to this module post-extraction)
    * `apps/recurse_gateway/lib/recurse_gateway/admin/browser_auth/workos.ex`
      (calls `mint/1` for the WorkOS dogfood-deploy sign-in path)
    * `specs/002-standalone-gateway-vertical-slice/contracts/recurse_broker_api.md`
      (Minted X-Observed-Identity JWT shape)
    * F002 FR-007 (broker minted JWT alg = ES256)
    * F002 FR-009 + Clarifications Q3 (principal custom claim shape)
  """

  @default_ttl_seconds 900
  @fixed_alg "ES256"

  @type mint_opts :: [
          subject: String.t(),
          issuer: String.t(),
          audience: String.t(),
          principal: map(),
          jwk: JOSE.JWK.t(),
          kid: String.t(),
          ttl_seconds: pos_integer(),
          now_unix: integer(),
          jti: String.t()
        ]

  @type mint_error ::
          :unexpected_signer_kty
          | :missing_subject
          | :missing_issuer
          | :missing_audience
          | :missing_principal
          | :missing_jwk
          | :missing_kid

  @doc """
  Mint an `X-Observed-Identity` JWT.

  Required `opts`:

    * `:subject` — JWT `sub` claim.
    * `:issuer` — JWT `iss` claim.
    * `:audience` — JWT `aud` claim.
    * `:principal` — the F002 FR-009 principal map (with at minimum
      `kind`, `issuer`, `subject` for `obo_human`).
    * `:jwk` — a `JOSE.JWK.t()` ES256 (kty=EC, crv=P-256) signing key.
    * `:kid` — the key id stamped into the JWT header.

  Optional:

    * `:ttl_seconds` — default 900 (15 min, matches broker default).
    * `:now_unix` — default `System.system_time(:second)`.
    * `:jti` — default 128 random bits hex; pass for deterministic
      tests.

  Returns `{:ok, compact_jws}` or `{:error, mint_error}`.
  """
  @spec mint(mint_opts()) :: {:ok, String.t()} | {:error, mint_error()}
  def mint(opts) when is_list(opts) do
    with {:ok, subject} <- required_opt(opts, :subject, :missing_subject),
         {:ok, issuer} <- required_opt(opts, :issuer, :missing_issuer),
         {:ok, audience} <- required_opt(opts, :audience, :missing_audience),
         {:ok, principal} <- required_opt(opts, :principal, :missing_principal),
         {:ok, jwk} <- required_opt(opts, :jwk, :missing_jwk),
         {:ok, kid} <- required_opt(opts, :kid, :missing_kid),
         :ok <- check_ec_key(jwk) do
      ttl = Keyword.get(opts, :ttl_seconds, @default_ttl_seconds)
      now = Keyword.get_lazy(opts, :now_unix, fn -> System.system_time(:second) end)
      jti = Keyword.get_lazy(opts, :jti, &random_jti/0)

      payload = %{
        "iss" => issuer,
        "sub" => subject,
        "aud" => audience,
        "iat" => now,
        "nbf" => now,
        "exp" => now + ttl,
        "jti" => jti,
        "principal" => principal
      }

      header = %{"alg" => @fixed_alg, "kid" => kid, "typ" => "JWT"}

      {_jws, compact} =
        jwk
        |> JOSE.JWT.sign(header, payload)
        |> JOSE.JWS.compact()

      {:ok, compact}
    end
  end

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  defp required_opt(opts, key, err) do
    case Keyword.fetch(opts, key) do
      {:ok, nil} -> {:error, err}
      {:ok, ""} -> {:error, err}
      {:ok, value} -> {:ok, value}
      :error -> {:error, err}
    end
  end

  # F002 FR-007 pins broker-minted JWTs to ES256. Accept a JOSE.JWK struct
  # or a plain map (e.g. tests passing a generated-then-externalized key).
  # Reject non-EC keys and EC keys on the wrong curve.
  defp check_ec_key(%JOSE.JWK{} = jwk) do
    {_mod, fields} = JOSE.JWK.to_map(jwk)
    check_ec_key(fields)
  end

  defp check_ec_key(%{"kty" => "EC", "crv" => "P-256"}), do: :ok
  defp check_ec_key(_), do: {:error, :unexpected_signer_kty}

  # 128 bits of entropy, lowercase hex. Equivalent collision space to
  # UUIDv4; avoids adding a uuid dep.
  defp random_jti do
    :crypto.strong_rand_bytes(16) |> Base.encode16(case: :lower)
  end
end
