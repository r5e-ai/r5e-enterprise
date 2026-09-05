defmodule RecurseBroker.JWT.Signer do
  @moduledoc """
  Mint `X-Observed-Identity` JWTs for the Recurse Standalone Identity Broker
  (F002 T085).

  Pure module — NO state. Iron Law check (elixir-thinking):

    1. Mutable state persisting across calls? No — each `mint/2` call is a
       pure function of `(claims, opts)` that reads from the (externally
       owned) `RecurseBroker.JWT.KeyRing` and returns a compact serialization.
    2. Concurrent execution? No — JWS signing is CPU-bound crypto on the
       caller process.
    3. Fault isolation? No — failure is `{:error, atom}`, never a crash.

  All three NO → plain functions. Signing keys (legitimate state, rotation
  overlap window) live in the `KeyRing` GenServer; this module composes them.

  ## Contract alignment (`contracts/recurse_broker_api.md`)

  The minted JWT's header + payload exactly matches the "Minted
  X-Observed-Identity JWT shape" section of the broker API contract:

    * Header: `%{"alg" => "ES256", "kid" => kid, "typ" => "JWT"}`.
    * Payload: `iss`, `sub`, `aud`, `iat`, `nbf = iat`, `exp = iat + ttl`,
      `jti`, `principal` (custom claim per FR-009 + Clarifications Q3).

  ES256 is hard-coded per F002 FR-007 — the broker always signs ES256
  regardless of what customer IdPs sign `subject_token` with. If the
  KeyRing returns a non-EC key (e.g. RSA from a misconfigured PEM path),
  mint errors `{:error, :unexpected_signer_kty}` rather than silently
  producing an RS256 token.

  ## Dependency injection

    * `:key_ring` — the module implementing `current_key/0`. Defaults to
      `RecurseBroker.JWT.KeyRing`. Tests inject a stub module to bypass
      the real KeyRing without starting its GenServer.
    * `:now_unix` — `System.system_time(:second)` by default; overridable
      for deterministic expiration-math tests.
    * `:jti` — by default, a fresh 128-bit random hex (UUIDv4-equivalent
      collision space). Overridable for deterministic tests.

  ## Return

    * `{:ok, compact_jws}` — 3-segment compact serialization, ready to
      hand back in the `access_token` field of the RFC 8693 response.
    * `{:error, reason}` — `:signer_unavailable` (KeyRing returned error),
      `:unexpected_signer_kty`, `:missing_subject`, `:missing_issuer`,
      `:missing_audience`, `:missing_principal`.

  ## Refactoring note (dogfood-deploy GAN-fix, 2026-04-26)

  The pure JWT-shape + JOSE compact-serialization logic was lifted to
  `Recurse.Shared.Identity.JwtMinter` so the WorkOS dogfood-deploy
  Gateway path can mint broker-shaped internal JWTs without depending
  on the broker (Constitution Principle V — provider-neutrality
  allowlist excludes `RecurseBroker.*` from gateway business logic).
  This module is now a thin wrapper that owns the broker-side
  `KeyRing` lookup and delegates the actual signing to
  `Recurse.Shared.Identity.JwtMinter.mint/1`.

  ## Cross-references

    * `apps/recurse_shared/lib/recurse_shared/identity/jwt_minter.ex`
      (the shared mint primitive both broker + gateway-WorkOS-path use)
    * `specs/002-standalone-gateway-vertical-slice/contracts/recurse_broker_api.md`
      (Minted X-Observed-Identity JWT shape)
    * `specs/002-standalone-gateway-vertical-slice/research.md` D2 (JOSE
      pitfalls; `from_map`-only remote keys; strict alg binding)
    * F002 FR-007 (broker minted JWT alg = ES256)
    * F002 FR-009 + Clarifications Q3 (principal custom claim shape)
    * `apps/recurse_broker/lib/recurse_broker/jwt/key_ring.ex` (consumer
      contract: `current_key/0 :: {:ok, {kid, jwk}} | {:error, _}`)
  """

  @type mint_opts :: [
          subject: String.t(),
          issuer: String.t(),
          audience: String.t(),
          principal: map(),
          ttl_seconds: pos_integer(),
          key_ring: module(),
          now_unix: (-> integer()) | integer(),
          jti: String.t()
        ]

  @type mint_error ::
          :signer_unavailable
          | Recurse.Shared.Identity.JwtMinter.mint_error()

  @doc """
  Mint an `X-Observed-Identity` JWT.

  Accepts `claims` as a map for forward-compatibility with callers that
  assemble the payload themselves, but the primary caller (SA2's
  TokenExchange Plug at T088) is expected to pass an empty `%{}` and let
  this module build the standard claim set from `opts`. The `claims` map
  is no longer merged into the payload — reserved keys
  (iss/sub/aud/iat/nbf/exp/jti/principal) are taken exclusively from
  `opts` to avoid forgery via `claims`-injection. The arity is preserved
  for backwards compatibility; non-empty `claims` are silently dropped.

  See moduledoc for required `opts`.
  """
  @spec mint(map(), mint_opts()) :: {:ok, String.t()} | {:error, mint_error()}
  def mint(_claims, opts) when is_list(opts) do
    case fetch_current_key(opts) do
      {:ok, {kid, jwk}} ->
        Recurse.Shared.Identity.JwtMinter.mint(
          opts
          |> Keyword.put(:jwk, jwk)
          |> Keyword.put(:kid, kid)
          |> normalize_now_unix()
        )

      {:error, reason} ->
        {:error, reason}
    end
  end

  # ---------------------------------------------------------------------------
  # Helpers — broker-side state lookup (KeyRing) only; pure mint logic now
  # lives in `Recurse.Shared.Identity.JwtMinter`.
  # ---------------------------------------------------------------------------

  defp fetch_current_key(opts) do
    mod = Keyword.get(opts, :key_ring, RecurseBroker.JWT.KeyRing)

    case mod.current_key() do
      {:ok, {kid, jwk}} when is_binary(kid) -> {:ok, {kid, jwk}}
      {:error, _} -> {:error, :signer_unavailable}
      _ -> {:error, :signer_unavailable}
    end
  end

  # The shared minter takes `:now_unix` as an integer; broker callers can
  # pass a 0-arity function for legacy clock-fixture compatibility. Resolve
  # the function here so the shared module's contract stays integer-only.
  defp normalize_now_unix(opts) do
    case Keyword.get(opts, :now_unix) do
      fun when is_function(fun, 0) -> Keyword.put(opts, :now_unix, fun.())
      _ -> opts
    end
  end
end
