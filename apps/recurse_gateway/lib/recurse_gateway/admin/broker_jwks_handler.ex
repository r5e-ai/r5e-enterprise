defmodule Recurse.Gateway.Admin.BrokerJwksHandler do
  @moduledoc """
  Publishes the BEAM's broker-signing public key as a standard
  RFC 7517 JWKS document.

  ## Why this exists

  In collapsed-broker deploys where the gateway IS its own broker, the
  WorkOS adapter mints internal JWTs at sign-in
  using the local PEM at `BROKER_JWT_SIGNING_KEY_PATH`. Downstream
  the gateway's own `JwtValidator` looks up the kid in `JwksCache`
  to verify the JWT. With nothing publishing the broker's JWKS, the
  lookup fails (`unknown_kid`) and every cookie-authenticated
  request 401s — even though the cookie envelope itself is valid.

  This endpoint closes that loop. The gateway publishes its own
  broker key here; `JwksCache` configured with the runtime-derived
  in-pod JWKS URL fetches it on first cache miss; lookups succeed.

  ## Why this is also right for production

  When the broker is split out as a separate service, the broker
  container exposes the EXACT same endpoint shape — JWKS at a
  configured path. The gateway's `JwksCache` config flips from the
  runtime-derived collapsed URL to the broker service URL. No special-case
  code on either side.

  ## Kid derivation

  Uses the same algorithm as `Recurse.Gateway.Admin.BrowserAuth.WorkOS`
  `derive_kid/2` so the kid PUBLISHED here matches the kid MINTED
  there. If they ever drift, the validator will fail closed —
  which is the correct posture, but it would be a bug.

  ## Public, no auth

  RFC 7517 JWKS is published-key info by definition. The endpoint is
  public, no cookie / no JWT required. Cache headers tell clients
  it's safe to cache for `:internal_jwt.jwks_cache_ttl_seconds`
  (default 300s, matches the consumer-side TTL).

  ## Response shape

  ```
  GET /v1/auth/jwks
  200 OK
  Content-Type: application/jwk-set+json
  Cache-Control: public, max-age=300

  {
    "keys": [
      {
        "kty": "EC",
        "crv": "P-256",
        "kid": "broker-signing-key",
        "use": "sig",
        "alg": "ES256",
        "x": "<base64url>",
        "y": "<base64url>"
      }
    ]
  }
  ```

  ## Error modes

  - 503 if `:internal_jwt.signing_key_path` is unset, missing, or
    unreadable. The gateway shouldn't have booted in this state per
    `Application.validate_internal_jwt_required_env!/0` — this
    handler defends against config-changed-since-boot or similar
    drift. Body is the F001 error envelope shape for consistency.
  - 500 on unexpected JOSE failures (extremely unlikely once the PEM
    has loaded once).
  """

  @behaviour Plug

  alias Plug.Conn

  require Logger

  @cache_ttl_default_seconds 300

  @impl Plug
  def init(opts), do: opts

  @impl Plug
  def call(%Conn{method: "GET"} = conn, _opts) do
    case build_jwks() do
      {:ok, jwks} ->
        ttl = jwks_cache_ttl_seconds()

        conn
        |> Conn.put_resp_content_type("application/jwk-set+json")
        |> Conn.put_resp_header("cache-control", "public, max-age=#{ttl}")
        |> Conn.send_resp(200, JSON.encode!(jwks))

      {:error, reason} ->
        Logger.warning("broker_jwks_unavailable",
          reason: inspect(reason),
          handler: __MODULE__
        )

        body =
          JSON.encode!(%{
            "error" => %{
              "code" => "ERR_SERVICE_UNAVAILABLE",
              "details" => %{"reason" => to_string(elem(reason, 0))},
              "message" => "Broker JWKS unavailable"
            }
          })

        conn
        |> Conn.put_resp_content_type("application/json")
        |> Conn.send_resp(503, body)
    end
  end

  def call(%Conn{} = conn, _opts) do
    # JWKS endpoints SHOULD only respond to GET per RFC 7517.
    conn
    |> Conn.put_resp_header("allow", "GET")
    |> Conn.send_resp(405, "")
  end

  # ---------------------------------------------------------------------------
  # JWKS construction
  # ---------------------------------------------------------------------------

  @doc """
  Build the JWKS map. Public for direct testing without exercising the
  Plug layer.
  """
  @spec build_jwks() :: {:ok, %{required(:keys) => [map()]}} | {:error, term()}
  def build_jwks do
    cfg = Application.get_env(:recurse_gateway, :internal_jwt, [])
    path = Keyword.get(cfg, :signing_key_path)

    cond do
      is_nil(path) or path == "" ->
        {:error, {:signing_key_path_unset, nil}}

      not File.regular?(path) ->
        {:error, {:signing_key_path_unreadable, path}}

      true ->
        try do
          private_jwk = JOSE.JWK.from_pem_file(path)
          public_jwk = JOSE.JWK.to_public(private_jwk)
          kid = derive_kid(path, private_jwk)

          {_module, jwk_map} = JOSE.JWK.to_map(public_jwk)

          # Augment with kid + use + alg per RFC 7517 §4. The base
          # JWK map from JOSE only carries the cryptographic
          # parameters; key-management metadata is added here.
          jwk_with_meta =
            jwk_map
            |> Map.put("kid", kid)
            |> Map.put("use", "sig")
            |> Map.put("alg", "ES256")

          {:ok, %{keys: [jwk_with_meta]}}
        rescue
          error -> {:error, {:jwk_load_failed, Exception.message(error)}}
        end
    end
  end

  # ---------------------------------------------------------------------------
  # Kid derivation — MUST match
  # `Recurse.Gateway.Admin.BrowserAuth.WorkOS.derive_kid/2` exactly,
  # else the validator's lookup misses and every internal JWT 401s.
  #
  # Kept in sync by:
  #   - Both call sites compute kid from (path, %JOSE.JWK{}).
  #   - Property test asserts `derive_kid` here ≡ derive_kid in
  #     workos.ex for arbitrary input pairs.
  #
  # If the two ever diverge, a single source of truth (e.g.,
  # `Recurse.Shared.JwkKid`) should host the algorithm and both
  # consumers delegate to it. Today the cycle isn't worth splitting.
  # ---------------------------------------------------------------------------

  defp derive_kid(path, %JOSE.JWK{} = jwk) do
    stem = path |> Path.basename() |> Path.rootname()

    if kid_shaped?(stem) do
      stem
    else
      thumb = JOSE.JWK.thumbprint(jwk)
      Base.url_encode64(:crypto.hash(:sha256, thumb), padding: false)
    end
  end

  defp kid_shaped?(stem) do
    stem != "" and
      String.match?(stem, ~r/^[A-Za-z0-9_.\-]+$/) and
      String.replace(stem, ".", "") != ""
  end

  # ---------------------------------------------------------------------------

  defp jwks_cache_ttl_seconds do
    cfg = Application.get_env(:recurse_gateway, :internal_jwt, [])
    Keyword.get(cfg, :jwks_cache_ttl_seconds, @cache_ttl_default_seconds)
  end
end
