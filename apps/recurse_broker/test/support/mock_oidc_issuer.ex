defmodule RecurseBroker.Test.MockOidcIssuer do
  @moduledoc """
  In-process mock OIDC issuer for broker tests (F002 T079 / T081 / T089).

  No HTTP server is spun up: this module generates an ES256 keypair per
  invocation and exposes:

    * `mint_id_token/2` / `mint_id_token/3` — sign a synthetic customer-IdP
      `id_token` against the generated private key; header `kid` defaults
      to `mock_issuer.kid` so it matches the JWKS advertised by
      `jwks_plug_fn/1`.

    * `jwks_plug_fn/1` — a `Req` request-level `plug:` callback that, when
      installed via `req_opts: [plug: jwks_plug_fn.(issuer)]`, responds
      with a deterministic JWKS JSON body for any GET under the issuer's
      origin. Used to stub `RecurseBroker.OIDC.DiscoveryCache.fetch_jwks/2`
      without spawning a real port. The `Req` `:plug` opt is documented at
      https://hexdocs.pm/req/Req.Steps.html#put_plug/1 — a zero-dep test
      affordance that hands `Req` a `Plug`-compatible 2-arity callback
      instead of making a real network call.

    * `public_jwk/1` — return the public JWK in plain-map form (same shape
      the JWKS endpoint serves), useful when a test wants to pre-populate
      an in-memory cache rather than exercise the Req fetch path.

  The issuer / key-state is captured in a struct so each property-test
  iteration can construct a fresh issuer and not pollute shared caches.
  Callers are expected to pass a **fresh issuer string per iteration** when
  racing against `DiscoveryCache` state (see T080's @moduledoc on why this
  matters).

  ## Why not a real HTTP server

  Spinning a Bandit or Cowboy listener per property-test iteration burns
  socket handles, races against port reuse under parallel invocations, and
  produces noisier failure modes (port-in-use crashes overlap with the
  invariants we're trying to measure). `Req`'s `plug:` DI keeps the test
  purely in-process — the generator controls the response shape, timing,
  and error paths deterministically.

  ## Cross-references

    * `specs/002-standalone-gateway-vertical-slice/contracts/recurse_broker_api.md`
      ("Minted X-Observed-Identity JWT shape" + "broker-role-mapping.yaml
      schema")
    * `specs/002-standalone-gateway-vertical-slice/contracts/property_test_surface_catalog_f002.md`
      §Surface O + §Surface P
    * `apps/recurse_broker/test/token_exchange_property_test.exs` (T079)
    * `apps/recurse_broker/test/jwks_kid_refresh_property_test.exs` (T080)
    * `apps/recurse_broker/test/endpoint_contract_test.exs` (T081)
    * `apps/recurse_gateway/test/integration/us1_with_real_broker_test.exs`
      (T089)

  Cross-app callers: gateway tests alias this module directly via
  `RecurseBroker.Test.MockOidcIssuer`. See mix.exs comment blocks in both
  recurse_broker and recurse_gateway for the rationale.
  """

  defstruct [:issuer, :kid, :private_jwk, :public_jwk]

  @type t :: %__MODULE__{
          issuer: String.t(),
          kid: String.t(),
          private_jwk: JOSE.JWK.t(),
          public_jwk: map()
        }

  @doc """
  Build a fresh mock issuer with a freshly-generated ES256 keypair.
  """
  @spec new(keyword()) :: t()
  def new(opts \\ []) do
    issuer = Keyword.get(opts, :issuer, "https://mock-oidc-#{unique_suffix()}.example.test")
    kid = Keyword.get(opts, :kid, "mock-key-" <> unique_suffix())

    private_jwk = JOSE.JWK.generate_key({:ec, "P-256"})
    {_, public_fields} = private_jwk |> JOSE.JWK.to_public() |> JOSE.JWK.to_map()

    public_jwk =
      public_fields
      |> Map.put("kid", kid)
      |> Map.put("use", "sig")
      |> Map.put("alg", "ES256")

    %__MODULE__{
      issuer: issuer,
      kid: kid,
      private_jwk: private_jwk,
      public_jwk: public_jwk
    }
  end

  @doc """
  Sign an `id_token` under the mock issuer.

  `claims` MUST at least include `"sub"` and `"aud"`. Defaults for `iat`,
  `nbf`, `exp`, `iss` are derived from the mock state + current time.
  """
  @spec mint_id_token(t(), map(), keyword()) :: String.t()
  def mint_id_token(%__MODULE__{} = issuer, claims, opts \\ []) when is_map(claims) do
    now = System.system_time(:second)

    defaults = %{
      "iss" => Keyword.get(opts, :iss_override, issuer.issuer),
      "iat" => now,
      "nbf" => now,
      "exp" => now + 900
    }

    payload = Map.merge(defaults, claims)

    header = %{
      "alg" => "ES256",
      "kid" => issuer.kid,
      "typ" => "JWT"
    }

    {_, compact} =
      issuer.private_jwk
      |> JOSE.JWT.sign(header, payload)
      |> JOSE.JWS.compact()

    compact
  end

  @doc """
  Return the public JWK in plain-map form (same shape served by
  `GET /oidc/jwks`).
  """
  @spec public_jwk(t()) :: map()
  def public_jwk(%__MODULE__{public_jwk: jwk}), do: jwk

  @doc """
  Return a `Req` `:plug` compatible function that serves:

    * `GET /.well-known/openid-configuration` — returns a minimal OIDC
      discovery document pointing `jwks_uri` back at the mock issuer's
      `/jwks` path.
    * `GET /jwks` (and any other GET) — returns `{"keys": [<public_jwk>]}`.

  Pass it via `req_opts: [plug: MockOidcIssuer.jwks_plug_fn(issuer)]`
  when you want `DiscoveryCache.fetch_jwks/2` to pull from the mock
  instead of making a real HTTP call. The DiscoveryCache's fetcher
  runs discovery *then* JWKS; both hops go through the same plug fn.

  ## Optional callback instrumentation

  Accepts a keyword `opts` with:

    * `:on_request` — 1-arity fun receiving the incoming `%Plug.Conn{}`
      *before* the response is sent. Use to bump an `:atomics` counter in
      T080's coalescing test or to sleep a random delay to force a race.
      Called for EVERY request — both discovery AND JWKS — so tests that
      want to count only JWKS hits should filter on `conn.request_path`.
    * `:response` — one of `:ok` (default; return the JWKS) or
      `{:error, status, body}` (respond with the given status for EVERY
      request, including discovery — enables "IdP is down" scenarios).
  """
  @spec jwks_plug_fn(t(), keyword()) :: (Plug.Conn.t(), any() -> Plug.Conn.t())
  def jwks_plug_fn(%__MODULE__{} = issuer, opts \\ []) do
    on_request = Keyword.get(opts, :on_request, fn _conn -> :ok end)
    response = Keyword.get(opts, :response, :ok)

    fn conn, _req_opts ->
      _ = on_request.(conn)

      case {response, conn.request_path} do
        {{:error, status, body}, _path} when is_integer(status) and is_binary(body) ->
          conn
          |> Plug.Conn.put_resp_header("content-type", "application/json")
          |> Plug.Conn.send_resp(status, body)

        {:ok, "/.well-known/openid-configuration"} ->
          discovery_body =
            JSON.encode!(%{
              "issuer" => issuer.issuer,
              "jwks_uri" => issuer.issuer <> "/jwks"
            })

          conn
          |> Plug.Conn.put_resp_header("content-type", "application/json")
          |> Plug.Conn.send_resp(200, discovery_body)

        {:ok, _other_path} ->
          body = JSON.encode!(%{"keys" => [public_jwk(issuer)]})

          conn
          |> Plug.Conn.put_resp_header("content-type", "application/json")
          |> Plug.Conn.send_resp(200, body)
      end
    end
  end

  defp unique_suffix do
    :crypto.strong_rand_bytes(6) |> Base.url_encode64(padding: false)
  end
end
