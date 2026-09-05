defmodule RecurseBroker.Endpoint do
  @moduledoc """
  Bandit-hosted HTTP endpoint for the Standalone Identity Broker (F002 T026/T087/T088).

  Three routes per F002 FR-008 + `contracts/recurse_broker_api.md`:

    * `POST /token/exchange` — RFC 8693 OAuth 2.0 Token Exchange;
      delegated to `RecurseBroker.TokenExchange` (T088).
    * `GET /oidc/jwks` — JWKS publication for Gateway discovery;
      delegated to `RecurseBroker.JWKS.Endpoint` (T087).
    * `GET /healthz` — liveness probe. For F002 MVP this always
      returns 200 while the port is bound. The contract specifies a
      503 path "if OIDC discovery has been failing for all configured
      issuers for ≥ 2 min" — that requires
      `RecurseBroker.OIDC.DiscoveryCache` to track last-success-per-
      issuer, which is a follow-up to T082. Until that lands, 200 is
      correct ("process is up; downstream health surfaced elsewhere").

  ## Why Bandit + Plug.Router and not Phoenix

  The broker is a narrow three-route service. Per research D2, Phoenix
  is pure overhead here; `Plug.Router` is the minimal idiom for this
  shape of HTTP surface.

  Per-route handlers are pure module-Plugs (`@behaviour Plug`), NOT
  sub-routers — the router above has exactly three dispatch targets
  and no shared middleware, so nesting routers would just add ceremony.

  ## Why the 404 catch-all, and no Plug.ErrorHandler

  `match _` below catches truly unknown paths with a JSON error shape
  so scanners and misconfigured clients get a predictable response
  rather than an HTML 404 page. Unhandled exceptions in downstream
  plugs surface as Bandit's default 500; explicit `Plug.ErrorHandler`
  wiring is a follow-up when the handlers grow more raise paths.

  ## Cross-references

    * `specs/002-standalone-gateway-vertical-slice/contracts/recurse_broker_api.md`
    * `specs/002-standalone-gateway-vertical-slice/tasks.md` T026, T087, T088
  """

  use Plug.Router

  plug(:match)

  # RFC 8693 token-exchange requests arrive form-urlencoded per
  # `contracts/recurse_broker_api.md`. Parse the body up front so
  # `POST /token/exchange` (handled in T088) can pull `grant_type`
  # etc. from `conn.body_params`. The `pass: ["*/*"]` allows the
  # JWKS + healthz routes to skip parsing unused content types.
  plug(Plug.Parsers, parsers: [:urlencoded], pass: ["*/*"])

  plug(:dispatch)

  post "/token/exchange" do
    RecurseBroker.TokenExchange.call(conn, [])
  end

  get "/oidc/jwks" do
    RecurseBroker.JWKS.Endpoint.call(conn, [])
  end

  get "/healthz" do
    send_resp(conn, 200, ~s|{"status":"ok","version":"0.2.0"}|)
  end

  match _ do
    send_resp(conn, 404, ~s|{"error":"not_found"}|)
  end

  @doc """
  Child spec wrapping Bandit with this Plug module.

  Accepts `:port` (default 4001) and `:scheme` (default `:http` —
  TLS termination in F002 is handled by the sidecar / ingress per
  docker-compose topology).
  """
  def child_spec(opts) do
    port = Keyword.get(opts, :port, 4001)
    scheme = Keyword.get(opts, :scheme, :http)

    Supervisor.child_spec(
      {Bandit, plug: __MODULE__, port: port, scheme: scheme},
      id: __MODULE__
    )
  end
end
