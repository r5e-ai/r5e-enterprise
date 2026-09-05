defmodule Recurse.Gateway.Plug.AdminStatic do
  @moduledoc """
  Static-asset plug for `/admin/*` that wraps `Plug.Static` with the F004
  security-headers pipeline (T145, Phase-9 polish).

  Sequence per request:

    1. Apply `Recurse.Gateway.Plug.SecurityHeaders` — sets CSP +
       frame-ancestors + Referrer-Policy + X-Content-Type-Options +
       X-Frame-Options on the response.
    2. Delegate to `Plug.Static` with the caller-supplied options.

  Both steps run synchronously on the Bandit-spawned request process; no
  GenServer state. The headers fire BEFORE `Plug.Static` writes the
  response so the SPA's HTML / JS / wasm assets all carry the locked-down
  CSP without per-asset wiring.

  ## Wire-in

  Mounted in `Recurse.Gateway.Router` via:

      forward "/admin",
        to: Recurse.Gateway.Plug.AdminStatic,
        init_opts: [
          static_opts: [
            at: "/admin",
            from: {:recurse_gateway, "priv/static/admin"},
            only: ~w(assets recurse-logo.svg favicon.ico vite.svg index.html),
            gzip: true
          ]
        ]

  The `:static_opts` keyword list is passed verbatim to `Plug.Static.init/1`.

  ## Iron Law check (`elixir:phoenix-thinking`)

  Pure module-plug. Sets headers, then delegates. No mutable state across
  calls; no concurrency; failures bubble (Plug.Static handles its own
  not-found semantics by `pass`-ing through).

  ## Cross-references

    * `apps/recurse_gateway/lib/recurse_gateway/plug/security_headers.ex`
    * `apps/recurse_gateway/lib/recurse_gateway/router.ex`
    * `specs/004-audit-console/tasks.md` T145
  """

  @behaviour Plug

  alias Recurse.Gateway.Plug.SecurityHeaders

  @impl Plug
  @spec init(keyword()) :: %{static_opts: term()}
  def init(opts) when is_list(opts) do
    static_opts = Keyword.fetch!(opts, :static_opts)
    %{static_opts: Plug.Static.init(static_opts)}
  end

  @impl Plug
  @spec call(Plug.Conn.t(), %{static_opts: term()}) :: Plug.Conn.t()
  def call(%Plug.Conn{} = conn, %{static_opts: static_opts}) do
    conn = conn
    |> SecurityHeaders.call(SecurityHeaders.init([]))
    |> Plug.Static.call(static_opts)

    if conn.state in [:sent, :chunked, :file] do
      conn
    else
      # SPA fallback: any /admin/* path that didn't resolve to a static
      # asset (deep links like /admin/login, /admin/dashboard,
      # /admin/policy-simulator/123) gets served the SPA index.html so
      # the client-side router can take over. Without this, Plug.Static
      # `pass`-es the conn through unsent and Bandit raises NotSentError.
      index_path = Path.join(:code.priv_dir(:recurse_gateway), "static/admin/index.html")
      conn
      |> Plug.Conn.put_resp_content_type("text/html")
      |> Plug.Conn.send_file(200, index_path)
    end
  end
end
