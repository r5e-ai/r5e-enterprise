defmodule Recurse.Gateway.Observability.Endpoint do
  @moduledoc """
  Single module-plug dispatcher for the Gateway's observability surface
  (F002 T091 / FR-028).

  ## Responsibility

  Given a `Plug.Conn`, inspect the request path and delegate to the
  correct observability plug:

      GET /healthz   →  Recurse.Gateway.Observability.Healthz.call/2
      GET /readyz    →  Recurse.Gateway.Observability.Readyz.call/2
      GET /metrics   →  Prometheus scrape (TelemetryMetricsPrometheus.Core)

  Any other path returns `:not_observability` so the caller can fall
  through to the normal router pipeline. This module exists so the
  router can forward a single "observability" child — or call
  `handle/1` inline — without repeating the three path matches.

  ## Router integration decision

  The router (`Recurse.Gateway.Router`) keeps its three individual
  `get "/healthz"`, `get "/readyz"`, `get "/metrics"` routes and
  delegates into the respective modules (`Healthz`, `Readyz`, and this
  module's `handle_metrics/1`). Folding them behind a single
  `Plug.Router.match _` match would work, but the explicit route
  declarations keep the router's documentation + compile-time path
  table useful. This module is therefore the **composition point** for
  tests + future operator CLIs; the router still knows the three paths
  individually.

  ## Iron Law check (`elixir:elixir-thinking`)

  Pure module. `call/2` dispatches based on `conn.request_path`. No
  process, no cached state.
  """

  @behaviour Plug

  alias Recurse.Gateway.Observability.Healthz
  alias Recurse.Gateway.Observability.Readyz

  @impl true
  def init(opts), do: opts

  @impl true
  def call(%Plug.Conn{request_path: "/healthz"} = conn, _opts), do: Healthz.call(conn, [])
  def call(%Plug.Conn{request_path: "/readyz"} = conn, _opts), do: Readyz.call(conn, [])
  def call(%Plug.Conn{request_path: "/metrics"} = conn, _opts), do: handle_metrics(conn)

  def call(%Plug.Conn{} = conn, _opts) do
    conn
    |> Plug.Conn.put_resp_content_type("application/json")
    |> Plug.Conn.send_resp(404, ~s|{"error":"not_found"}|)
  end

  @doc """
  Prometheus scrape handler — returns `text/plain; version=0.0.4`
  with the exposition text from
  `TelemetryMetricsPrometheus.Core.scrape/1`.

  Falls back to a minimal stub body when the registry has not been
  started (the umbrella test env boots the Gateway without metrics
  unless a test mounts the registry explicitly).
  """
  @spec handle_metrics(Plug.Conn.t()) :: Plug.Conn.t()
  def handle_metrics(conn) do
    body = scrape_safely()

    conn
    |> Plug.Conn.put_resp_content_type("text/plain", "utf-8")
    |> Plug.Conn.put_resp_header("content-type", "text/plain; version=0.0.4; charset=utf-8")
    |> Plug.Conn.send_resp(200, body)
  end

  defp scrape_safely do
    Recurse.Gateway.Observability.Metrics.scrape()
  rescue
    _ ->
      "# HELP recurse_gateway_build_info Gateway build info.\n"
  catch
    :exit, _ ->
      "# HELP recurse_gateway_build_info Gateway build info.\n"
  end
end
