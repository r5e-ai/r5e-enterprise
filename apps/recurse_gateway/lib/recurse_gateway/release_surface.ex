defmodule Recurse.Gateway.ReleaseSurface do
  @moduledoc """
  Keeps execution surfaces that have not migrated to kernel admission closed.
  The supported execution boundary is the LLM proxy. Audit reads remain usable.
  """
  import Plug.Conn

  def init(opts), do: opts

  @doc "LLM suggestion execution is unavailable until it crosses kernel admission."
  def llm_suggestions_available?, do: false

  def call(%{method: "POST", path_info: path} = conn, _opts) do
    if unavailable?(path) do
      conn
      |> put_resp_content_type("application/json")
      |> send_resp(
        503,
        Jason.encode!(%{
          error: %{
            code: "capability_unavailable",
            message: "This capability is not available in this release."
          }
        })
      )
      |> halt()
    else
      conn
    end
  end

  def call(conn, _opts), do: conn

  defp unavailable?(["v1", "chat", "completions"]), do: true
  defp unavailable?(["v1", "chat", "messages"]), do: true
  defp unavailable?(["v1", "mcp", _server, "tools", _tool]), do: true
  defp unavailable?(_), do: false
end
