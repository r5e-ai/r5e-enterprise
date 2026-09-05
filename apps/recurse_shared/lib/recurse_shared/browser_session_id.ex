defmodule Recurse.Shared.BrowserSessionId do
  @moduledoc """
  Browser audit-session identifier helper.

  Browser login paths use this value to correlate encrypted session-cookie
  state with `:ui_login` / `:ui_logout` receipts. The value is intentionally
  opaque: callers need a fresh, URL-safe string, not timestamp ordering.
  """

  @doc """
  Generate a fresh browser session ID.
  """
  @spec generate() :: String.t()
  def generate do
    16
    |> :crypto.strong_rand_bytes()
    |> Base.url_encode64(padding: false)
  end
end
