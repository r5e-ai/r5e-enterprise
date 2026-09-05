defmodule Recurse.Shared.BrowserSessionIdTest do
  use ExUnit.Case, async: true

  alias Recurse.Shared.BrowserSessionId

  test "generate/0 returns a URL-safe opaque session id" do
    id = BrowserSessionId.generate()

    assert is_binary(id)
    assert byte_size(id) == 22
    assert id =~ ~r/\A[A-Za-z0-9_-]+\z/
  end

  test "generate/0 produces distinct values" do
    ids = for _ <- 1..100, do: BrowserSessionId.generate()

    assert ids |> MapSet.new() |> MapSet.size() == 100
  end
end
