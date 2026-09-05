defmodule RecurseProvidersTest do
  use ExUnit.Case
  doctest RecurseProviders

  test "greets the world" do
    assert RecurseProviders.hello() == :world
  end
end
