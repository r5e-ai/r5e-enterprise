defmodule RecurseIntegrationTest do
  use ExUnit.Case
  doctest RecurseIntegration

  test "greets the world" do
    assert RecurseIntegration.hello() == :world
  end
end
