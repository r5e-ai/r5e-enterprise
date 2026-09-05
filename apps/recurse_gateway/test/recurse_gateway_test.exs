defmodule RecurseGatewayTest do
  use ExUnit.Case
  doctest RecurseGateway

  test "greets the world" do
    assert RecurseGateway.hello() == :world
  end
end
