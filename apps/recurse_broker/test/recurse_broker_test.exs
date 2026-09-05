defmodule RecurseBrokerTest do
  use ExUnit.Case
  doctest RecurseBroker

  test "greets the world" do
    assert RecurseBroker.hello() == :world
  end
end
