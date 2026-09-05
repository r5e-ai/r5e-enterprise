defmodule RecurseRuntimeTest do
  use ExUnit.Case
  doctest RecurseRuntime

  test "greets the world" do
    assert RecurseRuntime.hello() == :world
  end
end
