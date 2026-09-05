defmodule RecurseSharedTest do
  use ExUnit.Case
  doctest RecurseShared

  test "greets the world" do
    assert RecurseShared.hello() == :world
  end
end
