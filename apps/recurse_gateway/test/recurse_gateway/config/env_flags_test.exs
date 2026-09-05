defmodule Recurse.Gateway.Config.EnvFlagsTest do
  use ExUnit.Case, async: false

  alias Recurse.Gateway.Config.EnvFlags

  doctest EnvFlags

  @var "R5E_ENV_FLAGS_TEST_FLAG"

  setup do
    on_exit(fn -> System.delete_env(@var) end)
    :ok
  end

  test "unset or empty falls back to the default" do
    System.delete_env(@var)
    assert EnvFlags.strict_bool!(@var, true)
    refute EnvFlags.strict_bool!(@var, false)

    System.put_env(@var, "")
    assert EnvFlags.strict_bool!(@var, true)
  end

  test "only the literals true / false are accepted" do
    System.put_env(@var, "true")
    assert EnvFlags.strict_bool!(@var, false)

    System.put_env(@var, "false")
    refute EnvFlags.strict_bool!(@var, true)
  end

  test "any other spelling raises and names the variable (no fail-open)" do
    for bad <- ["ture", "0", "1", "TRUE", "False", "yes", "no", "off"] do
      System.put_env(@var, bad)

      assert_raise ArgumentError, ~r/#{@var} must be exactly "true" or "false"/, fn ->
        EnvFlags.strict_bool!(@var, true)
      end
    end
  end
end
