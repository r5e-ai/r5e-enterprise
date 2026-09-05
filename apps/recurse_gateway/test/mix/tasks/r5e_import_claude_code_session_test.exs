defmodule Mix.Tasks.R5e.Import.ClaudeCodeSessionTest do
  # async: false — toggles process-global state (`System.put_env`,
  # `Application.put_env`) under inspection.
  use ExUnit.Case, async: false

  alias Mix.Tasks.R5e.Import.ClaudeCodeSession, as: Task

  @env_var "RECURSE_IMPORT_DEFAULT_TENANT_ID"
  @ulid_fallback "01HZQ3R5E0DOGFOODAUDITDEVA1"

  setup do
    prev_env = System.get_env(@env_var)
    prev_app = Application.get_env(:recurse_gateway, :import)
    System.delete_env(@env_var)
    Application.delete_env(:recurse_gateway, :import)

    on_exit(fn ->
      restore_env(prev_env)
      restore_app(prev_app)
    end)

    :ok
  end

  describe "default_tenant_id/0 — layered resolution" do
    test "env var wins over config and ULID fallback" do
      System.put_env(@env_var, "org_from_env")

      Application.put_env(:recurse_gateway, :import,
        default_tenant_id: "org_from_config"
      )

      assert Task.default_tenant_id() == "org_from_env"
    end

    test "config wins when env var is unset" do
      Application.put_env(:recurse_gateway, :import,
        default_tenant_id: "org_from_config"
      )

      assert Task.default_tenant_id() == "org_from_config"
    end

    test "config wins when env var is set to empty string" do
      System.put_env(@env_var, "")

      Application.put_env(:recurse_gateway, :import,
        default_tenant_id: "org_from_config"
      )

      assert Task.default_tenant_id() == "org_from_config"
    end

    test "falls back to ULID constant when neither env nor config is set" do
      assert Task.default_tenant_id() == @ulid_fallback
    end

    test "falls back to ULID when config key is present but nil-valued" do
      Application.put_env(:recurse_gateway, :import, default_tenant_id: nil)
      assert Task.default_tenant_id() == @ulid_fallback
    end

    test "falls back to ULID when config key is empty string" do
      Application.put_env(:recurse_gateway, :import, default_tenant_id: "")
      assert Task.default_tenant_id() == @ulid_fallback
    end
  end

  defp restore_env(nil), do: System.delete_env(@env_var)
  defp restore_env(value), do: System.put_env(@env_var, value)

  defp restore_app(nil), do: Application.delete_env(:recurse_gateway, :import)
  defp restore_app(value), do: Application.put_env(:recurse_gateway, :import, value)
end
