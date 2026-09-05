defmodule Mix.Tasks.R5e.Audit.CleanseDevDataTest do
  # `async: false` — manipulates process env vars + Mix application config.
  use ExUnit.Case, async: false

  alias Mix.Tasks.R5e.Audit.CleanseDevData

  setup do
    # Snapshot/restore env vars the task reads.
    original_recurse_env = System.get_env("RECURSE_ENV")
    original_mix_env = System.get_env("MIX_ENV")

    on_exit(fn ->
      restore_env("RECURSE_ENV", original_recurse_env)
      restore_env("MIX_ENV", original_mix_env)
    end)

    :ok
  end

  describe "production-guard" do
    test "refuses to run when RECURSE_ENV=production (Mix.raise)" do
      System.put_env("RECURSE_ENV", "production")

      assert_raise Mix.Error, ~r/Refusing to cleanse/, fn ->
        # Argv: no flags. Should hit the env-guard and raise.
        CleanseDevData.run([])
      end
    end

    test "refuses to run when RECURSE_ENV=prod" do
      System.put_env("RECURSE_ENV", "prod")

      assert_raise Mix.Error, ~r/Refusing to cleanse/, fn ->
        CleanseDevData.run([])
      end
    end

    test "refuses to run when RECURSE_ENV is empty/unset and MIX_ENV is prod" do
      System.delete_env("RECURSE_ENV")
      System.put_env("MIX_ENV", "prod")

      assert_raise Mix.Error, ~r/Refusing to cleanse/, fn ->
        CleanseDevData.run([])
      end
    end

    test "raises a clear message including RECURSE_ENV value" do
      System.put_env("RECURSE_ENV", "production")

      err =
        try do
          CleanseDevData.run([])
        rescue
          e in Mix.Error -> e
        end

      assert err.message =~ "production"
      assert err.message =~ "i-understand-this-is-destructive"
    end
  end

  describe "production-guard bypass" do
    test "--i-understand-this-is-destructive bypasses env check (does not raise on guard)" do
      System.put_env("RECURSE_ENV", "production")

      # The task will fail later when it tries to TRUNCATE without a Repo,
      # but it MUST NOT raise the env-guard error — that's the contract
      # this test asserts. We catch any raise and inspect the message
      # to verify it's NOT a guard-rejection.
      err =
        try do
          CleanseDevData.run(["--i-understand-this-is-destructive"])
          nil
        rescue
          e -> e
        end

      if err do
        # Whatever raised, it MUST NOT be the env-guard message.
        message =
          case err do
            %Mix.Error{message: m} -> m
            other -> Exception.message(other)
          end

        refute message =~ "Refusing to cleanse",
               "guard bypass failed — got refusal message: #{message}"
      end
    end

    test "--force is an alias for the bypass" do
      System.put_env("RECURSE_ENV", "production")

      err =
        try do
          CleanseDevData.run(["--force"])
          nil
        rescue
          e -> e
        end

      if err do
        message =
          case err do
            %Mix.Error{message: m} -> m
            other -> Exception.message(other)
          end

        refute message =~ "Refusing to cleanse",
               "--force failed to bypass guard: #{message}"
      end
    end
  end

  describe "allowed environments" do
    test "RECURSE_ENV=development is in allow-list (does not raise on guard)" do
      System.put_env("RECURSE_ENV", "development")

      err =
        try do
          CleanseDevData.run([])
          nil
        rescue
          e -> e
        end

      if err do
        message =
          case err do
            %Mix.Error{message: m} -> m
            other -> Exception.message(other)
          end

        refute message =~ "Refusing to cleanse",
               "development env was rejected: #{message}"
      end
    end

    test "RECURSE_ENV=dogfood is in allow-list" do
      System.put_env("RECURSE_ENV", "dogfood")

      err =
        try do
          CleanseDevData.run([])
          nil
        rescue
          e -> e
        end

      if err do
        message =
          case err do
            %Mix.Error{message: m} -> m
            other -> Exception.message(other)
          end

        refute message =~ "Refusing to cleanse",
               "dogfood env was rejected: #{message}"
      end
    end
  end

  defp restore_env(name, nil), do: System.delete_env(name)
  defp restore_env(name, value), do: System.put_env(name, value)
end
