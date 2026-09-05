defmodule Recurse.Gateway.ReleaseTest do
  @moduledoc """
  Smoke tests for the F15 release-task module.

  We do NOT actually run migrations here — that requires a live DB
  + risks mutating the test sandbox in unexpected ways. Instead we
  assert the shape of the module:

    * `repos/0` returns the `:ecto_repos` config from
      `:recurse_providers` and is non-empty
    * The configured Repo is `Recurse.Providers.Repo`
    * `migrate/0` is exported with arity 0

  The actual migrator behavior is exercised in CI by running the
  pipeline against the audit-dev RDS instance. This test file is
  the wiring assert.
  """

  use ExUnit.Case, async: true

  # `function_exported?/3` only sees loaded modules; nothing else in the
  # suite touches Release, so load it explicitly (spec 012 S1 — the
  # container entrypoint now invokes `migrate/0`, so this wiring assert
  # matters).
  setup_all do
    {:module, _} = Code.ensure_loaded(Recurse.Gateway.Release)
    :ok
  end

  describe "repos/0" do
    test "returns the configured ecto_repos list" do
      repos = Recurse.Gateway.Release.repos()
      assert is_list(repos)
      assert repos != []
      assert Recurse.Providers.Repo in repos
    end
  end

  describe "module surface" do
    test "exports migrate/0" do
      assert function_exported?(Recurse.Gateway.Release, :migrate, 0)
    end

    test "exports repos/0" do
      assert function_exported?(Recurse.Gateway.Release, :repos, 0)
    end
  end
end
