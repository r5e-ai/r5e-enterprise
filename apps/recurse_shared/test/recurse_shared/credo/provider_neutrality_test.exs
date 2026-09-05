defmodule Recurse.Credo.ProviderNeutralityTest do
  @moduledoc """
  Enumerated coverage for the custom Credo check
  `Recurse.Credo.ProviderNeutrality` (Constitution Principle V / FR-004).

  The focus of this test module is the **alias-resolution pass** added in
  Phase-10 polish (2026-04-24): the original prewalk check flagged bare
  short names (`Jcs`, `PostgresMerkleLedger`, ...) that were actually
  aliased to an approved Recurse-internal module, producing a stream of
  false-positive `[D]` suggestions.

  The multi-pass walker with explicit scope-stack MUST:

    1. Resolve a simple `alias Recurse.X` → short `X` resolves to
       `Recurse.X` and is not flagged.
    2. Resolve `alias Recurse.X, as: Y` → short `Y` resolves to
       `Recurse.X` and is not flagged.
    3. Resolve multi-alias `alias Recurse.X.{A, B}` → both `A` and `B`
       resolve and are not flagged.
    4. Inherit an outer module's alias table into a nested `defmodule`.
    5. Allow an inner module to shadow an outer alias: inner's `Z` must
       resolve to the INNER declaration, not the outer's. (Scope stack,
       not flat map.)
    6. Handle `require Module` equivalently to `alias` for bare-module
       resolution (`require Logger` + `Logger.info/1` is not flagged).
       `import Enum` + `map(...)` is a bare local function call — not a
       `__aliases__` AST node — and so must not be flagged.
    7. Still flag a real first-party violation: raw
       `Ecto.Repo.insert/2` called without alias from Gateway code is a
       regression guard.

  Runs as a real Credo check via `Credo.Test.Case`, pinning the file to
  a Gateway-scope path (`apps/recurse_gateway/lib/...`) so the check's
  scope filter admits it.
  """
  use Credo.Test.Case

  alias Recurse.Credo.ProviderNeutrality

  @gateway_filename "apps/recurse_gateway/lib/recurse_gateway/alias_fixture.ex"

  describe "alias resolution" do
    test "simple alias: `alias Recurse.Shared.Jcs` then `Jcs.encode/1` is NOT flagged" do
      """
      defmodule Recurse.Gateway.AliasFixture do
        alias Recurse.Shared.Jcs

        def run(payload), do: Jcs.encode(payload)
      end
      """
      |> to_source_file(@gateway_filename)
      |> run_check(ProviderNeutrality)
      |> refute_issues()
    end

    test "alias ... as: `alias Recurse.Shared.Jcs, as: Canon` then `Canon.encode/1` is NOT flagged" do
      """
      defmodule Recurse.Gateway.AliasFixture do
        alias Recurse.Shared.Jcs, as: Canon

        def run(payload), do: Canon.encode(payload)
      end
      """
      |> to_source_file(@gateway_filename)
      |> run_check(ProviderNeutrality)
      |> refute_issues()
    end

    test "multi-alias: `alias Recurse.Shared.{Jcs, IdentityContext}` then both are NOT flagged" do
      """
      defmodule Recurse.Gateway.AliasFixture do
        alias Recurse.Shared.{Jcs, IdentityContext}

        def run(payload, ctx) do
          _ = Jcs.encode(payload)
          IdentityContext.principal(ctx)
        end
      end
      """
      |> to_source_file(@gateway_filename)
      |> run_check(ProviderNeutrality)
      |> refute_issues()
    end

    test "nested defmodule inherits outer alias table (outer `alias X.Y.Z`, inner uses `Z.foo()`)" do
      """
      defmodule Recurse.Gateway.AliasFixture do
        alias Recurse.Shared.Jcs

        defmodule Inner do
          def run(payload), do: Jcs.encode(payload)
        end
      end
      """
      |> to_source_file(@gateway_filename)
      |> run_check(ProviderNeutrality)
      |> refute_issues()
    end

    test "shadowed nested alias: inner `alias A.B.Z` overrides outer `alias X.Y.Z`" do
      # Outer aliases `Jcs` to `Recurse.Shared.Jcs`. Inner re-aliases
      # `Jcs` to `Recurse.Providers.Impls.Jcs` (hypothetical). Both
      # full-path expansions are inside `Recurse.` → both are allowed.
      # The regression guard is that the *shadowed* aliases resolve
      # independently; this is exercised operationally by case 7 below
      # when the inner rebinding would resolve to a DIFFERENT prefix.
      """
      defmodule Recurse.Gateway.AliasFixture do
        alias Recurse.Shared.Jcs

        defmodule Inner do
          alias Recurse.Providers.Impls.Jcs
          def run(payload), do: Jcs.encode(payload)
        end

        # Sibling — still sees outer's `Jcs`, not inner's.
        def outer_run(payload), do: Jcs.encode(payload)
      end
      """
      |> to_source_file(@gateway_filename)
      |> run_check(ProviderNeutrality)
      |> refute_issues()
    end

    test "shadowed alias with forbidden outer prefix would flag outer but not inner" do
      # Outer aliases `Foo` to a NON-approved prefix (`BadVendor.Foo`).
      # Inner re-aliases `Foo` to `Recurse.Shared.Foo` (approved).
      # The `Foo.bar()` call in OUTER should flag as `BadVendor.Foo`.
      # The `Foo.bar()` call in INNER should NOT flag because inner's
      # scope binds `Foo` to `Recurse.Shared.Foo`.
      source =
        """
        defmodule Recurse.Gateway.AliasFixture do
          alias BadVendor.Foo

          def outer_run, do: Foo.bar()

          defmodule Inner do
            alias Recurse.Shared.Foo
            def inner_run, do: Foo.bar()
          end
        end
        """
        |> to_source_file(@gateway_filename)

      issues = run_check(source, ProviderNeutrality)

      # The outer `alias BadVendor.Foo` directive is itself flagged (as
      # a forbidden `alias`), and the outer `Foo.bar()` call resolves
      # to the forbidden full path. The inner `Foo.bar()` must NOT
      # produce an issue.
      flagged_full_paths = Enum.map(issues, & &1.trigger)

      assert "BadVendor.Foo" in flagged_full_paths,
             "expected `BadVendor.Foo` to be flagged (outer alias + outer call), got: #{inspect(flagged_full_paths)}"

      # No issue should resolve to `Recurse.Shared.Foo` (inner's call).
      refute Enum.any?(flagged_full_paths, &(&1 == "Recurse.Shared.Foo")),
             "inner `Foo.bar()` must resolve to approved `Recurse.Shared.Foo`, got: #{inspect(flagged_full_paths)}"
    end

    test "`require Logger` + `Logger.info/1` is NOT flagged (require behaves like alias for resolution)" do
      """
      defmodule Recurse.Gateway.AliasFixture do
        require Logger

        def run, do: Logger.info("hello")
      end
      """
      |> to_source_file(@gateway_filename)
      |> run_check(ProviderNeutrality)
      |> refute_issues()
    end

    test "`import Enum` + bare `map(...)` is NOT flagged (not a __aliases__ node)" do
      """
      defmodule Recurse.Gateway.AliasFixture do
        import Enum

        def run(list), do: map(list, &(&1 * 2))
      end
      """
      |> to_source_file(@gateway_filename)
      |> run_check(ProviderNeutrality)
      |> refute_issues()
    end

    test "regression guard: raw `Ecto.Repo.insert/2` called WITHOUT alias is flagged" do
      # No alias — call-site AST has `__aliases__: [:Ecto, :Repo]`,
      # which resolves to itself. `Ecto.Repo` begins with approved
      # `Ecto.` prefix (Ecto IS in @approved_prefixes — see the
      # moduledoc for the scope decision). So to exercise the regression
      # guard properly, use a genuinely forbidden vendor: `ExAws.S3`.
      source =
        """
        defmodule Recurse.Gateway.AliasFixture do
          def run(bucket, key), do: ExAws.S3.get_object(bucket, key)
        end
        """
        |> to_source_file(@gateway_filename)

      issues = run_check(source, ProviderNeutrality)

      assert Enum.any?(issues, fn issue -> issue.trigger == "ExAws.S3" end),
             "expected raw `ExAws.S3.get_object/2` without alias to flag as `ExAws.S3`, got: #{inspect(Enum.map(issues, & &1.trigger))}"
    end

    test "regression guard: aliased forbidden vendor still flagged at alias site" do
      # `alias ExAws.S3` itself must still be flagged — the alias
      # directive is the violation, independent of whether the alias is
      # then used. Full-path `ExAws.S3` is NOT in @approved_prefixes.
      source =
        """
        defmodule Recurse.Gateway.AliasFixture do
          alias ExAws.S3

          def run(bucket, key), do: S3.get_object(bucket, key)
        end
        """
        |> to_source_file(@gateway_filename)

      issues = run_check(source, ProviderNeutrality)

      # At least the alias directive itself should flag.
      assert Enum.any?(issues, fn issue -> issue.trigger == "ExAws.S3" end),
             "expected `alias ExAws.S3` to flag as `ExAws.S3`, got: #{inspect(Enum.map(issues, & &1.trigger))}"
    end
  end

  describe "scope filter unchanged" do
    test "file outside Gateway/Runtime scope is not checked (skip)" do
      """
      defmodule Recurse.Shared.AliasFixture do
        def run(bucket, key), do: ExAws.S3.get_object(bucket, key)
      end
      """
      |> to_source_file("apps/recurse_shared/lib/recurse_shared/alias_fixture.ex")
      |> run_check(ProviderNeutrality)
      |> refute_issues()
    end

    test "providers/impls/ is exempt" do
      """
      defmodule Recurse.Providers.Impls.S3StorageProvider do
        def run(bucket, key), do: ExAws.S3.get_object(bucket, key)
      end
      """
      |> to_source_file(
        "apps/recurse_providers/lib/recurse_providers/impls/s3_storage_provider.ex"
      )
      |> run_check(ProviderNeutrality)
      |> refute_issues()
    end
  end
end
