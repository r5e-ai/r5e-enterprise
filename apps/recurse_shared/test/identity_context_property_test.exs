defmodule Recurse.Shared.IdentityContextPropertyTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Recurse.Shared.{IdentityContext, Principal, Ulid}

  describe "new/1 (SC-016 immutability)" do
    property "produces a resolved struct for any valid input" do
      check all(ctx_attrs <- context_attrs()) do
        ctx = IdentityContext.new(ctx_attrs)
        assert IdentityContext.resolved?(ctx)
        assert ctx.machine_identity == ctx_attrs.machine_identity
        assert ctx.principal == ctx_attrs.principal
        assert ctx.tenant_id == ctx_attrs.tenant_id
        assert ctx.correlation_id == ctx_attrs.correlation_id
        assert is_integer(ctx.resolved_at_usec) and ctx.resolved_at_usec > 0
      end
    end
  end

  describe "public API surface (SC-016)" do
    test "exposes exactly new/1 and resolved?/1 — no mutators" do
      exported =
        IdentityContext.module_info(:exports)
        |> Enum.reject(fn {fun, _arity} ->
          fun in [:__struct__, :module_info, :__info__]
        end)
        |> MapSet.new()

      expected =
        MapSet.new([
          {:new, 1},
          {:resolved?, 1}
        ])

      assert exported == expected,
             """
             IdentityContext public API must be exactly new/1 and resolved?/1.
             Extra exports found: #{inspect(MapSet.difference(exported, expected))}
             Missing exports: #{inspect(MapSet.difference(expected, exported))}
             """
    end

    test "no function returns a different IdentityContext given one" do
      # Static assertion: we only allow new/1 and resolved?/1. resolved?/1
      # returns a boolean, new/1 takes a map not a struct. Therefore no
      # function on this module has the "IdentityContext → IdentityContext"
      # signature that would constitute in-plane mutation.
      refute function_exported?(IdentityContext, :update, 1)
      refute function_exported?(IdentityContext, :update, 2)
      refute function_exported?(IdentityContext, :put, 3)
      refute function_exported?(IdentityContext, :with_principal, 2)
      refute function_exported?(IdentityContext, :with_machine_identity, 2)
    end
  end

  # --- generators ---

  defp safe_string do
    StreamData.string(:alphanumeric, min_length: 1, max_length: 16)
  end

  defp principal_gen do
    StreamData.one_of([
      gen all(issuer <- safe_string(), subject <- safe_string()) do
        Principal.obo_human(%{issuer: issuer, subject: subject})
      end,
      gen all(issuer <- safe_string(), account_id <- safe_string()) do
        Principal.service_account(%{issuer: issuer, account_id: account_id})
      end,
      gen all(tail <- safe_string()) do
        Principal.autonomous(%{spiffe_id: "spiffe://example.org/" <> tail})
      end
    ])
  end

  defp context_attrs do
    gen all(
          principal <- principal_gen(),
          machine <- StreamData.one_of([safe_string(), StreamData.constant("spiffe://x/y")])
        ) do
      %{
        machine_identity: machine,
        principal: principal,
        tenant_id: Ulid.generate(),
        correlation_id: Ulid.generate()
      }
    end
  end
end
