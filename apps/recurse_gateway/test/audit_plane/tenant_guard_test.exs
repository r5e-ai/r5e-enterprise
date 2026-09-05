defmodule Recurse.Gateway.AuditPlane.TenantGuardTest do
  @moduledoc """
  Issue #29 / B9. Pure unit tests; no DB, no Repo, no providers.
  """

  use ExUnit.Case, async: true

  alias Recurse.Gateway.AuditPlane.TenantGuard
  alias Recurse.Shared.IdentityContext

  describe "validate/2" do
    test "matching tenant_ids on IdentityContext + map -> :ok" do
      ctx = %IdentityContext{
        machine_identity: nil,
        principal: %{kind: :service_account, subject: "svc"},
        tenant_id: "org_01HZQ3R5E0DOGFOOD",
        correlation_id: "corr-1",
        resolved_at_usec: 1
      }

      assert TenantGuard.validate(ctx, %{tenant_id: "org_01HZQ3R5E0DOGFOOD"}) == :ok
    end

    test "matching tenant_ids on plain maps -> :ok" do
      assert TenantGuard.validate(
               %{tenant_id: "org_TEST"},
               %{tenant_id: "org_TEST"}
             ) == :ok
    end

    test "mismatched tenant_ids -> {:error, :tenant_mismatch}" do
      ctx = %IdentityContext{
        machine_identity: nil,
        principal: %{kind: :service_account, subject: "svc"},
        tenant_id: "org_A",
        correlation_id: "corr-1",
        resolved_at_usec: 1
      }

      assert TenantGuard.validate(ctx, %{tenant_id: "org_B"}) ==
               {:error, :tenant_mismatch}
    end

    test "missing tenant_id on resource -> {:error, :tenant_mismatch}" do
      assert TenantGuard.validate(%{tenant_id: "org_A"}, %{}) ==
               {:error, :tenant_mismatch}
    end

    test "missing tenant_id on caller -> {:error, :tenant_mismatch}" do
      assert TenantGuard.validate(%{}, %{tenant_id: "org_A"}) ==
               {:error, :tenant_mismatch}
    end

    test "nil tenant_id values -> {:error, :tenant_mismatch}" do
      assert TenantGuard.validate(%{tenant_id: nil}, %{tenant_id: nil}) ==
               {:error, :tenant_mismatch}
    end

    test "IdentityContext with nil tenant_id -> {:error, :tenant_mismatch} (GAN regression)" do
      # Regression pin from MR !31 GAN review (claude_cli + gemini_cli
      # 2-adapter consensus): the IdentityContext clause was missing the
      # `is_binary(caller)` guard, allowing %IdentityContext{tenant_id:
      # nil} vs %{tenant_id: nil} to match-and-return :ok. Defeats the
      # cross-tenant defence-in-depth invariant the moment a misconfigured
      # PrincipalProvider or buggy IdentityContextBuilder produces a
      # nil-tenant context.
      ctx = %IdentityContext{
        machine_identity: nil,
        principal: %{kind: :service_account, subject: "svc"},
        tenant_id: nil,
        correlation_id: "corr-1",
        resolved_at_usec: 1
      }

      assert TenantGuard.validate(ctx, %{tenant_id: nil}) ==
               {:error, :tenant_mismatch}
    end

    test "non-binary tenant_id -> {:error, :tenant_mismatch}" do
      assert TenantGuard.validate(%{tenant_id: 42}, %{tenant_id: 42}) ==
               {:error, :tenant_mismatch}
    end
  end
end
