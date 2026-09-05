defmodule Recurse.Gateway.AuditPlane.TenantGuard do
  @moduledoc """
  Validates that the calling identity's tenant matches the resource's
  tenant — defence-in-depth against accidentally serving cross-tenant
  data even though Standalone is single-tenant in Phase 1.

  ## Why this module exists (Issue #29 / Constitution Principle VII)

  Today only `PayloadBroker.authorize_tenant/2` (line 164) performs this
  check. `ReceiptsHandler`, `ExportHandler`, `LocalVerifyHandler`, and
  `SessionTimelineHandler` all silently trust the JWT's `tenant_id`
  claim and never re-validate it against the attestation's
  `tenant_id`. The bug is dormant because Standalone is single-tenant
  (every attestation has the same tenant_id as every JWT), but the
  moment we ship the multi-tenant story (F005+ or any deployment
  hosting two tenants on the same gateway), the gap becomes a
  cross-tenant data-leak vector.

  Per Constitution Principle VII this module retires the inline check
  in `PayloadBroker` AND adds the check at the four other audit-plane
  handlers that didn't have it. One source for "is the caller allowed
  to read this tenant's data."

  ## Iron Law

  Pure module. No process. Single function on data.

  ## Caller pattern

      with {:ok, attestation} <- fetch_attestation(...),
           :ok <- TenantGuard.validate(ctx, attestation),
           ... do
        # serve
      else
        {:error, :tenant_mismatch} ->
          # `Authz.send_forbidden/2` discriminates on the reason atom
          # and emits `ERR_FORBIDDEN_TENANT` for tenant-scope denies.
          # See `Recurse.Gateway.AuditPlane.Authz` moduledoc.
          Authz.send_forbidden(conn, :tenant_mismatch)
      end
  """

  alias Recurse.Shared.IdentityContext

  @doc """
  Validates that the caller's tenant_id matches the resource's
  tenant_id. Accepts either a struct (Attestation, IdentityContext)
  or any map carrying a `:tenant_id` key — handlers vary in what
  they fetch (some pre-decode into structs, some carry maps from
  raw query results).

  Returns `:ok` on match, `{:error, :tenant_mismatch}` otherwise.
  """
  @spec validate(IdentityContext.t() | %{tenant_id: String.t()}, %{tenant_id: String.t()}) ::
          :ok | {:error, :tenant_mismatch}
  def validate(%IdentityContext{tenant_id: caller}, %{tenant_id: caller})
      when is_binary(caller),
      do: :ok

  def validate(%{tenant_id: caller}, %{tenant_id: caller}) when is_binary(caller), do: :ok
  def validate(_caller, _resource), do: {:error, :tenant_mismatch}
end
