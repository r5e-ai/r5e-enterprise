defmodule Recurse.Gateway.Policy.BundleArchive do
  @moduledoc """
  Archive every Cedar bundle a loader activates, keyed by its canonical
  hash (spec 012 S6b, plan §16).

  ## Why

  A receipt's `policy_canonical_hash` names the bundle Cedar evaluated
  against. The evidence export resolves that hash through
  `Recurse.Gateway.AuditPlane.Resolvers.PolicyBundle`, which reads the
  F002 `policy_bundles` table first and only then falls back to the live
  bundle. Nothing ever wrote that table, so an export made after any
  policy change packed the *current* bundle and `recurse-verify` step 4
  failed (`loader_drift`). Now `BundleLoader` (filesystem) and
  `OciBundleManager` (OCI) call `archive/1` right after
  `Recurse.Gateway.Policy.Active.update/1`.

  ## Contract

    * One row per distinct `policy_canonical_hash`; re-activating the same
      bytes is a no-op.
    * The archive write is best-effort and NEVER blocks or fails
      activation: it runs after the atomic `:persistent_term` swap, every
      failure (no Repo, no tenant, DB error) is logged at warning and
      `{:error, reason}` is returned to the caller for telemetry only.
    * The table stores the bundle bytes themselves (the resolver reads
      them from the row), so no separate CAS put is made — a second copy
      would add a URI to track without adding anything a verifier could
      check that the row does not already provide.
    * `tenant_id` is the deployment tenant from `ProviderRegistry`
      (Standalone is single-tenant); the tenant row is upserted first so
      a boot-time activation before the first receipt satisfies the FK.

  Off in `:test` via `config :recurse_gateway, policy_bundle_archive_enabled?: false`
  (most tests start a loader without a shared sandbox connection); the
  archive test enables it explicitly.
  """

  alias Recurse.Gateway.Policy.Active
  alias Recurse.Gateway.PolicyBundleRef
  alias Recurse.Gateway.ProviderRegistry
  alias Recurse.Providers.Repo

  require Logger

  @cedar_version "4.9.1"

  @doc """
  Archive the bundle carried by an `Active` envelope. Returns `:ok`
  (archived or already present), `:skipped` (archive disabled or no
  tenant available), or `{:error, reason}` — never raises.
  """
  @spec archive(Active.t()) :: :ok | :skipped | {:error, term()}
  def archive(%Active{source: source, bundle: %PolicyBundleRef{} = ref} = active) do
    if enabled?() do
      case tenant_id() do
        {:ok, tenant_id} -> do_archive(tenant_id, source, ref, active.loaded_at)
        {:error, :no_tenant} -> :skipped
      end
    else
      :skipped
    end
  rescue
    error ->
      Logger.warning(fn ->
        "policy bundle archive raised for #{ref.bundle_id}: #{inspect(error)}"
      end)

      {:error, {:raised, error}}
  end

  @doc "True when a row for `canonical_hash` exists."
  @spec archived?(binary()) :: boolean()
  def archived?(canonical_hash) when is_binary(canonical_hash) do
    case Repo.query("SELECT 1 FROM policy_bundles WHERE policy_canonical_hash = $1 LIMIT 1", [
           canonical_hash
         ]) do
      {:ok, %{rows: [_ | _]}} -> true
      _ -> false
    end
  end

  defp do_archive(tenant_id, source, %PolicyBundleRef{} = ref, loaded_at) do
    if archived?(ref.canonical_hash) do
      :ok
    else
      insert(tenant_id, source, ref, loaded_at)
    end
  end

  defp insert(tenant_id, source, ref, loaded_at) do
    now = DateTime.utc_now()

    tenant_sql = """
    INSERT INTO tenants (tenant_id, display_name, tier, created_at)
    VALUES ($1, $1, 'standalone_gateway', $2)
    ON CONFLICT (tenant_id) DO NOTHING
    """

    bundle_sql = """
    INSERT INTO policy_bundles
      (id, tenant_id, policy_canonical_hash, bundle_bytes, cedar_version, loaded_at, source)
    VALUES ($1, $2, $3, $4, $5, $6, $7)
    """

    result =
      Repo.transaction(fn ->
        with {:ok, _} <- Repo.query(tenant_sql, [tenant_id, now]),
             {:ok, _} <-
               Repo.query(bundle_sql, [
                 Ecto.UUID.bingenerate(),
                 tenant_id,
                 ref.canonical_hash,
                 ref.bundle_bytes,
                 @cedar_version,
                 loaded_at || now,
                 source_string(source)
               ]) do
          :ok
        else
          {:error, reason} -> Repo.rollback(reason)
        end
      end)

    case result do
      {:ok, :ok} ->
        Logger.info("policy bundle archived: canonical_hash=#{ref.bundle_id} source=#{source}")
        :ok

      {:error, reason} ->
        Logger.warning(fn ->
          "policy bundle archive failed for #{ref.bundle_id} (activation unaffected): " <>
            inspect(reason)
        end)

        {:error, reason}
    end
  end

  defp source_string(:oci), do: "oci"
  defp source_string(_), do: "filesystem"

  defp enabled?, do: Application.get_env(:recurse_gateway, :policy_bundle_archive_enabled?, true)

  defp tenant_id do
    case ProviderRegistry.fetch() do
      {:ok, %{tenant_id: tenant_id}} when is_binary(tenant_id) and tenant_id != "" ->
        {:ok, tenant_id}

      _ ->
        case Application.get_env(:recurse_gateway, :llm_proxy_default_tenant_id) do
          tenant_id when is_binary(tenant_id) and tenant_id != "" -> {:ok, tenant_id}
          _ -> {:error, :no_tenant}
        end
    end
  end
end
