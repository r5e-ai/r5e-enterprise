defmodule Recurse.Providers.Repo.Migrations.PolicyBundlesWidenSourceCheck do
  @moduledoc """
  Spec 012 S6b (plan §16) — `policy_bundles` becomes the bundle archive.

  `Recurse.Gateway.Policy.BundleArchive` writes one row per bundle a
  loader activates (keyed by `policy_canonical_hash`), so an evidence
  export after a policy change resolves the bundle the receipt was
  evaluated against instead of the live one (`Resolvers.PolicyBundle`
  consults this table first). The F002 CHECK only allowed
  `'filesystem'`; the OCI loader activates bundles too.
  """

  use Ecto.Migration

  def up do
    drop(constraint(:policy_bundles, :policy_bundles_source_check))

    create(
      constraint(
        :policy_bundles,
        :policy_bundles_source_check,
        check: "source IN ('filesystem', 'oci')"
      )
    )
  end

  def down do
    drop(constraint(:policy_bundles, :policy_bundles_source_check))

    create(
      constraint(
        :policy_bundles,
        :policy_bundles_source_check,
        check: "source IN ('filesystem')"
      )
    )
  end
end
