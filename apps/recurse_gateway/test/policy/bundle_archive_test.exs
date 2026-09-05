defmodule Recurse.Gateway.Policy.BundleArchiveTest do
  @moduledoc """
  Spec 012 S6b — every bundle the filesystem loader activates is archived
  by canonical hash, and an evidence export made AFTER a reload resolves
  the bundle the receipt was evaluated against from the archive, not the
  live one (`recurse-verify` step 4 no longer sees `loader_drift`).
  """

  use ExUnit.Case, async: false

  setup_all do
    Recurse.Gateway.Test.KernelFixture.boot()
  end

  alias Recurse.Gateway.Attestation.EnvelopeBuilder
  alias Recurse.Gateway.AuditPlane.EvidenceZipBuilder
  alias Recurse.Gateway.AuditPlane.Resolvers.PolicyBundle
  alias Recurse.Gateway.Policy.Active
  alias Recurse.Gateway.Policy.BundleArchive
  alias Recurse.Gateway.Policy.BundleLoader
  alias Recurse.Gateway.ProviderRegistry
  alias Recurse.Gateway.Test.StubStorageProvider
  alias Recurse.Providers.Impls.PostgresMerkleLedger
  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.{SigningKey, Tenant}
  alias Recurse.Providers.Repo
  alias Recurse.Shared.IdentityContext
  alias Recurse.Shared.Principal

  @tenant_id "01TEN_S6B_BUNDLE_ARCHIVE"
  @entity_schema_path Path.expand("../../priv/cedar/schema.cedarschema.json", __DIR__)
  @loader_name Recurse.Gateway.Policy.BundleArchiveTest.Loader
  @bundle_a "permit(principal, action, resource);\n"
  @bundle_b "// tightened\nforbid(principal, action, resource);\n"
  @archive_chain_anchor <<0::size(256)>>

  setup do
    :ok = Ecto.Adapters.SQL.Sandbox.checkout(Repo)
    Ecto.Adapters.SQL.Sandbox.mode(Repo, {:shared, self()})
    Active.erase()
    :ok = StubStorageProvider.reset()

    Repo.insert!(
      Tenant.changeset(%Tenant{}, %{
        tenant_id: @tenant_id,
        display_name: "S6b bundle archive tenant",
        tier: :standalone_gateway,
        created_at: DateTime.utc_now()
      }),
      on_conflict: :nothing,
      conflict_target: :tenant_id
    )

    {:ok, storage_state} = StubStorageProvider.init(%{})

    ProviderRegistry.install_raw!(%{
      llm: {Recurse.Gateway.Test.StubLLM, %{}},
      ledger: {PostgresMerkleLedger, %{repo: Repo, pubsub: Recurse.PubSub, config: %{}}},
      storage: {StubStorageProvider, storage_state},
      secrets: {Recurse.Gateway.Test.StubSecretsProvider, %{}},
      tenant_id: @tenant_id,
      signer: "observed://gateway/s6b-archive-test"
    })

    previous = Application.get_env(:recurse_gateway, :policy_bundle_archive_enabled?)
    Application.put_env(:recurse_gateway, :policy_bundle_archive_enabled?, true)

    on_exit(fn ->
      Application.put_env(:recurse_gateway, :policy_bundle_archive_enabled?, previous)
      ProviderRegistry.uninstall()
      Active.erase()
    end)

    :ok
  end

  @tag :tmp_dir
  test "activation archives; a reload archives the new bundle and the old one stays resolvable",
       %{tmp_dir: tmp_dir} do
    bundle_path = Path.join(tmp_dir, "bundle.cedar")
    File.write!(bundle_path, @bundle_a)

    start_supervised!(
      {BundleLoader,
       [
         name: @loader_name,
         bundle_path: bundle_path,
         entity_schema_path: @entity_schema_path,
         trap_sighup: false
       ]}
    )

    {:ok, %Active{bundle: %{canonical_hash: hash_a}}} = Active.current()
    assert BundleArchive.archived?(hash_a)

    # Re-activating identical bytes is a no-op (one row per hash).
    :ok = BundleLoader.reload(@loader_name)

    # reload/1 casts; the following call from the same sender waits until
    # the complete reload (including archival after Active.update) finishes.
    assert {:ok, %{last_reload_error: nil}} = BundleLoader.status(@loader_name, 5_000)
    assert {:ok, %Active{bundle: %{canonical_hash: ^hash_a}}} = Active.current()

    assert {:ok, %{rows: [[1]]}} =
             Repo.query(
               "SELECT count(*)::int FROM policy_bundles WHERE policy_canonical_hash = $1",
               [hash_a]
             )

    File.write!(bundle_path, @bundle_b)
    :ok = BundleLoader.reload(@loader_name)

    assert {:ok, %{last_reload_error: nil}} = BundleLoader.status(@loader_name, 5_000)
    assert {:ok, %Active{bundle: %{bundle_bytes: @bundle_b}}} = Active.current()

    {:ok, %Active{bundle: %{canonical_hash: hash_b}}} = Active.current()
    assert hash_b != hash_a
    assert BundleArchive.archived?(hash_b)

    # The receipt's hash resolves from the archive while the loader holds B.
    assert {:ok, @bundle_a, :archive, ^hash_a} = PolicyBundle.resolve(hash_a)
    assert {:ok, @bundle_b, :archive, ^hash_b} = PolicyBundle.resolve(hash_b)

    # Export after the reload packs bundle A for a receipt evaluated under A.
    run_id = commit_receipt(hash_a)
    identity_ctx = identity_ctx()
    assert {:ok, zip_bytes} = EvidenceZipBuilder.build(run_id, identity_ctx)
    {:ok, entries} = :zip.unzip(zip_bytes, [:memory])
    files = Map.new(entries, fn {name, bytes} -> {to_string(name), bytes} end)

    assert files["policy_bundle.cedar"] == @bundle_a
    manifest = JSON.decode!(files["manifest.json"])
    assert manifest["policy_bundle_source"] == "archive"
    assert manifest["resolved_policy_hash"] == Base.encode16(hash_a, case: :lower)
  end

  test "archive is best-effort: disabled → :skipped, no tenant → :skipped, never raises" do
    active = %Active{
      source: :filesystem,
      loaded_at: DateTime.utc_now(),
      bundle: %Recurse.Gateway.PolicyBundleRef{
        bundle_id: "ab",
        canonical_hash: :crypto.hash(:sha256, "x"),
        loaded_at: DateTime.utc_now(),
        evaluator_handle: "x",
        bundle_bytes: "x"
      }
    }

    Application.put_env(:recurse_gateway, :policy_bundle_archive_enabled?, false)
    assert BundleArchive.archive(active) == :skipped

    Application.put_env(:recurse_gateway, :policy_bundle_archive_enabled?, true)
    ProviderRegistry.uninstall()
    previous_tenant = Application.get_env(:recurse_gateway, :llm_proxy_default_tenant_id)
    Application.delete_env(:recurse_gateway, :llm_proxy_default_tenant_id)

    try do
      assert BundleArchive.archive(active) == :skipped
    after
      if previous_tenant,
        do: Application.put_env(:recurse_gateway, :llm_proxy_default_tenant_id, previous_tenant)
    end
  end

  defp identity_ctx do
    IdentityContext.new(%{
      tenant_id: @tenant_id,
      machine_identity: "observed://gateway/s6b-archive-test",
      principal: Principal.service_account(%{issuer: "observed://gateway", account_id: "s6b"}),
      correlation_id: Recurse.Shared.Ulid.generate()
    })
  end

  defp commit_receipt(policy_hash) do
    run_id = Ecto.UUID.generate()

    {:ok, envelope} =
      EnvelopeBuilder.build_system(
        :ui_query,
        identity_ctx(),
        %{query_kind: "s6b"},
        run_id: run_id,
        session_id: run_id,
        turn_id: run_id,
        signer: "observed://gateway/s6b-archive-test",
        secrets_provider: ProviderRegistry.secrets_provider(),
        policy_canonical_hash: policy_hash
      )

    {:ok, _} = PostgresMerkleLedger.commit_attestation(envelope)
    seed_signing_key(envelope.signed_predicate.run_id)
    run_id
  end

  defp seed_signing_key(run_id) do
    att = Repo.get!(Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Attestation, run_id)
    now = DateTime.utc_now()

    identity = %{
      tenant_id: @tenant_id,
      kms_key_id: att.signer_kms_key_id,
      key_version: att.signer_key_version,
      public_key_pem: "-----BEGIN PUBLIC KEY-----\nTEST\n-----END PUBLIC KEY-----\n",
      algorithm: :ecdsa_p256,
      first_seen_at: now
    }

    chain_hash =
      :crypto.hash(:sha256, @archive_chain_anchor <> SigningKey.canonical_row_bytes(identity))

    attrs =
      identity
      |> Map.put(:last_seen_at, now)
      |> Map.put(:chain_hash, chain_hash)
      |> Map.put(:inserted_at, now)

    %SigningKey{}
    |> SigningKey.insert_changeset(attrs)
    |> Repo.insert(on_conflict: :nothing, conflict_target: [:kms_key_id, :key_version])
  end
end
