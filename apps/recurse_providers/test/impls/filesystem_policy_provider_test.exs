defmodule Recurse.Providers.Impls.FilesystemPolicyProviderTest do
  @moduledoc """
  Real-impl tests for `Recurse.Providers.Impls.FilesystemPolicyProvider` (F002 T045).

  Fixtures are the Wave 2-A reference policies under
  `apps/recurse_gateway/priv/reference_policies/` + the canonical entity
  schema at `apps/recurse_gateway/priv/cedar/schema.cedarschema.json`.
  """

  use ExUnit.Case, async: true

  alias Recurse.Providers.Impls.FilesystemPolicyProvider

  @reference_policies_dir Path.expand(
                            "../../../recurse_gateway/priv/reference_policies",
                            __DIR__
                          )
  @entity_schema_path Path.expand(
                        "../../../recurse_gateway/priv/cedar/schema.cedarschema.json",
                        __DIR__
                      )

  defp permissive_bundle_path, do: Path.join(@reference_policies_dir, "permissive_all.cedar")

  defp platform_roles_bundle_path,
    do: Path.join(@reference_policies_dir, "platform_roles.cedar")

  defp init_with(bundle_path) do
    FilesystemPolicyProvider.init(%{
      bundle_path: bundle_path,
      entity_schema_path: @entity_schema_path,
      reload_on_sighup: false
    })
  end

  describe "init/1" do
    test "loads the permissive-all reference bundle" do
      assert {:ok, state} = init_with(permissive_bundle_path())

      assert state.bundle_path == permissive_bundle_path()
      assert state.entity_schema_path == @entity_schema_path
      assert state.active.bundle_bytes == File.read!(permissive_bundle_path())
      assert byte_size(state.active.canonical_hash) == 32
      assert state.active.cedar_version == "4.9.1"
      assert %DateTime{} = state.active.loaded_at
    end

    test "loads the platform_roles reference bundle" do
      assert {:ok, state} = init_with(platform_roles_bundle_path())

      assert state.active.bundle_bytes == File.read!(platform_roles_bundle_path())
      assert byte_size(state.active.canonical_hash) == 32
    end

    test "fails when the bundle file is missing" do
      assert {:error, {:file_read_failure, :bundle, _, :enoent}} =
               FilesystemPolicyProvider.init(%{
                 bundle_path: "/nonexistent/bundle.cedar",
                 entity_schema_path: @entity_schema_path
               })
    end

    test "fails when the entity-schema file is missing" do
      assert {:error, {:file_read_failure, :entity_schema, _, :enoent}} =
               FilesystemPolicyProvider.init(%{
                 bundle_path: permissive_bundle_path(),
                 entity_schema_path: "/nonexistent/schema.json"
               })
    end

    test "fails when bundle config is missing" do
      assert {:error, {:missing_config, :bundle_path}} =
               FilesystemPolicyProvider.init(%{entity_schema_path: @entity_schema_path})
    end

    @tag :tmp_dir
    test "fails on a malformed bundle (Cedar parse failure)", %{tmp_dir: tmp_dir} do
      bad_path = Path.join(tmp_dir, "bundle.cedar")
      File.write!(bad_path, "this is not a cedar policy set {{{")

      assert {:error, {:bundle_parse_failure, _}} =
               FilesystemPolicyProvider.init(%{
                 bundle_path: bad_path,
                 entity_schema_path: @entity_schema_path
               })
    end
  end

  describe "fetch_active_bundle/1" do
    test "returns digest + bytes + canonical_hash + F002 metadata" do
      {:ok, state} = init_with(permissive_bundle_path())

      assert {:ok, active} = FilesystemPolicyProvider.fetch_active_bundle(state)

      expected_bytes = File.read!(permissive_bundle_path())
      assert active.bytes == expected_bytes
      assert active.digest == active.canonical_hash
      assert byte_size(active.canonical_hash) == 32
      assert active.source == :filesystem
      assert active.cedar_version == "4.9.1"
      assert %DateTime{} = active.loaded_at
    end

    test "canonical_hash matches Recurse.Cedar.canonical_hash/1 for the same input" do
      {:ok, state} = init_with(permissive_bundle_path())
      {:ok, active} = FilesystemPolicyProvider.fetch_active_bundle(state)

      expected = Recurse.Cedar.canonical_hash(File.read!(permissive_bundle_path()))
      assert active.canonical_hash == expected
    end
  end

  describe "fetch_bundle/2" do
    test "returns {:ok, _} when digest matches the active bundle" do
      {:ok, state} = init_with(permissive_bundle_path())
      {:ok, %{digest: digest}} = FilesystemPolicyProvider.fetch_active_bundle(state)

      assert {:ok, %{bytes: bytes, canonical_hash: hash}} =
               FilesystemPolicyProvider.fetch_bundle(state, digest)

      assert bytes == File.read!(permissive_bundle_path())
      assert hash == digest
    end

    test "returns {:error, :not_found} for unknown digest" do
      {:ok, state} = init_with(permissive_bundle_path())

      assert {:error, :not_found} = FilesystemPolicyProvider.fetch_bundle(state, <<0::256>>)
    end
  end

  describe "subscribe_supersede_notifications/2" do
    test "returns :ok with a no-op subscription handle" do
      {:ok, state} = init_with(permissive_bundle_path())

      assert {:ok, :noop_subscription} =
               FilesystemPolicyProvider.subscribe_supersede_notifications(state, self())
    end
  end

  describe "simulate/3, blast_radius/4, propose_from_event/2" do
    setup do
      {:ok, state} = init_with(permissive_bundle_path())
      %{state: state}
    end

    test "simulate/3 returns :not_applicable for the standalone slice", %{state: state} do
      assert {:error, {:not_applicable, :standalone_slice}} =
               FilesystemPolicyProvider.simulate(
                 state,
                 "permit(principal, action, resource);",
                 %{principal: %{}, action: %{}, resource: %{}, context: %{}}
               )
    end

    test "blast_radius/4 returns :not_applicable for the standalone slice", %{state: state} do
      identity_ctx = build_identity_context()

      assert {:error, {:not_applicable, :standalone_slice}} =
               FilesystemPolicyProvider.blast_radius(
                 state,
                 "permit(principal, action, resource);",
                 3600,
                 identity_ctx
               )
    end

    test "propose_from_event/2 returns :not_applicable for the standalone slice", %{state: state} do
      assert {:error, {:not_applicable, :standalone_slice}} =
               FilesystemPolicyProvider.propose_from_event(state, %{run_id: "run-1"})
    end
  end

  describe "capabilities/1" do
    test "advertises :filesystem_reload and :canonical_hash_computation" do
      {:ok, state} = init_with(permissive_bundle_path())
      caps = FilesystemPolicyProvider.capabilities(state)
      assert :filesystem_reload in caps
      assert :canonical_hash_computation in caps
    end
  end

  describe "healthcheck/1" do
    test ":ok when both bundle + schema are readable" do
      {:ok, state} = init_with(permissive_bundle_path())
      assert :ok = FilesystemPolicyProvider.healthcheck(state)
    end

    @tag :tmp_dir
    test "{:down, :bundle_missing} when bundle disappeared after boot", %{tmp_dir: tmp_dir} do
      bundle_path = Path.join(tmp_dir, "bundle.cedar")
      File.write!(bundle_path, "permit(principal, action, resource);")
      {:ok, state} = init_with(bundle_path)
      File.rm!(bundle_path)

      assert {:down, {:bundle_missing, ^bundle_path}} =
               FilesystemPolicyProvider.healthcheck(state)
    end
  end

  describe "terminate/2" do
    test "returns :ok" do
      {:ok, state} = init_with(permissive_bundle_path())
      assert :ok = FilesystemPolicyProvider.terminate(state, :normal)
    end
  end

  defp build_identity_context do
    principal =
      Recurse.Shared.Principal.service_account(%{
        issuer: "https://mock-idp.recurse.test",
        account_id: "impl-test"
      })

    Recurse.Shared.IdentityContext.new(%{
      machine_identity: "spiffe://mock.recurse.test/workload/impl-test",
      principal: principal,
      tenant_id: "tenant-test",
      correlation_id: "01HZZZZZZZZZZZZZZZZZZZZZZZ"
    })
  end
end
