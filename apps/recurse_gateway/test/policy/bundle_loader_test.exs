defmodule Recurse.Gateway.Policy.BundleLoaderTest do
  @moduledoc """
  Tests for `Recurse.Gateway.Policy.BundleLoader` (F002 T046).

  Covers:

    * Boot loads the bundle + populates `:persistent_term`.
    * `current_bundle/0` exposes the active reference.
    * `reload/0` refreshes the bundle on disk edit.
    * Reload-failure path keeps the prior bundle active + emits telemetry.
    * Opt-in mtime polling (spec 012 S5): in-place edit, atomic replace,
      broken bundle retained + reported via `status/2`, off by default.
    * Missing bundle at boot fails the GenServer start (fail-closed).

  `async: false` because the BundleLoader owns a global `:persistent_term`
  entry and (in non-test paths) installs an OS signal trap. Each test
  uses a uniquely-named GenServer + tmp_dir to avoid inter-test
  contamination; `:persistent_term` is still a VM-global resource so we
  serialize.
  """

  use ExUnit.Case, async: false

  alias Recurse.Gateway.Policy.Active
  alias Recurse.Gateway.Policy.BundleLoader
  alias Recurse.Gateway.PolicyBundleRef

  @entity_schema_path Path.expand(
                        "../../priv/cedar/schema.cedarschema.json",
                        __DIR__
                      )

  @permissive_policy "permit(principal, action, resource);\n"
  @deny_policy "forbid(principal, action, resource);\n"
  # Same decision as @deny_policy but a different byte count, for the
  # in-place-edit polling tests (see the signature note in the loader).
  @deny_policy_commented "// deny everything\nforbid(principal, action, resource);\n"
  @malformed_policy "not a cedar policy {{{"

  setup_all do
    previous = Application.get_all_env(:r5e)
    Application.stop(:recurse_fold)
    Application.stop(:r5e)

    dir =
      Path.join(System.tmp_dir!(), "r5e-bundle-loader-#{System.unique_integer([:positive])}")

    Application.put_env(:r5e, :data_dir, dir)
    Application.put_env(:r5e, :start_server, false)
    Application.put_env(:r5e, :seed_kernel_policy, true)
    Application.put_env(:r5e, :policy, Recurse.Fold.Policy.Cedar)
    Application.delete_env(:recurse_fold, :engine_build_address)
    {:ok, _} = Application.ensure_all_started(:recurse_fold)
    Active.erase()

    assert Application.fetch_env!(:r5e, :policy) == Recurse.Fold.Policy.Cedar
    assert Application.fetch_env!(:r5e, :seed_kernel_policy)
    assert R5e.Policy.KernelCedar.ready?()

    on_exit(fn ->
      Application.stop(:recurse_fold)
      Application.stop(:r5e)
      for {key, _} <- Application.get_all_env(:r5e), do: Application.delete_env(:r5e, key)
      for {key, value} <- previous, do: Application.put_env(:r5e, key, value)
      Application.delete_env(:recurse_fold, :engine_build_address)
      Active.erase()
      File.rm_rf!(dir)
    end)

    :ok
  end

  setup do
    # Clear the canonical `Active` store between tests. `current_bundle/0`
    # now delegates to `Recurse.Gateway.Policy.Active.current/0`;
    # `Active.erase/0` is the test-only erase-and-no-broadcast path.
    Recurse.Gateway.Policy.Active.erase()
    :ok
  end

  # Test-private name used across the test module. `async: false` + a
  # setup block that erases the persistent_term + start_supervised! (which
  # tears the process down on test exit) makes reuse-by-name safe without
  # dynamic-atom creation. Credo flags `:"name_#{n}"` atoms because they
  # are created at runtime and are not GC'd; using a compile-time alias
  # sidesteps that entirely.
  @loader_name Recurse.Gateway.Policy.BundleLoaderTest.Loader

  describe "boot-time load" do
    @tag :tmp_dir
    test "populates :persistent_term with a PolicyBundleRef", %{tmp_dir: tmp_dir} do
      bundle_path = Path.join(tmp_dir, "bundle.cedar")
      File.write!(bundle_path, @permissive_policy)

      start_supervised!(
        {BundleLoader,
         [
           name: @loader_name,
           bundle_path: bundle_path,
           entity_schema_path: @entity_schema_path,
           trap_sighup: false
         ]}
      )

      assert {:ok, %PolicyBundleRef{} = ref} = unwrap_active()
      assert ref.bundle_bytes == @permissive_policy
      assert byte_size(ref.canonical_hash) == 32
      assert ref.bundle_id == Base.encode16(ref.canonical_hash, case: :lower)
      assert ref.evaluator_handle == ref.bundle_bytes
      assert %DateTime{} = ref.loaded_at
      assert_admitted_projection(ref)
    end

    test "fails to start when bundle file is missing" do
      Process.flag(:trap_exit, true)

      {:error, {:policy_bundle_load_failure, reason}} =
        BundleLoader.start_link(
          name: @loader_name,
          bundle_path: "/nonexistent/bundle.cedar",
          entity_schema_path: @entity_schema_path,
          trap_sighup: false
        )

      assert match?({:file_read_failure, :bundle, _, :enoent}, reason)
    end

    @tag :tmp_dir
    test "fails to start when bundle is malformed", %{tmp_dir: tmp_dir} do
      Process.flag(:trap_exit, true)
      bundle_path = Path.join(tmp_dir, "bundle.cedar")
      File.write!(bundle_path, @malformed_policy)

      {:error, {:policy_bundle_load_failure, reason}} =
        BundleLoader.start_link(
          name: @loader_name,
          bundle_path: bundle_path,
          entity_schema_path: @entity_schema_path,
          trap_sighup: false
        )

      assert match?({:bundle_parse_failure, _}, reason)
    end
  end

  describe "reload/0" do
    @tag :tmp_dir
    test "swaps the active bundle when the file changes", %{tmp_dir: tmp_dir} do
      bundle_path = Path.join(tmp_dir, "bundle.cedar")
      File.write!(bundle_path, @permissive_policy)

      start_supervised!(
        {BundleLoader,
         [
           name: @loader_name,
           bundle_path: bundle_path,
           entity_schema_path: @entity_schema_path,
           trap_sighup: false
         ]}
      )

      {:ok, %PolicyBundleRef{bundle_id: id_before}} = unwrap_active()

      telemetry_ref = attach_telemetry(:reload_success)

      File.write!(bundle_path, @deny_policy)
      BundleLoader.reload(@loader_name)

      assert_receive {:telemetry, ^telemetry_ref, [:recurse, :policy, :reload_success], _, _},
                     1_000

      {:ok, %PolicyBundleRef{bundle_id: id_after, bundle_bytes: bytes_after}} =
        unwrap_active()

      assert id_before != id_after
      assert bytes_after == @deny_policy
    end

    @tag :tmp_dir
    test "keeps previous bundle and emits failure telemetry when reload fails", %{
      tmp_dir: tmp_dir
    } do
      bundle_path = Path.join(tmp_dir, "bundle.cedar")
      File.write!(bundle_path, @permissive_policy)

      start_supervised!(
        {BundleLoader,
         [
           name: @loader_name,
           bundle_path: bundle_path,
           entity_schema_path: @entity_schema_path,
           trap_sighup: false
         ]}
      )

      {:ok, %PolicyBundleRef{} = ref_before} = unwrap_active()

      telemetry_ref = attach_telemetry(:reload_failure)

      File.write!(bundle_path, @malformed_policy)
      BundleLoader.reload(@loader_name)

      assert_receive {:telemetry, ^telemetry_ref, [:recurse, :policy, :reload_failure],
                      measurements, metadata},
                     1_000

      assert measurements == %{count: 1}
      assert match?({:bundle_parse_failure, _}, metadata.reason)

      {:ok, ref_after} = unwrap_active()
      assert ref_after == ref_before
    end
  end

  describe "mtime polling (spec 012 S5)" do
    # 20 ms ticks keep the suite fast; assertions wait on telemetry, not
    # on sleeps, so the exact tick length is not load-bearing.
    @poll_ms 20

    @tag :tmp_dir
    test "detects an in-place edit without SIGHUP and swaps the bundle", %{tmp_dir: tmp_dir} do
      bundle_path = Path.join(tmp_dir, "bundle.cedar")
      File.write!(bundle_path, @permissive_policy)
      start_polling_loader(bundle_path)

      {:ok, %PolicyBundleRef{bundle_id: id_before}} = unwrap_active()

      assert {:ok, %{poll_ms: @poll_ms, active_hash_hex: ^id_before, last_reload_error: nil}} =
               BundleLoader.status(@loader_name)

      telemetry_ref = attach_telemetry(:reload_success)

      # Different byte count from the permissive policy so the
      # {mtime, size, inode} signature changes even inside the same
      # second on the same inode.
      File.write!(bundle_path, @deny_policy_commented)

      assert_receive {:telemetry, ^telemetry_ref, [:recurse, :policy, :reload_success], _,
                      %{trigger: :poll, canonical_hash_hex: id_after}},
                     2_000

      assert id_after != id_before
      {:ok, %PolicyBundleRef{bundle_id: ^id_after, bundle_bytes: bytes}} = unwrap_active()
      assert bytes == @deny_policy_commented

      assert {:ok,
              %{active_hash_hex: ^id_after, last_reload_at: %DateTime{}, last_reload_error: nil}} =
               BundleLoader.status(@loader_name)
    end

    @tag :tmp_dir
    test "detects an atomic replace (write temp + rename)", %{tmp_dir: tmp_dir} do
      bundle_path = Path.join(tmp_dir, "bundle.cedar")
      File.write!(bundle_path, @permissive_policy)
      start_polling_loader(bundle_path)

      {:ok, %PolicyBundleRef{bundle_id: id_before}} = unwrap_active()
      telemetry_ref = attach_telemetry(:reload_success)

      # What policy-sync.sh does: temp file in the same directory, then mv.
      tmp_path = Path.join(tmp_dir, "bundle.cedar.tmp")
      File.write!(tmp_path, @deny_policy)
      :ok = File.rename(tmp_path, bundle_path)

      assert_receive {:telemetry, ^telemetry_ref, [:recurse, :policy, :reload_success], _,
                      %{trigger: :poll, canonical_hash_hex: id_after}},
                     2_000

      assert id_after != id_before
      {:ok, %PolicyBundleRef{bundle_bytes: bytes}} = unwrap_active()
      assert bytes == @deny_policy
    end

    @tag :tmp_dir
    test "a broken bundle keeps the old one active, surfaces the error, and is not retried until the file changes",
         %{tmp_dir: tmp_dir} do
      bundle_path = Path.join(tmp_dir, "bundle.cedar")
      File.write!(bundle_path, @permissive_policy)
      start_polling_loader(bundle_path)

      {:ok, %PolicyBundleRef{} = ref_before} = unwrap_active()
      failure_ref = attach_telemetry(:reload_failure)

      File.write!(bundle_path, @malformed_policy)

      assert_receive {:telemetry, ^failure_ref, [:recurse, :policy, :reload_failure], %{count: 1},
                      %{trigger: :poll, reason: reason}},
                     2_000

      assert match?({:bundle_parse_failure, _}, reason)
      assert {:ok, ^ref_before} = unwrap_active()

      assert {:ok,
              %{
                active_hash_hex: active_hash_hex,
                last_reload_error: %{reason: ^reason, at: %DateTime{}}
              }} = BundleLoader.status(@loader_name)

      assert active_hash_hex == ref_before.bundle_id

      # Same broken file, unchanged signature: no second attempt.
      refute_receive {:telemetry, ^failure_ref, [:recurse, :policy, :reload_failure], _, _},
                     @poll_ms * 5

      # A fixed bundle clears the error.
      success_ref = attach_telemetry(:reload_success)
      File.write!(bundle_path, @deny_policy_commented)

      assert_receive {:telemetry, ^success_ref, [:recurse, :policy, :reload_success], _,
                      %{trigger: :poll}},
                     2_000

      assert {:ok, %{last_reload_error: nil}} = BundleLoader.status(@loader_name)
    end

    @tag :tmp_dir
    test "polling is off by default and reload/1 reports trigger :manual", %{tmp_dir: tmp_dir} do
      bundle_path = Path.join(tmp_dir, "bundle.cedar")
      File.write!(bundle_path, @permissive_policy)

      start_supervised!(
        {BundleLoader,
         [
           name: @loader_name,
           bundle_path: bundle_path,
           entity_schema_path: @entity_schema_path,
           trap_sighup: false
         ]}
      )

      assert {:ok, %{poll_ms: 0}} = BundleLoader.status(@loader_name)

      telemetry_ref = attach_telemetry(:reload_success)
      File.write!(bundle_path, @deny_policy)
      refute_receive {:telemetry, ^telemetry_ref, _, _, _}, 100

      BundleLoader.reload(@loader_name)

      assert_receive {:telemetry, ^telemetry_ref, [:recurse, :policy, :reload_success], _,
                      %{trigger: :manual}},
                     1_000
    end

    test "status/2 reports :not_running when no loader is registered" do
      assert {:error, :not_running} = BundleLoader.status(@loader_name)
    end

    defp start_polling_loader(bundle_path) do
      start_supervised!(
        {BundleLoader,
         [
           name: @loader_name,
           bundle_path: bundle_path,
           entity_schema_path: @entity_schema_path,
           trap_sighup: false,
           poll_ms: @poll_ms
         ]}
      )
    end
  end

  describe "current_bundle/0" do
    test "returns {:error, :not_loaded} before any BundleLoader has started" do
      assert {:error, :not_loaded} = unwrap_active()
    end
  end

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  # Unwrap the canonical `Active` envelope to a bare `%PolicyBundleRef{}`,
  # mirroring what `BundleLoader.current_bundle/0` did pre-canonical-Active.
  # Equivalent to `BundleLoader.current_bundle/0` but without the
  # deprecation warning on every call site.
  defp unwrap_active do
    case Active.current() do
      {:ok, %Active{bundle: %PolicyBundleRef{} = ref}} -> {:ok, ref}
      {:error, :not_loaded} -> {:error, :not_loaded}
    end
  end

  defp assert_admitted_projection(%PolicyBundleRef{bundle_bytes: bytes}) do
    source_ref = "bytes:sha256:" <> Base.encode16(:crypto.hash(:sha256, bytes), case: :lower)

    assert {:ok, entry} = Recurse.Fold.Policy.Cedar.active_bundle()
    assert get_in(entry, ["spec", "sourceRef", "$ref"]) == source_ref
    assert {:ok, ^bytes} = R5e.CAS.get(source_ref)

    event =
      Enum.find(R5e.Log.read_events(), fn event ->
        R5e.Admission.event_ref(event) == entry["admissionEvent"]
      end)

    assert is_map(event)
    assert {:ok, payload} = R5e.Log.payload(event)
    assert payload["policy"]["engine"] == "cedar"
  end

  defp attach_telemetry(event_suffix) do
    ref = make_ref()
    test_pid = self()
    event = [:recurse, :policy, event_suffix]
    handler_id = "bundle_loader_test_#{inspect(ref)}"

    :telemetry.attach(
      handler_id,
      event,
      fn evt, measurements, metadata, _config ->
        send(test_pid, {:telemetry, ref, evt, measurements, metadata})
      end,
      nil
    )

    on_exit(fn -> :telemetry.detach(handler_id) end)

    ref
  end
end
