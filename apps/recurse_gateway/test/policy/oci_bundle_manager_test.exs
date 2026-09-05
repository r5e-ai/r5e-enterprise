defmodule Recurse.Gateway.Policy.OciBundleManagerTest do
  @moduledoc """
  Tests for `Recurse.Gateway.Policy.OciBundleManager` (MR !119, Spec A).

  Covers:

    * Successful boot — provider init returns ok, persistent_term populated.
    * Boot fails closed when provider init returns an error.
    * `active_bundle/0` reads the cached bundle via persistent_term.
    * `activate/2` happy path — atomic swap, PubSub broadcast,
      persistent_term updated, GenServer state replaced.
    * `activate/2` failure — old bundle remains active, error returned.

  `async: false` because the GenServer registers under a fixed name
  AND owns a global `:persistent_term` entry. We pass test-scoped
  `:name` and `:persistent_term_key` overrides where possible to keep
  cross-test contamination minimal, but serialize the suite to be
  conservative.
  """

  use ExUnit.Case, async: false

  alias Recurse.Gateway.Policy.OciBundleManager

  # ---------------------------------------------------------------------------
  # Fake provider — implements the OciPolicyProvider contract surface this
  # GenServer cares about (`init/1`, `fetch_active_bundle/1`,
  # `terminate/2`). Driven by a stash key supplied via config.
  # ---------------------------------------------------------------------------

  defmodule FakeProvider do
    @behaviour Recurse.Providers.PolicyProvider

    @impl true
    def init(config) do
      # Drive the response purely off the ETS stash so callers can stage
      # different responses for the boot path vs. the activate path
      # without threading state through.
      case :ets.lookup(:oci_bundle_manager_test_stash, :init_response) do
        [{:init_response, {:ok, state}}] -> {:ok, state}
        [{:init_response, {:error, reason}}] -> {:error, reason}
        [] -> {:ok, %{ref: Map.get(config, :ref), bundle: default_bundle(config)}}
      end
    end

    @impl true
    def fetch_active_bundle(%{bundle: bundle}), do: {:ok, bundle}
    def fetch_active_bundle(_), do: {:error, :no_active_bundle}

    @impl true
    def fetch_bundle(_state, _digest), do: {:error, :not_found}

    @impl true
    def subscribe_supersede_notifications(_state, _callback),
      do: {:ok, "policy_provider:supersede"}

    @impl true
    def simulate(_state, _candidate, _mock), do: {:error, :not_applicable}

    @impl true
    def blast_radius(_state, _candidate, _window, _ctx), do: {:error, :not_applicable}

    @impl true
    def propose_from_event(_state, _event), do: {:error, :not_applicable}

    @impl true
    def capabilities(_state), do: [:test]

    @impl true
    def healthcheck(_state), do: :ok

    @impl true
    def terminate(_state, _reason), do: :ok

    defp default_bundle(config) do
      ref = Map.get(config, :ref, "test-ref")

      %{
        digest: :crypto.hash(:sha256, "bundle-bytes-for-#{ref}"),
        bytes: "permit(principal, action, resource);\n",
        canonical_hash: :crypto.hash(:sha256, "canonical-#{ref}"),
        cedar_version: "4.9.1",
        loaded_at: DateTime.utc_now(),
        source: :oci,
        source_ref: "test.registry/cedar-policies/test:#{ref}",
        manifest: %{"version" => ref, "name" => "test-bundle"}
      }
    end
  end

  setup do
    # Use ETS to coordinate FakeProvider responses across tests.
    if :ets.info(:oci_bundle_manager_test_stash) == :undefined do
      :ets.new(:oci_bundle_manager_test_stash, [:set, :public, :named_table])
    end

    :ets.delete_all_objects(:oci_bundle_manager_test_stash)

    # Ensure Phoenix.PubSub is running for broadcast tests. Reuse the
    # umbrella's `Recurse.PubSub` if it's already up (the
    # recurse_providers Application starts it); otherwise start a
    # test-scoped PubSub child.
    pubsub_name =
      if Process.whereis(Recurse.PubSub) do
        Recurse.PubSub
      else
        name = :oci_bundle_manager_test_pubsub

        case Process.whereis(name) do
          nil ->
            start_supervised!({Phoenix.PubSub, name: name})
            name

          _pid ->
            name
        end
      end

    # Test-scoped persistent_term key for the legacy
    # {:recurse_active_cedar_bundle, :default} entry to avoid
    # contamination across tests / dev iex sessions.
    pt_key = {:oci_bundle_manager_test, make_ref()}
    on_exit(fn -> :persistent_term.erase(pt_key) end)

    # `write_to_active?: false` is passed in every start_supervised!
    # below so this test never touches the canonical
    # `Recurse.Gateway.Policy.Active` store; tests focus on the
    # GenServer's own contract surface.

    {:ok, pt_key: pt_key, pubsub_name: pubsub_name}
  end

  describe "start_link/1 (boot)" do
    test "populates persistent_term on successful provider init", %{
      pt_key: pt_key,
      pubsub_name: pubsub
    } do
      ref = "1.0.0-init"
      bundle = build_bundle(ref)
      provider_state = %{ref: ref, bundle: bundle}
      :ets.insert(:oci_bundle_manager_test_stash, {:init_response, {:ok, provider_state}})

      pid =
        start_supervised!(
          {OciBundleManager,
           name: nil,
           config: %{ref: ref},
           provider_module: FakeProvider,
           persistent_term_key: pt_key,
           pubsub: pubsub,
           write_to_active?: false}
        )

      assert is_pid(pid)
      assert {:ok, ^bundle} = OciBundleManager.active_bundle(pt_key)
    end

    test "fails to start when provider init returns error", %{
      pt_key: pt_key,
      pubsub_name: pubsub
    } do
      Process.flag(:trap_exit, true)

      :ets.insert(
        :oci_bundle_manager_test_stash,
        {:init_response, {:error, :registry_unreachable}}
      )

      assert {:error, {:oci_bundle_load_failure, :registry_unreachable}} =
               OciBundleManager.start_link(
                 name: nil,
                 config: %{ref: "1.0.0-bad"},
                 provider_module: FakeProvider,
                 persistent_term_key: pt_key,
                 pubsub: pubsub
               )

      assert {:error, :not_loaded} = OciBundleManager.active_bundle(pt_key)
    end
  end

  describe "active_bundle/1" do
    test "returns {:error, :not_loaded} when persistent_term is empty", %{pt_key: pt_key} do
      assert {:error, :not_loaded} = OciBundleManager.active_bundle(pt_key)
    end
  end

  describe "activate/3 (hot-reload)" do
    test "swaps the bundle, broadcasts PubSub, and updates persistent_term", %{
      pt_key: pt_key,
      pubsub_name: pubsub
    } do
      original_ref = "1.0.0-orig"
      new_ref = "1.0.1-new"
      original_bundle = build_bundle(original_ref)
      new_bundle = build_bundle(new_ref)

      :ets.insert(
        :oci_bundle_manager_test_stash,
        {:init_response, {:ok, %{ref: original_ref, bundle: original_bundle}}}
      )

      pid =
        start_supervised!(
          {OciBundleManager,
           name: nil,
           config: %{ref: original_ref},
           provider_module: FakeProvider,
           persistent_term_key: pt_key,
           pubsub: pubsub,
           write_to_active?: false}
        )

      :ok = Phoenix.PubSub.subscribe(pubsub, OciBundleManager.pubsub_topic())

      # Swap stash for the activate call
      :ets.insert(
        :oci_bundle_manager_test_stash,
        {:init_response, {:ok, %{ref: new_ref, bundle: new_bundle}}}
      )

      {:ok, result} = OciBundleManager.activate(new_ref, server: pid)

      assert result.ref == new_ref
      assert result.new_digest == "sha256:" <> Base.encode16(new_bundle.digest, case: :lower)
      assert result.old_digest == "sha256:" <> Base.encode16(original_bundle.digest, case: :lower)
      assert %DateTime{} = result.activated_at

      assert_receive {:bundle_superseded, payload}, 2_000

      assert payload.old_digest ==
               "sha256:" <> Base.encode16(original_bundle.digest, case: :lower)

      assert payload.new_digest ==
               "sha256:" <> Base.encode16(new_bundle.digest, case: :lower)

      assert payload.source_ref == new_bundle.source_ref

      assert {:ok, ^new_bundle} = OciBundleManager.active_bundle(pt_key)
    end

    test "keeps the old bundle when activate fails (init returns error)", %{
      pt_key: pt_key,
      pubsub_name: pubsub
    } do
      original_ref = "1.0.0-orig"
      new_ref = "1.0.1-bad"
      original_bundle = build_bundle(original_ref)

      :ets.insert(
        :oci_bundle_manager_test_stash,
        {:init_response, {:ok, %{ref: original_ref, bundle: original_bundle}}}
      )

      pid =
        start_supervised!(
          {OciBundleManager,
           name: nil,
           config: %{ref: original_ref},
           provider_module: FakeProvider,
           persistent_term_key: pt_key,
           pubsub: pubsub,
           write_to_active?: false}
        )

      :ok = Phoenix.PubSub.subscribe(pubsub, OciBundleManager.pubsub_topic())

      # Make the activate call fail at init
      :ets.insert(
        :oci_bundle_manager_test_stash,
        {:init_response, {:error, :cosign_signature_mismatch}}
      )

      assert {:error, :cosign_signature_mismatch} =
               OciBundleManager.activate(new_ref, server: pid)

      # Old bundle still active in persistent_term
      assert {:ok, ^original_bundle} = OciBundleManager.active_bundle(pt_key)

      # No PubSub broadcast on failure
      refute_receive {:bundle_superseded, _}, 200
    end

    test "keeps the old bundle when fetch_active_bundle returns error after init", %{
      pt_key: pt_key,
      pubsub_name: pubsub
    } do
      original_ref = "1.0.0-orig"
      new_ref = "1.0.1-bundleless"
      original_bundle = build_bundle(original_ref)

      :ets.insert(
        :oci_bundle_manager_test_stash,
        {:init_response, {:ok, %{ref: original_ref, bundle: original_bundle}}}
      )

      pid =
        start_supervised!(
          {OciBundleManager,
           name: nil,
           config: %{ref: original_ref},
           provider_module: FakeProvider,
           persistent_term_key: pt_key,
           pubsub: pubsub,
           write_to_active?: false}
        )

      # Provider init succeeds but state has no :bundle (so
      # fetch_active_bundle returns {:error, :no_active_bundle})
      :ets.insert(
        :oci_bundle_manager_test_stash,
        {:init_response, {:ok, %{ref: new_ref}}}
      )

      assert {:error, :no_active_bundle} = OciBundleManager.activate(new_ref, server: pid)

      assert {:ok, ^original_bundle} = OciBundleManager.active_bundle(pt_key)
    end
  end

  describe "config_from_env!/0" do
    test "raises when a required env var is missing" do
      restore =
        capture_envs([
          "R5E_CEDAR_BUNDLE_REGISTRY",
          "R5E_CEDAR_BUNDLE_REPOSITORY",
          "R5E_CEDAR_BUNDLE_REF",
          "R5E_CEDAR_COSIGN_KEY_ARN",
          "R5E_CEDAR_BUNDLE_AUTH"
        ])

      System.delete_env("R5E_CEDAR_BUNDLE_REGISTRY")

      assert_raise RuntimeError, ~r/R5E_CEDAR_BUNDLE_REGISTRY/, fn ->
        OciBundleManager.config_from_env!()
      end

      restore.()
    end

    test "parses a bearer auth env var" do
      restore =
        capture_envs([
          "R5E_CEDAR_BUNDLE_REGISTRY",
          "R5E_CEDAR_BUNDLE_REPOSITORY",
          "R5E_CEDAR_BUNDLE_REF",
          "R5E_CEDAR_COSIGN_KEY_ARN",
          "R5E_CEDAR_BUNDLE_AUTH"
        ])

      System.put_env("R5E_CEDAR_BUNDLE_REGISTRY", "registry.example.com")
      System.put_env("R5E_CEDAR_BUNDLE_REPOSITORY", "cedar/policies")
      System.put_env("R5E_CEDAR_BUNDLE_REF", "1.0.0")
      System.put_env("R5E_CEDAR_COSIGN_KEY_ARN", "alias/test-cosign")
      System.put_env("R5E_CEDAR_BUNDLE_AUTH", ~s({"type":"bearer","token":"abc123"}))

      opts = OciBundleManager.config_from_env!()
      config = Keyword.fetch!(opts, :config)

      assert config.registry == "registry.example.com"
      assert config.repository == "cedar/policies"
      assert config.ref == "1.0.0"
      assert config.cosign_key_arn == "alias/test-cosign"
      assert config.auth == {:bearer, "abc123"}

      restore.()
    end

    test "parses an ecr_irsa auth env var" do
      restore =
        capture_envs([
          "R5E_CEDAR_BUNDLE_REGISTRY",
          "R5E_CEDAR_BUNDLE_REPOSITORY",
          "R5E_CEDAR_BUNDLE_REF",
          "R5E_CEDAR_COSIGN_KEY_ARN",
          "R5E_CEDAR_BUNDLE_AUTH"
        ])

      System.put_env("R5E_CEDAR_BUNDLE_REGISTRY", "123456789012.dkr.ecr.us-west-2.amazonaws.com")
      System.put_env("R5E_CEDAR_BUNDLE_REPOSITORY", "cedar-policies/platform-roles")
      System.put_env("R5E_CEDAR_BUNDLE_REF", "0.1.0-abc")
      System.put_env("R5E_CEDAR_COSIGN_KEY_ARN", "alias/r5e-cosign")
      System.put_env("R5E_CEDAR_BUNDLE_AUTH", ~s({"type":"ecr_irsa","region":"us-west-2"}))

      opts = OciBundleManager.config_from_env!()
      config = Keyword.fetch!(opts, :config)

      assert config.auth == {:ecr_irsa, "us-west-2"}

      restore.()
    end

    test "raises on malformed auth JSON" do
      restore =
        capture_envs([
          "R5E_CEDAR_BUNDLE_REGISTRY",
          "R5E_CEDAR_BUNDLE_REPOSITORY",
          "R5E_CEDAR_BUNDLE_REF",
          "R5E_CEDAR_COSIGN_KEY_ARN",
          "R5E_CEDAR_BUNDLE_AUTH"
        ])

      System.put_env("R5E_CEDAR_BUNDLE_REGISTRY", "registry.example.com")
      System.put_env("R5E_CEDAR_BUNDLE_REPOSITORY", "cedar/policies")
      System.put_env("R5E_CEDAR_BUNDLE_REF", "1.0.0")
      System.put_env("R5E_CEDAR_COSIGN_KEY_ARN", "alias/test-cosign")
      System.put_env("R5E_CEDAR_BUNDLE_AUTH", "not json")

      assert_raise RuntimeError, ~r/JSON object/, fn ->
        OciBundleManager.config_from_env!()
      end

      restore.()
    end
  end

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  defp build_bundle(ref) do
    %{
      digest: :crypto.hash(:sha256, "bundle-bytes-for-#{ref}"),
      bytes: "permit(principal, action, resource);\n",
      canonical_hash: :crypto.hash(:sha256, "canonical-#{ref}"),
      cedar_version: "4.9.1",
      loaded_at: DateTime.utc_now(),
      source: :oci,
      source_ref: "test.registry/cedar-policies/test:#{ref}",
      manifest: %{"version" => ref, "name" => "test-bundle"}
    }
  end

  # Capture current values of named env vars; return a 0-arity callback
  # that restores them on test exit. We invoke the callback explicitly
  # at the end of each test so a test that succeeds doesn't leave its
  # env state for the next one.
  defp capture_envs(names) do
    saved = Enum.map(names, fn name -> {name, System.get_env(name)} end)

    fn ->
      Enum.each(saved, fn
        {name, nil} -> System.delete_env(name)
        {name, v} -> System.put_env(name, v)
      end)
    end
  end
end
