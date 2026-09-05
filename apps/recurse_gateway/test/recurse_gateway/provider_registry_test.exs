defmodule Recurse.Gateway.ProviderRegistryTest do
  @moduledoc """
  Unit tests for `Recurse.Gateway.ProviderRegistry` — focused on the
  optional `:llm` slot semantics introduced when audit-dev / spec-009
  proxy-only deployments needed to boot without an `OPENAI_API_KEY`.

  Scope:
    * `install_raw!/1` accepts an install map omitting `:llm` and
      caches `:not_configured` for that role.
    * `install_raw!/1` accepts an explicit `:not_configured` value for
      `:llm` (operator-set or test-set; either way the cached state
      stores the atom unchanged).
    * `llm_provider/0` returns `{module, state}` when the slot is
      populated and the atom `:not_configured` when it isn't — this
      preserves backward compat for the four existing call sites
      that destructure `{llm_mod, llm_state} = ProviderRegistry.llm_provider()`
      against deploys where the slot IS populated.
    * `llm_provider/0` raises if the registry isn't installed at all
      (a config bug, distinct from the optional-slot posture).
    * Other accessors (`ledger_provider/0`, `secrets_provider/0`, …)
      remain strict — they still raise when the registry isn't
      installed, since those PIs are mandatory for any audit-plane
      deploy.

  `async: false` because every test mutates the BEAM-global
  `:persistent_term` cache. The setup block clears + restores around
  each test.
  """

  use ExUnit.Case, async: false

  alias Recurse.Gateway.ProviderRegistry

  @tenant_id "01HXPRTEST00000000000000PR"

  setup do
    # Clear before AND after — defends against a sibling test leaving
    # state behind, and against this test leaking state forward.
    ProviderRegistry.uninstall()
    on_exit(fn -> ProviderRegistry.uninstall() end)
    :ok
  end

  describe "install_raw!/1 — optional :llm slot" do
    test "omits :llm key entirely → cached llm = :not_configured" do
      :ok =
        ProviderRegistry.install_raw!(%{
          ledger: {LedgerStub, %{}},
          storage: {StorageStub, %{}},
          secrets: {SecretsStub, %{}},
          tenant_id: @tenant_id
        })

      assert {:ok, %{llm: :not_configured}} = ProviderRegistry.fetch()
    end

    test "explicit :llm => :not_configured → cached llm = :not_configured" do
      :ok =
        ProviderRegistry.install_raw!(%{
          llm: :not_configured,
          ledger: {LedgerStub, %{}},
          storage: {StorageStub, %{}},
          secrets: {SecretsStub, %{}},
          tenant_id: @tenant_id
        })

      assert {:ok, %{llm: :not_configured}} = ProviderRegistry.fetch()
    end

    test "populated :llm slot → cached llm = {module, state}" do
      :ok =
        ProviderRegistry.install_raw!(%{
          llm: {LlmStub, %{model: "gpt-4o-mini"}},
          ledger: {LedgerStub, %{}},
          storage: {StorageStub, %{}},
          secrets: {SecretsStub, %{}},
          tenant_id: @tenant_id
        })

      assert {:ok, %{llm: {LlmStub, %{model: "gpt-4o-mini"}}}} =
               ProviderRegistry.fetch()
    end

    test "other slots stay required — raises when :ledger is missing" do
      # Build the partial map dynamically so the static type-checker
      # doesn't flag this as an obvious contract violation; the
      # function-head pattern match is what enforces required keys at
      # runtime, and that's what we're asserting on here.
      partial =
        %{
          ledger: {LedgerStub, %{}},
          storage: {StorageStub, %{}},
          secrets: {SecretsStub, %{}},
          tenant_id: @tenant_id
        }
        |> Map.delete(:ledger)

      assert_raise FunctionClauseError, fn ->
        ProviderRegistry.install_raw!(partial)
      end
    end
  end

  describe "llm_provider/0 — return shape" do
    test "returns {module, state} when LLM slot is populated" do
      :ok =
        ProviderRegistry.install_raw!(%{
          llm: {LlmStub, %{api_key: "sk-test"}},
          ledger: {LedgerStub, %{}},
          storage: {StorageStub, %{}},
          secrets: {SecretsStub, %{}},
          tenant_id: @tenant_id
        })

      assert {LlmStub, %{api_key: "sk-test"}} = ProviderRegistry.llm_provider()
    end

    test "returns :not_configured when registry installed without :llm" do
      :ok =
        ProviderRegistry.install_raw!(%{
          ledger: {LedgerStub, %{}},
          storage: {StorageStub, %{}},
          secrets: {SecretsStub, %{}},
          tenant_id: @tenant_id
        })

      assert :not_configured = ProviderRegistry.llm_provider()
    end

    test "raises when registry isn't installed at all" do
      ProviderRegistry.uninstall()

      assert_raise RuntimeError,
                   ~r/Recurse\.Gateway\.ProviderRegistry not installed/,
                   fn -> ProviderRegistry.llm_provider() end
    end
  end

  describe "other accessors — strict semantics preserved" do
    setup do
      :ok =
        ProviderRegistry.install_raw!(%{
          ledger: {LedgerStub, %{repo: :stub_repo}},
          storage: {StorageStub, %{bucket: "stub-cas"}},
          secrets: {SecretsStub, %{key_arn: "stub-arn"}},
          tenant_id: @tenant_id
        })

      :ok
    end

    test "ledger_provider/0 returns {module, state}" do
      assert {LedgerStub, %{repo: :stub_repo}} = ProviderRegistry.ledger_provider()
    end

    test "storage_provider/0 returns {module, state}" do
      assert {StorageStub, %{bucket: "stub-cas"}} = ProviderRegistry.storage_provider()
    end

    test "secrets_provider/0 returns {module, state}" do
      assert {SecretsStub, %{key_arn: "stub-arn"}} = ProviderRegistry.secrets_provider()
    end

    test "tenant_id/0 returns the configured id" do
      assert @tenant_id == ProviderRegistry.tenant_id()
    end

    test "signer/0 defaults to observed://gateway when :signer omitted" do
      assert "observed://gateway" == ProviderRegistry.signer()
    end
  end

  describe "fetch/0 — public diagnostic surface" do
    test "returns {:error, :not_installed} before install" do
      assert {:error, :not_installed} = ProviderRegistry.fetch()
    end

    test "returns {:ok, cached_state} after install — :llm = :not_configured" do
      :ok =
        ProviderRegistry.install_raw!(%{
          ledger: {LedgerStub, %{}},
          storage: {StorageStub, %{}},
          secrets: {SecretsStub, %{}},
          tenant_id: @tenant_id
        })

      assert {:ok,
              %{
                llm: :not_configured,
                ledger: {LedgerStub, _},
                storage: {StorageStub, _},
                secrets: {SecretsStub, _},
                tenant_id: @tenant_id,
                signer: "observed://gateway"
              }} = ProviderRegistry.fetch()
    end
  end
end
