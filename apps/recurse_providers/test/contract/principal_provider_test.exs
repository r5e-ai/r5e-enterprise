defmodule Recurse.Providers.ContractTest.PrincipalProviderTest do
  @moduledoc """
  Contract test for `Recurse.Providers.PrincipalProvider` (T067).

  Covers all three principal kinds (`:obo_human`, `:service_account`,
  `:autonomous`) per FR-026 and asserts the `supports_rfc8693?/1`
  capability flag — the composition hook with `SecretsProvider` per
  FR-047.
  """

  use Recurse.Providers.ContractTest,
    for: Recurse.Providers.PrincipalProvider,
    mock: Recurse.Providers.Mocks.PrincipalProvider,
    stub_with: Recurse.Providers.Support.MockPrincipalProvider

  alias Recurse.Providers.Mocks.PrincipalProvider, as: Mock

  describe "PrincipalProvider — three principal kinds (FR-026)" do
    test "validate/3 returns an :obo_human principal" do
      state = init_state()
      assert {:ok, p} = Mock.validate(state, "mock-obo:alice", "aud")
      assert p.kind == :obo_human
      assert p.subject == "alice"
    end

    test "validate/3 returns a :service_account principal" do
      state = init_state()
      assert {:ok, p} = Mock.validate(state, "mock-sa:billing-bot", "aud")
      assert p.kind == :service_account
      assert p.account_id == "billing-bot"
    end

    test "validate/3 returns an :autonomous principal" do
      state = init_state()

      assert {:ok, p} =
               Mock.validate(state, "mock-auto:spiffe://mock.recurse.test/agent/auto-1", "aud")

      assert p.kind == :autonomous
      assert String.starts_with?(p.spiffe_id, "spiffe://")
    end

    test "validate/3 rejects unknown token shape with :invalid_signature" do
      state = init_state()
      assert {:error, :invalid_signature} = Mock.validate(state, "garbage", "aud")
    end

    test "inspect_kind/2 routes correctly without full validation" do
      state = init_state()
      assert {:ok, :obo_human} = Mock.inspect_kind(state, "mock-obo:x")
      assert {:ok, :service_account} = Mock.inspect_kind(state, "mock-sa:y")
      assert {:ok, :autonomous} = Mock.inspect_kind(state, "mock-auto:z")
    end
  end

  describe "PrincipalProvider — FR-047 capability composition" do
    test "supports_rfc8693?/1 returns true (composes with SecretsProvider)" do
      state = init_state()
      assert Mock.supports_rfc8693?(state) == true
    end

    test "capabilities/1 includes :rfc8693_exchange" do
      state = init_state()
      assert :rfc8693_exchange in Mock.capabilities(state)
    end
  end
end
