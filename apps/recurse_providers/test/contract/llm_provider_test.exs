defmodule Recurse.Providers.ContractTest.LLMProviderTest do
  @moduledoc """
  Contract test for `Recurse.Providers.LLMProvider` (T062).

  Universal round-trip coverage comes from the `ContractTest` harness;
  this module adds LLM-specific assertions around `chat_complete/3` and
  `chat_complete_stream/3`.
  """

  use Recurse.Providers.ContractTest,
    for: Recurse.Providers.LLMProvider,
    mock: Recurse.Providers.Mocks.LLMProvider,
    stub_with: Recurse.Providers.Support.MockLLMProvider

  alias Recurse.Providers.Mocks.LLMProvider, as: Mock

  describe "LLMProvider behaviour-specific round-trips" do
    test "chat_complete/3 returns OpenAI-compatible response shape" do
      state = init_state()
      {:ok, identity_ctx} = build_identity_context()

      assert {:ok, response} = Mock.chat_complete(state, %{"messages" => []}, identity_ctx)
      assert is_map(response)
      assert Map.has_key?(response, "id")
      assert Map.has_key?(response, "choices")
      assert is_list(response["choices"])
    end

    test "chat_complete_stream/3 returns an enumerable of delta chunks" do
      state = init_state()
      {:ok, identity_ctx} = build_identity_context()

      assert {:ok, stream} = Mock.chat_complete_stream(state, %{"messages" => []}, identity_ctx)
      chunks = Enum.to_list(stream)
      refute chunks == []
      assert Enum.all?(chunks, &is_map/1)
    end

    test "capabilities/1 advertises only known atoms" do
      state = init_state()
      caps = Mock.capabilities(state)
      allowed = [:sync, :streaming, :tool_calls, :vision, :function_calling]
      assert Enum.all?(caps, &(&1 in allowed))
    end
  end

  # Minimal IdentityContext builder — shared across contract tests that
  # need to pass one through a behaviour callback.
  defp build_identity_context do
    principal =
      Recurse.Shared.Principal.service_account(%{
        issuer: "https://mock-idp.recurse.test",
        account_id: "contract-test"
      })

    {:ok,
     Recurse.Shared.IdentityContext.new(%{
       machine_identity: "spiffe://mock.recurse.test/workload/contract-test",
       principal: principal,
       tenant_id: "tenant-test",
       correlation_id: "01HZZZZZZZZZZZZZZZZZZZZZZZ"
     })}
  end
end
