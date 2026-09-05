defmodule Recurse.Providers.Support.MockLLMProvider do
  @moduledoc """
  Fixed-data stub implementation of `Recurse.Providers.LLMProvider` (T062).

  Used as the `stub_with` target for `Recurse.Providers.Mocks.LLMProvider`
  in the contract-test harness. Returns a canonical OpenAI-compatible
  chat-completion response so the harness can assert structural shape
  without a real upstream.

  This is NOT a production impl — it's a pure-stateful-testing helper.
  Real impls live in `apps/recurse_providers/lib/recurse_providers/impls/`
  per Feature 002+ work.
  """

  @behaviour Recurse.Providers.LLMProvider

  @impl true
  def init(_config), do: {:ok, %{initialized: true}}

  @impl true
  def chat_complete(_state, _request, _identity_ctx) do
    {:ok,
     %{
       "id" => "chatcmpl-mock-0001",
       "object" => "chat.completion",
       "created" => 1_700_000_000,
       "model" => "mock-llm-1",
       "choices" => [
         %{
           "index" => 0,
           "message" => %{"role" => "assistant", "content" => "fixed mock completion"},
           "finish_reason" => "stop"
         }
       ],
       "usage" => %{"prompt_tokens" => 7, "completion_tokens" => 4, "total_tokens" => 11}
     }}
  end

  @impl true
  def chat_complete_stream(_state, _request, _identity_ctx) do
    chunks = [
      %{"choices" => [%{"delta" => %{"role" => "assistant"}, "index" => 0}]},
      %{"choices" => [%{"delta" => %{"content" => "fixed "}, "index" => 0}]},
      %{"choices" => [%{"delta" => %{"content" => "mock"}, "index" => 0}]},
      %{"choices" => [%{"delta" => %{}, "finish_reason" => "stop", "index" => 0}]}
    ]

    {:ok, chunks}
  end

  @impl true
  def capabilities(_state), do: [:sync, :streaming]

  @impl true
  def healthcheck(_state), do: :ok

  @impl true
  def terminate(_state, _reason), do: :ok
end
