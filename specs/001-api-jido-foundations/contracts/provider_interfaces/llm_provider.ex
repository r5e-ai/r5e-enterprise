defmodule Recurse.Providers.LLMProvider do
  @moduledoc """
  Provider Interface — LLMProvider.

  Spec source: FR-003 (one of seven Provider Interfaces per Constitution v1.3.0 Principle V).

  Abstracts WHERE LLM calls go. The Cedar engine and SPIFFE format are committed
  per `stack_cedar_spiffe_commitment.md`; this interface does NOT abstract the engine,
  only the integration boundary with the customer-chosen LLM endpoint.

  Reference implementations live in `apps/recurse_providers/lib/recurse_providers/impls/`:
  - `OpenAILLM` — api.openai.com
  - `AnthropicLLM` — api.anthropic.com
  - `BedrockLLM` — AWS Bedrock
  - `LocalVLLM` — local vLLM cluster (Air-Gapped Appliance reference)

  Conformance test suite lives in `apps/recurse_providers/test/contract/llm_provider_test.exs`
  and is the basis for the New-Provider Acceptance Checklist (Deliverable C / FR-004).
  """

  alias Recurse.Shared.IdentityContext

  @typedoc "OpenAI-compatible chat completion request shape"
  @type completion_request :: map()

  @typedoc "OpenAI-compatible chat completion response shape (sync)"
  @type completion_response :: map()

  @typedoc "Stream of OpenAI-compatible delta chunks"
  @type completion_stream :: Enumerable.t()

  @typedoc "Implementation-specific configuration passed to init/1"
  @type config :: map()

  @typedoc "Opaque per-implementation state returned from init/1"
  @type state :: term()

  @doc "Initialize the provider implementation with deployment-time configuration."
  @callback init(config) :: {:ok, state} | {:error, term()}

  @doc """
  Synchronous LLM call. Returns the full completion when ready.

  The IdentityContext is passed for telemetry and downstream-auth-injection (FR-047).
  Implementations MUST NOT inject identity into the request body — that's the Gateway's job.
  """
  @callback chat_complete(state, completion_request, IdentityContext.t()) ::
              {:ok, completion_response} | {:error, term()}

  @doc """
  Streaming LLM call. Returns an Enumerable of delta chunks.

  The Stream MUST end naturally (no Recurse-injected sentinels in the stream itself);
  the per-turn attestation is emitted by the caller (Gateway) AFTER stream end.
  """
  @callback chat_complete_stream(state, completion_request, IdentityContext.t()) ::
              {:ok, completion_stream} | {:error, term()}

  @doc """
  Capability flags — implementations declare what they support.
  Used by the Gateway to route correctly and by contract tests to skip irrelevant cases.
  """
  @callback capabilities(state) :: [
              :sync
              | :streaming
              | :tool_calls
              | :vision
              | :function_calling
            ]

  @doc "Healthcheck for `/healthz` aggregation (FR-014)."
  @callback healthcheck(state) :: :ok | {:degraded, reason :: term()} | {:down, reason :: term()}

  @doc "Graceful shutdown — close connection pools, flush in-flight calls if applicable."
  @callback terminate(state, reason :: term()) :: :ok
end
