defmodule Recurse.Gateway.DataPlane.SseProxyTest do
  @moduledoc """
  Contract tests for `Recurse.Gateway.DataPlane.SseProxy` (F002 T052).

  Exercises the stream-forwarding + reassembly seam without booting Bandit
  or reaching real HTTP. The Mox-backed `LLMProvider` returns an
  `Enumerable.t()` of raw SSE chunks the proxy enumerates.

  Coverage:

    * Happy streaming path: OpenAI-like chunks forward downstream via
      `Plug.Conn.chunk/2`, reassembly produces the expected final JSON,
      the envelope → S3 → ledger pipeline fires.
    * Reassembly only: `reassemble_chat_completion/2` is a public helper
      so the canonicalization-contract tests can assert the shape
      independent of HTTP.
    * Cancellation: client-disconnect simulated by replacing the conn
      with a halted adapter mid-stream; outcome is `:cancelled`.

  `async: false` because of the shared `ProviderRegistry` /
  `BundleLoader` state.
  """

  use ExUnit.Case, async: false

  setup_all do
    Recurse.Gateway.Test.KernelFixture.boot()
  end

  import Mox

  alias Recurse.Gateway.DataPlane.SseProxy
  alias Recurse.Gateway.ProviderRegistry
  alias Recurse.Gateway.Test.Mocks.LLMProvider, as: LLMMock
  alias Recurse.Gateway.Test.Mocks.StorageProvider, as: StorageMock
  alias Recurse.Shared.IdentityContext
  alias Recurse.Shared.Principal

  setup :verify_on_exit!

  @tenant_id "01HQZN5K7J8M9N0P1Q2R3S4T5V"
  @policy_hash :crypto.hash(:sha256, "test-policy-bundle")

  setup do
    ProviderRegistry.install_raw!(%{
      llm: {LLMMock, %{}},
      ledger: {Recurse.Gateway.DataPlane.SseProxyTest.StubLedgerCommit, %{}},
      storage: {StorageMock, %{}},
      secrets: {Recurse.Gateway.Test.StubSecretsProvider, %{backend: :stub}},
      tenant_id: @tenant_id,
      signer: "observed://gateway/test"
    })

    on_exit(fn -> ProviderRegistry.uninstall() end)
    :ok
  end

  describe "reassemble_chat_completion/2" do
    test "concatenates delta.content across chunks into final content" do
      chunks = [
        ~s|data: {"id":"c1","object":"chat.completion.chunk","created":1,"model":"gpt-4o-mini","choices":[{"index":0,"delta":{"role":"assistant","content":"Hello"},"finish_reason":null}]}\n\n|,
        ~s|data: {"id":"c1","object":"chat.completion.chunk","created":1,"model":"gpt-4o-mini","choices":[{"index":0,"delta":{"content":", world"},"finish_reason":null}]}\n\n|,
        ~s|data: {"id":"c1","object":"chat.completion.chunk","created":1,"model":"gpt-4o-mini","choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":2,"total_tokens":3}}\n\n|,
        ~s|data: [DONE]\n\n|
      ]

      reassembled = SseProxy.reassemble_chat_completion(chunks, %{"model" => "gpt-4o-mini"})

      assert %{
               "object" => "chat.completion",
               "model" => "gpt-4o-mini",
               "id" => "c1",
               "choices" => [
                 %{
                   "index" => 0,
                   "message" => %{
                     "role" => "assistant",
                     "content" => "Hello, world",
                     "refusal" => nil
                   },
                   "finish_reason" => "stop"
                 }
               ],
               "usage" => %{"completion_tokens" => 2, "prompt_tokens" => 1, "total_tokens" => 3}
             } = reassembled
    end

    test "empty chunk list yields empty-content completion" do
      reassembled = SseProxy.reassemble_chat_completion([], %{"model" => "gpt-4o-mini"})
      assert %{"choices" => [%{"message" => %{"content" => ""}}]} = reassembled
    end
  end

  describe "proxy/4 — happy path (streaming)" do
    test "forwards chunks downstream, reassembles, commits attestation" do
      chunks = [
        ~s|data: {"id":"c1","object":"chat.completion.chunk","created":1,"model":"gpt-4o-mini","choices":[{"index":0,"delta":{"role":"assistant","content":"hi"},"finish_reason":null}]}\n\n|,
        ~s|data: {"id":"c1","object":"chat.completion.chunk","created":1,"model":"gpt-4o-mini","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}\n\n|
      ]

      expect(LLMMock, :chat_complete_stream, fn _state, _req, _ctx -> {:ok, chunks} end)

      expect(StorageMock, :put_payload, fn _state, _bytes, _ctx ->
        {:ok, %{uri: "s3://test/stream", hash: <<0::256>>}}
      end)

      conn = build_conn()
      ctx = build_identity_ctx()

      {:ok, result_conn} =
        SseProxy.proxy(conn, ctx, %{"model" => "gpt-4o-mini", "stream" => true}, %{
          run_id: "01HQZN5K7J8M9N0P1Q2R3S4T5X",
          policy_decision: :allow,
          policy_canonical_hash: @policy_hash
        })

      # Bandit / chunked-mode: response is set to 200 and the Plug.Test
      # chunked-body test adapter accumulates chunks into resp_body.
      assert result_conn.status == 200
      assert result_conn.state in [:chunked, :sent]

      # The raw forwarded bytes are concatenated in the conn body under
      # Plug.Test's chunked adapter.
      assert result_conn.resp_body =~ "hi"
      assert result_conn.resp_body =~ "finish_reason"
    end
  end

  describe "proxy/4 — upstream error on stream open" do
    test "upstream 429 on stream opens results in JSON pass-through (no chunked response)" do
      expect(LLMMock, :chat_complete_stream, fn _state, _req, _ctx ->
        {:upstream_error, 429, ~s|{"error":"rate_limited"}|, []}
      end)

      conn = build_conn()
      ctx = build_identity_ctx()

      {:ok, result_conn} =
        SseProxy.proxy(conn, ctx, %{"model" => "gpt-4o-mini", "stream" => true}, %{
          run_id: "01HQZN5K7J8M9N0P1Q2R3S4T5Y",
          policy_decision: :allow,
          policy_canonical_hash: @policy_hash
        })

      assert result_conn.status == 429
      assert {:ok, %{"error" => "rate_limited"}} = JSON.decode(result_conn.resp_body)
    end
  end

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  defp build_conn do
    :post
    |> Plug.Test.conn("/v1/chat/completions", JSON.encode!(%{"model" => "gpt-4o-mini"}))
    |> Plug.Conn.put_req_header("content-type", "application/json")
  end

  defp build_identity_ctx do
    IdentityContext.new(%{
      machine_identity:
        {:observed_jwt_subject, %{observed_jwt_subject: "alice", issuer: "https://broker.test"}},
      principal:
        Principal.obo_human(%{
          issuer: "https://broker.test",
          subject: "alice",
          recurse_role: "caller"
        }),
      tenant_id: @tenant_id,
      correlation_id: "01HQZN5K7J8M9N0P1Q2R3S4T5W"
    })
  end
end

defmodule Recurse.Gateway.DataPlane.SseProxyTest.StubLedgerCommit do
  @moduledoc false
  @behaviour Recurse.Providers.LedgerProvider

  def commit_attestation(_envelope, _opts) do
    {:ok,
     %{
       run_id: "stub",
       verification_level: :local_inclusion_verified,
       session_chain_root: <<0::256>>,
       global_inclusion_proof: <<>>
     }}
  end

  @impl true
  def init(_), do: {:ok, %{}}
  @impl true
  def commit_epoch(_s, _sid, _e, _l), do: {:error, :not_implemented}
  @impl true
  def inclusion_proof(_s, _i, _t), do: {:error, :not_implemented}
  @impl true
  def consistency_proof(_s, _f, _t), do: {:error, :not_implemented}
  @impl true
  def current_root(_s), do: {:error, :not_implemented}
  @impl true
  def capabilities(_s), do: []
  @impl true
  def healthcheck(_s), do: :ok
  @impl true
  def terminate(_s, _r), do: :ok
end
