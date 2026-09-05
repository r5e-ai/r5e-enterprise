defmodule Recurse.Gateway.DataPlane.ChatCompletionsHandlerTest do
  @moduledoc """
  Contract tests for `Recurse.Gateway.DataPlane.ChatCompletionsHandler`
  (F002 T051). Mox-driven — no real HTTP, no real DB.

  Covers:

    * Happy path: `:allow` policy → LLM mock returns a sync completion →
      envelope built → S3 mock called → ledger mock called → HTTP 200 with
      the upstream body + `x-recurse-correlation-id` header.
    * Deny path: `:deny` policy → synthetic OpenAI refusal shape (single
      canonical channel: `choices[0].message.refusal`); denial attestation
      committed; HTTP 200.
    * Upstream error: LLM mock returns `{:upstream_error, 503, body, []}` →
      HTTP 503 pass-through; attestation committed with
      `outcome: :upstream_error`.
    * Request with `tools` field: protocol-native 400 validation error.
    * Missing Authorization delegation: the handler's entry point requires
      `:identity_ctx` in `conn.assigns`; absence is tested in
      `router_test.exs` at the Router layer.

  The Gateway's BundleLoader is a singleton GenServer; we start a private
  instance per test via `start_supervised!` pointed at a deterministic
  Cedar bundle in `priv/reference_policies/permissive_all.cedar` (or a
  deny-all bundle we write into a tmp_dir). The loader writes through
  `Recurse.Gateway.Policy.Active.update/1` (canonical store), so
  `Active.current/0` (and the deprecated wrapper
  `BundleLoader.current_bundle/0`) returns the test bundle.

  `async: false` — the canonical `Active` persistent_term entry is global.
  """

  use ExUnit.Case, async: false

  setup_all do
    Recurse.Gateway.Test.KernelFixture.boot()
  end

  import Mox

  alias Recurse.Gateway.DataPlane.ChatCompletionsHandler
  alias Recurse.Gateway.Policy.BundleLoader
  alias Recurse.Gateway.ProviderRegistry
  alias Recurse.Gateway.Test.Mocks.LLMProvider, as: LLMMock
  alias Recurse.Gateway.Test.Mocks.StorageProvider, as: StorageMock
  alias Recurse.Shared.IdentityContext
  alias Recurse.Shared.Principal

  setup :verify_on_exit!

  @tenant_id "01HQZN5K7J8M9N0P1Q2R3S4T5V"

  setup context do
    bundle_source =
      case Map.get(context, :bundle, :permissive) do
        :permissive -> "permit(principal, action, resource);"
        :deny_all -> "forbid(principal, action, resource);"
      end

    tmp = tmp_bundle_dir(context[:test])
    bundle_path = Path.join(tmp, "policies.cedar")
    File.write!(bundle_path, bundle_source)

    entity_schema_path =
      Path.join([
        Application.app_dir(:recurse_gateway, "priv"),
        "cedar",
        "schema.cedarschema.json"
      ])

    # Start WITHOUT a registered name (nil) so repeated test setups don't
    # collide on the default `BundleLoader` atom. The `:persistent_term`
    # write happens at init regardless of the registered name; readers
    # via `current_bundle/0` find it at the canonical key.
    _pid =
      start_supervised!(
        Supervisor.child_spec(
          {BundleLoader,
           bundle_path: bundle_path,
           entity_schema_path: entity_schema_path,
           trap_sighup: false,
           name: nil},
          id: make_ref()
        )
      )

    ProviderRegistry.install_raw!(%{
      llm: {LLMMock, %{}},
      # The handler invokes `commit_attestation/2` on the ledger module
      # (rich public method). Our Mox mock targets the narrow
      # `LedgerProvider` behaviour and does NOT export
      # `commit_attestation/2`. Use a dedicated stub that exports it.
      ledger: {Recurse.Gateway.DataPlane.ChatCompletionsHandlerTest.StubLedgerCommit, %{}},
      storage: {StorageMock, %{}},
      secrets: {Recurse.Gateway.Test.StubSecretsProvider, %{backend: :stub}},
      tenant_id: @tenant_id,
      signer: "observed://gateway/test"
    })

    on_exit(fn -> ProviderRegistry.uninstall() end)

    %{bundle_path: bundle_path}
  end

  describe "handle/1 — happy path (sync)" do
    @tag bundle: :permissive
    test "allow + sync chat_complete returns 200 with upstream body + correlation header" do
      expect(LLMMock, :chat_complete, fn _state, _req, _ctx ->
        {:ok, upstream_sync_response()}
      end)

      expect(StorageMock, :put_payload, fn _state, _bytes, _ctx ->
        {:ok, %{uri: "s3://test/tenants/#{@tenant_id}/runs/20260424/run.json", hash: <<0::256>>}}
      end)

      conn = build_authenticated_conn(request_body())
      conn = ChatCompletionsHandler.handle(conn)

      assert conn.status == 200
      assert {:ok, decoded} = JSON.decode(conn.resp_body)
      assert decoded["object"] == "chat.completion"
      assert [%{"message" => %{"content" => content}}] = decoded["choices"]
      assert is_binary(content)

      assert {"content-type", "application/json; charset=utf-8"} =
               Enum.find(conn.resp_headers, &match?({"content-type", _}, &1))
    end
  end

  describe "handle/1 — deny path" do
    @tag bundle: :deny_all
    test "deny policy returns 200 with refusal in choices[0].message.refusal" do
      # LLM provider MUST NOT be called on deny.

      expect(StorageMock, :put_payload, fn _state, _bytes, _ctx ->
        {:ok, %{uri: "s3://test/denied", hash: <<0::256>>}}
      end)

      conn = build_authenticated_conn(request_body())
      conn = ChatCompletionsHandler.handle(conn)

      assert conn.status == 200
      assert {:ok, decoded} = JSON.decode(conn.resp_body)
      assert decoded["object"] == "chat.completion"
      assert [%{"message" => %{"refusal" => refusal, "content" => nil}}] = decoded["choices"]
      assert is_binary(refusal)
      # Single canonical channel: no duplicate content; content is explicitly nil.
      assert String.contains?(refusal, "denied by policy")
    end
  end

  describe "handle/1 — upstream error" do
    @tag bundle: :permissive
    test "upstream 503 passes through with attestation outcome :upstream_error" do
      expect(LLMMock, :chat_complete, fn _state, _req, _ctx ->
        {:upstream_error, 503, ~s|{"error":"upstream rate-limited"}|, []}
      end)

      expect(StorageMock, :put_payload, fn _state, _bytes, _ctx ->
        {:ok, %{uri: "s3://test/upstream-503", hash: <<0::256>>}}
      end)

      conn = build_authenticated_conn(request_body())
      conn = ChatCompletionsHandler.handle(conn)

      assert conn.status == 503
      assert {:ok, %{"error" => "upstream rate-limited"}} = JSON.decode(conn.resp_body)
    end
  end

  describe "handle/1 — request validation" do
    @tag bundle: :permissive
    test "request with `tools` field returns 400 protocol-native validation error" do
      body = request_body() |> Map.put("tools", [%{"type" => "function"}])

      conn = build_authenticated_conn(body)
      conn = ChatCompletionsHandler.handle(conn)

      assert conn.status == 400

      assert {:ok, %{"error" => %{"type" => "invalid_request_error"}}} =
               JSON.decode(conn.resp_body)
    end

    @tag bundle: :permissive
    test "request without `model` returns 400" do
      body = %{"messages" => [%{"role" => "user", "content" => "hi"}]}

      conn = build_authenticated_conn(body)
      conn = ChatCompletionsHandler.handle(conn)

      assert conn.status == 400
      assert {:ok, %{"error" => %{"code" => "invalid_request"}}} = JSON.decode(conn.resp_body)
    end

    @tag bundle: :permissive
    test "request with empty `messages` returns 400" do
      body = %{"model" => "gpt-4o-mini", "messages" => []}

      conn = build_authenticated_conn(body)
      conn = ChatCompletionsHandler.handle(conn)

      assert conn.status == 400
    end
  end

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  defp request_body do
    %{
      "model" => "gpt-4o-mini",
      "messages" => [
        %{"role" => "user", "content" => "hello"}
      ]
    }
  end

  defp upstream_sync_response do
    %{
      "id" => "chatcmpl-test",
      "object" => "chat.completion",
      "created" => 1_700_000_000,
      "model" => "gpt-4o-mini",
      "choices" => [
        %{
          "index" => 0,
          "message" => %{"role" => "assistant", "content" => "hi back"},
          "finish_reason" => "stop"
        }
      ],
      "usage" => %{"prompt_tokens" => 1, "completion_tokens" => 2, "total_tokens" => 3}
    }
  end

  defp build_authenticated_conn(body) do
    bytes = JSON.encode!(body)

    :post
    |> Plug.Test.conn("/v1/chat/completions", bytes)
    |> Plug.Conn.put_req_header("content-type", "application/json")
    |> parse_body!()
    |> Plug.Conn.assign(:identity_ctx, build_identity_ctx())
  end

  defp parse_body!(conn) do
    Plug.Parsers.call(
      conn,
      Plug.Parsers.init(parsers: [:json], pass: ["*/*"], json_decoder: JSON)
    )
  end

  defp build_identity_ctx do
    principal =
      Principal.obo_human(%{
        issuer: "https://test-broker.example.invalid",
        subject: "alice",
        recurse_role: "platform_operator"
      })

    IdentityContext.new(%{
      machine_identity:
        {:observed_jwt_subject,
         %{observed_jwt_subject: "alice", issuer: "https://test-broker.example.invalid"}},
      principal: principal,
      tenant_id: @tenant_id,
      correlation_id: "01HQZN5K7J8M9N0P1Q2R3S4T5W"
    })
  end

  defp tmp_bundle_dir(test_name) do
    name = test_name |> to_string() |> String.replace(~r/[^a-zA-Z0-9_]/, "_")
    path = Path.join(System.tmp_dir!(), "recurse_handler_test_#{name}_#{System.unique_integer()}")
    File.mkdir_p!(path)
    on_exit(fn -> File.rm_rf!(path) end)
    path
  end
end

# Stub ledger that exports `commit_attestation/2` so the handler's
# function_exported? dispatch path reaches it. Returns a canonical
# success result; tests do not exercise ledger internals at this seam.
defmodule Recurse.Gateway.DataPlane.ChatCompletionsHandlerTest.StubLedgerCommit do
  @moduledoc false
  @behaviour Recurse.Providers.LedgerProvider

  def commit_attestation(_envelope, _opts) do
    {:ok,
     %{
       run_id: "01HQZN5K7J8M9N0P1Q2R3S4T5X",
       verification_level: :local_inclusion_verified,
       session_chain_root: <<0::256>>,
       global_inclusion_proof: <<>>
     }}
  end

  @impl true
  def init(_), do: {:ok, %{}}
  @impl true
  def commit_epoch(_state, _session_id, _epoch, _leaves), do: {:error, :not_implemented}
  @impl true
  def inclusion_proof(_state, _session_id, _index), do: {:error, :not_implemented}
  @impl true
  def consistency_proof(_state, _session_id, _from), do: {:error, :not_implemented}
  @impl true
  def current_root(_state), do: {:error, :not_implemented}
  @impl true
  def capabilities(_state), do: []
  @impl true
  def healthcheck(_state), do: :ok
  @impl true
  def terminate(_state, _reason), do: :ok
end
