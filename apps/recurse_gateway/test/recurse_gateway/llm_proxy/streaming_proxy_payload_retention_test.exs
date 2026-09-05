defmodule Recurse.Gateway.LlmProxy.StreamingProxyPayloadRetentionTest do
  @moduledoc """
  Spec 012 S6b — evidence capture end to end through `StreamingProxy`:
  the bytes the receipt's `prompt_hash` / `response_hash` cover are retained
  for mandatory kernel admission even when the legacy payload-retention flag
  is off; over the kernel CAS cap, the record says `payload_truncated`.
  """

  use ExUnit.Case, async: false

  import Ecto.Query, only: [from: 2]

  alias Recurse.Gateway.LlmProxy.StreamingProxy
  alias Recurse.Gateway.Policy.Active
  alias Recurse.Gateway.PolicyBundleRef
  alias Recurse.Gateway.ProviderRegistry
  alias Recurse.Gateway.Test.{KernelFixture, MockHttpUpstream, StubStorageProvider}
  alias Recurse.Providers.Impls.PostgresMerkleLedger
  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.{Attestation, Tenant}
  alias Recurse.Providers.Repo
  alias Recurse.Providers.Schemas.{LlmCallRecord, LlmProviderConfig}

  @tenant_id "01TEN_S6B_PROXY_RETENTION"
  @fixtures Path.expand("../../../../recurse_shared/test/fixtures/anthropic_messages", __DIR__)

  setup_all do
    :ok = KernelFixture.boot()
    activate_permit_all()
  end

  setup do
    :ok = Ecto.Adapters.SQL.Sandbox.checkout(Repo)
    Ecto.Adapters.SQL.Sandbox.mode(Repo, {:shared, self()})
    :ok = StubStorageProvider.reset()

    Repo.insert!(
      Tenant.changeset(%Tenant{}, %{
        tenant_id: @tenant_id,
        display_name: "S6b proxy retention tenant",
        tier: :standalone_gateway,
        created_at: DateTime.utc_now()
      }),
      on_conflict: :nothing,
      conflict_target: :tenant_id
    )

    {:ok, storage_state} = StubStorageProvider.init(%{})

    ProviderRegistry.install_raw!(%{
      llm: {Recurse.Gateway.Test.StubLLM, %{}},
      ledger: {PostgresMerkleLedger, %{repo: Repo, pubsub: Recurse.PubSub, config: %{}}},
      storage: {StubStorageProvider, storage_state},
      secrets: {Recurse.Gateway.Test.StubSecretsProvider, %{}},
      tenant_id: @tenant_id,
      signer: "observed://gateway/s6b-proxy-test"
    })

    {:ok, upstream} = MockHttpUpstream.start()

    previous = {
      Application.get_env(:recurse_gateway, :retain_payloads?),
      Application.get_env(:recurse_gateway, :retain_payloads_max_bytes),
      Application.get_env(:r5e, :cas_max_bytes)
    }

    on_exit(fn ->
      MockHttpUpstream.stop(upstream)
      ProviderRegistry.uninstall()
      {enabled, max, cas_max} = previous
      restore(:retain_payloads?, enabled)
      restore(:retain_payloads_max_bytes, max)
      restore_r5e(:cas_max_bytes, cas_max)
    end)

    {:ok, upstream: upstream}
  end

  defp restore(key, nil), do: Application.delete_env(:recurse_gateway, key)
  defp restore(key, value), do: Application.put_env(:recurse_gateway, key, value)
  defp restore_r5e(key, nil), do: Application.delete_env(:r5e, key)
  defp restore_r5e(key, value), do: Application.put_env(:r5e, key, value)

  defp activate_permit_all do
    source = "permit(principal, action, resource);"
    hash = Recurse.Cedar.canonical_hash(source)

    Active.update(%Active{
      source: :filesystem,
      source_ref: "streaming-proxy-payload-retention-test",
      loaded_at: DateTime.utc_now(),
      bundle: %PolicyBundleRef{
        bundle_id: Base.encode16(hash, case: :lower),
        canonical_hash: hash,
        loaded_at: DateTime.utc_now(),
        evaluator_handle: source,
        bundle_bytes: source
      }
    })
  end

  defp config(upstream) do
    %LlmProviderConfig{
      tenant_id: @tenant_id,
      provider: "anthropic",
      upstream_host: "127.0.0.1",
      upstream_port: upstream.port,
      transport_modes: ["https-sse"],
      auth_mode: :passthrough,
      api_format: :anthropic_messages,
      enabled: true,
      metadata: %{"scheme" => "http"}
    }
  end

  defp fixture(name), do: File.read!(Path.join(@fixtures, name))

  defp resp_body(%Plug.Conn{adapter: {_, %{chunks: chunks}}}) when is_list(chunks),
    do: IO.iodata_to_binary(chunks)

  defp resp_body(%Plug.Conn{adapter: {_, %{chunks: chunks}}}) when is_binary(chunks), do: chunks
  defp resp_body(%Plug.Conn{resp_body: body}) when is_binary(body), do: body

  defp run(upstream) do
    request = fixture("single_tool_use_bash.request.json")
    sse = fixture("single_tool_use_bash.sse")
    MockHttpUpstream.serve_sse(upstream, sse, chunk_size: 53)

    conn =
      Plug.Test.conn(:post, "/v1/messages", request)
      |> Map.update!(:req_headers, &[{"host", "localhost:4443"} | &1])
      |> Plug.Conn.put_req_header("content-type", "application/json")
      |> Plug.Conn.put_req_header(
        "authorization",
        "Bearer sk-ant-oat01-" <> String.duplicate("x", 100)
      )
      |> Plug.Conn.put_req_header("anthropic-version", "2023-06-01")

    result =
      StreamingProxy.proxy(conn, %{llm_provider_config: config(upstream), tenant_id: @tenant_id})

    assert result.status == 200

    record =
      Repo.one!(
        from(c in LlmCallRecord,
          where: c.tenant_id == @tenant_id,
          order_by: [desc: c.inserted_at],
          limit: 1
        )
      )

    {record, request, sse}
  end

  test "on: request + response bytes are stored under the receipt's hashes", %{upstream: upstream} do
    Application.put_env(:recurse_gateway, :retain_payloads?, true)
    {record, request, sse} = run(upstream)

    assert record.prompt_hash == :crypto.hash(:sha256, request)
    assert record.response_hash == :crypto.hash(:sha256, sse)
    assert record.payload_truncated == false

    puts_by_uri = Map.new(StubStorageProvider.puts(@tenant_id), &{&1.uri, &1})
    assert Map.fetch!(puts_by_uri, record.prompt_payload_uri).payload == request
    assert Map.fetch!(puts_by_uri, record.response_payload_uri).payload == sse

    # The predicate body is always retained, independent of the flag.
    att = Repo.get!(Attestation, record.signed_predicate_run_id)

    assert :crypto.hash(:sha256, Map.fetch!(puts_by_uri, att.predicate_body_uri).payload) ==
             att.payload_hash
  end

  test "legacy retention off cannot disable evidence required by admission", %{upstream: upstream} do
    Application.put_env(:recurse_gateway, :retain_payloads?, false)
    {record, request, _sse} = run(upstream)

    assert record.prompt_hash == :crypto.hash(:sha256, request)
    assert is_binary(record.prompt_payload_uri)
    assert is_binary(record.response_payload_uri)
    assert record.payload_truncated == false

    payloads = Enum.map(StubStorageProvider.puts(@tenant_id), & &1.payload)
    assert request in payloads

    att = Repo.get!(Attestation, record.signed_predicate_run_id)
    assert is_binary(att.predicate_body_uri)
  end

  test "over the response cap: no response bytes are retained and terminal success is interrupted",
       %{
         upstream: upstream
       } do
    request =
      JSON.encode!(%{
        "model" => "claude-haiku-4-5",
        "max_tokens" => 5,
        "messages" => [%{"role" => "user", "content" => "hello"}]
      })

    sse = fixture("single_tool_use_bash.sse")
    Application.put_env(:r5e, :cas_max_bytes, 1_000)
    assert byte_size(request) < 1_000
    assert byte_size(sse) > 1_000
    MockHttpUpstream.serve_sse(upstream, sse, chunk_size: 53)

    conn =
      Plug.Test.conn(:post, "/v1/messages", request)
      |> Map.update!(:req_headers, &[{"host", "localhost:4443"} | &1])
      |> Plug.Conn.put_req_header("content-type", "application/json")
      |> Plug.Conn.put_req_header("anthropic-version", "2023-06-01")

    result =
      StreamingProxy.proxy(conn, %{llm_provider_config: config(upstream), tenant_id: @tenant_id})

    body = resp_body(result)
    assert result.status == 200
    assert body =~ "gateway_interrupted"
    refute body =~ "message_stop"

    record =
      Repo.one!(
        from(c in LlmCallRecord,
          where: c.tenant_id == @tenant_id,
          order_by: [desc: c.inserted_at],
          limit: 1
        )
      )

    assert is_binary(record.prompt_payload_uri)
    assert record.response_payload_uri == nil
    assert record.payload_truncated == true
    refute sse in Enum.map(StubStorageProvider.puts(@tenant_id), & &1.payload)
  end
end
