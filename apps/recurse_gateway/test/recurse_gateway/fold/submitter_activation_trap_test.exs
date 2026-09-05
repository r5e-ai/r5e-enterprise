defmodule Recurse.Gateway.Fold.SubmitterActivationTrapTest do
  @moduledoc """
  Policy jurisdiction stays recoverable after tenant activation.

  A gateway bundle governs the workload Kinds `LlmCall` and `ToolCall`.
  Kernel policy continues to govern evidence objects and policy management,
  including the next `PolicyBundle/active` activation. This pins both sides:
  a narrowly scoped tenant bundle can deny a destructive tool while the rest
  of the evidence still lands, and that bundle cannot lock an operator out of
  a later activation.
  """

  use ExUnit.Case, async: false

  alias Recurse.Gateway.Fold.Submitter
  alias Recurse.Gateway.LlmProxy.StreamingProxy
  alias Recurse.Gateway.Policy.Active
  alias Recurse.Gateway.PolicyBundleRef
  alias Recurse.Gateway.ProviderRegistry
  alias Recurse.Gateway.Test.MockHttpUpstream
  alias Recurse.Providers.Impls.PostgresMerkleLedger
  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Tenant
  alias Recurse.Providers.Repo
  alias Recurse.Providers.Schemas.LlmProviderConfig

  @tenant_id "01TEN_S9C_FOLD_TRAP"
  @fixtures Path.expand("../../../../recurse_shared/test/fixtures/anthropic_messages", __DIR__)
  @client_session "3f2a1b9c-0000-4000-8000-bbbbbbbbbbbb"
  @group "gateway.r5e.io"
  @version "v1alpha1"

  # The complete tenant jurisdiction: model calls can proceed, while the
  # destructive Bash tool is denied. Evidence and management acts do not need
  # tenant-level `admit` permits because kernel policy governs them.
  @bundle """
  permit (principal, action == Action::"invoke_tool", resource);
  permit (principal, action == Action::"call_model", resource);

  forbid (principal, action == Action::"invoke_tool", resource == ToolUse::"Bash") when {
    context has tool_args && context.tool_args has command &&
    context.tool_args.command like "*rm -rf*"
  };
  """

  setup_all do
    Recurse.Fold.FreshKernel.boot()
  end

  setup do
    :ok = Ecto.Adapters.SQL.Sandbox.checkout(Repo)
    Ecto.Adapters.SQL.Sandbox.mode(Repo, {:shared, self()})

    Repo.insert!(
      Tenant.changeset(%Tenant{}, %{
        tenant_id: @tenant_id,
        display_name: "S9c fold activation trap tenant",
        tier: :standalone_gateway,
        created_at: DateTime.utc_now()
      }),
      on_conflict: :nothing,
      conflict_target: :tenant_id
    )

    ProviderRegistry.install_raw!(%{
      llm: {Recurse.Gateway.Test.StubLLM, %{}},
      ledger: {PostgresMerkleLedger, %{repo: Repo, pubsub: Recurse.PubSub, config: %{}}},
      storage: {Recurse.Gateway.Test.StubStorage, %{}},
      secrets: {Recurse.Gateway.Test.StubSecretsProvider, %{}},
      tenant_id: @tenant_id,
      signer: "observed://gateway/s9c-trap-test"
    })

    previous_active = Active.current()
    Active.update(active_for(@bundle, "s9c-trap-test"))

    previous_retain = Application.get_env(:recurse_gateway, :retain_payloads?)
    Application.put_env(:recurse_gateway, :retain_payloads?, true)

    Submitter.reset()
    {:ok, upstream} = MockHttpUpstream.start()

    on_exit(fn ->
      MockHttpUpstream.stop(upstream)
      ProviderRegistry.uninstall()
      Application.put_env(:recurse_gateway, :retain_payloads?, previous_retain)

      case previous_active do
        {:ok, active} -> Active.update(active)
        _ -> Active.erase()
      end
    end)

    {:ok, upstream: upstream}
  end

  defp active_for(source, ref) do
    hash = Recurse.Cedar.canonical_hash(source)

    %Active{
      source: :filesystem,
      source_ref: ref,
      loaded_at: DateTime.utc_now(),
      bundle: %PolicyBundleRef{
        bundle_id: Base.encode16(hash, case: :lower),
        canonical_hash: hash,
        loaded_at: DateTime.utc_now(),
        evaluator_handle: source,
        bundle_bytes: source
      }
    }
  end

  defp fixture(name), do: File.read!(Path.join(@fixtures, name))

  defp bash_rm_rf_sse do
    fixture("single_tool_use_bash.sse")
    |> String.replace(~s|"partial_json":": \\"l"|, ~s|"partial_json":": \\"rm -rf /tmp/x"|)
    |> String.replace(~s|"partial_json":"s -la\\""|, ~s|"partial_json":"\\""|)
  end

  defp run(upstream) do
    MockHttpUpstream.serve_sse(upstream, bash_rm_rf_sse(), chunk_size: 61)

    conn =
      Plug.Test.conn(
        :post,
        "/v1/messages?beta=true",
        fixture("single_tool_use_bash.request.json")
      )
      |> Map.update!(:req_headers, &[{"host", "localhost:4443"} | &1])
      |> Plug.Conn.put_req_header("content-type", "application/json")
      |> Plug.Conn.put_req_header(
        "authorization",
        "Bearer sk-ant-oat01-" <> String.duplicate("x", 100)
      )
      |> Plug.Conn.put_req_header("anthropic-version", "2023-06-01")
      |> Plug.Conn.put_req_header("x-claude-code-session-id", @client_session)

    result =
      StreamingProxy.proxy(conn, %{
        llm_provider_config: %LlmProviderConfig{
          tenant_id: @tenant_id,
          provider: "anthropic",
          upstream_host: "127.0.0.1",
          upstream_port: upstream.port,
          transport_modes: ["https-sse"],
          auth_mode: :passthrough,
          api_format: :anthropic_messages,
          enabled: true,
          metadata: %{"scheme" => "http"}
        },
        tenant_id: @tenant_id
      })

    assert result.status == 200
    result
  end

  defp admissions do
    for event <- R5e.Log.read_events(),
        event["kind"] in ["admission.granted", "admission.denied"],
        {:ok, payload} <- [R5e.Log.payload(event)] do
      %{
        seq: event["seq"],
        kind: R5e.Admission.target_path(payload),
        outcome: payload["outcome"],
        reason: payload["reason"]
      }
    end
  end

  defp last_seq, do: admissions() |> Enum.map(& &1.seq) |> Enum.max(fn -> 0 end)

  defp since(n), do: Enum.filter(admissions(), &(&1.seq > n))

  test "a workload bundle denies its tool without blocking evidence or the next activation",
       %{upstream: upstream} do
    # The activation itself is admitted: the bundle in force while it runs
    # is the fold's own default, which permits everything.
    assert {:ok, address} = Submitter.submit_bundle(active_for(@bundle, "s9c-trap-test"))

    assert {:ok, entry, _lineage} =
             R5e.ResourceStore.get(@group, @version, "PolicyBundle", "active")

    assert entry["spec"]["sourceRef"] == %{"$ref" => address}

    # From here on it governs the two workload Kinds. The request is admitted,
    # and the destructive ToolCall is recorded as a denial.
    mark = last_seq()
    run(upstream)
    acts = since(mark)

    # Evidence objects remain kernel-governed and admitted.
    for kind <- ["#{@group}/#{@version}/AgentSession", "core.r5e.io/v1/CasObject"] do
      assert %{outcome: "admitted"} = Enum.find(acts, &(&1.kind == kind))
    end

    assert %{outcome: "admitted"} =
             Enum.find(acts, &(&1.kind == "#{@group}/#{@version}/LlmCall"))

    # The ToolCall, denied by the rule the operator wrote — this half works.
    assert %{reason: tool_reason} =
             Enum.find(acts, &(&1.kind == "#{@group}/#{@version}/ToolCall"))

    assert tool_reason =~ ~s|cedar denied Action::"invoke_tool" on ToolUse::"Bash"|
    assert tool_reason =~ "matched policy2"
    # Policy management remains upstream-governed, so an operator can replace
    # this tenant bundle even though it declares no `admit` permission.
    later = @bundle <> "\n// a later edit by the operator\n"

    assert {:ok, later_address} =
             Submitter.submit_bundle(active_for(later, "s9c-trap-test-2"))

    assert {:ok, replacement, _} =
             R5e.ResourceStore.get(@group, @version, "PolicyBundle", "active")

    assert replacement["spec"]["sourceRef"] == %{"$ref" => later_address}
    assert replacement["supersedes"] == entry["admissionEvent"]
  end
end
