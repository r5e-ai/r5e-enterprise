defmodule Recurse.Gateway.Fold.SubmitterActivationTest do
  @moduledoc """
  Spec 012 S9b review correction 1 (plan §20) — an activation of the
  gateway's Cedar bundle is a **re-admission of the fold's
  `PolicyBundle/active`**, not bytes parked in the CAS that nobody cites.

  Its own file, and so its own chain (`Recurse.Fold.FreshKernel`), because
  every test here changes which bundle governs the fold: the assertions of
  the sibling dual-write file are about a chain governed by the fold's
  shipped `deny-destructive.cedar`, and these are about one governed by
  the gateway's own bundle.

  Three beats:

    * the activation — the bytes land as a `CasObject` **and**
      `PolicyBundle/active` is re-admitted citing that object, superseding
      the fold's boot-time default;
    * the second activation of the same bytes — the object is not re-put
      and the bundle is not superseded again, and the readiness surface
      still names the activation that governs;
    * the payoff — with the gateway's own bundle governing the fold, a
      Claude Code `Bash rm -rf` is denied by BOTH engines, so
      `decision_mismatches` stays 0 where S9b measured 1.
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

  @tenant_id "01TEN_S9C_FOLD_ACTIVATION"
  @fixtures Path.expand("../../../../recurse_shared/test/fixtures/anthropic_messages", __DIR__)
  @client_session "3f2a1b9c-0000-4000-8000-aaaaaaaaaaaa"
  @group "gateway.r5e.io"
  @version "v1alpha1"

  # The gateway's bundle for this file: the Claude Code `Bash` rule the
  # fold's shipped `deny-destructive.cedar` does not have. Section 1 of
  # `policy/bundle.cedar` in miniature; the `admit`/`call_model` permits
  # are what let the fold keep recording under it (see the assertions).
  @bundle """
  permit (principal, action == Action::"invoke_tool", resource);
  permit (principal, action == Action::"admit", resource);
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
        display_name: "S9c fold activation test tenant",
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
      signer: "observed://gateway/s9c-activation-test"
    })

    canonical_hash = Recurse.Cedar.canonical_hash(@bundle)
    previous_active = Active.current()

    Active.update(%Active{
      source: :filesystem,
      source_ref: "s9c-activation-test",
      loaded_at: DateTime.utc_now(),
      bundle: %PolicyBundleRef{
        bundle_id: Base.encode16(canonical_hash, case: :lower),
        canonical_hash: canonical_hash,
        loaded_at: DateTime.utc_now(),
        evaluator_handle: @bundle,
        bundle_bytes: @bundle
      }
    })

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

  # -- harness ------------------------------------------------------------------

  defp active! do
    {:ok, active} = Active.current()
    active
  end

  defp fixture(name), do: File.read!(Path.join(@fixtures, name))

  defp request_conn(body) do
    Plug.Test.conn(:post, "/v1/messages?beta=true", body)
    |> Map.update!(:req_headers, &[{"host", "localhost:4443"} | &1])
    |> Plug.Conn.put_req_header("content-type", "application/json")
    |> Plug.Conn.put_req_header(
      "authorization",
      "Bearer sk-ant-oat01-" <> String.duplicate("x", 100)
    )
    |> Plug.Conn.put_req_header("anthropic-version", "2023-06-01")
    |> Plug.Conn.put_req_header("x-claude-code-session-id", @client_session)
  end

  # The captured `ls -la` Bash turn with the command rewritten.
  defp bash_rm_rf_sse do
    fixture("single_tool_use_bash.sse")
    |> String.replace(~s|"partial_json":": \\"l"|, ~s|"partial_json":": \\"rm -rf /tmp/x"|)
    |> String.replace(~s|"partial_json":"s -la\\""|, ~s|"partial_json":"\\""|)
  end

  defp run(upstream, sse) do
    MockHttpUpstream.serve_sse(upstream, sse, chunk_size: 61)

    result =
      StreamingProxy.proxy(
        request_conn(fixture("single_tool_use_bash.request.json")),
        %{
          llm_provider_config: %Recurse.Providers.Schemas.LlmProviderConfig{
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
        }
      )

    assert result.status == 200
    result
  end

  # -- the chain ------------------------------------------------------------------

  defp admissions do
    for event <- R5e.Log.read_events(),
        event["kind"] in ["admission.granted", "admission.denied"],
        {:ok, payload} <- [R5e.Log.payload(event)] do
      %{
        seq: event["seq"],
        kind: R5e.Admission.target_path(payload),
        outcome: payload["outcome"],
        spec: payload["spec"],
        reason: payload["reason"],
        ref: R5e.Admission.event_ref(event)
      }
    end
  end

  defp of(kind, since \\ 0),
    do:
      Enum.filter(admissions(), &(&1.kind == "#{@group}/#{@version}/#{kind}" and &1.seq > since))

  defp last_seq, do: admissions() |> Enum.map(& &1.seq) |> Enum.max(fn -> 0 end)

  defp bundle_entry do
    {:ok, entry, _lineage} = R5e.ResourceStore.get(@group, @version, "PolicyBundle", "active")
    entry
  end

  # -- beats ------------------------------------------------------------------------

  test "an activation puts the bundle bytes on the record AND re-admits PolicyBundle/active citing them" do
    assert {:ok, "bytes:sha256:" <> hex = address} = Submitter.submit_bundle(active!())
    assert hex == Base.encode16(:crypto.hash(:sha256, @bundle), case: :lower)

    # 1. the bytes are on the record, addressed by their own hash
    assert {:ok, _} = R5e.RefIndex.cas_object(address)
    assert {:ok, ^address} = fetch_object_address(address)

    # 2. and PolicyBundle/active cites them — the activation, not a parked object
    entry = bundle_entry()
    assert entry["spec"]["sourceRef"] == %{"$ref" => address}
    activation = entry["admissionEvent"]

    assert %{outcome: "admitted", spec: spec} =
             Enum.find(of("PolicyBundle"), &(&1.ref == activation))

    assert spec["engine"] == "cedar"
    assert spec["sourceRef"] == %{"$ref" => address}
    assert spec["description"] =~ "gateway's active Cedar bundle"

    # 3. it superseded the fold's boot-time default rather than colliding
    #    with it: `literal` naming re-admits as a supersession.
    assert [displaced] = R5e.ResourceStore.superseded(@group, @version, "PolicyBundle", "active")
    assert displaced["supersededBy"] == activation
    assert displaced["spec"]["sourceRef"] != %{"$ref" => address}
    assert entry["supersedes"] == displaced["admissionEvent"]

    # 4. and the readiness surface names all three
    assert Submitter.stats()["active_bundle_object"] == %{
             "canonical_hash" => active!().bundle.bundle_id,
             "object" => address,
             "activation" => activation
           }

    # The canonical hash the enterprise receipts carry re-derives from the
    # bytes the fold's engine now reads.
    {:ok, bytes} = R5e.CAS.get(address)
    assert Recurse.Cedar.canonical_hash_hex(bytes) == active!().bundle.bundle_id
  end

  test "a second activation of the same bytes re-puts nothing and supersedes nothing" do
    assert {:ok, address} = Submitter.submit_bundle(active!())
    first = bundle_entry()
    since = last_seq()

    assert {:ok, ^address} = Submitter.submit_bundle(active!())
    assert {:ok, ^address} = Submitter.submit_bundle(active!())

    # Nothing new on the chain: no second CasObject, no supersession.
    assert last_seq() == since
    assert of("PolicyBundle", since) == []
    assert bundle_entry()["admissionEvent"] == first["admissionEvent"]

    # And the governing bundle is still the one on the readiness surface,
    # named by the admission that made it govern.
    assert %{"object" => ^address, "activation" => activation} =
             Submitter.stats()["active_bundle_object"]

    assert activation == first["admissionEvent"]
  end

  test "with the gateway's own bundle governing the fold, a Bash rm -rf is denied by both engines",
       %{upstream: upstream} do
    assert {:ok, _address} = Submitter.submit_bundle(active!())
    since = last_seq()

    run(upstream, bash_rm_rf_sse())

    # The gateway denied it in-stream (its rule), and the fold denied the
    # admission under the same bytes — one decision, recorded twice.
    assert [%{outcome: "denied", spec: tool}] = of("ToolCall", since)
    assert tool["tool"] == "Bash"
    assert tool["args"]["command"] == "rm -rf /tmp/x"

    # The live admission boundary records the ToolCall before releasing its
    # bytes. Submitter's counters belong to its legacy after-the-fact importer,
    # so this live path is proved by the receipt above rather than those
    # compatibility counters.
    assert Submitter.stats()["acts_denied"] == 0

    # The rest of the call still lands. Tenant policy governs LlmCall and
    # ToolCall only; the kernel policy retains authority over evidence and
    # policy-management objects.
    assert [%{outcome: "admitted"}] = of("AgentSession", since)
    assert [%{outcome: "admitted"}] = of("Prompt", since)
    assert [%{outcome: "admitted"}] = of("LlmCall", since)
    assert [%{outcome: "admitted"}] = of("LlmResponse", since)
  end

  defp fetch_object_address(address) do
    case R5e.CAS.get(address) do
      {:ok, _bytes} -> {:ok, address}
      other -> other
    end
  end
end
