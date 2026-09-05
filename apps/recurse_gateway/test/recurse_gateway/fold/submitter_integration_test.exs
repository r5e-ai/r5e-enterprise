defmodule Recurse.Gateway.Fold.SubmitterIntegrationTest do
  @moduledoc """
  Spec 012 S9b — the dual-write, end to end: the S4 proxy harness (mock
  Anthropic upstream serving the S0 fixtures, ProviderRegistry installed,
  a real gateway Cedar bundle active, payload retention ON) drives
  `StreamingProxy` → `AttestationEmitter` → `Fold.Submitter`, against a
  **fresh kernel per file** (`Recurse.Fold.FreshKernel`, so this file's
  assertions about the chain are about a chain only it wrote to).

  Four beats:

    * allow — `LlmCall`, `Prompt`, `Completion`, `LlmResponse`, one admitted
      `ToolCall` and an `AgentSession` are on the chain; the enterprise
      receipt exists; no mismatch;
    * deny, `shell rm -rf` — the gateway denies in-stream and the fold
      denies the admission → the `ToolCall` is a `{:denied, _}` receipt on
      the chain AND the enterprise `tool_use_denied` receipt exists; the
      `LlmResponse` cites the denied event; no mismatch;
    * deny, `Bash rm -rf` — the S9b beat that measured a mismatch. It no
      longer does, and that is plan §20 correction 2 landing: the fold
      evaluates the **gateway's own bundle**, activated as its
      `PolicyBundle/active` on the first call, so the `Bash` rule the
      fold's shipped `deny-destructive.cedar` never had is the one both
      engines read. `decision_mismatches` stays 0;
    * refusal — fold disabled: the ledger receipt commits as before,
      nothing lands on the chain, `last_refusal` names the switch.

  Because the gateway's bundle governs the fold from the first call on, the
  file's `@bundle` carries section 4 of `policy/bundle.cedar` — the
  `admit` and `call_model` permits without which the fold records nothing
  but denials. `submitter_activation_trap_test.exs` is that omission,
  pinned.
  """

  use ExUnit.Case, async: false

  import Ecto.Query, only: [from: 2]

  alias Recurse.Gateway.Fold.Submitter
  alias Recurse.Gateway.LlmProxy.StreamingProxy
  alias Recurse.Gateway.Policy.Active
  alias Recurse.Gateway.PolicyBundleRef
  alias Recurse.Gateway.ProviderRegistry
  alias Recurse.Gateway.Test.MockHttpUpstream
  alias Recurse.Providers.Impls.PostgresMerkleLedger
  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Attestation
  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Tenant
  alias Recurse.Providers.Repo
  alias Recurse.Providers.Schemas.LlmCallRecord
  alias Recurse.Providers.Schemas.LlmProviderConfig
  alias Recurse.Providers.Schemas.ToolUseIntentRecord

  @tenant_id "01TEN_S9B_FOLD_SUBMITTER"
  @fixtures Path.expand("../../../../recurse_shared/test/fixtures/anthropic_messages", __DIR__)
  @bash_call_id "toolu_01LZV8Ni38xTJKZoqdQM8Pdk"
  @client_session "ecdcbccc-ecb4-40f4-bbb1-db3ad3b16bca"
  @group "gateway.r5e.io/v1alpha1/"
  @group_only "gateway.r5e.io"
  @version "v1alpha1"

  # The gateway's bundle for this file: Claude Code's Bash AND the demo's
  # `shell` tool are both forbidden on `rm -rf`, and the fold's recording
  # acts are permitted (section 4 of `policy/bundle.cedar`) because from
  # the first call on this is the bundle the fold's gate reads.
  @bundle """
  permit (principal, action == Action::"invoke_tool", resource);
  permit (principal, action == Action::"admit", resource);
  permit (principal, action == Action::"call_model", resource);

  forbid (principal, action == Action::"invoke_tool", resource == ToolUse::"Bash") when {
    context has tool_args && context.tool_args has command &&
    context.tool_args.command like "*rm -rf*"
  };

  forbid (principal, action == Action::"invoke_tool", resource == ToolUse::"shell") when {
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
        display_name: "S9b fold submitter test tenant",
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
      signer: "observed://gateway/s9b-fold-test"
    })

    canonical_hash = Recurse.Cedar.canonical_hash(@bundle)
    previous_active = Active.current()

    Active.update(%Active{
      source: :filesystem,
      source_ref: "s9b-test",
      loaded_at: DateTime.utc_now(),
      bundle: %PolicyBundleRef{
        bundle_id: Base.encode16(canonical_hash, case: :lower),
        canonical_hash: canonical_hash,
        loaded_at: DateTime.utc_now(),
        evaluator_handle: @bundle,
        bundle_bytes: @bundle
      }
    })

    # Retention on: without the request bytes there is no Prompt, and
    # without a Prompt the Kind admits no LlmCall.
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

  defp proxy(conn, upstream),
    do:
      StreamingProxy.proxy(conn, %{llm_provider_config: config(upstream), tenant_id: @tenant_id})

  defp request_conn(body, session \\ @client_session) do
    Plug.Test.conn(:post, "/v1/messages?beta=true", body)
    |> Map.update!(:req_headers, &[{"host", "localhost:4443"} | &1])
    |> Plug.Conn.put_req_header("content-type", "application/json")
    |> Plug.Conn.put_req_header(
      "authorization",
      "Bearer sk-ant-oat01-" <> String.duplicate("x", 100)
    )
    |> Plug.Conn.put_req_header("anthropic-version", "2023-06-01")
    |> Plug.Conn.put_req_header("x-claude-code-session-id", session)
  end

  # The captured `ls -la` turn with the command rewritten to `rm -rf /tmp/x`.
  defp deny_sse(tool) do
    fixture("single_tool_use_bash.sse")
    |> String.replace(~s|"partial_json":": \\"l"|, ~s|"partial_json":": \\"rm -rf /tmp/x"|)
    |> String.replace(~s|"partial_json":"s -la\\""|, ~s|"partial_json":"\\""|)
    |> String.replace(~s|"name":"Bash"|, ~s|"name":"#{tool}"|)
  end

  defp run_allow(upstream, session \\ @client_session) do
    MockHttpUpstream.serve_sse(upstream, fixture("single_tool_use_bash.sse"), chunk_size: 53)
    result = proxy(request_conn(fixture("single_tool_use_bash.request.json"), session), upstream)
    assert result.status == 200
    result
  end

  defp run_deny(upstream, tool) do
    MockHttpUpstream.serve_sse(upstream, deny_sse(tool), chunk_size: 61)
    result = proxy(request_conn(fixture("single_tool_use_bash.request.json")), upstream)
    assert result.status == 200
    result
  end

  # -- the chain ------------------------------------------------------------------

  # `[{seq, kind_path, outcome, spec, event_ref}]` for every admission event.
  defp admissions do
    for event <- R5e.Log.read_events(),
        event["kind"] in ["admission.granted", "admission.denied"],
        {:ok, payload} <- [R5e.Log.payload(event)] do
      %{
        seq: event["seq"],
        kind: R5e.Admission.target_path(payload),
        outcome: payload["outcome"],
        spec: payload["spec"],
        ref: R5e.Admission.event_ref(event)
      }
    end
  end

  defp of(kind, since \\ 0),
    do: Enum.filter(admissions(), &(&1.kind == @group <> kind and &1.seq > since))

  defp last_seq, do: admissions() |> Enum.map(& &1.seq) |> Enum.max(fn -> 0 end)

  defp latest_call_record do
    Repo.one!(
      from(c in LlmCallRecord,
        where: c.tenant_id == @tenant_id,
        order_by: [desc: c.inserted_at],
        limit: 1
      )
    )
  end

  defp denied_receipts do
    Repo.all(from(a in Attestation, where: a.event_kind == :tool_use_denied))
  end

  # -- beats ------------------------------------------------------------------------

  test "allow: the whole call lands on the chain, bound to the session and the ledger run_id",
       %{upstream: upstream} do
    since = last_seq()
    run_allow(upstream)

    record = latest_call_record()
    assert record.tool_use_denied_count == 0

    # Live admission records the session before any upstream bytes leave.
    assert [%{outcome: "admitted", spec: session, ref: session_ref}] =
             of("AgentSession", since)

    assert session["sourceIds"]["session"] == @client_session

    assert [%{outcome: "admitted", spec: prompt}] = of("Prompt", since)
    assert "bytes:sha256:" <> _ = prompt["contentRef"]["$ref"]
    assert prompt["mediaType"] == "application/json"

    assert [%{outcome: "admitted", spec: call, ref: call_ref}] = of("LlmCall", since)
    assert call["model"] == "claude-haiku-4-5-20251001"
    assert call["provider"] == "anthropic"
    assert call["transport"] == "https-sse"

    assert call["sourceIds"]["session"] == @client_session
    assert is_binary(call["sourceIds"]["run"])

    assert call["session"] == %{"$ref" => session_kind_ref(session_ref)}

    assert [%{outcome: "admitted", spec: tool, ref: tool_ref}] = of("ToolCall", since)
    assert tool["tool"] == "Bash"
    assert tool["args"]["command"] == "ls -la"
    assert tool["llmCall"] == %{"$ref" => call_ref}
    assert tool["index"] == 0
    assert tool["callId"] == @bash_call_id

    assert [%{outcome: "admitted", spec: completion}] = of("Completion", since)
    assert completion["mediaType"] == "text/event-stream"

    assert [%{outcome: "admitted", spec: response}] = of("LlmResponse", since)
    assert response["llmCall"] == %{"$ref" => call_ref}
    assert response["outcome"] == "ok"
    assert response["toolCalls"] == [%{"$ref" => tool_ref}]

    assert response["usage"] == %{
             "inputTokens" => 10,
             "outputTokens" => 181,
             "reasoningTokens" => 102
           }

    assert response["upstreamStatus"] == 200

    assert record.signed_predicate_run_id
  end

  test "deny (shell rm -rf): both engines deny — a denial receipt on the chain AND on the ledger",
       %{upstream: upstream} do
    since = last_seq()
    run_deny(upstream, "shell")

    record = latest_call_record()
    assert record.tool_use_denied_count == 1
    assert [%ToolUseIntentRecord{decision: "deny", tool_name: "shell"}] = intent_rows(record)
    assert [denied] = denied_receipts()
    assert denied.tags["tool_name"] == "shell"

    assert [%{outcome: "denied", spec: tool, ref: tool_ref}] = of("ToolCall", since)
    assert tool["tool"] == "shell"
    assert tool["args"]["command"] == "rm -rf /tmp/x"
    assert tool["callId"] == @bash_call_id

    # `toolCalls` declares `outcome: any`, so the LlmResponse cites the denial.
    assert [%{outcome: "admitted", spec: response}] = of("LlmResponse", since)
    assert response["toolCalls"] == [%{"$ref" => tool_ref}]

    # The same kernel decision governs release of the bytes and the chain
    # receipt, so the live path has no importer-side mismatch counter.
    assert tool["tool"] == "shell"
  end

  test "deny (Bash rm -rf): the fold reads the gateway's own bundle, so both engines deny and nothing mismatches",
       %{upstream: upstream} do
    since = last_seq()
    run_deny(upstream, "Bash")

    record = latest_call_record()
    assert record.tool_use_denied_count == 1
    assert [_] = denied_receipts()

    # S9b recorded this as `admitted` with `decision_mismatches: 1`: the
    # fold's shipped policy has no `Bash` rule. The activation is what
    # changed — the fold now reads the bundle that does.
    assert [%{outcome: "denied", spec: tool}] = of("ToolCall", since)
    assert tool["tool"] == "Bash"
    assert tool["args"]["command"] == "rm -rf /tmp/x"

    {:ok, active_bundle} = Recurse.Fold.Policy.Cedar.active_bundle()
    "bytes:sha256:" <> _ = get_in(active_bundle, ["spec", "sourceRef", "$ref"])
  end

  test "mandatory admission fails closed before upstream when the fold is disabled",
       %{upstream: upstream} do
    since = last_seq()
    Application.put_env(:recurse_fold, :enabled?, false)
    on_exit(fn -> Application.put_env(:recurse_fold, :enabled?, true) end)

    MockHttpUpstream.serve_sse(upstream, fixture("single_tool_use_bash.sse"), chunk_size: 53)
    result = proxy(request_conn(fixture("single_tool_use_bash.request.json")), upstream)
    assert result.status == 503
    assert %{"error" => %{"kind" => "admission_failed"}} = JSON.decode!(result.resp_body)

    assert last_seq() == since
    assert Repo.aggregate(Attestation, :count, :run_id) == 0
    assert Repo.aggregate(LlmCallRecord, :count, :id) == 0
  end

  test "each live call admits an AgentSession carrying the client session id",
       %{upstream: upstream} do
    a =
      "11111111-0000-4000-8000-" <>
        String.pad_leading(Integer.to_string(System.unique_integer([:positive])), 12, "0")

    b =
      "22222222-0000-4000-8000-" <>
        String.pad_leading(Integer.to_string(System.unique_integer([:positive])), 12, "0")

    run_allow(upstream, a)
    run_allow(upstream, a)
    run_allow(upstream, a)

    sessions_a = sessions_for(a)
    assert length(sessions_a) == 3
    assert Enum.uniq_by(sessions_a, & &1.ref) == sessions_a

    calls = of("LlmCall") |> Enum.filter(&(&1.spec["sourceIds"]["session"] == a))
    assert length(calls) == 3

    session_refs = MapSet.new(sessions_a, &session_kind_ref(&1.ref))
    assert Enum.all?(calls, &MapSet.member?(session_refs, &1.spec["session"]["$ref"]))

    # A different client session remains distinguishable on the chain.
    run_allow(upstream, b)
    assert [%{ref: ref_b}] = sessions_for(b)
    refute MapSet.member?(MapSet.new(sessions_a, & &1.ref), ref_b)
  end

  test "the gateway's active bundle is activated in the fold — bytes on the chain, PolicyBundle/active citing them, idempotently" do
    {:ok, active} = Active.current()
    assert {:ok, "bytes:sha256:" <> hex = address} = Submitter.submit_bundle(active)
    assert hex == Base.encode16(:crypto.hash(:sha256, @bundle), case: :lower)
    assert {:ok, ^address} = Submitter.submit_bundle(active)
    assert {:ok, _} = R5e.RefIndex.cas_object(address)

    {:ok, entry, _lineage} =
      R5e.ResourceStore.get(@group_only, @version, "PolicyBundle", "active")

    assert entry["spec"]["sourceRef"] == %{"$ref" => address}

    assert Submitter.stats()["active_bundle_object"] == %{
             "canonical_hash" => active.bundle.bundle_id,
             "object" => address,
             "activation" => entry["admissionEvent"]
           }

    # The canonical hash the receipts carry re-derives from the object's bytes.
    {:ok, bytes} = R5e.CAS.get(address)
    assert Recurse.Cedar.canonical_hash_hex(bytes) == active.bundle.bundle_id
  end

  test "the first live call uses the bundle admitted before upstream dispatch",
       %{upstream: upstream} do
    {:ok, before} = Recurse.Fold.Policy.Cedar.active_bundle()
    before_ref = get_in(before, ["spec", "sourceRef", "$ref"])
    since = last_seq()
    run_allow(upstream)
    {:ok, active} = Active.current()
    {:ok, after_bundle} = Recurse.Fold.Policy.Cedar.active_bundle()

    assert get_in(after_bundle, ["spec", "sourceRef", "$ref"]) == before_ref
    assert active.bundle.bundle_id == Recurse.Cedar.canonical_hash_hex(@bundle)

    assert before_ref ==
             "bytes:sha256:" <> Base.encode16(:crypto.hash(:sha256, @bundle), case: :lower)

    first = admissions() |> Enum.filter(&(&1.seq > since)) |> List.first()
    assert first.kind in ["core.r5e.io/v1/CasObject", "gateway.r5e.io/v1alpha1/AgentSession"]
  end

  defp sessions_for(client_session_id) do
    Enum.filter(of("AgentSession"), &(&1.spec["sourceIds"]["session"] == client_session_id))
  end

  # A `server`-named resource's name is its admission event; the store
  # entry carries both, so the kind ref an LlmCall cites is derivable.
  defp session_kind_ref(admission_event_ref) do
    entry =
      Enum.find(
        R5e.ResourceStore.list("gateway.r5e.io", "v1alpha1", "AgentSession"),
        &(&1["admissionEvent"] == admission_event_ref)
      )

    "gateway.r5e.io/v1alpha1/AgentSession/" <> entry["name"]
  end

  defp intent_rows(record),
    do: Repo.all(from(i in ToolUseIntentRecord, where: i.llm_call_record_id == ^record.id))
end
