defmodule Recurse.Gateway.LlmProxy.AttestationEmitterRetentionTest do
  @moduledoc """
  Spec 012 S6b — the emitter retains what the signature commits to.

    * The JCS predicate body put in the StorageProvider is byte-for-byte
      the input of the signed `payload_hash`, for the parent
      `:llm_call_attested` and every `:tool_use_denied` child, and the
      returned URI lands in `attestations.predicate_body_uri`.
    * A StorageProvider that fails never costs the receipt: it commits
      with `predicate_body_uri = nil` and a warning is logged.
    * Detached payloads (`request_payload` / `response_payload`) are put
      under `prompt_hash` / `response_hash` and their URIs recorded on the
      LlmCallRecord; `:truncated` sets `payload_truncated`; bytes that do
      not hash to the predicate's value are refused.
  """

  use ExUnit.Case, async: false

  import Ecto.Query, only: [from: 2]
  import ExUnit.CaptureLog, only: [with_log: 1]

  alias Recurse.Gateway.LlmProxy.AttestationEmitter
  alias Recurse.Gateway.ProviderRegistry
  alias Recurse.Gateway.Test.StubStorageProvider
  alias Recurse.Providers.Impls.PostgresMerkleLedger
  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Attestation
  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Tenant
  alias Recurse.Providers.Repo
  alias Recurse.Providers.Schemas.LlmCallRecord
  alias Recurse.Shared.LlmProxy.ToolUseIntent

  @tenant_id "01HQZN5K7J8M9N0P1Q2R3S4T_S6B"
  @prompt ~s|{"model":"claude","messages":[{"role":"user","content":"hi"}]}|
  @response "event: message_start\ndata: {}\n\nevent: message_stop\ndata: {}\n\n"

  defmodule FailingStorage do
    @moduledoc false
    @behaviour Recurse.Providers.StorageProvider
    @impl true
    def init(_), do: {:ok, %{}}
    @impl true
    def put_payload(_state, _bytes, _ctx), do: {:error, :disk_full}
    @impl true
    def get_payload(_state, _uri, _ctx), do: {:error, :not_found}
    @impl true
    def delete_payload(_state, _uri, _ctx), do: :ok
    @impl true
    def capabilities(_state), do: [:put, :get]
    @impl true
    def healthcheck(_state), do: :ok
    @impl true
    def terminate(_state, _reason), do: :ok
  end

  setup do
    :ok = Ecto.Adapters.SQL.Sandbox.checkout(Repo)
    Ecto.Adapters.SQL.Sandbox.mode(Repo, {:shared, self()})
    :ok = StubStorageProvider.reset()

    Repo.insert!(
      Tenant.changeset(%Tenant{}, %{
        tenant_id: @tenant_id,
        display_name: "S6b retention test tenant",
        tier: :standalone_gateway,
        created_at: DateTime.utc_now()
      }),
      on_conflict: :nothing,
      conflict_target: :tenant_id
    )

    install(StubStorageProvider)
    on_exit(fn -> ProviderRegistry.uninstall() end)
    :ok
  end

  defp install(storage_mod) do
    {:ok, storage_state} = storage_mod.init(%{})

    ProviderRegistry.install_raw!(%{
      llm: {Recurse.Gateway.Test.StubLLM, %{}},
      ledger: {PostgresMerkleLedger, %{repo: Repo, pubsub: Recurse.PubSub, config: %{}}},
      storage: {storage_mod, storage_state},
      secrets: {Recurse.Gateway.Test.StubSecretsProvider, %{}},
      tenant_id: @tenant_id,
      signer: "observed://gateway/s6b-retention-test"
    })
  end

  describe "predicate body retention" do
    test "the bytes put are the bytes hashed, for the parent and each denial" do
      intents = [
        {intent("call_a", "Bash", %{"command" => "ls"}), {:allow}},
        {intent("call_d", "Bash", %{"command" => "rm -rf /"}),
         {:deny, %{rule_id: "no_rm", reason: "blocked"}}}
      ]

      assert {:ok, parent_run_id} = AttestationEmitter.emit_call_attestation(call_state(intents))

      puts_by_hash = Map.new(StubStorageProvider.puts(@tenant_id), &{&1.hash, &1})

      parent = Repo.get!(Attestation, parent_run_id)
      assert is_binary(parent.predicate_body_uri)
      assert %{uri: uri, payload: body} = Map.fetch!(puts_by_hash, parent.payload_hash)
      assert uri == parent.predicate_body_uri
      assert :crypto.hash(:sha256, body) == parent.payload_hash
      # The retained bytes decode to the in-toto statement the emitter built.
      assert %{"predicateType" => "https://recurse.r5e.io/llm-call/v1"} = JSON.decode!(body)

      [child] = Repo.all(from(a in Attestation, where: a.event_kind == :tool_use_denied))
      assert is_binary(child.predicate_body_uri)
      assert %{uri: child_uri, payload: child_body} = Map.fetch!(puts_by_hash, child.payload_hash)
      assert child_uri == child.predicate_body_uri
      assert :crypto.hash(:sha256, child_body) == child.payload_hash

      # S6b: the denial carries the parent call's prompt/response hashes so
      # the retained payloads can be bound to the child's own signature.
      decoded = JSON.decode!(child_body)
      assert decoded["predicate"]["parent_llm_call_run_id"] == parent_run_id

      assert decoded["predicate"]["prompt_hash"] ==
               "sha256:" <> Base.encode16(:crypto.hash(:sha256, @prompt), case: :lower)

      assert decoded["predicate"]["response_hash"] ==
               "sha256:" <> Base.encode16(:crypto.hash(:sha256, @response), case: :lower)
    end

    test "a failing StorageProvider keeps the receipt (predicate_body_uri nil) and warns" do
      install(FailingStorage)

      {result, log} =
        with_log(fn ->
          AttestationEmitter.emit_call_attestation(
            call_state([{intent("c", "Bash", %{}), {:allow}}], request_payload: {:ok, @prompt})
          )
        end)

      assert {:ok, run_id} = result
      att = Repo.get!(Attestation, run_id)
      assert att.predicate_body_uri == nil
      assert byte_size(att.payload_hash) == 32
      assert log =~ "predicate body not retained"
      assert log =~ "receipt committed without predicate_body_uri"

      record = Repo.one!(from(c in LlmCallRecord, where: c.signed_predicate_run_id == ^run_id))
      assert record.prompt_payload_uri == nil
      assert record.payload_truncated == false
      assert log =~ "request payload not retained"
    end
  end

  describe "detached payload retention" do
    test "captured bytes are stored under the predicate's hashes and recorded on the LlmCallRecord" do
      assert {:ok, run_id} =
               AttestationEmitter.emit_call_attestation(
                 call_state([],
                   request_payload: {:ok, @prompt},
                   response_payload: {:ok, @response}
                 )
               )

      record = Repo.one!(from(c in LlmCallRecord, where: c.signed_predicate_run_id == ^run_id))
      puts_by_uri = Map.new(StubStorageProvider.puts(@tenant_id), &{&1.uri, &1})

      assert %{payload: @prompt, hash: prompt_hash} =
               Map.fetch!(puts_by_uri, record.prompt_payload_uri)

      assert prompt_hash == record.prompt_hash

      assert %{payload: @response, hash: response_hash} =
               Map.fetch!(puts_by_uri, record.response_payload_uri)

      assert response_hash == record.response_hash
      assert record.payload_truncated == false
    end

    test "retention off / absent leaves the URIs nil; :truncated sets payload_truncated" do
      assert {:ok, off_run_id} = AttestationEmitter.emit_call_attestation(call_state([]))
      off = Repo.one!(from(c in LlmCallRecord, where: c.signed_predicate_run_id == ^off_run_id))

      assert {off.prompt_payload_uri, off.response_payload_uri, off.payload_truncated} ==
               {nil, nil, false}

      assert {:ok, disabled_run_id} =
               AttestationEmitter.emit_call_attestation(
                 call_state([], request_payload: :disabled, response_payload: :disabled)
               )

      disabled =
        Repo.one!(from(c in LlmCallRecord, where: c.signed_predicate_run_id == ^disabled_run_id))

      assert {disabled.prompt_payload_uri, disabled.response_payload_uri} == {nil, nil}

      assert {:ok, trunc_run_id} =
               AttestationEmitter.emit_call_attestation(
                 call_state([], request_payload: {:ok, @prompt}, response_payload: :truncated)
               )

      trunc =
        Repo.one!(from(c in LlmCallRecord, where: c.signed_predicate_run_id == ^trunc_run_id))

      assert is_binary(trunc.prompt_payload_uri)
      assert trunc.response_payload_uri == nil
      assert trunc.payload_truncated == true

      # Only predicate bodies + the one retained prompt were put.
      payloads = Enum.map(StubStorageProvider.puts(@tenant_id), & &1.payload)
      assert @prompt in payloads
      refute @response in payloads
    end

    test "bytes that do not hash to the predicate's value are refused" do
      {result, log} =
        with_log(fn ->
          AttestationEmitter.emit_call_attestation(
            call_state([], request_payload: {:ok, "not the prompt"})
          )
        end)

      assert {:ok, run_id} = result
      record = Repo.one!(from(c in LlmCallRecord, where: c.signed_predicate_run_id == ^run_id))
      assert record.prompt_payload_uri == nil
      assert log =~ "captured request bytes do not hash to request_hash"
      refute "not the prompt" in Enum.map(StubStorageProvider.puts(@tenant_id), & &1.payload)
    end
  end

  describe "S6c handoff: outer-container policy_decision" do
    test "tool_use_denied rows commit as :deny; the parent is :allow unless every intent was denied" do
      mixed = [
        {intent("a", "Bash", %{"command" => "ls"}), {:allow}},
        {intent("d", "Bash", %{"command" => "rm -rf /"}),
         {:deny, %{rule_id: "no_rm", reason: "blocked"}}}
      ]

      assert {:ok, mixed_run_id} = AttestationEmitter.emit_call_attestation(call_state(mixed))
      assert Repo.get!(Attestation, mixed_run_id).policy_decision == :allow

      assert [%Attestation{policy_decision: :deny}] =
               Repo.all(
                 from(a in Attestation,
                   where: a.event_kind == :tool_use_denied and a.turn_id == ^mixed_run_id
                 )
               )

      all_denied = [
        {intent("d1", "Bash", %{"command" => "rm -rf /"}),
         {:deny, %{rule_id: "no_rm", reason: "blocked"}}},
        {intent("e1", "Bash", %{"command" => "x"}), {:error, :gate_down}}
      ]

      assert {:ok, denied_run_id} =
               AttestationEmitter.emit_call_attestation(call_state(all_denied))

      assert Repo.get!(Attestation, denied_run_id).policy_decision == :deny

      assert {:ok, none_run_id} = AttestationEmitter.emit_call_attestation(call_state([]))
      assert Repo.get!(Attestation, none_run_id).policy_decision == :allow
    end
  end

  defp intent(call_id, tool_name, args) do
    {:ok, intent} =
      ToolUseIntent.new(%{
        call_id: call_id,
        tool_name: tool_name,
        tool_args: args,
        provider_event_span: %{start_byte_offset: 0, end_byte_offset: 10, event_indices: [0]}
      })

    intent
  end

  defp call_state(intents, extra \\ []) do
    Map.merge(
      %{
        tenant_id: @tenant_id,
        principal_id: "claude-code:s6b",
        principal_kind: "obo_human",
        session_id: "session-s6b",
        started_at: DateTime.utc_now(),
        completed_at: DateTime.utc_now() |> DateTime.add(100, :millisecond),
        model: "claude-haiku-4-5",
        provider: "anthropic",
        upstream_host: "api.anthropic.com",
        transport: :https_sse,
        api_format: :anthropic_messages,
        request_path: "/v1/messages",
        prompt_hash: :crypto.hash(:sha256, @prompt),
        response_hash: :crypto.hash(:sha256, @response),
        prompt_token_count: 10,
        completion_token_count: 20,
        cedar_bundle_hash: :crypto.hash(:sha256, "bundle"),
        upstream_status_code: 200,
        intents: intents,
        latency_ms: 100,
        added_latency_ms: 0
      },
      Map.new(extra)
    )
  end
end
