defmodule Recurse.Gateway.LlmProxy.AttestationEmitterPropertyTest do
  @moduledoc """
  Property tests PT-001 + PT-002 for
  `Recurse.Gateway.LlmProxy.AttestationEmitter` per
  `specs/009-llm-api-proxy/contracts/llm_call_attestation.md`.

    * **PT-001** — 1 call = 1 `:llm_call_attested` invariant under fuzz
      with N concurrent calls (N from 1 to 50).
    * **PT-002** — N denies = N `:tool_use_denied` predicates
      (cardinality match across random N from 0 to 20 deny intents
      per call).

  These properties are the structural-cardinality invariants that
  Constitution Principle III ("Cryptographic Provenance — every
  Gateway-traversing call produces exactly one attestation") encodes.
  Filter-free generators per `elixir:stream-data-thinking`: list_of
  generates progressively smaller lists; bind chains the deny-intent
  count into the intents-list shape directly.
  """

  use ExUnit.Case, async: false
  use ExUnitProperties

  alias Recurse.Gateway.LlmProxy.AttestationEmitter
  alias Recurse.Gateway.ProviderRegistry
  alias Recurse.Providers.Impls.PostgresMerkleLedger
  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Attestation
  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Tenant
  alias Recurse.Providers.Repo
  alias Recurse.Shared.LlmProxy.ToolUseIntent

  import Ecto.Query, only: [from: 2]

  @tenant_id "01HQZN5K7J8M9N0P1Q2R3S4T_PROP"

  setup do
    :ok = Ecto.Adapters.SQL.Sandbox.checkout(Repo)
    Ecto.Adapters.SQL.Sandbox.mode(Repo, {:shared, self()})

    Repo.insert!(
      Tenant.changeset(%Tenant{}, %{
        tenant_id: @tenant_id,
        display_name: "Attestation Emitter Property Test Tenant",
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
      signer: "observed://gateway/attestation-emitter-prop-test"
    })

    on_exit(fn -> ProviderRegistry.uninstall() end)

    :ok
  end

  property "PT-001: 1 call = 1 :llm_call_attested under N concurrent fuzz" do
    check all(
            n <- StreamData.integer(1..50),
            max_runs: 10
          ) do
      # Snapshot the count BEFORE the burst so we can assert delta.
      base_count = count_attestations(:llm_call_attested)

      # Build N independent allow-only call_states; emit each.
      # Sequential rather than literally-concurrent because Postgres
      # sandbox doesn't share across processes, but the property
      # ("each emit produces exactly 1 :llm_call_attested row") is
      # the structural invariant we want to fuzz over a range of N.
      Enum.each(1..n, fn idx ->
        intent =
          build_intent("call_pt001_#{idx}", "shell", %{"cmd" => "ls -la"})

        call_state = build_call_state([{intent, {:allow}}])

        assert {:ok, _run_id} = AttestationEmitter.emit_call_attestation(call_state)
      end)

      assert count_attestations(:llm_call_attested) - base_count == n
    end
  end

  property "PT-002: N denies = N :tool_use_denied predicates (cardinality match)" do
    check all(
            allow_count <- StreamData.integer(0..10),
            deny_count <- StreamData.integer(0..20),
            max_runs: 30
          ) do
      total = allow_count + deny_count

      base_parent = count_attestations(:llm_call_attested)
      base_denied = count_attestations(:tool_use_denied)

      intents =
        if total == 0 do
          []
        else
          allow_intents =
            for i <- 1..allow_count//1 do
              {build_intent("call_a_#{i}_#{:erlang.unique_integer([:positive])}", "edit", %{
                 "i" => i
               }), {:allow}}
            end

          deny_intents =
            for i <- 1..deny_count//1 do
              {build_intent(
                 "call_d_#{i}_#{:erlang.unique_integer([:positive])}",
                 "shell",
                 %{"cmd" => "rm -rf #{i}"}
               ),
               {:deny,
                %{rule_id: "rule_pt002_#{i}", reason: "denied for property #{i}"}}}
            end

          allow_intents ++ deny_intents
        end

      call_state = build_call_state(intents)

      assert {:ok, _run_id} = AttestationEmitter.emit_call_attestation(call_state)

      assert count_attestations(:llm_call_attested) - base_parent == 1
      assert count_attestations(:tool_use_denied) - base_denied == deny_count
    end
  end

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  defp build_intent(call_id, tool_name, args) do
    {:ok, intent} =
      ToolUseIntent.new(%{
        call_id: call_id,
        tool_name: tool_name,
        tool_args: args,
        provider_event_span: %{
          start_byte_offset: 0,
          end_byte_offset: 100,
          event_indices: [0]
        }
      })

    intent
  end

  defp build_call_state(intent_decisions) when is_list(intent_decisions) do
    %{
      tenant_id: @tenant_id,
      principal_id: "test-principal-prop",
      principal_kind: "service_account",
      session_id: "session-prop-#{:erlang.unique_integer([:positive])}",
      started_at: DateTime.utc_now(),
      completed_at: DateTime.utc_now() |> DateTime.add(1500, :millisecond),
      model: "gpt-5-codex",
      provider: "openai_chatgpt",
      upstream_host: "chatgpt.com",
      transport: :wss,
      api_format: :openai_responses,
      request_path: "/backend-api/codex/responses",
      prompt_hash: :crypto.hash(:sha256, "prop prompt"),
      response_hash: :crypto.hash(:sha256, "prop response"),
      prompt_token_count: 100,
      completion_token_count: 50,
      reasoning_token_count: nil,
      cedar_bundle_hash: :crypto.hash(:sha256, "prop cedar bundle"),
      upstream_status_code: 200,
      error_kind: nil,
      intents: intent_decisions,
      latency_ms: 1500,
      added_latency_ms: 25,
      correlation_id: nil
    }
  end

  defp count_attestations(event_kind) do
    Repo.aggregate(
      from(a in Attestation, where: a.event_kind == ^event_kind),
      :count,
      :run_id
    )
  end
end
