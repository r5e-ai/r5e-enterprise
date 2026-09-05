defmodule Recurse.Gateway.LlmProxy.AttestationEmitterTest do
  @moduledoc """
  Contract tests CT-001..CT-005 for
  `Recurse.Gateway.LlmProxy.AttestationEmitter` per
  `specs/009-llm-api-proxy/contracts/llm_call_attestation.md`.

  Test contracts:

    * **CT-001** — single allow-only call → 1 `:llm_call_attested`,
      0 `:tool_use_denied` predicates.
    * **CT-002** — call with 2 allow + 3 deny → 1 `:llm_call_attested` +
      3 `:tool_use_denied` predicates. Each `:tool_use_denied`
      references the parent via `parent_llm_call_run_id`.
    * **CT-003** — failed call (upstream 500) → 1 `:llm_call_attested`
      with `error_kind: "upstream_5xx"`, 0 `:tool_use_denied`.
    * **CT-004** — predicate canonical form is JCS-stable. Same input →
      byte-identical predicate hash across two emit invocations.
    * **CT-005** — DSSE-signed predicate verifies end-to-end via the
      stored envelope's `payload_hash` field (same KMS path used by
      `EnvelopeBuilder.build_system/4`).

  `async: false` because the ProviderRegistry is a global singleton
  and we share it across tests in this module.
  """

  use ExUnit.Case, async: false

  alias Recurse.Gateway.LlmProxy.AttestationEmitter
  alias Recurse.Gateway.ProviderRegistry
  alias Recurse.Providers.Impls.PostgresMerkleLedger
  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Attestation
  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Tenant
  alias Recurse.Providers.Repo
  alias Recurse.Providers.Schemas.LlmCallRecord
  alias Recurse.Providers.Schemas.ToolUseIntentRecord
  alias Recurse.Shared.LlmProxy.ToolUseIntent

  import Ecto.Query, only: [from: 2]

  @tenant_id "01HQZN5K7J8M9N0P1Q2R3S4T_EMIT"

  setup do
    :ok = Ecto.Adapters.SQL.Sandbox.checkout(Repo)
    Ecto.Adapters.SQL.Sandbox.mode(Repo, {:shared, self()})

    Repo.insert!(
      Tenant.changeset(%Tenant{}, %{
        tenant_id: @tenant_id,
        display_name: "Attestation Emitter Test Tenant",
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
      signer: "observed://gateway/attestation-emitter-test"
    })

    on_exit(fn -> ProviderRegistry.uninstall() end)

    :ok
  end

  describe "CT-001: single allow-only call" do
    test "emits 1 :llm_call_attested + 0 :tool_use_denied" do
      intent = build_intent("call_001", "shell", %{"cmd" => "ls"})
      call_state = build_call_state([{intent, {:allow}}])

      assert {:ok, run_id} = AttestationEmitter.emit_call_attestation(call_state)

      assert count_attestations(:llm_call_attested) == 1
      assert count_attestations(:tool_use_denied) == 0

      # Round-trip the parent run_id through the row.
      assert %Attestation{run_id: ^run_id, event_kind: :llm_call_attested} =
               Repo.get!(Attestation, run_id)

      # The mirror row matches the predicate run_id.
      assert %LlmCallRecord{
               signed_predicate_run_id: ^run_id,
               tool_use_intent_count: 1,
               tool_use_denied_count: 0
             } =
               Repo.one!(from(c in LlmCallRecord, where: c.signed_predicate_run_id == ^run_id))

      # The single ToolUseIntentRecord is the allow row.
      assert [%ToolUseIntentRecord{decision: "allow"}] =
               Repo.all(
                 from(i in ToolUseIntentRecord,
                   join: c in LlmCallRecord,
                   on: i.llm_call_record_id == c.id,
                   where: c.signed_predicate_run_id == ^run_id
                 )
               )
    end
  end

  describe "CT-002: 2 allow + 3 deny" do
    test "emits 1 :llm_call_attested + 3 :tool_use_denied predicates linking to parent" do
      intents = [
        {build_intent("call_a1", "shell", %{"cmd" => "ls"}), {:allow}},
        {build_intent("call_d1", "shell", %{"cmd" => "rm -rf /"}),
         {:deny, %{rule_id: "rule_no_destructive", reason: "blocked rm -rf"}}},
        {build_intent("call_a2", "edit", %{"file" => "main.ex"}), {:allow}},
        {build_intent("call_d2", "shell", %{"cmd" => "curl evil.com"}),
         {:deny, %{rule_id: "rule_no_egress", reason: "blocked egress"}}},
        {build_intent("call_d3", "fs_write", %{"path" => "/etc/passwd"}),
         {:deny, %{rule_id: "rule_protected_path", reason: "blocked protected path"}}}
      ]

      call_state = build_call_state(intents)

      assert {:ok, parent_run_id} = AttestationEmitter.emit_call_attestation(call_state)

      assert count_attestations(:llm_call_attested) == 1
      assert count_attestations(:tool_use_denied) == 3

      # Each :tool_use_denied predicate references the parent via
      # `parent_llm_call_run_id` in the in-toto Statement body. The
      # body is hashed into `payload_hash` (predicate-only system-event
      # variant) and not directly stored — re-derive it here from the
      # call_state + parent_run_id and confirm the hash matches.
      denied_rows =
        Repo.all(from(a in Attestation, where: a.event_kind == :tool_use_denied))

      assert length(denied_rows) == 3

      # Each denial intent's expected predicate hash must appear in the
      # set of stored `payload_hash` values.
      stored_hashes = MapSet.new(denied_rows, & &1.payload_hash)

      for {intent, {:deny, deny_payload}} <- intents do
        expected_hash =
          expected_denied_payload_hash(call_state, parent_run_id, intent, deny_payload)

        assert MapSet.member?(stored_hashes, expected_hash),
               "expected denied payload hash for #{intent.call_id} not found"
      end

      # Mirror row counts match.
      assert %LlmCallRecord{tool_use_intent_count: 5, tool_use_denied_count: 3} =
               Repo.one!(
                 from(c in LlmCallRecord, where: c.signed_predicate_run_id == ^parent_run_id)
               )
    end
  end

  describe "CT-003: failed call (upstream 500)" do
    test "emits 1 :llm_call_attested with error_kind: upstream_5xx, 0 :tool_use_denied" do
      call_state =
        build_call_state([])
        |> Map.put(:upstream_status_code, 500)
        |> Map.put(:error_kind, "upstream_5xx")

      assert {:ok, run_id} = AttestationEmitter.emit_call_attestation(call_state)

      assert count_attestations(:llm_call_attested) == 1
      assert count_attestations(:tool_use_denied) == 0

      # Mirror row carries the error_kind tag.
      assert %LlmCallRecord{error_kind: "upstream_5xx", upstream_status_code: 500} =
               Repo.one!(from(c in LlmCallRecord, where: c.signed_predicate_run_id == ^run_id))

      # The in-toto Statement predicate body (hashed into
      # `payload_hash`) carries `error_kind`. Re-derive the expected
      # body from the call_state and confirm the hash matches.
      assert %Attestation{payload_hash: stored_hash} = Repo.get!(Attestation, run_id)

      assert stored_hash == expected_call_payload_hash(call_state)
    end
  end

  describe "spec 012 S2 — receipt classification (kind) + client session id" do
    test "kind and client_session_id land on the signed predicate and the receipt tags" do
      call_state =
        build_call_state([])
        |> Map.merge(%{
          transport: :https_sse,
          upstream_host: "api.anthropic.com",
          provider: "anthropic",
          api_format: :anthropic_messages,
          model: "claude-haiku-4-5-20251001",
          kind: :side_query,
          client_session_id: "ecdcbccc-ecb4-40f4-bbb1-db3ad3b16bca"
        })

      predicate = AttestationEmitter.call_predicate_map(call_state)["predicate"]
      assert predicate["kind"] == "side_query"
      assert predicate["client_session_id"] == "ecdcbccc-ecb4-40f4-bbb1-db3ad3b16bca"
      assert predicate["upstream_host"] == "api.anthropic.com"
      assert predicate["api_format"] == "anthropic_messages"

      assert {:ok, run_id} = AttestationEmitter.emit_call_attestation(call_state)

      att = Repo.get!(Attestation, run_id)
      assert att.event_kind == :llm_call_attested
      assert att.upstream_status_code == 200

      assert %{
               "kind" => "side_query",
               "client_session_id" => "ecdcbccc-ecb4-40f4-bbb1-db3ad3b16bca",
               "upstream_host" => "api.anthropic.com",
               "api_format" => "anthropic_messages",
               "transport" => "https-sse",
               "model" => "claude-haiku-4-5-20251001",
               "tool_use_intent_count" => 0,
               "decision_summary" => "no tools"
             } = att.tags

      # Still hashes like every other predicate: kind is inside the signed body.
      assert att.payload_hash == expected_call_payload_hash(call_state)
    end

    test "absent kind (WS bridge) is recorded as null, not invented" do
      call_state = build_call_state([])
      refute Map.has_key?(call_state, :kind)

      assert AttestationEmitter.call_predicate_map(call_state)["predicate"]["kind"] == nil

      assert {:ok, run_id} = AttestationEmitter.emit_call_attestation(call_state)
      att = Repo.get!(Attestation, run_id)
      refute Map.has_key?(att.tags, "kind")
      assert att.tags["upstream_host"] == "chatgpt.com"
    end
  end

  describe "CT-004: JCS-stable canonical form" do
    test "same input produces byte-identical predicate hash across two emits" do
      intent = build_intent("call_jcs", "shell", %{"cmd" => "echo hi"})

      # Use a deterministic timestamp so the predicate body is stable.
      fixed_time = ~U[2026-05-07 12:00:00.000000Z]

      call_state =
        build_call_state([{intent, {:allow}}])
        |> Map.put(:started_at, fixed_time)
        |> Map.put(:completed_at, fixed_time)

      assert {:ok, run_id_a} = AttestationEmitter.emit_call_attestation(call_state)
      assert {:ok, run_id_b} = AttestationEmitter.emit_call_attestation(call_state)

      # Different run_ids (each emit mints a fresh UUID), but
      # payload_hash should be IDENTICAL because everything else is
      # byte-stable (including the fixed timestamp).
      [%Attestation{payload_hash: hash_a}, %Attestation{payload_hash: hash_b}] =
        Repo.all(
          from(a in Attestation,
            where: a.run_id in ^[run_id_a, run_id_b],
            order_by: [asc: a.run_id],
            select: %{run_id: a.run_id, payload_hash: a.payload_hash}
          )
        )
        |> Enum.map(&struct(Attestation, &1))

      assert hash_a == hash_b
      assert byte_size(hash_a) == 32
    end
  end

  describe "CT-005: end-to-end DSSE signature" do
    test "stored envelope round-trips: payload_hash matches SHA-256 of canonical predicate bytes" do
      intent = build_intent("call_e2e", "shell", %{"cmd" => "ls"})
      call_state = build_call_state([{intent, {:allow}}])

      assert {:ok, run_id} = AttestationEmitter.emit_call_attestation(call_state)

      # Read back the stored attestation. Its `payload_hash` MUST
      # equal SHA-256 over the JCS-encoded in-toto Statement body
      # built from the call_state — the verifier path reproduces the
      # bytes from the call inputs and checks the hash.
      assert %Attestation{
               event_kind: :llm_call_attested,
               payload_hash: stored_hash,
               dsse_signature: signature,
               signer_kms_key_id: signer_kms_key_id,
               signer_key_version: signer_key_version
             } = Repo.get!(Attestation, run_id)

      assert stored_hash == expected_call_payload_hash(call_state)
      assert byte_size(stored_hash) == 32

      # DSSE signature is non-empty (signed by the configured KMS path
      # — `StubSecretsProvider` returns a SHA-512 digest of the PAE
      # bytes; structural round-trip is what we verify, the bytes are
      # not cryptographically meaningful in test).
      assert is_binary(signature) and byte_size(signature) > 0

      # Signer metadata persisted on the row carries the test KMS key
      # handle threaded through the secrets provider.
      assert is_binary(signer_kms_key_id) and signer_kms_key_id != ""
      assert is_binary(signer_key_version) or is_nil(signer_key_version)
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

  # ---------------------------------------------------------------------------
  # Spec 012 S4 — recognizer identity + completeness (plan §11)
  # ---------------------------------------------------------------------------

  describe "S4: parser + parse fields" do
    test "parser_identity/3 and parse_completeness/1 build the fields from a parser summary" do
      summary = %{
        format: "anthropic_messages/2023-06-01;betas=oauth-2025-04-20",
        events_total: 21,
        events_unhandled: 2,
        unhandled_types: ["event:telemetry", "block:widget", "block:widget"]
      }

      parser =
        AttestationEmitter.parser_identity(
          Recurse.Shared.LlmProxy.Parsers.AnthropicMessages,
          summary,
          :anthropic_messages
        )

      assert parser.module == "Recurse.Shared.LlmProxy.Parsers.AnthropicMessages"
      assert parser.version == Recurse.Shared.LlmProxy.Parsers.AnthropicMessages.version()
      assert parser.version =~ ~r/^[0-9a-f]{16}$/
      assert parser.format == "anthropic_messages/2023-06-01;betas=oauth-2025-04-20"

      assert AttestationEmitter.parse_completeness(summary) == %{
               events_total: 21,
               events_unhandled: 2,
               unhandled_types: ["block:widget", "event:telemetry"],
               status: "ok"
             }

      # Defaults: no summary (no response bytes) still names the format.
      assert AttestationEmitter.parser_identity(nil, %{}, :anthropic_messages) ==
               %{module: "unknown", version: "unknown", format: "anthropic_messages"}

      assert AttestationEmitter.parse_completeness(nil) ==
               %{events_total: 0, events_unhandled: 0, unhandled_types: [], status: "ok"}
    end

    test "the llm-call predicate and the receipt tags carry parser + parse; the denial carries call_id + parser" do
      intent = build_intent("toolu_01DENY", "Bash", %{"command" => "rm -rf /tmp/x"})
      deny = %{rule_id: "policy0", reason: "denied_by_cedar_policy"}

      call_state =
        [{intent, {:deny, deny}}]
        |> build_call_state()
        |> Map.merge(%{
          api_format: :anthropic_messages,
          parser: %{
            module: "Recurse.Shared.LlmProxy.Parsers.AnthropicMessages",
            version: "0123456789abcdef",
            format: "anthropic_messages/2023-06-01"
          },
          parse: %{events_total: 21, events_unhandled: 1, unhandled_types: ["event:telemetry"]}
        })

      predicate = AttestationEmitter.call_predicate_map(call_state)["predicate"]

      assert predicate["parser"] == %{
               "module" => "Recurse.Shared.LlmProxy.Parsers.AnthropicMessages",
               "version" => "0123456789abcdef",
               "format" => "anthropic_messages/2023-06-01"
             }

      assert predicate["parse"] == %{
               "events_total" => 21,
               "events_unhandled" => 1,
               "unhandled_types" => ["event:telemetry"],
               "status" => "ok"
             }

      denied =
        AttestationEmitter.denied_predicate_map(call_state, "parent-run", intent, deny)[
          "predicate"
        ]

      assert denied["call_id"] == "toolu_01DENY"
      assert denied["parent_llm_call_run_id"] == "parent-run"
      assert denied["parser"]["version"] == "0123456789abcdef"

      assert {:ok, run_id} = AttestationEmitter.emit_call_attestation(call_state)
      att = Repo.get!(Attestation, run_id)
      assert att.tags["parser_module"] == "Recurse.Shared.LlmProxy.Parsers.AnthropicMessages"
      assert att.tags["parser_version"] == "0123456789abcdef"
      assert att.tags["parser_format"] == "anthropic_messages/2023-06-01"
      assert att.tags["parse_events_total"] == 21
      assert att.tags["parse_events_unhandled"] == 1
      assert att.tags["parse_unhandled_types"] == ["event:telemetry"]
      assert att.tags["tool_use_intent_count"] == 1
      assert att.tags["decision_summary"] == "all deny"

      # The denial links to its parent through turn_id + the predicate body.
      assert [denied_row] =
               Repo.all(from(a in Attestation, where: a.event_kind == :tool_use_denied))

      assert denied_row.turn_id == run_id
    end

    test "receipts carry the canonical hash of the bundle the call was evaluated against (S5 finding)" do
      bundle_hash = :crypto.hash(:sha256, "permit(principal, action, resource);")
      intent = build_intent("toolu_01POL", "Bash", %{"command" => "rm -rf /tmp/x"})
      deny = %{rule_id: "policy0", reason: "denied_by_cedar_policy"}

      call_state =
        [{intent, {:deny, deny}}]
        |> build_call_state()
        |> Map.put(:cedar_bundle_hash, bundle_hash)

      assert {:ok, run_id} = AttestationEmitter.emit_call_attestation(call_state)
      sentinel = Recurse.Gateway.AuditPlane.PredicateOnlyUri.system_event_no_policy_hash()

      parent = Repo.get!(Attestation, run_id)
      assert parent.policy_canonical_hash == bundle_hash
      refute parent.policy_canonical_hash == sentinel

      assert [denied_row] =
               Repo.all(from(a in Attestation, where: a.event_kind == :tool_use_denied))

      assert denied_row.policy_canonical_hash == bundle_hash

      # No bundle loaded (all-zero hash from the proxy's forward-without-gate
      # path) keeps the sentinel: that call genuinely had no policy.
      no_bundle = build_call_state([]) |> Map.put(:cedar_bundle_hash, <<0::256>>)
      assert {:ok, run_id2} = AttestationEmitter.emit_call_attestation(no_bundle)
      assert Repo.get!(Attestation, run_id2).policy_canonical_hash == sentinel
    end

    test "a call state without the fields still records them (defaults)" do
      call_state = build_call_state([])
      predicate = AttestationEmitter.call_predicate_map(call_state)["predicate"]

      assert predicate["parser"] == %{
               "module" => "unknown",
               "version" => "unknown",
               "format" => "openai_responses"
             }

      assert predicate["parse"] == %{
               "events_total" => 0,
               "events_unhandled" => 0,
               "unhandled_types" => [],
               "status" => "ok"
             }

      assert {:ok, run_id} = AttestationEmitter.emit_call_attestation(call_state)
      att = Repo.get!(Attestation, run_id)
      assert att.tags["parse_events_unhandled"] == 0
      assert att.tags["parse_unhandled_types"] == []
    end
  end

  # ---------------------------------------------------------------------------
  # Spec 012 S4 review — gate errors, parse status, identity provenance
  # ---------------------------------------------------------------------------

  describe "S4 review" do
    test "a gate error is decision \"error\" on the predicate, a tool_use_denied child, and a written row" do
      allowed = build_intent("toolu_OK", "Read", %{"file_path" => "/a"})
      errored = build_intent("toolu_ERR", "Bash", %{"command" => "ls"})

      call_state =
        [{allowed, {:allow}}, {errored, {:error, :cedar_eval_error}}]
        |> build_call_state()
        |> Map.merge(%{
          client_session_id: "sess-1",
          principal_id: "claude-code:00000000-0000-0000-0000-000000000000",
          principal_kind: "obo_human"
        })

      predicate = AttestationEmitter.call_predicate_map(call_state)["predicate"]

      assert [
               %{"decision" => "allow", "call_id" => "toolu_OK"},
               %{
                 "decision" => "error",
                 "call_id" => "toolu_ERR",
                 "deny_reason" => "policy_evaluation_error",
                 "gate_error" => ":cedar_eval_error",
                 "cedar_rule_id" => nil
               }
             ] = predicate["tool_use_intents"]

      assert predicate["decision_summary"] == "1 allow, 1 deny (1 error)"
      assert predicate["principal_source"] == "client_metadata"
      assert predicate["principal_source_note"] =~ "client-asserted"
      assert predicate["parse"]["status"] == "ok"

      assert {:ok, run_id} = AttestationEmitter.emit_call_attestation(call_state)

      record = Repo.one!(from(c in LlmCallRecord, where: c.signed_predicate_run_id == ^run_id))
      assert record.tool_use_intent_count == 2
      assert record.tool_use_denied_count == 1
      assert record.decision_summary == "1 allow, 1 deny (1 error)"

      assert [
               %ToolUseIntentRecord{
                 call_id: "toolu_ERR",
                 decision: "deny",
                 deny_reason: "policy_evaluation_error",
                 cedar_rule_id: nil
               },
               %ToolUseIntentRecord{call_id: "toolu_OK", decision: "allow"}
             ] =
               Repo.all(
                 from(i in ToolUseIntentRecord,
                   where: i.llm_call_record_id == ^record.id,
                   order_by: i.call_id
                 )
               )

      assert [denied] = Repo.all(from(a in Attestation, where: a.event_kind == :tool_use_denied))
      assert denied.turn_id == run_id
      assert denied.tags["deny_reason"] == "policy_evaluation_error"
      assert denied.tags["call_id"] == "toolu_ERR"
      assert denied.tags["tool_name"] == "Bash"
      assert denied.tags["client_session_id"] == "sess-1"
      assert denied.tags["principal_source"] == "client_metadata"
      assert denied.tags["principal_source_note"] =~ "corroborated only by the upstream"

      parent = Repo.get!(Attestation, run_id)
      assert parent.tags["principal_source"] == "client_metadata"
      assert parent.tags["decision_summary"] == "1 allow, 1 deny (1 error)"
      assert parent.tags["parse_status"] == "ok"

      denied_pred =
        AttestationEmitter.denied_predicate_map(call_state, run_id, errored, %{
          rule_id: nil,
          reason: "policy_evaluation_error",
          gate_error: ":cedar_eval_error"
        })["predicate"]

      assert denied_pred["client_session_id"] == "sess-1"
      assert denied_pred["principal_source"] == "client_metadata"
      assert denied_pred["deny_reason"] == "policy_evaluation_error"
      assert denied_pred["gate_error"] == ":cedar_eval_error"
    end

    test "an all-error call still writes the receipt" do
      call_state =
        build_call_state([
          {build_intent("toolu_E1", "Bash", %{"command" => "ls"}), {:error, :no_bundle}}
        ])

      assert {:ok, run_id} = AttestationEmitter.emit_call_attestation(call_state)
      record = Repo.one!(from(c in LlmCallRecord, where: c.signed_predicate_run_id == ^run_id))
      assert record.tool_use_denied_count == 1
      assert record.decision_summary == "all deny (1 error)"
      assert count_attestations(:tool_use_denied) == 1
    end

    test "parse.status follows the proxy's parser_failed? flag; betas are recorded separately from the format" do
      summary = %{
        events_total: 3,
        events_unhandled: 1,
        unhandled_types: ["parser:raised"],
        betas_requested: ["oauth-2025-04-20", "claude-code-20250219"],
        format: "anthropic_messages/2023-06-01"
      }

      ok_state =
        build_call_state([])
        |> Map.put(:parse, AttestationEmitter.parse_completeness(summary))

      assert AttestationEmitter.call_predicate_map(ok_state)["predicate"]["parse"] == %{
               "events_total" => 3,
               "events_unhandled" => 1,
               "unhandled_types" => ["parser:raised"],
               "status" => "ok",
               "betas_requested" => ["oauth-2025-04-20", "claude-code-20250219"]
             }

      failed_state = Map.put(ok_state, :parser_failed?, true)

      assert AttestationEmitter.call_predicate_map(failed_state)["predicate"]["parse"]["status"] ==
               "failed"

      assert AttestationEmitter.parse_completeness(summary, parser_failed?: true).status ==
               "failed"

      refute Map.has_key?(AttestationEmitter.parse_completeness(%{}), :betas_requested)

      assert {:ok, run_id} = AttestationEmitter.emit_call_attestation(failed_state)
      att = Repo.get!(Attestation, run_id)
      assert att.tags["parse_status"] == "failed"
      assert att.tags["parse_betas_requested"] == ["oauth-2025-04-20", "claude-code-20250219"]

      # Default: nothing failed.
      assert {:ok, run_id2} = AttestationEmitter.emit_call_attestation(build_call_state([]))
      assert Repo.get!(Attestation, run_id2).tags["parse_status"] == "ok"
    end

    test "principal_source and upstream_org_id are recorded on the predicate and tags" do
      call_state =
        build_call_state([])
        |> Map.merge(%{
          principal_source: :jwt,
          upstream_response_headers: [
            {"content-type", "text/event-stream"},
            {"Anthropic-Organization-Id", "org_123"}
          ]
        })

      predicate = AttestationEmitter.call_predicate_map(call_state)["predicate"]
      assert predicate["principal_source"] == "jwt"
      assert predicate["principal_source_note"] == nil
      assert predicate["upstream_org_id"] == "org_123"

      assert {:ok, run_id} = AttestationEmitter.emit_call_attestation(call_state)
      att = Repo.get!(Attestation, run_id)
      assert att.tags["principal_source"] == "jwt"
      assert att.tags["upstream_org_id"] == "org_123"
      refute Map.has_key?(att.tags, "principal_source_note")

      # Derived when the caller does not pass it (WS bridge, older callers).
      assert AttestationEmitter.principal_source(%{principal_id: "anonymous"}) == "anonymous"

      assert AttestationEmitter.principal_source(%{principal_id: "claude-code:abc"}) ==
               "client_metadata"

      assert AttestationEmitter.principal_source(%{principal_id: "user-1"}) == "jwt"

      assert AttestationEmitter.principal_source(%{principal_id: "x", principal_source: "bogus"}) ==
               "anonymous"

      assert AttestationEmitter.principal_source(%{
               principal_id: "x",
               principal_source: "mtls_svid"
             }) == "mtls_svid"

      assert AttestationEmitter.upstream_org_id(%{upstream_org_id: "org_9"}) == "org_9"
      assert AttestationEmitter.upstream_org_id(%{upstream_response_headers: []}) == nil
      assert AttestationEmitter.upstream_org_id(%{}) == nil
    end
  end

  defp build_call_state(intent_decisions) when is_list(intent_decisions) do
    %{
      tenant_id: @tenant_id,
      principal_id: "test-principal-001",
      principal_kind: "service_account",
      session_id: "session-test-001",
      started_at: DateTime.utc_now(),
      completed_at: DateTime.utc_now() |> DateTime.add(1500, :millisecond),
      model: "gpt-5-codex",
      provider: "openai_chatgpt",
      upstream_host: "chatgpt.com",
      transport: :wss,
      api_format: :openai_responses,
      request_path: "/backend-api/codex/responses",
      prompt_hash: :crypto.hash(:sha256, "test prompt"),
      response_hash: :crypto.hash(:sha256, "test response"),
      prompt_token_count: 1000,
      completion_token_count: 200,
      reasoning_token_count: 50,
      cedar_bundle_hash: :crypto.hash(:sha256, "test cedar bundle"),
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

  # Mirrors `EnvelopeBuilder.stringify_top_level_keys/1`. The verifier
  # path (this test) and the signer path (build_system/4) MUST agree on
  # the exact JCS input shape, otherwise the hash diverges.
  defp stringify_top_level_keys_for_test(map) when is_map(map) do
    Map.new(map, fn
      {k, v} when is_atom(k) -> {Atom.to_string(k), v}
      {k, v} when is_binary(k) -> {k, v}
    end)
  end

  defp expected_call_payload_hash(call_state) do
    AttestationEmitter.call_predicate_map(call_state)
    |> stringify_top_level_keys_for_test()
    |> Recurse.Shared.Jcs.encode()
    |> then(&:crypto.hash(:sha256, &1))
  end

  defp expected_denied_payload_hash(call_state, parent_run_id, intent, deny_payload) do
    AttestationEmitter.denied_predicate_map(call_state, parent_run_id, intent, deny_payload)
    |> stringify_top_level_keys_for_test()
    |> Recurse.Shared.Jcs.encode()
    |> then(&:crypto.hash(:sha256, &1))
  end
end
