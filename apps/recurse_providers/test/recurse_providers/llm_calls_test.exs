defmodule Recurse.Providers.LlmCallsTest do
  @moduledoc """
  DB-layer tests for `Recurse.Providers.LlmCalls.write_call_with_intents/2`
  and the `llm_call_records` + `tool_use_intent_records` schemas' DB
  invariants.

  Uses the live Ecto SQL Sandbox (per the F002 T097 pattern in
  `postgres_merkle_ledger_schema_test.exs`). Requires `mix ecto.migrate`
  to have run against the test DB.
  """

  use ExUnit.Case, async: false

  alias Ecto.Adapters.SQL
  alias Ecto.Adapters.SQL.Sandbox

  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.{
    Attestation,
    Session,
    Tenant
  }

  alias Recurse.Providers.LlmCalls
  alias Recurse.Providers.Repo
  alias Recurse.Providers.Schemas.LlmCallRecord
  alias Recurse.Providers.Schemas.ToolUseIntentRecord
  alias Recurse.Shared.Ulid

  @sha32_a :crypto.hash(:sha256, "fixture-a")
  @sha32_b :crypto.hash(:sha256, "fixture-b")
  @sha32_c :crypto.hash(:sha256, "fixture-c")

  setup do
    :ok = Sandbox.checkout(Repo)
    Sandbox.mode(Repo, {:shared, self()})

    tenant_id = Ulid.generate()

    {:ok, _} =
      Repo.insert(
        Tenant.changeset(%Tenant{}, %{
          tenant_id: tenant_id,
          display_name: "LlmCallsTest tenant",
          tier: :standalone_gateway,
          created_at: DateTime.utc_now()
        })
      )

    {:ok, %Session{session_id: session_id}} =
      Repo.insert(
        Session.changeset(%Session{}, %{
          tenant_id: tenant_id,
          session_scope: :discovery_session,
          state: :active,
          session_start: DateTime.utc_now(),
          principal_kind: :obo_human,
          principal_canonical: :crypto.hash(:sha256, "principal-canonical")
        })
      )

    run_id = seed_attestation(tenant_id, session_id)

    {:ok, tenant_id: tenant_id, session_id: session_id, run_id: run_id}
  end

  defp seed_attestation(tenant_id, session_id) do
    run_id = Ecto.UUID.generate()
    turn_id = Ecto.UUID.generate()

    {:ok, _} =
      Repo.insert(
        Attestation.changeset(%Attestation{run_id: run_id}, %{
          session_id: session_id,
          turn_id: turn_id,
          event_kind: :llm_call,
          machine_identity: %{"observed_jwt_subject" => "alice"},
          principal: %{"kind" => "obo_human", "subject" => "alice"},
          tenant_id: tenant_id,
          policy_canonical_hash: @sha32_a,
          payload_hash: @sha32_b,
          payload_uri: "s3://bucket/runs/#{run_id}.json",
          correlation_id: Ulid.generate(),
          signer_kms_key_id: "arn:aws:kms:us-east-1:123:key/test",
          signer_key_version: "1",
          timestamp: DateTime.utc_now(),
          signed_predicate_bytes: "predicate-#{run_id}",
          dsse_signature: <<0::size(8 * 72)>>,
          verification_level: :signed,
          tier_completeness_advisory: :partial,
          policy_decision: :allow,
          outcome: :success
        })
      )

    run_id
  end

  defp valid_call_attrs(opts) do
    %{
      tenant_id: Keyword.fetch!(opts, :tenant_id),
      signed_predicate_run_id: Keyword.fetch!(opts, :run_id),
      principal_id: "spiffe://r5e/principal/abc",
      principal_kind: "obo_human",
      session_id: Keyword.get(opts, :session_id_str, "client-session-001"),
      provider: "openai_chatgpt",
      upstream_host: "chatgpt.com",
      transport: "wss",
      model: "gpt-5-codex",
      api_format: "openai_responses",
      request_path: "/backend-api/codex/responses",
      prompt_hash: @sha32_a,
      response_hash: @sha32_b,
      prompt_token_count: 100,
      completion_token_count: 50,
      reasoning_token_count: 10,
      tool_use_intent_count: Keyword.get(opts, :intent_count, 2),
      tool_use_denied_count: Keyword.get(opts, :denied_count, 1),
      decision_summary: Keyword.get(opts, :decision_summary, "1 allow, 1 deny"),
      cedar_bundle_hash: @sha32_c,
      upstream_status_code: 200,
      latency_ms: 4523,
      added_latency_ms: 87,
      started_at: DateTime.utc_now(),
      completed_at: DateTime.utc_now()
    }
  end

  defp valid_intent_attrs(opts) do
    %{
      tenant_id: Keyword.fetch!(opts, :tenant_id),
      tool_name: Keyword.get(opts, :tool_name, "edit"),
      tool_args_hash: @sha32_a,
      tool_args_inlined: %{"path" => "/etc/foo"},
      decision: Keyword.get(opts, :decision, "allow"),
      tool_args_size_bytes: 247,
      call_id: Keyword.get(opts, :call_id, "call_#{:rand.uniform(99_999)}"),
      extracted_at: DateTime.utc_now()
    }
  end

  defp valid_deny_intent_attrs(opts) do
    opts
    |> valid_intent_attrs()
    |> Map.merge(%{
      decision: "deny",
      cedar_rule_id: "rule_no_destructive",
      deny_reason: "blocked"
    })
  end

  describe "write_call_with_intents/2 — happy path" do
    test "inserts call + N intents atomically", %{tenant_id: tenant_id, run_id: run_id} do
      call_attrs = valid_call_attrs(tenant_id: tenant_id, run_id: run_id)

      intents = [
        valid_intent_attrs(tenant_id: tenant_id, tool_name: "edit", call_id: "call_1"),
        valid_deny_intent_attrs(tenant_id: tenant_id, tool_name: "shell", call_id: "call_2")
      ]

      assert {:ok, %{call: %LlmCallRecord{} = call, intents: returned_intents}} =
               LlmCalls.write_call_with_intents(call_attrs, intents)

      assert call.tenant_id == tenant_id
      assert call.signed_predicate_run_id == run_id
      assert call.tool_use_intent_count == 2
      assert call.tool_use_denied_count == 1

      assert [%ToolUseIntentRecord{} = i1, %ToolUseIntentRecord{} = i2] = returned_intents
      assert i1.tool_name == "edit"
      assert i1.decision == "allow"
      assert i1.llm_call_record_id == call.id
      assert i2.tool_name == "shell"
      assert i2.decision == "deny"
      assert i2.llm_call_record_id == call.id
    end

    test "zero-intent call is allowed", %{tenant_id: tenant_id, run_id: run_id} do
      call_attrs =
        valid_call_attrs(
          tenant_id: tenant_id,
          run_id: run_id,
          intent_count: 0,
          denied_count: 0,
          decision_summary: "all allow"
        )

      assert {:ok, %{call: call, intents: []}} =
               LlmCalls.write_call_with_intents(call_attrs, [])

      assert call.tool_use_intent_count == 0
    end
  end

  describe "write_call_with_intents/2 — invariants" do
    test "rejects mismatch between declared intent_count and actual intents", %{
      tenant_id: tenant_id,
      run_id: run_id
    } do
      call_attrs = valid_call_attrs(tenant_id: tenant_id, run_id: run_id, intent_count: 5)
      intents = [valid_intent_attrs(tenant_id: tenant_id)]

      assert {:error, :tool_use_intent_count_mismatch} =
               LlmCalls.write_call_with_intents(call_attrs, intents)

      # And nothing was written.
      assert [] = Repo.all(LlmCallRecord)
    end

    test "rejects mismatch between declared denied_count and actual denials", %{
      tenant_id: tenant_id,
      run_id: run_id
    } do
      call_attrs =
        valid_call_attrs(
          tenant_id: tenant_id,
          run_id: run_id,
          intent_count: 1,
          denied_count: 1
        )

      # The single intent says decision = "allow"; declared denied = 1.
      intents = [valid_intent_attrs(tenant_id: tenant_id)]

      assert {:error, :tool_use_denied_count_mismatch} =
               LlmCalls.write_call_with_intents(call_attrs, intents)
    end
  end

  describe "write_call_with_intents/2 — rollback on intent failure" do
    test "intent changeset error rolls back call insert", %{
      tenant_id: tenant_id,
      run_id: run_id
    } do
      call_attrs = valid_call_attrs(tenant_id: tenant_id, run_id: run_id, intent_count: 2, denied_count: 0)

      bad_intent = valid_intent_attrs(tenant_id: tenant_id) |> Map.delete(:tool_name)
      intents = [valid_intent_attrs(tenant_id: tenant_id), bad_intent]

      assert {:error, {:intent, 1}, %Ecto.Changeset{valid?: false} = cs} =
               LlmCalls.write_call_with_intents(call_attrs, intents)

      assert Keyword.has_key?(cs.errors, :tool_name)

      # The call insert is rolled back — no row committed.
      assert [] = Repo.all(LlmCallRecord)
      assert [] = Repo.all(ToolUseIntentRecord)
    end

    test "call changeset error returns :call branch and persists nothing", %{
      tenant_id: tenant_id,
      run_id: run_id
    } do
      call_attrs =
        valid_call_attrs(
          tenant_id: tenant_id,
          run_id: run_id,
          intent_count: 0,
          denied_count: 0,
          decision_summary: "all allow"
        )
        |> Map.put(:transport, "carrier-pigeon")

      assert {:error, :call, %Ecto.Changeset{valid?: false} = cs} =
               LlmCalls.write_call_with_intents(call_attrs, [])

      assert Keyword.has_key?(cs.errors, :transport)
      assert [] = Repo.all(LlmCallRecord)
    end
  end

  describe "FK ON DELETE CASCADE" do
    test "deleting the call removes its intents", %{tenant_id: tenant_id, run_id: run_id} do
      call_attrs =
        valid_call_attrs(tenant_id: tenant_id, run_id: run_id, intent_count: 2, denied_count: 0)

      intents = [
        valid_intent_attrs(tenant_id: tenant_id, call_id: "call_a"),
        valid_intent_attrs(tenant_id: tenant_id, call_id: "call_b")
      ]

      {:ok, %{call: call}} = LlmCalls.write_call_with_intents(call_attrs, intents)

      assert 2 = Repo.aggregate(ToolUseIntentRecord, :count, :id)

      Repo.delete!(call)

      assert 0 = Repo.aggregate(ToolUseIntentRecord, :count, :id)
    end
  end

  describe "DB-layer invariants" do
    test "schema_migrations contains both 20260507000002 and 20260507000003 rows" do
      %{rows: rows} =
        SQL.query!(
          Repo,
          "SELECT version FROM schema_migrations WHERE version IN ($1, $2) ORDER BY version",
          [20_260_507_000_002, 20_260_507_000_003]
        )

      assert [[20_260_507_000_002], [20_260_507_000_003]] = rows
    end

    test "expected llm_call_records indexes exist" do
      %{rows: rows} =
        SQL.query!(
          Repo,
          """
          SELECT indexname FROM pg_indexes
          WHERE tablename = 'llm_call_records'
          ORDER BY indexname
          """,
          []
        )

      names = Enum.map(rows, &List.first/1)
      assert "llm_call_records_tenant_started_at_index" in names
      assert "llm_call_records_tenant_principal_started_at_index" in names
      assert "llm_call_records_tenant_model_started_at_index" in names
      assert "llm_call_records_tenant_decision_started_at_index" in names
      assert "llm_call_records_signed_predicate_run_id_index" in names
      assert "llm_call_records_tenant_session_index" in names
    end

    test "the partial decision_summary index has the WHERE predicate" do
      %{rows: [[indexdef]]} =
        SQL.query!(
          Repo,
          """
          SELECT indexdef FROM pg_indexes
          WHERE indexname = 'llm_call_records_tenant_decision_started_at_index'
          """,
          []
        )

      assert indexdef =~ "WHERE"
      assert indexdef =~ "all allow"
    end

    test "expected tool_use_intent_records indexes exist" do
      %{rows: rows} =
        SQL.query!(
          Repo,
          """
          SELECT indexname FROM pg_indexes
          WHERE tablename = 'tool_use_intent_records'
          ORDER BY indexname
          """,
          []
        )

      names = Enum.map(rows, &List.first/1)
      assert "tool_use_intent_records_tenant_tool_decision_index" in names
      assert "tool_use_intent_records_tenant_decision_extracted_index" in names
      assert "tool_use_intent_records_llm_call_record_id_index" in names
    end

    test "DB CHECK rejects unknown transport via raw SQL", %{
      tenant_id: tenant_id,
      run_id: run_id
    } do
      assert_raise Postgrex.Error, ~r/transport_check/, fn ->
        SQL.query!(
          Repo,
          """
          INSERT INTO llm_call_records
            (tenant_id, signed_predicate_run_id, principal_id, principal_kind,
             session_id, provider, upstream_host, transport, model, api_format,
             request_path, prompt_hash, response_hash,
             prompt_token_count, completion_token_count,
             tool_use_intent_count, tool_use_denied_count, decision_summary,
             cedar_bundle_hash, upstream_status_code,
             latency_ms, added_latency_ms, started_at, completed_at, inserted_at)
          VALUES
            ($1, $2, 'p', 'obo_human', 's', 'openai_chatgpt', 'chatgpt.com',
             'carrier-pigeon', 'gpt-5', 'openai_responses',
             '/x', $3, $3, 1, 1, 0, 0, 'all allow', $3, 200,
             1, 0, NOW(), NOW(), NOW())
          """,
          [tenant_id, Ecto.UUID.dump!(run_id), @sha32_a]
        )
      end
    end
  end
end
