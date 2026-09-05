defmodule Recurse.Providers.Schemas.LlmCallRecordTest do
  @moduledoc """
  Schema-layer (in-memory) unit tests for
  `Recurse.Providers.Schemas.LlmCallRecord`.

  Exercises `changeset/2`: required fields, enum rejection
  (transport, principal_kind, error_kind), hash-length, count + latency
  consistency. Does NOT hit Postgres — the DB-layer CHECK constraints +
  FK index are exercised by the migration smoke test in
  `test/recurse_providers/llm_calls_test.exs`.
  """

  use ExUnit.Case, async: true

  alias Recurse.Providers.Schemas.LlmCallRecord

  @tenant_id "01ARZ3NDEKTSV4RRFFQ69G5FAV"
  @run_id "01b9a8c0-83cb-49b0-9ed4-1b5dfc7e3f00"
  @sha32 :crypto.strong_rand_bytes(32)

  defp valid_attrs(overrides \\ %{}) do
    %{
      tenant_id: @tenant_id,
      signed_predicate_run_id: @run_id,
      principal_id: "spiffe://r5e/principal/abc",
      principal_kind: "obo_human",
      session_id: "session-123",
      provider: "openai_chatgpt",
      upstream_host: "chatgpt.com",
      transport: "wss",
      model: "gpt-5-codex",
      api_format: "openai_responses",
      request_path: "/backend-api/codex/responses",
      prompt_hash: @sha32,
      response_hash: @sha32,
      prompt_token_count: 100,
      completion_token_count: 50,
      reasoning_token_count: 10,
      tool_use_intent_count: 2,
      tool_use_denied_count: 1,
      decision_summary: "1 allow, 1 deny",
      cedar_bundle_hash: @sha32,
      upstream_status_code: 200,
      latency_ms: 4523,
      added_latency_ms: 87,
      started_at: ~U[2026-05-07 12:00:00.000000Z],
      completed_at: ~U[2026-05-07 12:00:04.523000Z]
    }
    |> Map.merge(overrides)
  end

  describe "changeset/2 — happy path" do
    test "valid attrs produce a valid changeset" do
      cs = LlmCallRecord.changeset(%LlmCallRecord{}, valid_attrs())
      assert cs.valid?, "expected valid; got errors: #{inspect(cs.errors)}"
    end

    test "error_kind = nil is accepted (success case)" do
      cs = LlmCallRecord.changeset(%LlmCallRecord{}, valid_attrs(%{error_kind: nil}))
      assert cs.valid?
    end

    test "reasoning_token_count = nil is accepted (non-Responses-API)" do
      cs =
        LlmCallRecord.changeset(
          %LlmCallRecord{},
          valid_attrs(%{reasoning_token_count: nil})
        )

      assert cs.valid?
    end

    test "chatgpt_account_id is optional" do
      attrs = valid_attrs() |> Map.delete(:chatgpt_account_id)
      cs = LlmCallRecord.changeset(%LlmCallRecord{}, attrs)
      assert cs.valid?
    end
  end

  describe "changeset/2 — required fields" do
    test "missing all required fields surfaces all errors" do
      cs = LlmCallRecord.changeset(%LlmCallRecord{}, %{})
      refute cs.valid?

      keys = Keyword.keys(cs.errors)
      assert :tenant_id in keys
      assert :signed_predicate_run_id in keys
      assert :principal_id in keys
      assert :principal_kind in keys
      assert :session_id in keys
      assert :provider in keys
      assert :upstream_host in keys
      assert :transport in keys
      assert :model in keys
      assert :api_format in keys
      assert :request_path in keys
      assert :prompt_hash in keys
      assert :response_hash in keys
      assert :decision_summary in keys
      assert :cedar_bundle_hash in keys
      assert :upstream_status_code in keys
      assert :latency_ms in keys
      assert :added_latency_ms in keys
      assert :started_at in keys
      assert :completed_at in keys
    end

    test "missing only one required field is enough to invalidate" do
      attrs = Map.delete(valid_attrs(), :model)
      cs = LlmCallRecord.changeset(%LlmCallRecord{}, attrs)
      refute cs.valid?
      assert Keyword.has_key?(cs.errors, :model)
    end
  end

  describe "transport enum" do
    test "accepts wss" do
      cs = LlmCallRecord.changeset(%LlmCallRecord{}, valid_attrs(%{transport: "wss"}))
      assert cs.valid?
    end

    test "accepts https-sse" do
      cs = LlmCallRecord.changeset(%LlmCallRecord{}, valid_attrs(%{transport: "https-sse"}))
      assert cs.valid?
    end

    test "rejects unknown transport" do
      cs =
        LlmCallRecord.changeset(%LlmCallRecord{}, valid_attrs(%{transport: "carrier-pigeon"}))

      refute cs.valid?
      assert Keyword.has_key?(cs.errors, :transport)
    end
  end

  describe "principal_kind enum" do
    test "accepts every contracted value" do
      for v <- ["obo_human", "service_account", "autonomous"] do
        cs = LlmCallRecord.changeset(%LlmCallRecord{}, valid_attrs(%{principal_kind: v}))
        assert cs.valid?
      end
    end

    test "rejects unknown principal_kind" do
      cs = LlmCallRecord.changeset(%LlmCallRecord{}, valid_attrs(%{principal_kind: "robot"}))
      refute cs.valid?
      assert Keyword.has_key?(cs.errors, :principal_kind)
    end
  end

  describe "error_kind enum (nullable)" do
    test "accepts every documented non-null value" do
      for v <- [
            "upstream_4xx",
            "upstream_5xx",
            "parser_failure",
            "policy_evaluation_failure",
            "upstream_connection_failed"
          ] do
        cs = LlmCallRecord.changeset(%LlmCallRecord{}, valid_attrs(%{error_kind: v}))
        assert cs.valid?, "expected #{v} to be accepted; errors: #{inspect(cs.errors)}"
      end
    end

    test "rejects unknown error_kind" do
      cs = LlmCallRecord.changeset(%LlmCallRecord{}, valid_attrs(%{error_kind: "exploded"}))
      refute cs.valid?
      assert Keyword.has_key?(cs.errors, :error_kind)
    end
  end

  describe "count consistency" do
    test "rejects tool_use_denied_count > tool_use_intent_count" do
      cs =
        LlmCallRecord.changeset(
          %LlmCallRecord{},
          valid_attrs(%{tool_use_intent_count: 1, tool_use_denied_count: 2})
        )

      refute cs.valid?
      assert Keyword.has_key?(cs.errors, :tool_use_denied_count)
    end

    test "rejects negative token count" do
      cs =
        LlmCallRecord.changeset(%LlmCallRecord{}, valid_attrs(%{prompt_token_count: -1}))

      refute cs.valid?
      assert Keyword.has_key?(cs.errors, :prompt_token_count)
    end
  end

  describe "latency consistency" do
    test "rejects added_latency_ms > latency_ms" do
      cs =
        LlmCallRecord.changeset(
          %LlmCallRecord{},
          valid_attrs(%{latency_ms: 100, added_latency_ms: 200})
        )

      refute cs.valid?
      assert Keyword.has_key?(cs.errors, :added_latency_ms)
    end
  end

  describe "hash length" do
    test "rejects prompt_hash that is not 32 bytes" do
      cs =
        LlmCallRecord.changeset(
          %LlmCallRecord{},
          valid_attrs(%{prompt_hash: <<0x00, 0x01, 0x02>>})
        )

      refute cs.valid?
      assert Keyword.has_key?(cs.errors, :prompt_hash)
    end

    test "rejects response_hash that is not 32 bytes" do
      cs =
        LlmCallRecord.changeset(
          %LlmCallRecord{},
          valid_attrs(%{response_hash: <<>>})
        )

      refute cs.valid?
      assert Keyword.has_key?(cs.errors, :response_hash)
    end

    test "rejects cedar_bundle_hash that is not 32 bytes" do
      cs =
        LlmCallRecord.changeset(
          %LlmCallRecord{},
          valid_attrs(%{cedar_bundle_hash: :crypto.strong_rand_bytes(31)})
        )

      refute cs.valid?
      assert Keyword.has_key?(cs.errors, :cedar_bundle_hash)
    end
  end

  describe "decision_summary" do
    test "is free-form (no enum validation)" do
      for v <- ["all allow", "all deny", "1 allow, 2 deny", "totally bogus but accepted"] do
        cs = LlmCallRecord.changeset(%LlmCallRecord{}, valid_attrs(%{decision_summary: v}))
        assert cs.valid?
      end
    end
  end
end
