defmodule Recurse.Providers.Repo.Migrations.ToolUseIntentRecords do
  @moduledoc """
  Spec 009 (LLM API Proxy + Tool-Use Policy Gating) — Phase 5 migration #3 of 4.

  Creates `tool_use_intent_records` — per-tool-use-intent audit row written
  by the Phase-5 attestation emitter. One LlmCallRecord owns 0..N intent
  records (allowed AND denied — the denial case additionally emits a
  `:tool_use_denied` predicate, but the row is the queryable shape for
  both decisions).

  Source of truth: `specs/009-llm-api-proxy/data-model.md` §ToolUseIntentRecord.

  ## Notes on shape

    * FK to `llm_call_records.id` with `ON DELETE CASCADE` — when an
      LlmCallRecord is deleted (rare; primarily for retention sweeps)
      its intents go with it. Audit data is normally append-only; the
      cascade keeps the schema honest if a row IS removed.
    * `tool_args_inlined` is JSONB (Ecto `:map`) and is NULLABLE — when
      the tool args exceed the inlining threshold (FR-IV: detached
      payloads), only `tool_args_hash` is stored here and the raw bytes
      live in customer-controlled storage via the existing payload
      broker.
    * `decision` is a closed enum (`allow | deny`) enforced via CHECK.
    * `cedar_rule_id` and `deny_reason` are nullable — they're only
      meaningful for the `deny` branch; for `allow`-by-default both are
      null.
    * `parallel_index` is null for non-parallel calls; for OpenAI's
      `parallel_tool_calls=true` it's the 0-based index in the
      response's parallel-tool array.
    * `call_id` correlates to OpenAI Responses API's `call_id` field on
      the `function_call` item — Phase-5 needs it to match a
      `function_call_output` back to the originating intent.

  ## Indexes

    * FK index on `llm_call_record_id` (created automatically by
      `references/2` — referenced by Postgres `ON DELETE CASCADE`).
    * `(tenant_id, tool_name, decision)` — "all calls of tool X with
      decision Y" queries.
    * `(tenant_id, decision, extracted_at DESC)` — "recent denials
      across all tools" feed.
  """

  use Ecto.Migration

  def change do
    create table(:tool_use_intent_records) do
      add :tenant_id,
          references(:tenants, column: :tenant_id, type: :string, on_delete: :restrict),
          null: false

      add :llm_call_record_id,
          references(:llm_call_records, on_delete: :delete_all),
          null: false

      add :tool_name, :string, null: false
      add :tool_args_hash, :binary, null: false
      add :tool_args_inlined, :map
      add :decision, :string, null: false
      add :cedar_rule_id, :string
      add :deny_reason, :string
      add :tool_args_size_bytes, :integer, null: false
      add :parallel_index, :integer
      add :call_id, :string, null: false
      add :extracted_at, :utc_datetime_usec, null: false

      timestamps(type: :utc_datetime_usec, updated_at: false)
    end

    # Per-tool-decision lookup.
    create index(:tool_use_intent_records, [:tenant_id, :tool_name, :decision],
             name: :tool_use_intent_records_tenant_tool_decision_index
           )

    # Recent-denials feed across all tools.
    create index(
             :tool_use_intent_records,
             [:tenant_id, :decision, "extracted_at DESC"],
             name: :tool_use_intent_records_tenant_decision_extracted_index
           )

    # FK index — Ecto creates one for `references/2` but be explicit so
    # the index name is predictable for the migration smoke test.
    create index(:tool_use_intent_records, [:llm_call_record_id],
             name: :tool_use_intent_records_llm_call_record_id_index
           )

    # decision must be allow or deny.
    create constraint(
             :tool_use_intent_records,
             :tool_use_intent_records_decision_check,
             check: "decision IN ('allow', 'deny')"
           )

    # SHA-256 hash length.
    create constraint(
             :tool_use_intent_records,
             :tool_use_intent_records_tool_args_hash_len_check,
             check: "octet_length(tool_args_hash) = 32"
           )

    # Sizes and indexes are non-negative.
    create constraint(
             :tool_use_intent_records,
             :tool_use_intent_records_size_check,
             check:
               "tool_args_size_bytes >= 0 AND (parallel_index IS NULL OR parallel_index >= 0)"
           )

    # Deny rows must carry a deny_reason; allow rows must NOT (the data
    # shape distinguishes the two cases unambiguously). cedar_rule_id is
    # also tied to the deny branch — null for allow-by-default.
    create constraint(
             :tool_use_intent_records,
             :tool_use_intent_records_decision_consistency_check,
             check: """
             (decision = 'allow' AND deny_reason IS NULL AND cedar_rule_id IS NULL)
             OR
             (decision = 'deny' AND deny_reason IS NOT NULL)
             """
           )
  end
end
