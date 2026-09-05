defmodule Recurse.Providers.Repo.Migrations.LlmCallRecords do
  @moduledoc """
  Spec 009 (LLM API Proxy + Tool-Use Policy Gating) — Phase 5 migration #2 of 4.

  Creates `llm_call_records` — denormalized per-LLM-call audit row written
  by the Phase-5 attestation emitter alongside the canonical
  `:llm_call_attested` predicate. Phase-4's audit-plane endpoint queries
  this table for the CISO "LLM Calls" view; Sub-3.7 (attestation emitter)
  writes one row per call via `Recurse.Providers.LlmCalls.write_call_with_intents/2`.

  Source of truth: `specs/009-llm-api-proxy/data-model.md` §LlmCallRecord.

  ## Notes on shape

    * `tenant_id` is the `:string` ULID, FK to `tenants.tenant_id` per the
      F002 convention (matches `LlmProviderConfig` and `attestations`).
    * `signed_predicate_run_id` references `attestations.run_id`
      (`:binary_id`) per the !153 reconciliation — see
      `20260506000004_sbom_binding_predicates.exs` for the same pattern.
    * `decision_summary` is a free-form formatted string (e.g.,
      "1 allow, 2 deny", "all allow", "all deny") — NOT a closed enum,
      so no CHECK on its value. The partial index uses the literal
      `'all allow'` for the "show me denials" hot path.
    * `error_kind` is nullable (null on success) and constrained via CHECK
      to match the `streaming_proxy.md` failure-mode table:
      `upstream_4xx | upstream_5xx | parser_failure |
       policy_evaluation_failure | upstream_connection_failed`.
    * `transport` is constrained to `wss | https-sse` matching
      `LlmProviderConfig.transport_modes` element values.
    * Hash columns (`prompt_hash`, `response_hash`, `cedar_bundle_hash`)
      are 32-byte SHA-256 outputs enforced by `octet_length` CHECKs.
    * `timestamps(updated_at: false)` — the row is append-only audit;
      audit data is never updated.

  ## Indexes

    * `(tenant_id, started_at DESC)` — chronological audit listing
    * `(tenant_id, principal_id, started_at DESC)` — per-principal history
    * `(tenant_id, model, started_at DESC)` — per-model usage
    * partial `(tenant_id, decision_summary, started_at DESC) WHERE
       decision_summary != 'all allow'` — denial dashboard
    * `(signed_predicate_run_id)` — reverse lookup from attestation
    * `(tenant_id, session_id)` — per-session correlation (Codex sessions)
  """

  use Ecto.Migration

  def change do
    create table(:llm_call_records) do
      add :tenant_id,
          references(:tenants, column: :tenant_id, type: :string, on_delete: :restrict),
          null: false

      add :signed_predicate_run_id,
          references(:attestations,
            column: :run_id,
            type: :binary_id,
            on_delete: :restrict
          ),
          null: false

      add :principal_id, :string, null: false
      add :principal_kind, :string, null: false
      add :chatgpt_account_id, :string
      add :session_id, :string, null: false
      add :provider, :string, null: false
      add :upstream_host, :string, null: false
      add :transport, :string, null: false
      add :model, :string, null: false
      add :api_format, :string, null: false
      add :request_path, :string, null: false
      add :prompt_hash, :binary, null: false
      add :response_hash, :binary, null: false
      add :prompt_token_count, :integer, null: false
      add :completion_token_count, :integer, null: false
      add :reasoning_token_count, :integer
      add :tool_use_intent_count, :integer, null: false, default: 0
      add :tool_use_denied_count, :integer, null: false, default: 0
      add :decision_summary, :string, null: false
      add :cedar_bundle_hash, :binary, null: false
      add :upstream_status_code, :integer, null: false
      add :error_kind, :string
      add :latency_ms, :integer, null: false
      add :added_latency_ms, :integer, null: false
      add :started_at, :utc_datetime_usec, null: false
      add :completed_at, :utc_datetime_usec, null: false

      timestamps(type: :utc_datetime_usec, updated_at: false)
    end

    # Chronological per-tenant audit listing (default sort).
    create index(:llm_call_records, [:tenant_id, "started_at DESC"],
             name: :llm_call_records_tenant_started_at_index
           )

    # Per-principal history.
    create index(:llm_call_records, [:tenant_id, :principal_id, "started_at DESC"],
             name: :llm_call_records_tenant_principal_started_at_index
           )

    # Per-model usage.
    create index(:llm_call_records, [:tenant_id, :model, "started_at DESC"],
             name: :llm_call_records_tenant_model_started_at_index
           )

    # Partial index for the denial dashboard. Filters out the common
    # `all allow` case so the index stays small.
    create index(
             :llm_call_records,
             [:tenant_id, :decision_summary, "started_at DESC"],
             name: :llm_call_records_tenant_decision_started_at_index,
             where: "decision_summary != 'all allow'"
           )

    # Reverse lookup from a signed-predicate attestation row.
    create index(:llm_call_records, [:signed_predicate_run_id],
             name: :llm_call_records_signed_predicate_run_id_index
           )

    # Per-session correlation (e.g., a single Codex session_id covers
    # many turns and so many LlmCallRecords).
    create index(:llm_call_records, [:tenant_id, :session_id],
             name: :llm_call_records_tenant_session_index
           )

    # transport must match LlmProviderConfig.transport_modes element values.
    create constraint(
             :llm_call_records,
             :llm_call_records_transport_check,
             check: "transport IN ('wss', 'https-sse')"
           )

    # principal_kind enum per data-model.md.
    create constraint(
             :llm_call_records,
             :llm_call_records_principal_kind_check,
             check: "principal_kind IN ('obo_human', 'service_account', 'autonomous')"
           )

    # error_kind enum per streaming_proxy.md failure-mode table. Nullable
    # = success (no error). The CHECK allows NULL; only constrains the
    # set of legal non-NULL values.
    create constraint(
             :llm_call_records,
             :llm_call_records_error_kind_check,
             check: """
             error_kind IS NULL OR error_kind IN (
               'upstream_4xx',
               'upstream_5xx',
               'parser_failure',
               'policy_evaluation_failure',
               'upstream_connection_failed'
             )
             """
           )

    # Hash length invariants — every hash column is SHA-256 (32 bytes).
    create constraint(
             :llm_call_records,
             :llm_call_records_prompt_hash_len_check,
             check: "octet_length(prompt_hash) = 32"
           )

    create constraint(
             :llm_call_records,
             :llm_call_records_response_hash_len_check,
             check: "octet_length(response_hash) = 32"
           )

    create constraint(
             :llm_call_records,
             :llm_call_records_cedar_bundle_hash_len_check,
             check: "octet_length(cedar_bundle_hash) = 32"
           )

    # Token counts and latencies are non-negative; reasoning_token_count
    # is nullable (null on non-Responses-API calls) and when present is
    # also non-negative.
    create constraint(
             :llm_call_records,
             :llm_call_records_token_counts_check,
             check: """
             prompt_token_count >= 0
             AND completion_token_count >= 0
             AND tool_use_intent_count >= 0
             AND tool_use_denied_count >= 0
             AND tool_use_denied_count <= tool_use_intent_count
             AND (reasoning_token_count IS NULL OR reasoning_token_count >= 0)
             """
           )

    create constraint(
             :llm_call_records,
             :llm_call_records_latencies_check,
             check:
               "latency_ms >= 0 AND added_latency_ms >= 0 AND added_latency_ms <= latency_ms"
           )
  end
end
