defmodule Recurse.Providers.Schemas.LlmCallRecord do
  @moduledoc """
  Ecto schema for the `llm_call_records` table — denormalized per-LLM-call
  audit row. Written by the Phase-5 attestation emitter
  (Sub-3.7) and read by the Phase-4 audit-plane endpoint (Sub-4.1) for
  the CISO "LLM Calls" view.

  Source of truth: `specs/009-llm-api-proxy/data-model.md` §LlmCallRecord.
  Migration: `priv/repo/migrations/20260507000002_llm_call_records.exs`.

  This row is the queryable shape that mirrors the canonical signed
  predicate (`event_kind = :llm_call_attested` in the `attestations`
  table). The signed predicate is the source of truth (DSSE-wrapped,
  Merkle-anchored); this row is the index.

  ## Enum shapes

    * `:transport` — `"wss" | "https-sse"` (matches LlmProviderConfig
      transport_modes element values)
    * `:principal_kind` — `"obo_human" | "service_account" | "autonomous"`
    * `:error_kind` — nullable; when present, one of `"upstream_4xx" |
      "upstream_5xx" | "parser_failure" | "policy_evaluation_failure" |
      "upstream_connection_failed"` per `streaming_proxy.md` failure-mode table
    * `:decision_summary` — free-form formatted string
      (e.g., `"1 allow, 2 deny"`, `"all allow"`, `"all deny"`); NOT a
      closed enum so no inclusion validation. The partial DB index keys
      off the literal `'all allow'` for the denial dashboard hot path.

  In-memory `validate_inclusion` rejects unknown enum strings at
  changeset time; Postgres CHECK constraints reject unknown strings
  inserted via `Ecto.Adapters.SQL.query!/3` or other bypass paths. Drift
  between the two layers is a bug — keep them in lockstep with the
  migration.
  """

  use Ecto.Schema

  import Ecto.Changeset

  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Tenant
  alias Recurse.Providers.Schemas.ToolUseIntentRecord

  @transport_values ["wss", "https-sse"]

  @principal_kind_values ["obo_human", "service_account", "autonomous"]

  @error_kind_values [
    "upstream_4xx",
    "upstream_5xx",
    "parser_failure",
    "policy_evaluation_failure",
    "upstream_connection_failed"
  ]

  @derive {Jason.Encoder,
           only: [
             :id,
             :tenant_id,
             :signed_predicate_run_id,
             :principal_id,
             :principal_kind,
             :chatgpt_account_id,
             :session_id,
             :provider,
             :upstream_host,
             :transport,
             :model,
             :api_format,
             :request_path,
             :prompt_token_count,
             :completion_token_count,
             :reasoning_token_count,
             :tool_use_intent_count,
             :tool_use_denied_count,
             :decision_summary,
             :upstream_status_code,
             :error_kind,
             :latency_ms,
             :added_latency_ms,
             :started_at,
             :completed_at,
             :inserted_at
           ]}

  schema "llm_call_records" do
    belongs_to(:tenant, Tenant,
      foreign_key: :tenant_id,
      references: :tenant_id,
      type: :string
    )

    field(:signed_predicate_run_id, Ecto.UUID)
    field(:principal_id, :string)
    field(:principal_kind, :string)
    field(:chatgpt_account_id, :string)
    field(:session_id, :string)
    field(:provider, :string)
    field(:upstream_host, :string)
    field(:transport, :string)
    field(:model, :string)
    field(:api_format, :string)
    field(:request_path, :string)
    field(:prompt_hash, :binary)
    field(:response_hash, :binary)
    field(:prompt_token_count, :integer)
    field(:completion_token_count, :integer)
    field(:reasoning_token_count, :integer)
    field(:tool_use_intent_count, :integer, default: 0)
    field(:tool_use_denied_count, :integer, default: 0)
    field(:decision_summary, :string)
    field(:cedar_bundle_hash, :binary)
    field(:upstream_status_code, :integer)
    field(:error_kind, :string)
    field(:latency_ms, :integer)
    field(:added_latency_ms, :integer)
    field(:started_at, :utc_datetime_usec)
    field(:completed_at, :utc_datetime_usec)
    # Spec 012 S6b — detached payload retention (R5E_RETAIN_PAYLOADS).
    # Where the bytes `prompt_hash` / `response_hash` cover were put in the
    # StorageProvider; NULL when retention is off, the capture was
    # truncated, or the put failed. `payload_truncated` says a direction
    # exceeded R5E_RETAIN_PAYLOADS_MAX_BYTES (nothing stored for it).
    field(:prompt_payload_uri, :string)
    field(:response_payload_uri, :string)
    field(:payload_truncated, :boolean, default: false)

    has_many(:intents, ToolUseIntentRecord, foreign_key: :llm_call_record_id)

    timestamps(type: :utc_datetime_usec, updated_at: false)
  end

  @type t :: %__MODULE__{}

  @cast_fields [
    :tenant_id,
    :signed_predicate_run_id,
    :principal_id,
    :principal_kind,
    :chatgpt_account_id,
    :session_id,
    :provider,
    :upstream_host,
    :transport,
    :model,
    :api_format,
    :request_path,
    :prompt_hash,
    :response_hash,
    :prompt_token_count,
    :completion_token_count,
    :reasoning_token_count,
    :tool_use_intent_count,
    :tool_use_denied_count,
    :decision_summary,
    :cedar_bundle_hash,
    :upstream_status_code,
    :error_kind,
    :latency_ms,
    :added_latency_ms,
    :started_at,
    :completed_at,
    :prompt_payload_uri,
    :response_payload_uri,
    :payload_truncated
  ]

  @required_fields [
    :tenant_id,
    :signed_predicate_run_id,
    :principal_id,
    :principal_kind,
    :session_id,
    :provider,
    :upstream_host,
    :transport,
    :model,
    :api_format,
    :request_path,
    :prompt_hash,
    :response_hash,
    :prompt_token_count,
    :completion_token_count,
    :tool_use_intent_count,
    :tool_use_denied_count,
    :decision_summary,
    :cedar_bundle_hash,
    :upstream_status_code,
    :latency_ms,
    :added_latency_ms,
    :started_at,
    :completed_at
  ]

  @doc """
  Cast + validate an `LlmCallRecord` row.

  In-memory validations:
    * required fields present
    * `:transport` ∈ `#{inspect(@transport_values)}`
    * `:principal_kind` ∈ `#{inspect(@principal_kind_values)}`
    * `:error_kind` is nullable; when present must be one of
      `#{inspect(@error_kind_values)}`
    * token counts and latencies are non-negative
    * `:tool_use_denied_count <= :tool_use_intent_count`
    * `:added_latency_ms <= :latency_ms`
    * SHA-256 hash columns (`:prompt_hash`, `:response_hash`,
      `:cedar_bundle_hash`) are exactly 32 bytes

  DB-layer CHECK constraints + FK constraints catch any bypass paths;
  the schema-level checks are for changeset feedback in the writer.
  """
  @spec changeset(t() | %__MODULE__{}, map()) :: Ecto.Changeset.t()
  def changeset(struct, attrs) do
    struct
    |> cast(attrs, @cast_fields)
    |> validate_required(@required_fields)
    |> validate_inclusion(:transport, @transport_values)
    |> validate_inclusion(:principal_kind, @principal_kind_values)
    |> validate_error_kind()
    |> validate_number(:prompt_token_count, greater_than_or_equal_to: 0)
    |> validate_number(:completion_token_count, greater_than_or_equal_to: 0)
    |> validate_number(:reasoning_token_count, greater_than_or_equal_to: 0)
    |> validate_number(:tool_use_intent_count, greater_than_or_equal_to: 0)
    |> validate_number(:tool_use_denied_count, greater_than_or_equal_to: 0)
    |> validate_number(:latency_ms, greater_than_or_equal_to: 0)
    |> validate_number(:added_latency_ms, greater_than_or_equal_to: 0)
    |> validate_count_consistency()
    |> validate_latency_consistency()
    |> validate_hash_length(:prompt_hash)
    |> validate_hash_length(:response_hash)
    |> validate_hash_length(:cedar_bundle_hash)
    |> foreign_key_constraint(:tenant_id)
    |> foreign_key_constraint(:signed_predicate_run_id,
      name: :llm_call_records_signed_predicate_run_id_fkey
    )
  end

  defp validate_error_kind(changeset) do
    validate_change(changeset, :error_kind, fn :error_kind, value ->
      cond do
        is_nil(value) -> []
        value in @error_kind_values -> []
        true -> [error_kind: "is invalid; expected one of #{inspect(@error_kind_values)} or nil"]
      end
    end)
  end

  defp validate_count_consistency(changeset) do
    intent = get_field(changeset, :tool_use_intent_count)
    denied = get_field(changeset, :tool_use_denied_count)

    if is_integer(intent) and is_integer(denied) and denied > intent do
      add_error(
        changeset,
        :tool_use_denied_count,
        "must be <= tool_use_intent_count"
      )
    else
      changeset
    end
  end

  defp validate_latency_consistency(changeset) do
    latency = get_field(changeset, :latency_ms)
    added = get_field(changeset, :added_latency_ms)

    if is_integer(latency) and is_integer(added) and added > latency do
      add_error(changeset, :added_latency_ms, "must be <= latency_ms")
    else
      changeset
    end
  end

  defp validate_hash_length(changeset, field) do
    validate_change(changeset, field, fn ^field, value ->
      cond do
        is_nil(value) -> []
        is_binary(value) and byte_size(value) == 32 -> []
        true -> [{field, "must be 32 bytes (SHA-256)"}]
      end
    end)
  end
end
