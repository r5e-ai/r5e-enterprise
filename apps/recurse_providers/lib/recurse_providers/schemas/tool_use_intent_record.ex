defmodule Recurse.Providers.Schemas.ToolUseIntentRecord do
  @moduledoc """
  Ecto schema for the `tool_use_intent_records` table — per-tool-use-intent
  audit row written by the Phase-5 attestation emitter (Sub-3.7) as a
  child of an `LlmCallRecord`. One LlmCallRecord owns 0..N intents
  covering both allowed AND denied decisions.

  Source of truth: `specs/009-llm-api-proxy/data-model.md` §ToolUseIntentRecord.
  Migration: `priv/repo/migrations/20260507000003_tool_use_intent_records.exs`.

  ## Detached payload (Constitution Principle IV)

  `tool_args_inlined` is `:map` (JSONB) and is NULLABLE: when the tool
  args exceed the inlining threshold, only `tool_args_hash` is stored
  here and the raw bytes live in customer-controlled storage via the
  existing payload broker. The hash is always present.

  ## Decision-branch consistency

  The `decision` field is a closed `"allow" | "deny"` enum. Two
  follow-on fields encode the deny branch:

    * `cedar_rule_id` — null for `allow`-by-default; set to the rule ID
      that fired for `deny`
    * `deny_reason` — null for `allow`; required for `deny`

  Both DB CHECK and changeset validation enforce that:
    * `decision = "allow"` → both `cedar_rule_id` and `deny_reason` are
      nil
    * `decision = "deny"` → `deny_reason` is required (cedar_rule_id may
      still be null for fail-closed evaluation failures)

  ## Parallel tool calls

  `parallel_index` is null for non-parallel calls; for OpenAI's
  `parallel_tool_calls=true` it's the 0-based index of this intent in
  the response's parallel-tool array.
  """

  use Ecto.Schema

  import Ecto.Changeset

  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Tenant

  @decision_values ["allow", "deny"]

  @derive {Jason.Encoder,
           only: [
             :id,
             :tenant_id,
             :llm_call_record_id,
             :tool_name,
             :decision,
             :cedar_rule_id,
             :deny_reason,
             :tool_args_size_bytes,
             :parallel_index,
             :call_id,
             :extracted_at,
             :inserted_at
           ]}

  schema "tool_use_intent_records" do
    belongs_to :tenant, Tenant,
      foreign_key: :tenant_id,
      references: :tenant_id,
      type: :string

    belongs_to :llm_call_record, Recurse.Providers.Schemas.LlmCallRecord

    field :tool_name, :string
    field :tool_args_hash, :binary
    field :tool_args_inlined, :map
    field :decision, :string
    field :cedar_rule_id, :string
    field :deny_reason, :string
    field :tool_args_size_bytes, :integer
    field :parallel_index, :integer
    field :call_id, :string
    field :extracted_at, :utc_datetime_usec

    timestamps(type: :utc_datetime_usec, updated_at: false)
  end

  @type t :: %__MODULE__{}

  @cast_fields [
    :tenant_id,
    :llm_call_record_id,
    :tool_name,
    :tool_args_hash,
    :tool_args_inlined,
    :decision,
    :cedar_rule_id,
    :deny_reason,
    :tool_args_size_bytes,
    :parallel_index,
    :call_id,
    :extracted_at
  ]

  @required_fields [
    :tenant_id,
    :tool_name,
    :tool_args_hash,
    :decision,
    :tool_args_size_bytes,
    :call_id,
    :extracted_at
  ]

  @doc """
  Cast + validate a `ToolUseIntentRecord` row.

  In-memory validations:
    * required fields present (NOTE: `:llm_call_record_id` is NOT in
      `@required_fields` — the Sub-3.7 attestation emitter inserts via
      `Ecto.Multi` where the call's `id` is wired in by the second
      Multi step, not present at changeset time)
    * `:decision` ∈ `#{inspect(@decision_values)}`
    * `:tool_args_size_bytes >= 0`
    * `:parallel_index >= 0` when present
    * `:tool_args_hash` is exactly 32 bytes (SHA-256)
    * decision-branch consistency: `allow` → no rule/reason; `deny` →
      reason required

  DB-layer CHECK constraints + FK constraints catch any bypass paths.
  """
  @spec changeset(t() | %__MODULE__{}, map()) :: Ecto.Changeset.t()
  def changeset(struct, attrs) do
    struct
    |> cast(attrs, @cast_fields)
    |> validate_required(@required_fields)
    |> validate_inclusion(:decision, @decision_values)
    |> validate_number(:tool_args_size_bytes, greater_than_or_equal_to: 0)
    |> validate_number(:parallel_index, greater_than_or_equal_to: 0)
    |> validate_hash_length(:tool_args_hash)
    |> validate_decision_consistency()
    |> foreign_key_constraint(:tenant_id)
    |> foreign_key_constraint(:llm_call_record_id)
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

  defp validate_decision_consistency(changeset) do
    decision = get_field(changeset, :decision)
    cedar_rule_id = get_field(changeset, :cedar_rule_id)
    deny_reason = get_field(changeset, :deny_reason)

    case decision do
      "allow" ->
        changeset
        |> reject_when_nonnil(:cedar_rule_id, cedar_rule_id, "must be nil when decision = allow")
        |> reject_when_nonnil(:deny_reason, deny_reason, "must be nil when decision = allow")

      "deny" ->
        if is_nil(deny_reason) do
          add_error(changeset, :deny_reason, "must be present when decision = deny")
        else
          changeset
        end

      _ ->
        # validate_inclusion already added the error
        changeset
    end
  end

  defp reject_when_nonnil(changeset, _field, nil, _msg), do: changeset
  defp reject_when_nonnil(changeset, field, _value, msg), do: add_error(changeset, field, msg)
end
